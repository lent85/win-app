/*
 * Copyright (c) 2026 Proton AG
 *
 * This file is part of ProtonVPN.
 *
 * ProtonVPN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using ProtonVPN.Logging.Contracts;
using ProtonVPN.Logging.Contracts.Events.SplitTunnelLogs;
using ProtonVPN.NetworkFilter;
using ProtonVPN.Service.SplitTunneling;
using Action = ProtonVPN.NetworkFilter.Action;

namespace ProtonVPN.Service.MultiTunnel;

public interface IMultiTunnelWfpManager : IDisposable
{
    void ApplyMultiTunnelPolicy(
        IReadOnlyDictionary<string, TunnelSlotRuntimeState> tunnelStates,
        IReadOnlyList<SelectiveRoutingRule> priorityRules,
        IReadOnlyDictionary<Guid, IReadOnlyList<IPAddress>> resolvedDomainIpsByRule,
        IPAddress physicalIpv4Address,
        IPAddress? physicalIpv6Address,
        RuleTargetType defaultTargetType = RuleTargetType.Direct,
        string defaultTunnelId = "T1");

    void Disable();
}

/// <summary>
/// Manages Windows Filtering Platform (WFP) contexts and priority-ordered filters for Multi-Tunnel Proton VPN.
/// Reuses the EV-signed ProtonVPN.CalloutDriver.sys without kernel driver changes by creating one
/// ProviderContext per active tunnel slot (T1..T5: 10.{2+k}.0.2) plus one for Direct physical bypass.
/// </summary>
public sealed class MultiTunnelWfpManager : IMultiTunnelWfpManager
{
    private const uint WfpMultiTunnelSublayerWeight = 10002;
    private const uint SafetyEndpointPermitWeight = 65000;
    private const uint SafetySecondaryInterfacePermitWeight = 64900;
    private const uint SafetyTunnelSubnetPermitWeight = 64800;
    private const uint SafetyLoopbackPermitWeight = 64700;

    private static readonly Guid ConnectRedirectV4CalloutKey = Guid.Parse("{3c5a284f-af01-51fa-4361-6c6c50424144}");
    private static readonly Guid ConnectRedirectV6CalloutKey = Guid.Parse("{3c5a284f-af01-51fa-4361-6c6c50424145}");
    private static readonly Guid BindRedirectV4CalloutKey = Guid.Parse("{10636af3-50d6-4f53-acb7-d5af33217fca}");
    private static readonly Guid BindRedirectV6CalloutKey = Guid.Parse("{10636af3-50d6-4f53-acb7-d5af33217faa}");

    private readonly ILogger _logger;
    private readonly object _syncLock = new();

    private IpFilter? _ipFilter;
    private Sublayer? _sublayer;
    private Callout? _connectCalloutV4;
    private Callout? _bindCalloutV4;
    private Callout? _connectCalloutV6;
    private Callout? _bindCalloutV6;

    public MultiTunnelWfpManager(ILogger logger)
    {
        _logger = logger;
    }

    public void ApplyMultiTunnelPolicy(
        IReadOnlyDictionary<string, TunnelSlotRuntimeState> tunnelStates,
        IReadOnlyList<SelectiveRoutingRule> priorityRules,
        IReadOnlyDictionary<Guid, IReadOnlyList<IPAddress>> resolvedDomainIpsByRule,
        IPAddress physicalIpv4Address,
        IPAddress? physicalIpv6Address,
        RuleTargetType defaultTargetType = RuleTargetType.Direct,
        string defaultTunnelId = "T1")
    {
        bool includeIpv6 = physicalIpv6Address is not null || tunnelStates.Values.Any(t => t.ClientIpv6 is not null);

        lock (_syncLock)
        {
            for (int attempt = 0; attempt < 2; attempt++)
            {
                EnsureSession(includeIpv6);
                if (_ipFilter is null || _sublayer is null || _connectCalloutV4 is null || _bindCalloutV4 is null)
                {
                    return;
                }

                _ipFilter.Session.StartTransaction();
                try
                {
                    // Replace all filters atomically within a single WFP transaction to eliminate filter-gap leaks
                    _sublayer.DestroyAllFilters();

                    // 1. Create ProviderContext for Direct physical interface
                    ProviderContext directContextV4 = CreateRedirectContext("Direct-V4", physicalIpv4Address);
                    ProviderContext? directContextV6 = physicalIpv6Address is not null
                        ? CreateRedirectContext("Direct-V6", physicalIpv6Address)
                        : null;

                    // 2. Create ProviderContexts for connected Tunnel Slots T1..T5
                    Dictionary<string, ProviderContext> tunnelContextsV4 = new(StringComparer.OrdinalIgnoreCase);
                    Dictionary<string, ProviderContext> tunnelContextsV6 = new(StringComparer.OrdinalIgnoreCase);

                    foreach ((string slotId, TunnelSlotRuntimeState slot) in tunnelStates)
                    {
                        if (!slot.IsConnected)
                        {
                            continue;
                        }

                        tunnelContextsV4[slotId] = CreateRedirectContext($"{slotId}-V4", slot.ClientIpv4);
                        if (slot.ClientIpv6 is not null)
                        {
                            tunnelContextsV6[slotId] = CreateRedirectContext($"{slotId}-V6", slot.ClientIpv6);
                        }
                    }

                    // 3. Install high-priority safety exemptions (endpoints, secondary NICs, tunnel subnets, loopback)
                    ApplySafetyExemptions(tunnelStates, includeIpv6);

                    // 4. Compile Priority Rules in ascending PriorityOrder (higher WFP weight = higher priority)
                    foreach (SelectiveRoutingRule rule in priorityRules.Where(r => r.IsEnabled && r.HasAnyCondition).OrderBy(r => r.PriorityOrder))
                    {
                        uint weight = PriorityRuleEngine.ComputeWfpWeight(rule.PriorityOrder);
                        ApplyRuleFilters(
                            rule,
                            weight,
                            tunnelStates,
                            tunnelContextsV4,
                            tunnelContextsV6,
                            directContextV4,
                            directContextV6,
                            _connectCalloutV4,
                            _bindCalloutV4,
                            _connectCalloutV6,
                            _bindCalloutV6,
                            resolvedDomainIpsByRule);
                    }

                    // 5. Enforce Default Unmatched Policy at DefaultPolicyWfpWeight (100)
                    ApplyDefaultPolicyFilters(
                        defaultTargetType,
                        defaultTunnelId,
                        tunnelContextsV4,
                        tunnelContextsV6,
                        directContextV4,
                        directContextV6,
                        _connectCalloutV4,
                        _connectCalloutV6);

                    _ipFilter.Session.CommitTransaction();
                    return;
                }
                catch (Exception ex)
                {
                    try
                    {
                        _ipFilter.Session.AbortTransaction();
                    }
                    catch
                    {
                    }

                    RemoveSession();
                    if (attempt == 1)
                    {
                        _logger.Error<SplitTunnelLog>("MultiTunnelWfpManager: Failed to commit WFP policy transaction.", ex);
                        throw;
                    }
                }
            }
        }
    }

    private void ApplyRuleFilters(
        SelectiveRoutingRule rule,
        uint weight,
        IReadOnlyDictionary<string, TunnelSlotRuntimeState> tunnelStates,
        IReadOnlyDictionary<string, ProviderContext> tunnelContextsV4,
        IReadOnlyDictionary<string, ProviderContext> tunnelContextsV6,
        ProviderContext directContextV4,
        ProviderContext? directContextV6,
        Callout connectCalloutV4,
        Callout bindCalloutV4,
        Callout? connectCalloutV6,
        Callout? bindCalloutV6,
        IReadOnlyDictionary<Guid, IReadOnlyList<IPAddress>> resolvedDomainIpsByRule)
    {
        if (_sublayer is null)
        {
            return;
        }

        // Determine effective ProviderContext or Kill-Switch Block action for this rule
        bool shouldBlock = false;
        ProviderContext? targetCtxV4 = null;
        ProviderContext? targetCtxV6 = null;

        if (rule.TargetType == RuleTargetType.Block)
        {
            shouldBlock = true;
        }
        else if (rule.TargetType == RuleTargetType.Direct)
        {
            targetCtxV4 = directContextV4;
            targetCtxV6 = directContextV6;
        }
        else
        {
            string slotId = rule.TargetTunnelId.ToUpperInvariant();
            if (tunnelContextsV4.TryGetValue(slotId, out ProviderContext? ctxV4))
            {
                targetCtxV4 = ctxV4;
                tunnelContextsV6.TryGetValue(slotId, out targetCtxV6);
            }
            else if (rule.FallbackBehavior == TunnelFallbackBehavior.FallbackToTunnel &&
                     !string.IsNullOrWhiteSpace(rule.FallbackTunnelId) &&
                     tunnelContextsV4.TryGetValue(rule.FallbackTunnelId.ToUpperInvariant(), out ProviderContext? fbCtxV4))
            {
                targetCtxV4 = fbCtxV4;
                tunnelContextsV6.TryGetValue(rule.FallbackTunnelId.ToUpperInvariant(), out targetCtxV6);
            }
            else if (rule.FallbackBehavior == TunnelFallbackBehavior.FallbackToDirect)
            {
                targetCtxV4 = directContextV4;
                targetCtxV6 = directContextV6;
            }
            else
            {
                // Per-Tunnel Kill-Switch active for disconnected target tunnel
                shouldBlock = true;
            }
        }

        DisplayData display = new($"ProtonVPN Rule #{rule.PriorityOrder}: {rule.Name}", "Priority Selective Routing Filter");

        // A. App-based rules
        if (rule.HasAppCondition && !rule.HasDomainCondition && !rule.HasIpCondition)
        {
            foreach (string rawAppPath in SplitEntries(rule.AppPattern!))
            {
                foreach (string appPath in ResolveAppExecutablePaths(rawAppPath))
                {
                    if (shouldBlock)
                    {
                        SafeRunWfpFilter(() =>
                        {
                            _sublayer.CreateAppFilter(display, Action.HardBlock, Layer.AppAuthConnectV4, weight, appPath, isDnsPortExcluded: false);
                            _sublayer.CreateAppFilter(display, Action.HardBlock, Layer.AppAuthConnectV6, weight, appPath, isDnsPortExcluded: false);
                        }, $"Rule #{rule.PriorityOrder} AppBlock '{appPath}'");
                    }
                    else if (targetCtxV4 is not null)
                    {
                        SafeRunWfpFilter(() =>
                        {
                            _sublayer.CreateAppCalloutFilter(display, Layer.AppConnectRedirectV4, weight, connectCalloutV4, targetCtxV4, appPath, isDnsPortExcluded: false);
                            _sublayer.CreateAppCalloutFilter(display, Layer.BindRedirectV4, weight, bindCalloutV4, targetCtxV4, appPath, isDnsPortExcluded: false);
                            _sublayer.CreateAppFilter(display, Action.HardPermit, Layer.AppAuthConnectV4, weight, appPath, isDnsPortExcluded: false);

                            if (targetCtxV6 is not null && connectCalloutV6 is not null && bindCalloutV6 is not null)
                            {
                                _sublayer.CreateAppCalloutFilter(display, Layer.AppConnectRedirectV6, weight, connectCalloutV6, targetCtxV6, appPath, isDnsPortExcluded: false);
                                _sublayer.CreateAppCalloutFilter(display, Layer.BindRedirectV6, weight, bindCalloutV6, targetCtxV6, appPath, isDnsPortExcluded: false);
                            }
                            else
                            {
                                _sublayer.CreateAppFilter(display, Action.HardBlock, Layer.AppAuthConnectV6, weight, appPath, isDnsPortExcluded: false);
                            }
                        }, $"Rule #{rule.PriorityOrder} AppRedirect '{appPath}'");
                    }
                }
            }
        }

        // B. Domain-resolved IP rules (installed dynamically by MultiTunnelDnsProxy with rule's priority weight)
        if (rule.HasDomainCondition && resolvedDomainIpsByRule.TryGetValue(rule.Id, out IReadOnlyList<IPAddress>? domainIps))
        {
            foreach (IPAddress ip in domainIps)
            {
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    if (shouldBlock)
                    {
                        SafeRunWfpFilter(
                            () => _sublayer.CreateRemoteIPv4Filter(display, Action.HardBlock, Layer.AppAuthConnectV4, weight, ip.ToString()),
                            $"Rule #{rule.PriorityOrder} DomainBlock '{ip}'");
                    }
                    else if (targetCtxV4 is not null)
                    {
                        SafeRunWfpFilter(() =>
                        {
                            _sublayer.CreateRemoteIPv4CalloutFilter(display, Layer.AppConnectRedirectV4, weight, connectCalloutV4, targetCtxV4, ip.ToString());
                            _sublayer.CreateRemoteIPv4Filter(display, Action.HardPermit, Layer.AppAuthConnectV4, weight, ip.ToString());
                        }, $"Rule #{rule.PriorityOrder} DomainRedirect '{ip}'");
                    }
                }
            }
        }

        // C. Explicit IP / CIDR rules
        if (rule.HasIpCondition)
        {
            foreach (string rawCidr in SplitEntries(rule.IpCidrPattern!))
            {
                if (!TryParseNetworkAddress(rawCidr, out NetworkAddress netAddr))
                {
                    continue;
                }

                if (shouldBlock)
                {
                    SafeRunWfpFilter(() =>
                    {
                        Layer authLayer = netAddr.IsIpv6 ? Layer.AppAuthConnectV6 : Layer.AppAuthConnectV4;
                        _sublayer.CreateRemoteNetworkIPFilter(display, Action.HardBlock, authLayer, weight, netAddr);
                    }, $"Rule #{rule.PriorityOrder} CidrBlock '{rawCidr}'");
                }
                else if (!netAddr.IsIpv6 && targetCtxV4 is not null)
                {
                    SafeRunWfpFilter(() =>
                    {
                        _sublayer.CreateRemoteNetworkCalloutFilter(display, Layer.AppConnectRedirectV4, weight, connectCalloutV4, targetCtxV4, netAddr);
                        _sublayer.CreateRemoteNetworkIPFilter(display, Action.HardPermit, Layer.AppAuthConnectV4, weight, netAddr);
                    }, $"Rule #{rule.PriorityOrder} CidrRedirectV4 '{rawCidr}'");
                }
                else if (netAddr.IsIpv6 && targetCtxV6 is not null && connectCalloutV6 is not null)
                {
                    SafeRunWfpFilter(() =>
                    {
                        _sublayer.CreateRemoteNetworkCalloutFilter(display, Layer.AppConnectRedirectV6, weight, connectCalloutV6, targetCtxV6, netAddr);
                        _sublayer.CreateRemoteNetworkIPFilter(display, Action.HardPermit, Layer.AppAuthConnectV6, weight, netAddr);
                    }, $"Rule #{rule.PriorityOrder} CidrRedirectV6 '{rawCidr}'");
                }
            }
        }

        // D. Explicit Port / Protocol rules (standalone port/protocol rule without App/Domain/IP scope)
        if (rule.HasPortCondition && !string.IsNullOrWhiteSpace(rule.PortPattern) &&
            !rule.HasAppCondition && !rule.HasDomainCondition && !rule.HasIpCondition)
        {
            Action portAction = shouldBlock ? Action.HardBlock : Action.HardPermit;
            foreach (uint port in ExpandPortsBounded(rule.PortPattern, maxPorts: 64))
            {
                SafeRunWfpFilter(() =>
                {
                    if (rule.Protocol is RuleProtocol.Any or RuleProtocol.Tcp)
                    {
                        _sublayer.CreateRemoteTcpPortFilter(display, portAction, Layer.AppAuthConnectV4, weight, port);
                        _sublayer.CreateRemoteTcpPortFilter(display, portAction, Layer.AppAuthConnectV6, weight, port);
                    }

                    if (rule.Protocol is RuleProtocol.Any or RuleProtocol.Udp)
                    {
                        _sublayer.CreateRemoteUdpPortFilter(display, portAction, Layer.AppAuthConnectV4, weight, port);
                        _sublayer.CreateRemoteUdpPortFilter(display, portAction, Layer.AppAuthConnectV6, weight, port);
                    }
                }, $"Rule #{rule.PriorityOrder} Port {port}/{rule.Protocol}");
            }
        }
    }

    private void SafeRunWfpFilter(System.Action action, string context)
    {
        try
        {
            action();
        }
        catch (NetworkFilterException ex)
        {
            _logger.Warn<SplitTunnelLog>($"MultiTunnelWfpManager: Failed to create filter for {context} (Code: {ex.Code}).");
        }
    }

    private static IEnumerable<uint> ExpandPortsBounded(string portPattern, int maxPorts)
    {
        HashSet<uint> ports = [];
        foreach (string token in SplitEntries(portPattern))
        {
            int dashIdx = token.IndexOf('-');
            if (dashIdx > 0)
            {
                if (uint.TryParse(token[..dashIdx].Trim(), out uint start) &&
                    uint.TryParse(token[(dashIdx + 1)..].Trim(), out uint end))
                {
                    if (start > end)
                    {
                        (start, end) = (end, start);
                    }

                    start = Math.Clamp(start, 1u, 65535u);
                    end = Math.Clamp(end, 1u, 65535u);
                    for (uint p = start; p <= end && ports.Count < maxPorts; p++)
                    {
                        ports.Add(p);
                    }
                }
            }
            else if (uint.TryParse(token.Trim(), out uint single) && single is >= 1 and <= 65535)
            {
                ports.Add(single);
            }

            if (ports.Count >= maxPorts)
            {
                break;
            }
        }

        return ports;
    }

    private ProviderContext CreateRedirectContext(string label, IPAddress bindAddress)
    {
        return _ipFilter!.CreateProviderContext(
            new DisplayData
            {
                Name = $"ProtonVPN MultiTunnel Redirect Context ({label})",
                Description = $"Redirects matching flows to local source address {bindAddress}",
            },
            new ConnectRedirectData(bindAddress));
    }

    private void EnsureSession(bool includeIpv6)
    {
        if (_ipFilter is null || _sublayer is null || _connectCalloutV4 is null || _bindCalloutV4 is null)
        {
            RemoveSession();

            _ipFilter = IpFilter.Create(
                Session.Dynamic(),
                new DisplayData { Name = "Proton AG", Description = "ProtonVPN Multi-Tunnel Selective Routing Provider" });

            _sublayer = _ipFilter.CreateSublayer(
                new DisplayData { Name = "ProtonVPN Multi-Tunnel Selective Routing Sublayer" },
                WfpMultiTunnelSublayerWeight);

            _connectCalloutV4 = _ipFilter.CreateCallout(
                new DisplayData("ProtonVPN MultiTunnel Connect Redirect V4", "Redirects TCP/connect flows to target tunnel or physical NIC"),
                ConnectRedirectV4CalloutKey,
                Layer.AppConnectRedirectV4);

            _bindCalloutV4 = _ipFilter.CreateCallout(
                new DisplayData("ProtonVPN MultiTunnel UDP Bind Redirect V4", "Redirects UDP sockets to target tunnel or physical NIC"),
                BindRedirectV4CalloutKey,
                Layer.BindRedirectV4);
        }

        if (includeIpv6 && (_connectCalloutV6 is null || _bindCalloutV6 is null))
        {
            _connectCalloutV6 = _ipFilter.CreateCallout(
                new DisplayData("ProtonVPN MultiTunnel Connect Redirect V6", "Redirects IPv6 TCP/connect flows"),
                ConnectRedirectV6CalloutKey,
                Layer.AppConnectRedirectV6);

            _bindCalloutV6 = _ipFilter.CreateCallout(
                new DisplayData("ProtonVPN MultiTunnel UDP Bind Redirect V6", "Redirects IPv6 UDP sockets"),
                BindRedirectV6CalloutKey,
                Layer.BindRedirectV6);
        }
    }

    private void ApplySafetyExemptions(IReadOnlyDictionary<string, TunnelSlotRuntimeState> tunnelStates, bool includeIpv6)
    {
        if (_sublayer is null)
        {
            return;
        }

        DisplayData endpointDisplay = new("ProtonVPN MultiTunnel Endpoint Permit", "Permits outer VPN server endpoints without redirect loop");
        HashSet<string> permittedEndpoints = new(StringComparer.OrdinalIgnoreCase);

        foreach (TunnelSlotRuntimeState slot in tunnelStates.Values.Where(s => s.IsConnected))
        {
            if (!string.IsNullOrWhiteSpace(slot.EntryIp) &&
                permittedEndpoints.Add(slot.EntryIp) &&
                IPAddress.TryParse(slot.EntryIp, out IPAddress? entryIp))
            {
                if (entryIp.AddressFamily == AddressFamily.InterNetwork)
                {
                    NetworkAddress netAddr = NetworkAddress.FromIpv4(entryIp.ToString(), "255.255.255.255");
                    SafeRunWfpFilter(() =>
                    {
                        _sublayer.CreateRemoteNetworkIPFilter(endpointDisplay, Action.HardPermit, Layer.AppConnectRedirectV4, SafetyEndpointPermitWeight, netAddr);
                        _sublayer.CreateRemoteNetworkIPFilter(endpointDisplay, Action.HardPermit, Layer.AppAuthConnectV4, SafetyEndpointPermitWeight, netAddr);
                    }, $"SafetyEndpointV4 '{slot.EntryIp}'");
                }
                else if (entryIp.AddressFamily == AddressFamily.InterNetworkV6 && includeIpv6)
                {
                    NetworkAddress netAddr = NetworkAddress.FromIpv6(entryIp.ToString(), 128);
                    SafeRunWfpFilter(() =>
                    {
                        _sublayer.CreateRemoteNetworkIPFilter(endpointDisplay, Action.HardPermit, Layer.AppConnectRedirectV6, SafetyEndpointPermitWeight, netAddr);
                        _sublayer.CreateRemoteNetworkIPFilter(endpointDisplay, Action.HardPermit, Layer.AppAuthConnectV6, SafetyEndpointPermitWeight, netAddr);
                    }, $"SafetyEndpointV6 '{slot.EntryIp}'");
                }
            }

            if (slot.InterfaceIndex > 0 && !string.Equals(slot.SlotId, "T1", StringComparison.OrdinalIgnoreCase))
            {
                DisplayData ifaceDisplay = new($"ProtonVPN MultiTunnel Interface Permit ({slot.SlotId})", "Permits secondary tunnel interface traffic");
                SafeRunWfpFilter(() =>
                {
                    _sublayer.CreateNetInterfaceFilter(ifaceDisplay, Action.HardPermit, Layer.AppAuthConnectV4, slot.InterfaceIndex, SafetySecondaryInterfacePermitWeight);
                    if (includeIpv6)
                    {
                        _sublayer.CreateNetInterfaceFilter(ifaceDisplay, Action.HardPermit, Layer.AppAuthConnectV6, slot.InterfaceIndex, SafetySecondaryInterfacePermitWeight);
                    }
                }, $"SafetyInterface '{slot.SlotId}' (#{slot.InterfaceIndex})");
            }

            byte[] ipBytes = slot.ClientIpv4.GetAddressBytes();
            if (ipBytes.Length == 4)
            {
                NetworkAddress subnetAddr = NetworkAddress.FromIpv4($"{ipBytes[0]}.{ipBytes[1]}.0.0", "255.255.0.0");
                DisplayData subnetDisplay = new($"ProtonVPN MultiTunnel Subnet Permit ({slot.SlotId})", "Permits internal tunnel LocalAgent/DNS subnet");
                SafeRunWfpFilter(() =>
                {
                    _sublayer.CreateRemoteNetworkIPFilter(subnetDisplay, Action.HardPermit, Layer.AppConnectRedirectV4, SafetyTunnelSubnetPermitWeight, subnetAddr);
                    _sublayer.CreateRemoteNetworkIPFilter(subnetDisplay, Action.HardPermit, Layer.AppAuthConnectV4, SafetyTunnelSubnetPermitWeight, subnetAddr);
                }, $"SafetySubnet '{slot.SlotId}'");
            }
        }

        DisplayData loopbackDisplay = new("ProtonVPN MultiTunnel Loopback Permit", "Permits loopback traffic without redirect");
        SafeRunWfpFilter(() =>
        {
            _sublayer.CreateLoopbackFilter(loopbackDisplay, Action.HardPermit, Layer.AppConnectRedirectV4, SafetyLoopbackPermitWeight);
            _sublayer.CreateLoopbackFilter(loopbackDisplay, Action.HardPermit, Layer.AppAuthConnectV4, SafetyLoopbackPermitWeight);
            if (includeIpv6)
            {
                _sublayer.CreateLoopbackFilter(loopbackDisplay, Action.HardPermit, Layer.AppConnectRedirectV6, SafetyLoopbackPermitWeight);
                _sublayer.CreateLoopbackFilter(loopbackDisplay, Action.HardPermit, Layer.AppAuthConnectV6, SafetyLoopbackPermitWeight);
            }
        }, "SafetyLoopback");
    }

    private void ApplyDefaultPolicyFilters(
        RuleTargetType defaultTargetType,
        string defaultTunnelId,
        IReadOnlyDictionary<string, ProviderContext> tunnelContextsV4,
        IReadOnlyDictionary<string, ProviderContext> tunnelContextsV6,
        ProviderContext directContextV4,
        ProviderContext? directContextV6,
        Callout connectCalloutV4,
        Callout? connectCalloutV6)
    {
        if (_sublayer is null)
        {
            return;
        }

        uint weight = PriorityRuleEngine.DefaultPolicyWfpWeight;
        DisplayData display = new("ProtonVPN MultiTunnel Default Policy", "Catch-all routing policy when no priority rule matches");
        NetworkAddress allIpv4 = NetworkAddress.FromIpv4("0.0.0.0", "0.0.0.0");
        NetworkAddress allIpv6 = NetworkAddress.FromIpv6("::", 0);

        bool shouldBlock = false;
        ProviderContext? targetCtxV4 = null;
        ProviderContext? targetCtxV6 = null;

        if (defaultTargetType == RuleTargetType.Block)
        {
            shouldBlock = true;
        }
        else if (defaultTargetType == RuleTargetType.Direct)
        {
            targetCtxV4 = directContextV4;
            targetCtxV6 = directContextV6;
        }
        else
        {
            string slotId = string.IsNullOrWhiteSpace(defaultTunnelId) ? "T1" : defaultTunnelId.Trim().ToUpperInvariant();
            if (tunnelContextsV4.TryGetValue(slotId, out ProviderContext? ctxV4))
            {
                targetCtxV4 = ctxV4;
                tunnelContextsV6.TryGetValue(slotId, out targetCtxV6);
            }
            else
            {
                shouldBlock = true;
            }
        }

        if (shouldBlock)
        {
            SafeRunWfpFilter(() =>
            {
                _sublayer.CreateRemoteNetworkIPFilter(display, Action.HardBlock, Layer.AppAuthConnectV4, weight, allIpv4);
                _sublayer.CreateRemoteNetworkIPFilter(display, Action.HardBlock, Layer.AppAuthConnectV6, weight, allIpv6);
            }, "DefaultPolicy Block");
            return;
        }

        if (targetCtxV4 is not null)
        {
            SafeRunWfpFilter(() =>
            {
                _sublayer.CreateRemoteNetworkCalloutFilter(display, Layer.AppConnectRedirectV4, weight, connectCalloutV4, targetCtxV4, allIpv4);
                _sublayer.CreateRemoteNetworkIPFilter(display, Action.HardPermit, Layer.AppAuthConnectV4, weight, allIpv4);

                if (targetCtxV6 is not null && connectCalloutV6 is not null)
                {
                    _sublayer.CreateRemoteNetworkCalloutFilter(display, Layer.AppConnectRedirectV6, weight, connectCalloutV6, targetCtxV6, allIpv6);
                    _sublayer.CreateRemoteNetworkIPFilter(display, Action.HardPermit, Layer.AppAuthConnectV6, weight, allIpv6);
                }
            }, $"DefaultPolicy {defaultTargetType}");
        }
    }

    private IReadOnlyList<string> ResolveAppExecutablePaths(string rawAppEntry)
    {
        string trimmed = rawAppEntry.Trim().Trim('"');
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return [];
        }

        if (Path.IsPathRooted(trimmed))
        {
            return File.Exists(trimmed) ? [trimmed] : [];
        }

        HashSet<string> resolved = new(StringComparer.OrdinalIgnoreCase);
        string exeName = trimmed.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? trimmed : $"{trimmed}.exe";
        string processName = Path.GetFileNameWithoutExtension(exeName);

        try
        {
            foreach (Process proc in Process.GetProcessesByName(processName))
            {
                using (proc)
                {
                    try
                    {
                        string? path = proc.MainModule?.FileName;
                        if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
                        {
                            resolved.Add(path);
                        }
                    }
                    catch
                    {
                    }
                }
            }
        }
        catch
        {
        }

        foreach (string candidate in GetCommonInstallCandidates(processName.ToLowerInvariant(), exeName))
        {
            if (File.Exists(candidate))
            {
                resolved.Add(candidate);
            }
        }

        if (resolved.Count == 0)
        {
            _logger.Debug<SplitTunnelLog>(
                $"MultiTunnelWfpManager: No running process or standard install path found for '{rawAppEntry}'.");
        }

        return resolved.ToList();
    }

    private static IEnumerable<string> GetCommonInstallCandidates(string normalizedBaseName, string exeName)
    {
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        return normalizedBaseName switch
        {
            "chrome" =>
            [
                Path.Combine(programFiles, "Google", "Chrome", "Application", "chrome.exe"),
                Path.Combine(programFilesX86, "Google", "Chrome", "Application", "chrome.exe"),
                Path.Combine(localAppData, "Google", "Chrome", "Application", "chrome.exe"),
            ],
            "msedge" =>
            [
                Path.Combine(programFilesX86, "Microsoft", "Edge", "Application", "msedge.exe"),
                Path.Combine(programFiles, "Microsoft", "Edge", "Application", "msedge.exe"),
            ],
            "firefox" =>
            [
                Path.Combine(programFiles, "Mozilla Firefox", "firefox.exe"),
                Path.Combine(programFilesX86, "Mozilla Firefox", "firefox.exe"),
            ],
            "brave" =>
            [
                Path.Combine(programFiles, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
                Path.Combine(programFilesX86, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
                Path.Combine(localAppData, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
            ],
            "qbittorrent" =>
            [
                Path.Combine(programFiles, "qBittorrent", "qbittorrent.exe"),
                Path.Combine(programFilesX86, "qBittorrent", "qbittorrent.exe"),
            ],
            "transmission" or "transmission-qt" or "transmission-gtk" =>
            [
                Path.Combine(programFiles, "Transmission", "transmission-qt.exe"),
                Path.Combine(programFilesX86, "Transmission", "transmission-qt.exe"),
            ],
            "deluge" =>
            [
                Path.Combine(programFiles, "Deluge", "deluge.exe"),
                Path.Combine(programFilesX86, "Deluge", "deluge.exe"),
            ],
            "utorrent" =>
            [
                Path.Combine(appData, "uTorrent", "uTorrent.exe"),
            ],
            "telegram" or "telegram-desktop" =>
            [
                Path.Combine(appData, "Telegram Desktop", "Telegram.exe"),
                Path.Combine(programFiles, "Telegram Desktop", "Telegram.exe"),
            ],
            "discord" =>
            [
                Path.Combine(localAppData, "Discord", "Update.exe"),
            ],
            "zoom" =>
            [
                Path.Combine(appData, "Zoom", "bin", "Zoom.exe"),
                Path.Combine(programFiles, "Zoom", "bin", "Zoom.exe"),
            ],
            "steam" =>
            [
                Path.Combine(programFilesX86, "Steam", "steam.exe"),
                Path.Combine(programFiles, "Steam", "steam.exe"),
            ],
            "teams" or "ms-teams" =>
            [
                Path.Combine(localAppData, "Microsoft", "Teams", "current", "Teams.exe"),
            ],
            "slack" =>
            [
                Path.Combine(localAppData, "slack", "slack.exe"),
                Path.Combine(programFiles, "Slack", "slack.exe"),
            ],
            _ =>
            [
                Path.Combine(programFiles, normalizedBaseName, exeName),
                Path.Combine(programFilesX86, normalizedBaseName, exeName),
            ],
        };
    }

    public void Disable()
    {
        lock (_syncLock)
        {
            RemoveSession();
        }
    }

    private void RemoveSession()
    {
        try
        {
            _ipFilter?.Session.Close();
        }
        catch (NetworkFilterException ex)
        {
            _logger.Error<SplitTunnelLog>($"MultiTunnelWfpManager: Error closing WFP session ({ex.Code}).", ex);
        }
        finally
        {
            _ipFilter = null;
            _sublayer = null;
            _connectCalloutV4 = null;
            _bindCalloutV4 = null;
            _connectCalloutV6 = null;
            _bindCalloutV6 = null;
        }
    }

    private static string[] SplitEntries(string raw)
    {
        return raw.Split([',', ';', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static bool TryParseNetworkAddress(string cidrOrIp, out NetworkAddress result)
    {
        result = default;
        string trimmed = cidrOrIp.Trim();
        int slashIdx = trimmed.IndexOf('/');
        string ipPart = slashIdx >= 0 ? trimmed[..slashIdx].Trim() : trimmed;

        if (!IPAddress.TryParse(ipPart, out IPAddress? ip))
        {
            return false;
        }

        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            int prefix = 32;
            if (slashIdx >= 0 && (!int.TryParse(trimmed[(slashIdx + 1)..].Trim(), out prefix) || prefix is < 0 or > 32))
            {
                return false;
            }

            uint maskInt = prefix == 0 ? 0 : 0xFFFFFFFFu << (32 - prefix);
            byte[] maskBytes =
            [
                (byte)((maskInt >> 24) & 0xFF),
                (byte)((maskInt >> 16) & 0xFF),
                (byte)((maskInt >> 8) & 0xFF),
                (byte)(maskInt & 0xFF),
            ];
            result = NetworkAddress.FromIpv4(ip.ToString(), new IPAddress(maskBytes).ToString());
            return true;
        }

        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            int prefix = 128;
            if (slashIdx >= 0 && (!int.TryParse(trimmed[(slashIdx + 1)..].Trim(), out prefix) || prefix is < 0 or > 128))
            {
                return false;
            }

            result = NetworkAddress.FromIpv6(ip.ToString(), prefix);
            return true;
        }

        return false;
    }

    public void Dispose()
    {
        Disable();
    }
}
