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
using System.Runtime.InteropServices;
using ProtonVPN.Logging.Contracts;
using ProtonVPN.Logging.Contracts.Events.SplitTunnelLogs;
using ProtonVPN.NetworkFilter;
using ProtonVPN.Service.SplitTunneling;
using Action = ProtonVPN.NetworkFilter.Action;
using FirewallIpFilter = ProtonVPN.Service.Firewall.IpFilter;
using FirewallSessionType = ProtonVPN.NetworkFilter.SessionType;

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
    // ProtonVPN.IpFilter.dll / WFP FWP_UINT8 filter weight must be in 0..15.
    private const uint SafetyFilterWeight = 15;
    private const uint MaxRuleFilterWeight = 14;
    private const uint MinRuleFilterWeight = 2;
    private const uint DefaultPolicyFilterWeight = 1;
    private const uint FirewallBridgePermitWeight = 14;
    private const uint FirewallDefaultDirectWeight = 2;
    private const uint ProcessQueryLimitedInformation = 0x1000;

    private static readonly Guid ConnectRedirectV4CalloutKey = Guid.Parse("{3c5a284f-af01-51fa-4361-6c6c50424144}");
    private static readonly Guid ConnectRedirectV6CalloutKey = Guid.Parse("{3c5a284f-af01-51fa-4361-6c6c50424145}");
    private static readonly Guid BindRedirectV4CalloutKey = Guid.Parse("{10636af3-50d6-4f53-acb7-d5af33217fca}");
    private static readonly Guid BindRedirectV6CalloutKey = Guid.Parse("{10636af3-50d6-4f53-acb7-d5af33217faa}");

    private readonly ILogger _logger;
    private readonly FirewallIpFilter? _firewallIpFilter;
    private readonly object _syncLock = new();
    private readonly List<(FirewallSessionType SessionType, Guid FilterId)> _firewallBridgeFilters = [];

    private IpFilter? _ipFilter;
    private Sublayer? _sublayer;
    private Callout? _connectCalloutV4;
    private Callout? _bindCalloutV4;
    private Callout? _connectCalloutV6;
    private Callout? _bindCalloutV6;

    public MultiTunnelWfpManager(ILogger logger, FirewallIpFilter? firewallIpFilter = null)
    {
        _logger = logger;
        _firewallIpFilter = firewallIpFilter;
    }

    /// <summary>
    /// Maps rule priority (1 = highest) into valid native WFP FWP_UINT8 weight (2..14).
    /// Safety exemptions use 15; unmatched default catch-all uses 1.
    /// </summary>
    public static uint ComputeNativeWfpWeight(int priorityOrder)
    {
        int order = Math.Max(1, priorityOrder);
        return (uint)Math.Clamp((int)MaxRuleFilterWeight - (order - 1), (int)MinRuleFilterWeight, (int)MaxRuleFilterWeight);
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

                    // 4. Compile Priority Rules in ascending PriorityOrder (higher native WFP weight 2..14 = higher priority)
                    int appFilterGroupsCreated = 0;
                    foreach (SelectiveRoutingRule rule in priorityRules.Where(r => r.IsEnabled && r.HasAnyCondition).OrderBy(r => r.PriorityOrder))
                    {
                        uint weight = ComputeNativeWfpWeight(rule.PriorityOrder);
                        appFilterGroupsCreated += ApplyRuleFilters(
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

                    // 5. Enforce Default Unmatched Policy at native WFP weight 1
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

                    // 6. Bridge secondary slot interfaces & Direct rules in ProtonVPN's main Firewall sublayer
                    ApplyFirewallBridgeFilters(
                        tunnelStates,
                        priorityRules,
                        resolvedDomainIpsByRule,
                        defaultTargetType,
                        includeIpv6);

                    _logger.Info<SplitTunnelLog>(
                        $"MultiTunnelWfpManager: Committed WFP policy ({appFilterGroupsCreated} app filter group(s), {_firewallBridgeFilters.Count} firewall bridge filter(s)).");
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

    private int ApplyRuleFilters(
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
            return 0;
        }

        int appFilterGroupsCreated = 0;

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
                IReadOnlyList<string> resolvedPaths = ResolveAppExecutablePaths(rawAppPath);
                if (resolvedPaths.Count == 0)
                {
                    _logger.Warn<SplitTunnelLog>(
                        $"MultiTunnelWfpManager: Rule #{rule.PriorityOrder} '{rule.Name}' app '{rawAppPath}' resolved to 0 executable paths; waiting for process launch or browse exact .exe.");
                }

                foreach (string appPath in resolvedPaths)
                {
                    if (shouldBlock)
                    {
                        SafeRunWfpFilter(() =>
                        {
                            _sublayer.CreateAppFilter(display, Action.HardBlock, Layer.AppAuthConnectV4, weight, appPath, isDnsPortExcluded: false);
                            _sublayer.CreateAppFilter(display, Action.HardBlock, Layer.AppAuthConnectV6, weight, appPath, isDnsPortExcluded: false);
                            appFilterGroupsCreated++;
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
                                _sublayer.CreateAppFilter(display, Action.HardPermit, Layer.AppAuthConnectV6, weight, appPath, isDnsPortExcluded: false);
                            }
                            else
                            {
                                _sublayer.CreateAppFilter(display, Action.HardBlock, Layer.AppAuthConnectV6, weight, appPath, isDnsPortExcluded: false);
                            }
                            appFilterGroupsCreated++;
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

        return appFilterGroupsCreated;
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
                        _sublayer.CreateRemoteNetworkIPFilter(endpointDisplay, Action.HardPermit, Layer.AppConnectRedirectV4, SafetyFilterWeight, netAddr);
                        _sublayer.CreateRemoteNetworkIPFilter(endpointDisplay, Action.HardPermit, Layer.AppAuthConnectV4, SafetyFilterWeight, netAddr);
                    }, $"SafetyEndpointV4 '{slot.EntryIp}'");
                }
                else if (entryIp.AddressFamily == AddressFamily.InterNetworkV6 && includeIpv6)
                {
                    NetworkAddress netAddr = NetworkAddress.FromIpv6(entryIp.ToString(), 128);
                    SafeRunWfpFilter(() =>
                    {
                        _sublayer.CreateRemoteNetworkIPFilter(endpointDisplay, Action.HardPermit, Layer.AppConnectRedirectV6, SafetyFilterWeight, netAddr);
                        _sublayer.CreateRemoteNetworkIPFilter(endpointDisplay, Action.HardPermit, Layer.AppAuthConnectV6, SafetyFilterWeight, netAddr);
                    }, $"SafetyEndpointV6 '{slot.EntryIp}'");
                }
            }

            if (slot.InterfaceIndex > 0 && !string.Equals(slot.SlotId, "T1", StringComparison.OrdinalIgnoreCase))
            {
                DisplayData ifaceDisplay = new($"ProtonVPN MultiTunnel Interface Permit ({slot.SlotId})", "Permits secondary tunnel interface traffic");
                SafeRunWfpFilter(() =>
                {
                    _sublayer.CreateNetInterfaceFilter(ifaceDisplay, Action.HardPermit, Layer.AppAuthConnectV4, slot.InterfaceIndex, SafetyFilterWeight);
                    if (includeIpv6)
                    {
                        _sublayer.CreateNetInterfaceFilter(ifaceDisplay, Action.HardPermit, Layer.AppAuthConnectV6, slot.InterfaceIndex, SafetyFilterWeight);
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
                    _sublayer.CreateRemoteNetworkIPFilter(subnetDisplay, Action.HardPermit, Layer.AppConnectRedirectV4, SafetyFilterWeight, subnetAddr);
                    _sublayer.CreateRemoteNetworkIPFilter(subnetDisplay, Action.HardPermit, Layer.AppAuthConnectV4, SafetyFilterWeight, subnetAddr);
                }, $"SafetySubnet '{slot.SlotId}'");
            }
        }

        DisplayData loopbackDisplay = new("ProtonVPN MultiTunnel Loopback Permit", "Permits loopback traffic without redirect");
        SafeRunWfpFilter(() =>
        {
            _sublayer.CreateLoopbackFilter(loopbackDisplay, Action.HardPermit, Layer.AppConnectRedirectV4, SafetyFilterWeight);
            _sublayer.CreateLoopbackFilter(loopbackDisplay, Action.HardPermit, Layer.AppAuthConnectV4, SafetyFilterWeight);
            if (includeIpv6)
            {
                _sublayer.CreateLoopbackFilter(loopbackDisplay, Action.HardPermit, Layer.AppConnectRedirectV6, SafetyFilterWeight);
                _sublayer.CreateLoopbackFilter(loopbackDisplay, Action.HardPermit, Layer.AppAuthConnectV6, SafetyFilterWeight);
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

        uint weight = DefaultPolicyFilterWeight;
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
                else if (defaultTargetType == RuleTargetType.Tunnel)
                {
                    _sublayer.CreateRemoteNetworkIPFilter(display, Action.HardBlock, Layer.AppAuthConnectV6, weight, allIpv6);
                }
            }, $"DefaultPolicy {defaultTargetType}");
        }
    }

    private void ApplyFirewallBridgeFilters(
        IReadOnlyDictionary<string, TunnelSlotRuntimeState> tunnelStates,
        IReadOnlyList<SelectiveRoutingRule> priorityRules,
        IReadOnlyDictionary<Guid, IReadOnlyList<IPAddress>> resolvedDomainIpsByRule,
        RuleTargetType defaultTargetType,
        bool includeIpv6)
    {
        ClearFirewallBridgeFilters();
        if (_firewallIpFilter is null)
        {
            return;
        }

        List<(FirewallSessionType SessionType, Sublayer Sublayer)> targetSublayers = [];
        if (_firewallIpFilter.DynamicSublayer is not null)
        {
            targetSublayers.Add((FirewallSessionType.Dynamic, _firewallIpFilter.DynamicSublayer));
        }

        try
        {
            if (_firewallIpFilter.PermanentSublayer is not null && _firewallIpFilter.PermanentSublayer.GetFilterCount() > 0)
            {
                targetSublayers.Add((FirewallSessionType.Permanent, _firewallIpFilter.PermanentSublayer));
            }
        }
        catch
        {
        }

        if (targetSublayers.Count == 0)
        {
            return;
        }

        foreach ((FirewallSessionType sessionType, Sublayer fwSublayer) in targetSublayers)
        {
            foreach (TunnelSlotRuntimeState slot in tunnelStates.Values.Where(s => s.IsConnected && s.InterfaceIndex > 0 && !string.Equals(s.SlotId, "T1", StringComparison.OrdinalIgnoreCase)))
            {
                DisplayData ifaceDisplay = new($"ProtonVPN MultiTunnel Secondary Interface Permit ({slot.SlotId})", "Allows redirected Multi-Tunnel slot traffic through firewall sublayer");
                SafeAddBridgeFilter(sessionType, () => fwSublayer.CreateNetInterfaceFilter(ifaceDisplay, Action.HardPermit, Layer.AppAuthConnectV4, slot.InterfaceIndex, FirewallBridgePermitWeight, persistent: false));
                if (includeIpv6)
                {
                    SafeAddBridgeFilter(sessionType, () => fwSublayer.CreateNetInterfaceFilter(ifaceDisplay, Action.HardPermit, Layer.AppAuthConnectV6, slot.InterfaceIndex, FirewallBridgePermitWeight, persistent: false));
                    SafeAddBridgeFilter(sessionType, () => fwSublayer.CreateNetInterfaceFilter(ifaceDisplay, Action.HardPermit, Layer.AppAuthRecvAcceptV6, slot.InterfaceIndex, FirewallBridgePermitWeight, persistent: false));
                }
            }

            foreach (SelectiveRoutingRule rule in priorityRules.Where(r => r.IsEnabled && r.HasAnyCondition))
            {
                bool isEffectiveDirect = rule.TargetType == RuleTargetType.Direct ||
                    (rule.TargetType == RuleTargetType.Tunnel &&
                     (!tunnelStates.TryGetValue(rule.TargetTunnelId.ToUpperInvariant(), out TunnelSlotRuntimeState? targetSlot) || !targetSlot.IsConnected) &&
                     rule.FallbackBehavior == TunnelFallbackBehavior.FallbackToDirect);

                if (!isEffectiveDirect)
                {
                    continue;
                }

                DisplayData directRuleDisplay = new($"ProtonVPN MultiTunnel Direct Permit #{rule.PriorityOrder}", rule.Name);
                if (rule.HasAppCondition && !rule.HasDomainCondition && !rule.HasIpCondition)
                {
                    foreach (string rawApp in SplitEntries(rule.AppPattern!))
                    {
                        foreach (string appPath in ResolveAppExecutablePaths(rawApp))
                        {
                            SafeAddBridgeFilter(sessionType, () => fwSublayer.CreateAppFilter(directRuleDisplay, Action.HardPermit, Layer.AppAuthConnectV4, FirewallBridgePermitWeight, appPath, isDnsPortExcluded: false, persistent: false));
                            if (includeIpv6)
                            {
                                SafeAddBridgeFilter(sessionType, () => fwSublayer.CreateAppFilter(directRuleDisplay, Action.HardPermit, Layer.AppAuthConnectV6, FirewallBridgePermitWeight, appPath, isDnsPortExcluded: false, persistent: false));
                            }
                        }
                    }
                }

                if (rule.HasIpCondition)
                {
                    foreach (string rawCidr in SplitEntries(rule.IpCidrPattern!))
                    {
                        if (TryParseNetworkAddress(rawCidr, out NetworkAddress netAddr))
                        {
                            Layer authLayer = netAddr.IsIpv6 ? Layer.AppAuthConnectV6 : Layer.AppAuthConnectV4;
                            SafeAddBridgeFilter(sessionType, () => fwSublayer.CreateRemoteNetworkIPFilter(directRuleDisplay, Action.HardPermit, authLayer, FirewallBridgePermitWeight, netAddr, persistent: false));
                        }
                    }
                }

                if (rule.HasDomainCondition && resolvedDomainIpsByRule.TryGetValue(rule.Id, out IReadOnlyList<IPAddress>? ips))
                {
                    foreach (IPAddress ip in ips.Where(i => i.AddressFamily == AddressFamily.InterNetwork))
                    {
                        SafeAddBridgeFilter(sessionType, () => fwSublayer.CreateRemoteIPv4Filter(directRuleDisplay, Action.HardPermit, Layer.AppAuthConnectV4, FirewallBridgePermitWeight, ip.ToString(), persistent: false));
                    }
                }
            }

            if (defaultTargetType == RuleTargetType.Direct)
            {
                DisplayData defaultDirectDisplay = new("ProtonVPN MultiTunnel Default Direct Permit", "Allows unmatched traffic to go Direct past base kill-switch block");
                SafeAddBridgeFilter(sessionType, () => fwSublayer.CreateLayerFilter(defaultDirectDisplay, Action.SoftPermit, Layer.AppAuthConnectV4, FirewallDefaultDirectWeight, persistent: false));
            }
        }
    }

    private void SafeAddBridgeFilter(FirewallSessionType sessionType, Func<Guid> createFilter)
    {
        try
        {
            Guid id = createFilter();
            if (id != Guid.Empty)
            {
                _firewallBridgeFilters.Add((sessionType, id));
            }
        }
        catch (NetworkFilterException ex)
        {
            _logger.Warn<SplitTunnelLog>($"MultiTunnelWfpManager: Failed to create firewall bridge filter (Code: {ex.Code}).");
        }
    }

    private void ClearFirewallBridgeFilters()
    {
        if (_firewallIpFilter is null || _firewallBridgeFilters.Count == 0)
        {
            _firewallBridgeFilters.Clear();
            return;
        }

        foreach ((FirewallSessionType sessionType, Guid filterId) in _firewallBridgeFilters)
        {
            try
            {
                _firewallIpFilter.GetSublayer(sessionType)?.DestroyFilter(filterId);
            }
            catch
            {
            }
        }

        _firewallBridgeFilters.Clear();
    }

    public static IReadOnlyList<string> ResolveAppExecutablePaths(
        string rawAppEntry,
        IEnumerable<string>? additionalUserProfileRoots = null)
    {
        string trimmed = rawAppEntry.Trim().Trim('"');
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return [];
        }

        if (Path.IsPathRooted(trimmed))
        {
            if (!File.Exists(trimmed))
            {
                return [];
            }

            HashSet<string> rootedMatches = new(StringComparer.OrdinalIgnoreCase) { trimmed };
            try
            {
                string? dir = Path.GetDirectoryName(trimmed);
                string fileName = Path.GetFileName(trimmed);
                if (!string.IsNullOrEmpty(dir) && !string.IsNullOrEmpty(fileName) && Directory.Exists(dir))
                {
                    foreach (string subDir in Directory.EnumerateDirectories(dir))
                    {
                        string candidate = Path.Combine(subDir, fileName);
                        if (File.Exists(candidate))
                        {
                            rootedMatches.Add(candidate);
                        }
                    }
                }
            }
            catch
            {
            }

            return rootedMatches.ToList();
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
                    string? path = TryGetProcessImagePath(proc);
                    if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
                    {
                        resolved.Add(path);
                    }
                }
            }
        }
        catch
        {
        }

        foreach (string candidate in GetInstallCandidates(processName.ToLowerInvariant(), exeName, additionalUserProfileRoots))
        {
            if (File.Exists(candidate))
            {
                resolved.Add(candidate);
            }
        }

        return resolved.ToList();
    }

    private static string? TryGetProcessImagePath(Process proc)
    {
        if (OperatingSystem.IsWindows())
        {
            IntPtr hProcess = IntPtr.Zero;
            try
            {
                hProcess = OpenProcess(ProcessQueryLimitedInformation, false, proc.Id);
                if (hProcess != IntPtr.Zero)
                {
                    char[] buffer = new char[1024];
                    int size = buffer.Length;
                    if (QueryFullProcessImageName(hProcess, 0, buffer, ref size) && size > 0)
                    {
                        return new string(buffer, 0, size);
                    }
                }
            }
            catch
            {
            }
            finally
            {
                if (hProcess != IntPtr.Zero)
                {
                    CloseHandle(hProcess);
                }
            }
        }

        try
        {
            return proc.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(
        IntPtr hProcess,
        int dwFlags,
        [Out] char[] lpExeName,
        ref int lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private static IEnumerable<string> GetInstallCandidates(
        string normalizedBaseName,
        string exeName,
        IEnumerable<string>? additionalUserProfileRoots)
    {
        List<string> results = [];

        List<string> localAppDataDirs = [];
        List<string> roamingAppDataDirs = [];

        string envLocal = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!string.IsNullOrWhiteSpace(envLocal))
        {
            localAppDataDirs.Add(envLocal);
        }

        string envRoaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (!string.IsNullOrWhiteSpace(envRoaming))
        {
            roamingAppDataDirs.Add(envRoaming);
        }

        List<string> userRoots = [];
        if (additionalUserProfileRoots is not null)
        {
            userRoots.AddRange(additionalUserProfileRoots.Where(d => !string.IsNullOrWhiteSpace(d) && Directory.Exists(d)));
        }

        if (OperatingSystem.IsWindows())
        {
            string usersParent = @"C:\Users";
            try
            {
                string profileDir = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                if (!string.IsNullOrWhiteSpace(profileDir))
                {
                    string? parent = Path.GetDirectoryName(profileDir);
                    if (!string.IsNullOrWhiteSpace(parent) &&
                        string.Equals(Path.GetFileName(parent), "Users", StringComparison.OrdinalIgnoreCase))
                    {
                        usersParent = parent;
                    }
                }

                if (Directory.Exists(usersParent))
                {
                    foreach (string dir in Directory.EnumerateDirectories(usersParent))
                    {
                        string leaf = Path.GetFileName(dir);
                        if (string.Equals(leaf, "Public", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(leaf, "Default", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(leaf, "Default User", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(leaf, "All Users", StringComparison.OrdinalIgnoreCase))
                        {
                            continue;
                        }
                        userRoots.Add(dir);
                    }
                }
            }
            catch
            {
            }
        }

        foreach (string profileRoot in userRoots.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            string local = Path.Combine(profileRoot, "AppData", "Local");
            if (Directory.Exists(local))
            {
                localAppDataDirs.Add(local);
            }

            string roaming = Path.Combine(profileRoot, "AppData", "Roaming");
            if (Directory.Exists(roaming))
            {
                roamingAppDataDirs.Add(roaming);
            }
        }

        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        void AddIfNotEmpty(string root, params string[] parts)
        {
            if (string.IsNullOrWhiteSpace(root))
            {
                return;
            }
            string[] all = new string[parts.Length + 1];
            all[0] = root;
            Array.Copy(parts, 0, all, 1, parts.Length);
            results.Add(Path.Combine(all));
        }

        void AddWithVersionedSubdirs(string baseDir, string targetExe)
        {
            if (string.IsNullOrWhiteSpace(baseDir))
            {
                return;
            }
            results.Add(Path.Combine(baseDir, targetExe));
            try
            {
                if (Directory.Exists(baseDir))
                {
                    foreach (string subDir in Directory.EnumerateDirectories(baseDir))
                    {
                        string candidate = Path.Combine(subDir, targetExe);
                        if (File.Exists(candidate))
                        {
                            results.Add(candidate);
                        }
                    }
                }
            }
            catch
            {
            }
        }

        switch (normalizedBaseName)
        {
            case "opera":
            case "opera_gx":
            case "operagx":
                AddWithVersionedSubdirs(Path.Combine(programFiles, "Opera"), "opera.exe");
                AddWithVersionedSubdirs(Path.Combine(programFiles, "Opera GX"), "opera.exe");
                AddWithVersionedSubdirs(Path.Combine(programFilesX86, "Opera"), "opera.exe");
                foreach (string local in localAppDataDirs.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    AddWithVersionedSubdirs(Path.Combine(local, "Programs", "Opera"), "opera.exe");
                    AddWithVersionedSubdirs(Path.Combine(local, "Programs", "Opera GX"), "opera.exe");
                    AddWithVersionedSubdirs(Path.Combine(local, "Programs", "Opera Air"), "opera.exe");
                }
                break;

            case "chrome":
                AddIfNotEmpty(programFiles, "Google", "Chrome", "Application", "chrome.exe");
                AddIfNotEmpty(programFilesX86, "Google", "Chrome", "Application", "chrome.exe");
                foreach (string local in localAppDataDirs.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    AddIfNotEmpty(local, "Google", "Chrome", "Application", "chrome.exe");
                }
                break;

            case "msedge":
                AddIfNotEmpty(programFilesX86, "Microsoft", "Edge", "Application", "msedge.exe");
                AddIfNotEmpty(programFiles, "Microsoft", "Edge", "Application", "msedge.exe");
                break;

            case "firefox":
                AddIfNotEmpty(programFiles, "Mozilla Firefox", "firefox.exe");
                AddIfNotEmpty(programFilesX86, "Mozilla Firefox", "firefox.exe");
                break;

            case "brave":
                AddIfNotEmpty(programFiles, "BraveSoftware", "Brave-Browser", "Application", "brave.exe");
                AddIfNotEmpty(programFilesX86, "BraveSoftware", "Brave-Browser", "Application", "brave.exe");
                foreach (string local in localAppDataDirs.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    AddIfNotEmpty(local, "BraveSoftware", "Brave-Browser", "Application", "brave.exe");
                }
                break;

            case "vivaldi":
                AddIfNotEmpty(programFiles, "Vivaldi", "Application", "vivaldi.exe");
                foreach (string local in localAppDataDirs.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    AddIfNotEmpty(local, "Vivaldi", "Application", "vivaldi.exe");
                }
                break;

            case "qbittorrent":
                AddIfNotEmpty(programFiles, "qBittorrent", "qbittorrent.exe");
                AddIfNotEmpty(programFilesX86, "qBittorrent", "qbittorrent.exe");
                break;

            case "transmission":
            case "transmission-qt":
            case "transmission-gtk":
                AddIfNotEmpty(programFiles, "Transmission", "transmission-qt.exe");
                AddIfNotEmpty(programFilesX86, "Transmission", "transmission-qt.exe");
                break;

            case "deluge":
                AddIfNotEmpty(programFiles, "Deluge", "deluge.exe");
                AddIfNotEmpty(programFilesX86, "Deluge", "deluge.exe");
                break;

            case "utorrent":
                foreach (string roaming in roamingAppDataDirs.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    AddIfNotEmpty(roaming, "uTorrent", "uTorrent.exe");
                }
                break;

            case "telegram":
            case "telegram-desktop":
                AddIfNotEmpty(programFiles, "Telegram Desktop", "Telegram.exe");
                foreach (string roaming in roamingAppDataDirs.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    AddIfNotEmpty(roaming, "Telegram Desktop", "Telegram.exe");
                }
                break;

            case "discord":
                foreach (string local in localAppDataDirs.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    AddWithVersionedSubdirs(Path.Combine(local, "Discord"), "Discord.exe");
                    AddIfNotEmpty(local, "Discord", "Update.exe");
                }
                break;

            case "zoom":
                AddIfNotEmpty(programFiles, "Zoom", "bin", "Zoom.exe");
                foreach (string roaming in roamingAppDataDirs.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    AddIfNotEmpty(roaming, "Zoom", "bin", "Zoom.exe");
                }
                break;

            case "steam":
                AddIfNotEmpty(programFilesX86, "Steam", "steam.exe");
                AddIfNotEmpty(programFiles, "Steam", "steam.exe");
                break;

            case "teams":
            case "ms-teams":
                foreach (string local in localAppDataDirs.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    AddIfNotEmpty(local, "Microsoft", "Teams", "current", "Teams.exe");
                }
                break;

            case "slack":
                AddIfNotEmpty(programFiles, "Slack", "slack.exe");
                foreach (string local in localAppDataDirs.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    AddWithVersionedSubdirs(Path.Combine(local, "slack"), "slack.exe");
                }
                break;

            default:
                AddWithVersionedSubdirs(Path.Combine(programFiles, normalizedBaseName), exeName);
                AddWithVersionedSubdirs(Path.Combine(programFilesX86, normalizedBaseName), exeName);
                foreach (string local in localAppDataDirs.Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    AddWithVersionedSubdirs(Path.Combine(local, "Programs", normalizedBaseName), exeName);
                    AddWithVersionedSubdirs(Path.Combine(local, normalizedBaseName), exeName);
                }
                break;
        }

        return results;
    }

    public void Disable()
    {
        lock (_syncLock)
        {
            ClearFirewallBridgeFilters();
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
