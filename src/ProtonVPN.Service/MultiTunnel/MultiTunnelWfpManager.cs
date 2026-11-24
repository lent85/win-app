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
using System.Linq;
using System.Net;
using ProtonVPN.Logging.Contracts;
using ProtonVPN.Logging.Contracts.Events.SplitTunnelLogs;
using ProtonVPN.NetworkFilter;
using ProtonVPN.Service.SplitTunneling;
using Action = ProtonVPN.NetworkFilter.Action;

namespace ProtonVPN.Service.MultiTunnel;

/// <summary>
/// Manages Windows Filtering Platform (WFP) contexts and priority-ordered filters for Multi-Tunnel Proton VPN.
/// Reuses the EV-signed ProtonVPN.CalloutDriver.sys without kernel driver changes by creating one
/// ProviderContext per active tunnel slot (T1..T5: 10.{2+k}.0.2) plus one for Direct physical bypass.
/// </summary>
public sealed class MultiTunnelWfpManager : IDisposable
{
    private const uint WfpMultiTunnelSublayerWeight = 10001;

    private static readonly Guid ConnectRedirectV4CalloutKey = Guid.Parse("{3c5a284f-af01-51fa-4361-6c6c50424144}");
    private static readonly Guid ConnectRedirectV6CalloutKey = Guid.Parse("{3c5a284f-af01-51fa-4361-6c6c50424145}");
    private static readonly Guid BindRedirectV4CalloutKey = Guid.Parse("{10636af3-50d6-4f53-acb7-d5af33217fca}");
    private static readonly Guid BindRedirectV6CalloutKey = Guid.Parse("{10636af3-50d6-4f53-acb7-d5af33217faa}");

    private readonly ILogger _logger;
    private readonly object _syncLock = new();

    private IpFilter? _ipFilter;
    private Sublayer? _sublayer;

    public MultiTunnelWfpManager(ILogger logger)
    {
        _logger = logger;
    }

    public void ApplyMultiTunnelPolicy(
        IReadOnlyDictionary<string, TunnelSlotRuntimeState> tunnelStates,
        IReadOnlyList<SelectiveRoutingRule> priorityRules,
        IReadOnlyDictionary<Guid, IReadOnlyList<IPAddress>> resolvedDomainIpsByRule,
        IPAddress physicalIpv4Address,
        IPAddress? physicalIpv6Address)
    {
        lock (_syncLock)
        {
            RecreateSession();
            if (_ipFilter is null || _sublayer is null)
            {
                return;
            }

            _ipFilter.Session.StartTransaction();
            try
            {
                Callout connectCalloutV4 = _ipFilter.CreateCallout(
                    new DisplayData("ProtonVPN MultiTunnel Connect Redirect V4", "Redirects TCP/connect flows to target tunnel or physical NIC"),
                    ConnectRedirectV4CalloutKey,
                    Layer.AppConnectRedirectV4);

                Callout bindCalloutV4 = _ipFilter.CreateCallout(
                    new DisplayData("ProtonVPN MultiTunnel UDP Bind Redirect V4", "Redirects UDP sockets to target tunnel or physical NIC"),
                    BindRedirectV4CalloutKey,
                    Layer.BindRedirectV4);

                Callout? connectCalloutV6 = physicalIpv6Address is not null || tunnelStates.Values.Any(t => t.ClientIpv6 is not null)
                    ? _ipFilter.CreateCallout(
                        new DisplayData("ProtonVPN MultiTunnel Connect Redirect V6", "Redirects IPv6 TCP/connect flows"),
                        ConnectRedirectV6CalloutKey,
                        Layer.AppConnectRedirectV6)
                    : null;

                Callout? bindCalloutV6 = connectCalloutV6 is not null
                    ? _ipFilter.CreateCallout(
                        new DisplayData("ProtonVPN MultiTunnel UDP Bind Redirect V6", "Redirects IPv6 UDP sockets"),
                        BindRedirectV6CalloutKey,
                        Layer.BindRedirectV6)
                    : null;

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

                // 3. Compile Priority Rules in ascending PriorityOrder (higher WFP weight = higher priority)
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
                        connectCalloutV4,
                        bindCalloutV4,
                        connectCalloutV6,
                        bindCalloutV6,
                        resolvedDomainIpsByRule);
                }

                _ipFilter.Session.CommitTransaction();
            }
            catch (Exception ex)
            {
                _ipFilter.Session.AbortTransaction();
                _logger.Error<SplitTunnelLog>("MultiTunnelWfpManager: Failed to commit WFP policy transaction.", ex);
                throw;
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
            foreach (string appPath in SplitEntries(rule.AppPattern!))
            {
                if (shouldBlock)
                {
                    _sublayer.CreateAppFilter(display, Action.HardBlock, Layer.AppAuthConnectV4, weight, appPath, isDnsPortExcluded: false);
                    _sublayer.CreateAppFilter(display, Action.HardBlock, Layer.AppAuthConnectV6, weight, appPath, isDnsPortExcluded: false);
                }
                else if (targetCtxV4 is not null)
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
                        _sublayer.CreateRemoteIPv4Filter(display, Action.HardBlock, Layer.AppAuthConnectV4, weight, ip.ToString());
                    }
                    else if (targetCtxV4 is not null)
                    {
                        _sublayer.CreateRemoteIPv4CalloutFilter(display, Layer.AppConnectRedirectV4, weight, connectCalloutV4, targetCtxV4, ip.ToString());
                        _sublayer.CreateRemoteIPv4Filter(display, Action.HardPermit, Layer.AppAuthConnectV4, weight, ip.ToString());
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
                    Layer authLayer = netAddr.IsIpv6 ? Layer.AppAuthConnectV6 : Layer.AppAuthConnectV4;
                    _sublayer.CreateRemoteNetworkIPFilter(display, Action.HardBlock, authLayer, weight, netAddr);
                }
                else if (!netAddr.IsIpv6 && targetCtxV4 is not null)
                {
                    _sublayer.CreateRemoteNetworkCalloutFilter(display, Layer.AppConnectRedirectV4, weight, connectCalloutV4, targetCtxV4, netAddr);
                    _sublayer.CreateRemoteNetworkIPFilter(display, Action.HardPermit, Layer.AppAuthConnectV4, weight, netAddr);
                }
                else if (netAddr.IsIpv6 && targetCtxV6 is not null && connectCalloutV6 is not null)
                {
                    _sublayer.CreateRemoteNetworkCalloutFilter(display, Layer.AppConnectRedirectV6, weight, connectCalloutV6, targetCtxV6, netAddr);
                    _sublayer.CreateRemoteNetworkIPFilter(display, Action.HardPermit, Layer.AppAuthConnectV6, weight, netAddr);
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
            }
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

    private void RecreateSession()
    {
        RemoveSession();

        _ipFilter = IpFilter.Create(
            Session.Dynamic(),
            new DisplayData { Name = "Proton AG", Description = "ProtonVPN Multi-Tunnel Selective Routing Provider" });

        _sublayer = _ipFilter.CreateSublayer(
            new DisplayData { Name = "ProtonVPN Multi-Tunnel Selective Routing Sublayer" },
            WfpMultiTunnelSublayerWeight);
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
