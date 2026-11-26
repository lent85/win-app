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
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ProtonVPN.Common.Core.Networking;
using ProtonVPN.Configurations.Contracts;
using ProtonVPN.Logging.Contracts;
using ProtonVPN.Logging.Contracts.Events.SplitTunnelLogs;
using ProtonVPN.OperatingSystems.Network.Contracts;
using ProtonVPN.OperatingSystems.Network.Contracts.Routing;
using ProtonVPN.ProcessCommunication.Contracts.Entities.MultiTunnel;
using ProtonVPN.ProcessCommunication.Contracts.Entities.Vpn;
using ProtonVPN.Service.Driver;
using ProtonVPN.Service.Settings;

namespace ProtonVPN.Service.MultiTunnel;

public sealed class MultiTunnelService : IMultiTunnelService
{
    private readonly ILogger _logger;
    private readonly MultiTunnelOrchestrator _orchestrator;
    private readonly IMultiTunnelWfpManager _wfpManager;
    private readonly ICalloutDriver _calloutDriver;
    private readonly INetworkUtilities _networkUtilities;
    private readonly ISystemNetworkInterfaces _networkInterfaces;
    private readonly IConfiguration _config;
    private readonly IServiceSettings _serviceSettings;
    private readonly IMultiTunnelSlotRunner _slotRunner;
    private readonly IRoutingTableHelper? _routingTableHelper;

    public bool EnableBackgroundDnsResolution { get; set; } = true;
    public bool EnableAppProcessWatcher { get; set; } = true;

    private readonly object _lock = new();
    private readonly Dictionary<string, TunnelSlotStateIpcEntity> _configuredSlotMeta = new(StringComparer.OrdinalIgnoreCase);

    private bool _isEnabled;
    private bool _isPrimaryVpnConnected;
    private VpnProtocol _lastProtocol = VpnProtocol.WireGuardUdp;
    private string? _lastAppliedFingerprint;
    private string? _lastDomainRulesSignature;
    private CancellationTokenSource? _dnsResolveCts;
    private CancellationTokenSource? _appWatchCts;

    public bool IsEnabled
    {
        get
        {
            lock (_lock)
            {
                return _isEnabled;
            }
        }
    }

    public MultiTunnelService(
        ILogger logger,
        MultiTunnelOrchestrator orchestrator,
        IMultiTunnelWfpManager wfpManager,
        ICalloutDriver calloutDriver,
        INetworkUtilities networkUtilities,
        ISystemNetworkInterfaces networkInterfaces,
        IConfiguration config,
        IServiceSettings serviceSettings,
        IMultiTunnelSlotRunner? slotRunner = null,
        IRoutingTableHelper? routingTableHelper = null)
    {
        _logger = logger;
        _orchestrator = orchestrator;
        _wfpManager = wfpManager;
        _calloutDriver = calloutDriver;
        _networkUtilities = networkUtilities;
        _networkInterfaces = networkInterfaces;
        _config = config;
        _serviceSettings = serviceSettings;
        _slotRunner = slotRunner!;
        _routingTableHelper = routingTableHelper;
    }

    public void ApplyPolicy(MultiTunnelPolicyIpcEntity policy)
    {
        if (policy is null)
        {
            return;
        }

        lock (_lock)
        {
            _isEnabled = policy.IsMultiTunnelEnabled;

            List<SelectiveRoutingRule> rules = (policy.PriorityRules ?? [])
                .Where(r => r is not null)
                .Select(MapRuleFromIpc)
                .OrderBy(r => r.PriorityOrder)
                .ToList();

            _orchestrator.SetPriorityRules(
                rules,
                MapTargetTypeFromIpc(policy.DefaultTargetType),
                policy.DefaultTunnelId);

            string domainRulesSignature = BuildDomainRulesSignature(rules);
            if (!string.Equals(domainRulesSignature, _lastDomainRulesSignature, StringComparison.Ordinal))
            {
                _lastDomainRulesSignature = domainRulesSignature;
                _orchestrator.DnsRoutingTable.Clear();
            }

            IReadOnlyDictionary<string, TunnelSlotRuntimeState> currentSlots = _orchestrator.GetSlotStates();
            foreach (TunnelSlotStateIpcEntity slot in policy.TunnelSlots ?? [])
            {
                if (slot is null || string.IsNullOrWhiteSpace(slot.SlotId))
                {
                    continue;
                }

                string normalizedId = slot.SlotId.Trim().ToUpperInvariant();
                if (!currentSlots.TryGetValue(normalizedId, out TunnelSlotRuntimeState? runtimeSlot))
                {
                    continue;
                }

                _configuredSlotMeta[normalizedId] = slot;

                if (string.Equals(normalizedId, "T1", StringComparison.OrdinalIgnoreCase) && _isPrimaryVpnConnected)
                {
                    // Preserve live T1 connection and interface IP, while updating display metadata if provided
                    if (!string.IsNullOrWhiteSpace(slot.ServerCountryCode))
                    {
                        runtimeSlot.CountryCode = slot.ServerCountryCode;
                    }
                    if (!string.IsNullOrWhiteSpace(slot.ServerName))
                    {
                        runtimeSlot.ServerName = slot.ServerName;
                    }
                    continue;
                }

                if (_slotRunner is not null)
                {
                    // Runtime connection state for T2..T5 is owned by ConnectSlotAsync/DisconnectSlotAsync.
                    if (!runtimeSlot.IsConnected)
                    {
                        runtimeSlot.CountryCode = slot.ServerCountryCode ?? string.Empty;
                        runtimeSlot.ServerName = slot.ServerName ?? string.Empty;
                        runtimeSlot.EntryIp = slot.EntryIp ?? string.Empty;
                        runtimeSlot.ExitIp = slot.ExitIp ?? string.Empty;
                    }
                    continue;
                }

                if (slot.Status == VpnStatusIpcEntity.Connected)
                {
                    IPAddress? parsedIpv6 = !string.IsNullOrWhiteSpace(slot.ClientIpv6Address) &&
                                            IPAddress.TryParse(slot.ClientIpv6Address, out IPAddress? v6) &&
                                            v6.AddressFamily == AddressFamily.InterNetworkV6
                        ? v6
                        : null;

                    _orchestrator.ActivateSlot(
                        normalizedId,
                        slot.ServerCountryCode ?? string.Empty,
                        slot.ServerName ?? string.Empty,
                        slot.EntryIp ?? string.Empty,
                        slot.ExitIp ?? string.Empty,
                        interfaceIndex: 0,
                        clientIpv6: parsedIpv6);

                    if (IPAddress.TryParse(slot.ClientIpv4Address, out IPAddress? parsedClientIp))
                    {
                        runtimeSlot.ClientIpv4 = parsedClientIp;
                    }
                    if (IPAddress.TryParse(slot.ServerGatewayIpv4Address, out IPAddress? parsedGatewayIp))
                    {
                        runtimeSlot.ServerGatewayIpv4 = parsedGatewayIp;
                    }
                }
                else
                {
                    if (runtimeSlot.IsConnected)
                    {
                        _orchestrator.DeactivateSlot(normalizedId, out _);
                    }
                    runtimeSlot.CountryCode = slot.ServerCountryCode ?? string.Empty;
                    runtimeSlot.ServerName = slot.ServerName ?? string.Empty;
                    runtimeSlot.EntryIp = slot.EntryIp ?? string.Empty;
                    runtimeSlot.ExitIp = slot.ExitIp ?? string.Empty;
                }
            }

            if (!_isEnabled)
            {
                _logger.Info<SplitTunnelLog>("MultiTunnelService: Policy disabled; clearing MultiTunnel WFP filters.");
                CancelBackgroundDnsResolution();
                CancelAppProcessWatcher();
                DisableWfpLocked();
                return;
            }

            bool anyConnected = _orchestrator.GetSlotStates().Values.Any(s => s.IsConnected);
            if (anyConnected)
            {
                ReapplyWfpPolicySafe();
                ScheduleDomainResolution(rules);
                ScheduleAppProcessWatcher(rules);
            }
            else
            {
                CancelBackgroundDnsResolution();
                CancelAppProcessWatcher();
                DisableWfpLocked();
            }
        }
    }

    public void OnVpnConnected(VpnState state)
    {
        lock (_lock)
        {
            _isPrimaryVpnConnected = true;
            _lastProtocol = state.VpnProtocol;

            _configuredSlotMeta.TryGetValue("T1", out TunnelSlotStateIpcEntity? meta);
            string countryCode = meta?.ServerCountryCode ?? string.Empty;
            string serverName = meta?.ServerName ?? string.Empty;
            string remoteIp = state.RemoteIp ?? meta?.EntryIp ?? string.Empty;
            string exitIp = meta?.ExitIp ?? remoteIp;

            IPAddress? localIp = !string.IsNullOrWhiteSpace(state.LocalIp) &&
                                 IPAddress.TryParse(state.LocalIp, out IPAddress? parsedLocalIp)
                ? parsedLocalIp
                : null;
            IPAddress? t1DefaultIp = _orchestrator.GetSlotStates().TryGetValue("T1", out TunnelSlotRuntimeState? existingT1)
                ? existingT1.ClientIpv4
                : null;
            IPAddress? liveIpv6 = ResolveLiveInterfaceIpv6(localIp ?? t1DefaultIp);

            _orchestrator.ActivateSlot(
                "T1",
                countryCode,
                serverName,
                remoteIp,
                exitIp,
                interfaceIndex: 0,
                clientIpv6: liveIpv6);

            IReadOnlyDictionary<string, TunnelSlotRuntimeState> slots = _orchestrator.GetSlotStates();
            if (slots.TryGetValue("T1", out TunnelSlotRuntimeState? t1Slot) && localIp is not null)
            {
                t1Slot.ClientIpv4 = localIp;
            }

            if (_isEnabled)
            {
                IReadOnlyList<SelectiveRoutingRule> rules = _orchestrator.GetPriorityRules();
                ReapplyWfpPolicySafe();
                ScheduleDomainResolution(rules);
                ScheduleAppProcessWatcher(rules);
            }
        }
    }

    public void OnVpnDisconnected(VpnState state, bool isReconnecting)
    {
        lock (_lock)
        {
            if (isReconnecting)
            {
                return;
            }

            _isPrimaryVpnConnected = false;
            _orchestrator.DeactivateSlot("T1", out _);

            bool anyOtherConnected = _orchestrator.GetSlotStates().Values.Any(s => s.IsConnected);
            if (_isEnabled && anyOtherConnected)
            {
                ReapplyWfpPolicySafe();
            }
            else
            {
                CancelBackgroundDnsResolution();
                CancelAppProcessWatcher();
                DisableWfpLocked();
            }
        }
    }

    public async Task<MultiTunnelSlotConnectionResultIpcEntity> ConnectSlotAsync(
        MultiTunnelSlotConnectionRequestIpcEntity request,
        CancellationToken cancelToken)
    {
        MultiTunnelSlotConnectionResultIpcEntity result = _slotRunner is not null
            ? await _slotRunner.ConnectSlotAsync(request, cancelToken).ConfigureAwait(false)
            : new MultiTunnelSlotConnectionResultIpcEntity { Success = false, SlotId = request.SlotId, ErrorMessage = "Slot runner unavailable." };

        if (result.Success)
        {
            lock (_lock)
            {
                if (_isEnabled)
                {
                    IReadOnlyList<SelectiveRoutingRule> rules = _orchestrator.GetPriorityRules();
                    ReapplyWfpPolicySafe();
                    ScheduleDomainResolution(rules);
                    ScheduleAppProcessWatcher(rules);
                }
            }
        }

        return result;
    }

    public async Task DisconnectSlotAsync(string slotId, CancellationToken cancelToken)
    {
        if (_slotRunner is not null)
        {
            await _slotRunner.DisconnectSlotAsync(slotId, cancelToken).ConfigureAwait(false);
        }

        lock (_lock)
        {
            bool anyConnected = _orchestrator.GetSlotStates().Values.Any(s => s.IsConnected);
            if (_isEnabled && anyConnected)
            {
                ReapplyWfpPolicySafe();
            }
            else
            {
                CancelBackgroundDnsResolution();
                CancelAppProcessWatcher();
                DisableWfpLocked();
            }
        }
    }

    public MultiTunnelTrafficSnapshotIpcEntity GetTrafficSnapshot(NetworkTraffic primaryTraffic)
    {
        MultiTunnelTrafficSnapshotIpcEntity snapshot = new();

        lock (_lock)
        {
            snapshot.Slots.Add(new SlotNetworkTrafficIpcEntity
            {
                SlotId = "T1",
                BytesDownloaded = primaryTraffic.BytesDownloaded,
                BytesUploaded = primaryTraffic.BytesUploaded,
                IsConnected = _isPrimaryVpnConnected,
            });
        }

        if (_slotRunner is not null)
        {
            snapshot.Slots.AddRange(_slotRunner.GetSlotTrafficSnapshot());
        }

        return snapshot;
    }

    public void OnServiceStop()
    {
        _slotRunner?.DisconnectAllAsync().GetAwaiter().GetResult();

        lock (_lock)
        {
            CancelBackgroundDnsResolution();
            CancelAppProcessWatcher();
            DisableWfpLocked();
        }
    }

    public MultiTunnelPolicyIpcEntity GetCurrentPolicy()
    {
        lock (_lock)
        {
            IReadOnlyDictionary<string, TunnelSlotRuntimeState> runtimeSlots = _orchestrator.GetSlotStates();
            List<TunnelSlotStateIpcEntity> ipcSlots = [];

            foreach (TunnelSlotRuntimeState runtime in runtimeSlots.Values.OrderBy(s => s.SlotIndex))
            {
                _configuredSlotMeta.TryGetValue(runtime.SlotId, out TunnelSlotStateIpcEntity? meta);
                ipcSlots.Add(new TunnelSlotStateIpcEntity
                {
                    SlotId = runtime.SlotId,
                    SlotIndex = runtime.SlotIndex,
                    AdapterName = $"ProtonVPN-{runtime.SlotId}",
                    Status = runtime.IsConnected ? VpnStatusIpcEntity.Connected : VpnStatusIpcEntity.Disconnected,
                    ClientIpv4Address = runtime.ClientIpv4.ToString(),
                    ServerGatewayIpv4Address = runtime.ServerGatewayIpv4.ToString(),
                    ClientIpv6Address = runtime.ClientIpv6?.ToString(),
                    ServerCountryCode = runtime.CountryCode,
                    ServerName = runtime.ServerName,
                    EntryIp = runtime.EntryIp,
                    ExitIp = runtime.ExitIp,
                    BouncingLabel = meta?.BouncingLabel ?? string.Empty,
                    Protocol = meta?.Protocol ?? VpnProtocolIpcEntity.WireGuardUdp,
                    NetShieldMode = meta?.NetShieldMode ?? 2,
                    PortForwardingEnabled = meta?.PortForwardingEnabled ?? false,
                    ActiveForwardedPort = meta?.ActiveForwardedPort ?? 0,
                    IsDefaultRouteTunnel = meta?.IsDefaultRouteTunnel ?? (runtime.SlotIndex == 0),
                });
            }

            List<SelectiveRoutingRuleIpcEntity> ipcRules = _orchestrator
                .GetPriorityRules()
                .Select(MapRuleToIpc)
                .ToList();

            return new MultiTunnelPolicyIpcEntity
            {
                IsMultiTunnelEnabled = _isEnabled,
                DefaultTargetType = MapTargetTypeToIpc(_orchestrator.DefaultTargetType),
                DefaultTunnelId = _orchestrator.DefaultTunnelId,
                TunnelSlots = ipcSlots,
                PriorityRules = ipcRules,
            };
        }
    }

    public RoutingDecisionIpcEntity EvaluateTraffic(TrafficQueryIpcEntity query)
    {
        TrafficQuery domainQuery = new(
            AppPath: query.AppPath,
            ProcessName: query.ProcessName,
            ActualAppSha256: query.ActualAppSha256,
            Domain: query.Domain,
            RemoteIp: query.RemoteIp,
            RemotePort: query.RemotePort,
            Protocol: MapProtocolFromIpc(query.Protocol));

        RoutingDecision decision = _orchestrator.EvaluateTraffic(domainQuery);

        return new RoutingDecisionIpcEntity
        {
            EffectiveTargetType = MapTargetTypeToIpc(decision.EffectiveTargetType),
            EffectiveTunnelId = decision.EffectiveTunnelId,
            MatchedRuleId = decision.MatchedRule?.Id,
            MatchedRulePriority = decision.MatchedRule?.PriorityOrder ?? 0,
            MatchedRuleName = decision.MatchedRule?.Name ?? string.Empty,
            IsFallbackApplied = decision.IsFallbackApplied,
            IsKillSwitchBlocked = decision.IsKillSwitchBlocked,
            IsHashMismatchBlocked = decision.IsHashMismatchBlocked,
            WfpFilterWeight = decision.WfpFilterWeight,
            Explanation = decision.Explanation,
        };
    }

    private void ReapplyWfpPolicySafe()
    {
        try
        {
            IPAddress? physicalIpv4 = null;
            IPAddress? physicalIpv6 = null;

            if (MultiTunnelNetworkHelper.TryResolvePhysicalInterface(
                    _networkInterfaces,
                    _routingTableHelper,
                    out _,
                    out IPAddress? resolvedV4,
                    out IPAddress? resolvedV6,
                    out _,
                    out _))
            {
                physicalIpv4 = resolvedV4;
                physicalIpv6 = resolvedV6;
            }
            else
            {
                string excludedHardwareId = _config.GetHardwareId(_lastProtocol, _serviceSettings.OpenVpnAdapter);
                IPAddress candidateIpv4 = _networkUtilities.GetBestInterfaceIPv4Address(excludedHardwareId);
                if (!MultiTunnelNetworkHelper.IsTunnelSubnetIpv4(candidateIpv4))
                {
                    physicalIpv4 = candidateIpv4;
                    INetworkInterface bestInterface = _networkInterfaces.GetBestInterfaceExcludingHardwareId(excludedHardwareId);
                    physicalIpv6 = !string.IsNullOrEmpty(bestInterface?.Id)
                        ? bestInterface.GetPreferredIpv6UnicastAddress()
                        : null;
                }
            }

            if (physicalIpv4 is null || physicalIpv4.Equals(IPAddress.None) || physicalIpv4.Equals(IPAddress.Any))
            {
                _logger.Warn<SplitTunnelLog>("MultiTunnelService: Physical IPv4 address unavailable; skipping WFP policy apply.");
                return;
            }

            IReadOnlyDictionary<string, TunnelSlotRuntimeState> slots = _orchestrator.GetSlotStates();
            IReadOnlyList<SelectiveRoutingRule> rules = _orchestrator.GetPriorityRules();
            IReadOnlyDictionary<Guid, IReadOnlyList<IPAddress>> domainIps = _orchestrator.DnsRoutingTable.GetActiveAddressesByRule();
            RuleTargetType defaultTargetType = _orchestrator.DefaultTargetType;
            string defaultTunnelId = _orchestrator.DefaultTunnelId;

            string fingerprint = BuildPolicyFingerprint(
                slots,
                rules,
                domainIps,
                physicalIpv4,
                physicalIpv6,
                defaultTargetType,
                defaultTunnelId);

            if (string.Equals(fingerprint, _lastAppliedFingerprint, StringComparison.Ordinal))
            {
                return;
            }

            _calloutDriver.Start();
            _wfpManager.ApplyMultiTunnelPolicy(
                slots,
                rules,
                domainIps,
                physicalIpv4,
                physicalIpv6,
                defaultTargetType,
                defaultTunnelId);
            _lastAppliedFingerprint = fingerprint;
            _logger.Info<SplitTunnelLog>($"MultiTunnelService: Applied WFP policy ({rules.Count(r => r.IsEnabled)} active rules, physical IPv4 {physicalIpv4}, default {defaultTargetType}).");
        }
        catch (Exception ex)
        {
            _lastAppliedFingerprint = null;
            _logger.Error<SplitTunnelLog>("MultiTunnelService: Failed to apply Multi-Tunnel WFP policy.", ex);
        }
    }

    private IPAddress? ResolveLiveInterfaceIpv6(IPAddress? localIpv4)
    {
        if (localIpv4 is null)
        {
            return null;
        }

        try
        {
            INetworkInterface[]? interfaces = _networkInterfaces.GetInterfaces();
            if (interfaces is null)
            {
                return null;
            }

            foreach (INetworkInterface iface in interfaces)
            {
                List<NetworkAddress> addresses = iface.GetUnicastAddresses();
                if (!addresses.Any(a => !a.IsIpV6 && a.Ip.Equals(localIpv4)))
                {
                    continue;
                }

                IPAddress? preferred = iface.GetPreferredIpv6UnicastAddress();
                if (preferred is not null &&
                    preferred.AddressFamily == AddressFamily.InterNetworkV6 &&
                    !IPAddress.IsLoopback(preferred) &&
                    !preferred.IsIPv6LinkLocal)
                {
                    return preferred;
                }

                NetworkAddress fallbackV6 = addresses.FirstOrDefault(a =>
                    a.IsIpV6 &&
                    !IPAddress.IsLoopback(a.Ip) &&
                    !a.Ip.IsIPv6LinkLocal);

                return fallbackV6.Ip is not null && fallbackV6.Ip.AddressFamily == AddressFamily.InterNetworkV6
                    ? fallbackV6.Ip
                    : null;
            }
        }
        catch
        {
        }

        return null;
    }

    private void DisableWfpLocked()
    {
        _lastAppliedFingerprint = null;
        _wfpManager.Disable();
    }

    private void CancelBackgroundDnsResolution()
    {
        CancellationTokenSource? cts = _dnsResolveCts;
        _dnsResolveCts = null;
        if (cts is null)
        {
            return;
        }

        try
        {
            cts.Cancel();
        }
        catch
        {
        }
    }

    private void ScheduleDomainResolution(IReadOnlyList<SelectiveRoutingRule> rules)
    {
        if (!EnableBackgroundDnsResolution)
        {
            return;
        }

        List<SelectiveRoutingRule> domainRules = rules
            .Where(r => r.IsEnabled && r.HasDomainCondition && !string.IsNullOrWhiteSpace(r.DomainPattern))
            .OrderBy(r => r.PriorityOrder)
            .ToList();

        if (domainRules.Count == 0)
        {
            CancelBackgroundDnsResolution();
            return;
        }

        CancelBackgroundDnsResolution();
        CancellationTokenSource cts = new();
        _dnsResolveCts = cts;
        CancellationToken ct = cts.Token;

        _ = Task.Run(async () =>
        {
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    await ResolveDomainRulesAsync(domainRules, ct).ConfigureAwait(false);
                    await Task.Delay(TimeSpan.FromSeconds(180), ct).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                _logger.Debug<SplitTunnelLog>($"MultiTunnelService: Background domain resolution error: {ex.Message}");
            }
            finally
            {
                cts.Dispose();
            }
        }, ct);
    }

    private async Task ResolveDomainRulesAsync(IReadOnlyList<SelectiveRoutingRule> domainRules, CancellationToken ct)
    {
        List<string> candidates = [];
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

        foreach (SelectiveRoutingRule rule in domainRules)
        {
            foreach (string raw in (rule.DomainPattern ?? string.Empty).Split([',', ';', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                string token = raw.Trim().ToLowerInvariant();
                if (token.StartsWith("keyword:", StringComparison.Ordinal) || token == "*")
                {
                    continue;
                }

                if (token.StartsWith("*.", StringComparison.Ordinal))
                {
                    string baseHost = token[2..].Trim('.');
                    if (!string.IsNullOrWhiteSpace(baseHost) && baseHost.Contains('.'))
                    {
                        if (seen.Add(baseHost))
                        {
                            candidates.Add(baseHost);
                        }
                        string wwwHost = "www." + baseHost;
                        if (seen.Add(wwwHost))
                        {
                            candidates.Add(wwwHost);
                        }
                    }
                }
                else
                {
                    string host = token.Trim('.');
                    if (!string.IsNullOrWhiteSpace(host) && host.Contains('.') && seen.Add(host))
                    {
                        candidates.Add(host);
                    }
                }

                if (candidates.Count >= 64)
                {
                    break;
                }
            }

            if (candidates.Count >= 64)
            {
                break;
            }
        }

        if (candidates.Count == 0)
        {
            return;
        }

        bool anyRegistered = false;
        foreach (string host in candidates)
        {
            if (ct.IsCancellationRequested)
            {
                return;
            }

            try
            {
                using CancellationTokenSource timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(TimeSpan.FromMilliseconds(1500));
                IPAddress[] addresses = await System.Net.Dns.GetHostAddressesAsync(host, timeoutCts.Token).ConfigureAwait(false);
                if (addresses.Length == 0)
                {
                    continue;
                }

                RoutingDecision decision = _orchestrator.EvaluateTraffic(new TrafficQuery(Domain: host));
                if (decision.MatchedRule is null)
                {
                    continue;
                }

                List<DnsResolvedRecord> records = addresses
                    .Where(a => a.AddressFamily == AddressFamily.InterNetwork ||
                                (a.AddressFamily == AddressFamily.InterNetworkV6 && !IPAddress.IsLoopback(a) && !a.IsIPv6LinkLocal))
                    .Select(a => new DnsResolvedRecord(a, 300))
                    .ToList();

                if (records.Count > 0)
                {
                    _orchestrator.DnsRoutingTable.RegisterResolvedAddresses(host, decision, records);
                    anyRegistered = true;
                }
            }
            catch
            {
            }
        }

        if (anyRegistered && !ct.IsCancellationRequested)
        {
            lock (_lock)
            {
                if (_isEnabled && _orchestrator.GetSlotStates().Values.Any(s => s.IsConnected))
                {
                    ReapplyWfpPolicySafe();
                }
            }
        }
    }

    private void ScheduleAppProcessWatcher(IReadOnlyList<SelectiveRoutingRule> rules)
    {
        if (!EnableAppProcessWatcher)
        {
            return;
        }

        List<SelectiveRoutingRule> appRules = rules
            .Where(r => r.IsEnabled && r.HasAppCondition && !string.IsNullOrWhiteSpace(r.AppPattern))
            .OrderBy(r => r.PriorityOrder)
            .ToList();

        if (appRules.Count == 0)
        {
            CancelAppProcessWatcher();
            return;
        }

        CancelAppProcessWatcher();
        CancellationTokenSource cts = new();
        _appWatchCts = cts;
        CancellationToken ct = cts.Token;
        string initialResolvedSignature = ComputeResolvedAppsSignature(appRules);

        _ = Task.Run(async () =>
        {
            string previousSignature = initialResolvedSignature;
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
                    string currentSignature = ComputeResolvedAppsSignature(appRules);
                    if (!string.Equals(currentSignature, previousSignature, StringComparison.Ordinal))
                    {
                        previousSignature = currentSignature;
                        lock (_lock)
                        {
                            if (_isEnabled && _orchestrator.GetSlotStates().Values.Any(s => s.IsConnected))
                            {
                                _lastAppliedFingerprint = null;
                                ReapplyWfpPolicySafe();
                            }
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                _logger.Debug<SplitTunnelLog>($"MultiTunnelService: App process watcher error: {ex.Message}");
            }
            finally
            {
                cts.Dispose();
            }
        }, ct);
    }

    private void CancelAppProcessWatcher()
    {
        CancellationTokenSource? cts = _appWatchCts;
        _appWatchCts = null;
        if (cts is null)
        {
            return;
        }

        try
        {
            cts.Cancel();
        }
        catch
        {
        }
    }

    private static string BuildDomainRulesSignature(IEnumerable<SelectiveRoutingRule> rules)
    {
        StringBuilder sb = new();
        foreach (SelectiveRoutingRule r in rules.Where(r => r.IsEnabled && r.HasDomainCondition).OrderBy(r => r.PriorityOrder))
        {
            sb.Append(r.Id).Append('#').Append(r.PriorityOrder).Append(':')
              .Append(r.DomainPattern).Append('|')
              .Append(r.TargetType).Append('|')
              .Append(r.TargetTunnelId).Append('|')
              .Append(r.FallbackBehavior).Append('|')
              .Append(r.FallbackTunnelId).Append(';');
        }
        return sb.ToString();
    }

    private static string ComputeResolvedAppsSignature(IEnumerable<SelectiveRoutingRule> appRules)
    {
        List<string> tokens = [];
        foreach (SelectiveRoutingRule rule in appRules)
        {
            foreach (string raw in (rule.AppPattern ?? string.Empty).Split([',', ';', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                foreach (string resolved in MultiTunnelWfpManager.ResolveAppExecutablePaths(raw))
                {
                    tokens.Add(resolved);
                }
            }
        }

        tokens.Sort(StringComparer.OrdinalIgnoreCase);
        return string.Join("|", tokens.Distinct(StringComparer.OrdinalIgnoreCase));
    }

    private static string BuildPolicyFingerprint(
        IReadOnlyDictionary<string, TunnelSlotRuntimeState> slots,
        IReadOnlyList<SelectiveRoutingRule> rules,
        IReadOnlyDictionary<Guid, IReadOnlyList<IPAddress>> domainIps,
        IPAddress physicalIpv4,
        IPAddress? physicalIpv6,
        RuleTargetType defaultTargetType,
        string defaultTunnelId)
    {
        StringBuilder sb = new();
        sb.Append(physicalIpv4).Append('|').Append(physicalIpv6?.ToString() ?? "").Append('|')
          .Append(defaultTargetType).Append('|').Append(defaultTunnelId).Append(';');

        foreach (TunnelSlotRuntimeState s in slots.Values.Where(x => x.IsConnected).OrderBy(x => x.SlotIndex))
        {
            sb.Append(s.SlotId).Append(':')
              .Append(s.ClientIpv4).Append(':')
              .Append(s.ClientIpv6?.ToString() ?? "").Append(':')
              .Append(s.EntryIp).Append(':')
              .Append(s.InterfaceIndex).Append(';');
        }

        List<SelectiveRoutingRule> enabledRules = rules
            .Where(x => x.IsEnabled && x.HasAnyCondition)
            .OrderBy(x => x.PriorityOrder)
            .ToList();

        foreach (SelectiveRoutingRule r in enabledRules)
        {
            sb.Append(r.Id).Append('#').Append(r.PriorityOrder).Append(':')
              .Append(r.AppPattern).Append('|')
              .Append(r.DomainPattern).Append('|')
              .Append(r.IpCidrPattern).Append('|')
              .Append(r.PortPattern).Append('|')
              .Append(r.Protocol).Append('|')
              .Append(r.TargetType).Append('|')
              .Append(r.TargetTunnelId).Append('|')
              .Append(r.FallbackBehavior).Append('|')
              .Append(r.FallbackTunnelId);

            if (domainIps.TryGetValue(r.Id, out IReadOnlyList<IPAddress>? ips) && ips.Count > 0)
            {
                sb.Append('{').Append(string.Join(",", ips.Select(i => i.ToString()).OrderBy(x => x, StringComparer.Ordinal))).Append('}');
            }
            sb.Append(';');
        }

        sb.Append("RESOLVED_APPS=").Append(ComputeResolvedAppsSignature(enabledRules.Where(r => r.HasAppCondition)));
        return sb.ToString();
    }

    private static SelectiveRoutingRule MapRuleFromIpc(SelectiveRoutingRuleIpcEntity src)
    {
        return new SelectiveRoutingRule
        {
            Id = src.Id == Guid.Empty ? Guid.NewGuid() : src.Id,
            PriorityOrder = src.PriorityOrder,
            Name = src.Name ?? string.Empty,
            IsEnabled = src.IsEnabled,
            AppPattern = src.AppPattern,
            ExpectedAppSha256 = src.AppSha256,
            IncludeChildProcesses = src.IncludeChildProcesses,
            DomainPattern = src.DomainPattern,
            IpCidrPattern = src.IpCidrPattern,
            PortPattern = src.PortPattern,
            Protocol = MapProtocolFromIpc(src.Protocol),
            TargetType = MapTargetTypeFromIpc(src.TargetType),
            TargetTunnelId = string.IsNullOrWhiteSpace(src.TargetTunnelId) ? "T1" : src.TargetTunnelId.ToUpperInvariant(),
            FallbackBehavior = MapFallbackFromIpc(src.FallbackBehavior),
            FallbackTunnelId = src.FallbackTunnelId,
        };
    }

    private static SelectiveRoutingRuleIpcEntity MapRuleToIpc(SelectiveRoutingRule src)
    {
        return new SelectiveRoutingRuleIpcEntity
        {
            Id = src.Id,
            PriorityOrder = src.PriorityOrder,
            Name = src.Name,
            IsEnabled = src.IsEnabled,
            AppPattern = src.AppPattern,
            AppSha256 = src.ExpectedAppSha256,
            IncludeChildProcesses = src.IncludeChildProcesses,
            DomainPattern = src.DomainPattern,
            IpCidrPattern = src.IpCidrPattern,
            PortPattern = src.PortPattern,
            Protocol = MapProtocolToIpc(src.Protocol),
            TargetType = MapTargetTypeToIpc(src.TargetType),
            TargetTunnelId = src.TargetTunnelId,
            FallbackBehavior = MapFallbackToIpc(src.FallbackBehavior),
            FallbackTunnelId = src.FallbackTunnelId,
        };
    }

    private static RuleTargetType MapTargetTypeFromIpc(RuleTargetTypeIpcEntity val) => val switch
    {
        RuleTargetTypeIpcEntity.Tunnel => RuleTargetType.Tunnel,
        RuleTargetTypeIpcEntity.Block => RuleTargetType.Block,
        _ => RuleTargetType.Direct,
    };

    private static RuleTargetTypeIpcEntity MapTargetTypeToIpc(RuleTargetType val) => val switch
    {
        RuleTargetType.Tunnel => RuleTargetTypeIpcEntity.Tunnel,
        RuleTargetType.Block => RuleTargetTypeIpcEntity.Block,
        _ => RuleTargetTypeIpcEntity.Direct,
    };

    private static RuleProtocol MapProtocolFromIpc(RuleProtocolIpcEntity val) => val switch
    {
        RuleProtocolIpcEntity.Tcp => RuleProtocol.Tcp,
        RuleProtocolIpcEntity.Udp => RuleProtocol.Udp,
        _ => RuleProtocol.Any,
    };

    private static RuleProtocolIpcEntity MapProtocolToIpc(RuleProtocol val) => val switch
    {
        RuleProtocol.Tcp => RuleProtocolIpcEntity.Tcp,
        RuleProtocol.Udp => RuleProtocolIpcEntity.Udp,
        _ => RuleProtocolIpcEntity.Any,
    };

    private static TunnelFallbackBehavior MapFallbackFromIpc(TunnelFallbackBehaviorIpcEntity val) => val switch
    {
        TunnelFallbackBehaviorIpcEntity.FallbackToTunnel => TunnelFallbackBehavior.FallbackToTunnel,
        TunnelFallbackBehaviorIpcEntity.FallbackToDirect => TunnelFallbackBehavior.FallbackToDirect,
        _ => TunnelFallbackBehavior.KillSwitchBlock,
    };

    private static TunnelFallbackBehaviorIpcEntity MapFallbackToIpc(TunnelFallbackBehavior val) => val switch
    {
        TunnelFallbackBehavior.FallbackToTunnel => TunnelFallbackBehaviorIpcEntity.FallbackToTunnel,
        TunnelFallbackBehavior.FallbackToDirect => TunnelFallbackBehaviorIpcEntity.FallbackToDirect,
        _ => TunnelFallbackBehaviorIpcEntity.KillSwitchBlock,
    };
}
