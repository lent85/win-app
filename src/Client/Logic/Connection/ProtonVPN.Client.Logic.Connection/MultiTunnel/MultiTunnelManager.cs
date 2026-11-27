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

using System.Net;
using System.Text.Json;
using ProtonVPN.Client.EventMessaging.Contracts;
using ProtonVPN.Client.Logic.Connection.Contracts;
using ProtonVPN.Client.Logic.Connection.Contracts.Messages;
using ProtonVPN.Client.Logic.Connection.Contracts.Models;
using ProtonVPN.Client.Logic.Connection.Contracts.Models.Intents;
using ProtonVPN.Client.Logic.Connection.Contracts.Models.Intents.Locations.Countries;
using ProtonVPN.Client.Logic.Connection.Contracts.Models.Intents.Locations.Servers;
using ProtonVPN.Client.Logic.Connection.Contracts.MultiTunnel;
using ProtonVPN.Client.Logic.Connection.Contracts.RequestCreators;
using ProtonVPN.Client.Logic.Servers.Contracts;
using ProtonVPN.Client.Logic.Servers.Contracts.Enums;
using ProtonVPN.Client.Logic.Servers.Contracts.Extensions;
using ProtonVPN.Client.Logic.Servers.Contracts.Models;
using ProtonVPN.Client.Logic.Services.Contracts;
using ProtonVPN.Client.Settings.Contracts;
using ProtonVPN.Client.Settings.Contracts.Messages;
using ProtonVPN.Common.Core.Extensions;
using ProtonVPN.Common.Legacy.Abstract;
using ProtonVPN.Common.Legacy.PortForwarding;
using ProtonVPN.Logging.Contracts;
using ProtonVPN.Logging.Contracts.Events.ConnectionLogs;
using ProtonVPN.ProcessCommunication.Contracts.Entities.MultiTunnel;
using ProtonVPN.ProcessCommunication.Contracts.Entities.PortForwarding;
using ProtonVPN.ProcessCommunication.Contracts.Entities.Settings;
using ProtonVPN.ProcessCommunication.Contracts.Entities.Vpn;
using ProtonVPN.StatisticalEvents.Contracts.Dimensions;

namespace ProtonVPN.Client.Logic.Connection.MultiTunnel;

public sealed class MultiTunnelManager : IMultiTunnelManager,
    IEventMessageReceiver<ConnectionStatusChangedMessage>,
    IEventMessageReceiver<ConnectionDetailsChangedMessage>,
    IEventMessageReceiver<SettingChangedMessage>,
    IEventMessageReceiver<PortForwardingPortChangedMessage>,
    IEventMessageReceiver<PortForwardingStatusChangedMessage>
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true,
    };

    private readonly ILogger _logger;
    private readonly ISettings _settings;
    private readonly IVpnServiceCaller _vpnServiceCaller;
    private readonly IConnectionManager _connectionManager;
    private readonly IEventMessageSender _eventMessageSender;
    private readonly IConnectionRequestCreator? _connectionRequestCreator;
    private readonly IServersLoader? _serversLoader;
    private readonly IPortForwardingManager? _portForwardingManager;
    private readonly IMainSettingsRequestCreator? _mainSettingsRequestCreator;

    private readonly object _lock = new();
    private readonly HashSet<string> _busySlots = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _disconnectRequestedSlots = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? _connectAllCts;
    private MultiTunnelPolicyConfig _config = new();
    private List<MultiTunnelRuleConflict> _conflicts = [];

    public bool IsEnabled
    {
        get { lock (_lock) { return _config.IsMultiTunnelEnabled; } }
    }

    public RuleTargetTypeIpcEntity DefaultTargetType
    {
        get { lock (_lock) { return _config.DefaultTargetType; } }
    }

    public string DefaultTunnelId
    {
        get { lock (_lock) { return _config.DefaultTunnelId; } }
    }

    public IReadOnlyList<MultiTunnelSlotConfig> Slots
    {
        get { lock (_lock) { return _config.Slots.OrderBy(s => s.SlotIndex).ToList(); } }
    }

    public IReadOnlyList<MultiTunnelRuleConfig> Rules
    {
        get { lock (_lock) { return _config.Rules.OrderBy(r => r.PriorityOrder).ToList(); } }
    }

    public IReadOnlyList<MultiTunnelRuleConflict> Conflicts
    {
        get { lock (_lock) { return _conflicts.ToList(); } }
    }

    public int EnabledRuleCount
    {
        get { lock (_lock) { return _config.Rules.Count(r => r.IsEnabled && r.HasAnyCondition); } }
    }

    public int ConnectedSlotCount
    {
        get { lock (_lock) { return _config.Slots.Count(s => s.IsConnected); } }
    }

    public bool IsAnySlotConnecting
    {
        get { lock (_lock) { return _config.Slots.Any(s => s.IsConnecting); } }
    }

    public MultiTunnelManager(
        ILogger logger,
        ISettings settings,
        IVpnServiceCaller vpnServiceCaller,
        IConnectionManager connectionManager,
        IEventMessageSender eventMessageSender,
        IConnectionRequestCreator? connectionRequestCreator = null,
        IServersLoader? serversLoader = null,
        IPortForwardingManager? portForwardingManager = null,
        IMainSettingsRequestCreator? mainSettingsRequestCreator = null)
    {
        _logger = logger;
        _settings = settings;
        _vpnServiceCaller = vpnServiceCaller;
        _connectionManager = connectionManager;
        _eventMessageSender = eventMessageSender;
        _connectionRequestCreator = connectionRequestCreator;
        _serversLoader = serversLoader;
        _portForwardingManager = portForwardingManager;
        _mainSettingsRequestCreator = mainSettingsRequestCreator;

        LoadFromSettings();
        ReconcileWithServiceAsync().FireAndForget();
    }

    public async Task SetEnabledAsync(bool enabled)
    {
        List<string> slotsToDisconnect = [];
        if (!enabled)
        {
            lock (_lock)
            {
                slotsToDisconnect = _config.Slots
                    .Where(s => !string.Equals(s.SlotId, "T1", StringComparison.OrdinalIgnoreCase) && (s.IsConnected || s.IsConnecting))
                    .OrderByDescending(s => s.SlotIndex)
                    .Select(s => s.SlotId)
                    .ToList();
            }

            foreach (string slotId in slotsToDisconnect)
            {
                await DisconnectSlotAsync(slotId);
            }
        }

        lock (_lock)
        {
            _config.IsMultiTunnelEnabled = enabled;
            NormalizeAndPersistLocked();
        }

        NotifyChanged();
        await SyncPolicyToServiceAsync();
        await ApplyPrimarySettingsAsync();
    }

    public async Task SetDefaultRoutingAsync(RuleTargetTypeIpcEntity defaultTargetType, string defaultTunnelId)
    {
        lock (_lock)
        {
            _config.DefaultTargetType = defaultTargetType;
            _config.DefaultTunnelId = string.IsNullOrWhiteSpace(defaultTunnelId) ? "T1" : defaultTunnelId.Trim().ToUpperInvariant();
            NormalizeAndPersistLocked();
        }

        NotifyChanged();
        await SyncPolicyToServiceAsync();
    }

    public bool IsSlotPortForwardingEnabled(string slotId)
    {
        if (string.IsNullOrWhiteSpace(slotId))
        {
            return _settings.IsPortForwardingEnabled;
        }

        lock (_lock)
        {
            MultiTunnelSlotConfig? slot = _config.Slots.FirstOrDefault(s =>
                string.Equals(s.SlotId, slotId.Trim(), StringComparison.OrdinalIgnoreCase));
            return slot is not null
                ? slot.ResolveEffectivePortForwarding(_settings.IsPortForwardingEnabled)
                : _settings.IsPortForwardingEnabled;
        }
    }

    public async Task SetSlotPortForwardingOverrideAsync(string slotId, bool? overrideValue)
    {
        if (string.IsNullOrWhiteSpace(slotId))
        {
            return;
        }

        string normalizedId = slotId.Trim().ToUpperInvariant();
        bool changed = false;
        bool effectivePf = _settings.IsPortForwardingEnabled;

        lock (_lock)
        {
            MultiTunnelSlotConfig? slot = _config.Slots.FirstOrDefault(s =>
                string.Equals(s.SlotId, normalizedId, StringComparison.OrdinalIgnoreCase));
            if (slot is null || slot.PortForwardingOverride == overrideValue)
            {
                return;
            }

            slot.PortForwardingOverride = overrideValue;
            effectivePf = slot.ResolveEffectivePortForwarding(_settings.IsPortForwardingEnabled);
            if (!effectivePf)
            {
                slot.ActiveForwardedPort = null;
                slot.PortForwardingStatus = PortMappingStatus.Stopped;
                slot.HasPortForwardingError = false;
            }
            NormalizeAndPersistLocked();
            changed = true;
        }

        if (!changed)
        {
            return;
        }

        if (IsEnabled && string.Equals(normalizedId, "T1", StringComparison.OrdinalIgnoreCase))
        {
            await ApplyPrimarySettingsAsync();
        }

        NotifyChanged();
        await SyncPolicyToServiceAsync();
    }

    private async Task ApplyPrimarySettingsAsync()
    {
        if (!_connectionManager.IsConnected || _mainSettingsRequestCreator is null)
        {
            return;
        }

        try
        {
            MainSettingsIpcEntity settings = _mainSettingsRequestCreator.Create(_connectionManager.CurrentConnectionIntent);
            await _vpnServiceCaller.ApplySettingsAsync(settings);
        }
        catch (Exception ex)
        {
            _logger.Warn<ConnectionLog>($"MultiTunnelManager: Failed to apply primary tunnel settings: {ex.Message}");
        }
    }

    public async Task<MultiTunnelSlotConfig?> AddSlotAsync(
        string countryCode,
        string serverName,
        string city = "",
        string entryIp = "",
        string exitIp = "")
    {
        if (string.IsNullOrWhiteSpace(countryCode))
        {
            return null;
        }

        MultiTunnelSlotConfig? created;
        lock (_lock)
        {
            if (_config.Slots.Count >= MultiTunnelSlotConfig.MaxSlots)
            {
                return null;
            }

            HashSet<int> usedIndices = _config.Slots.Select(s => s.SlotIndex).ToHashSet();
            int nextIndex = -1;
            for (int i = 0; i < MultiTunnelSlotConfig.MaxSlots; i++)
            {
                if (!usedIndices.Contains(i))
                {
                    nextIndex = i;
                    break;
                }
            }

            if (nextIndex < 0)
            {
                return null;
            }

            string effectiveServer = string.IsNullOrWhiteSpace(serverName)
                ? $"{countryCode.Trim().ToUpperInvariant()}#Fastest"
                : serverName.Trim();

            created = MultiTunnelSlotConfig.CreateDefault(nextIndex, countryCode, effectiveServer, city, entryIp, exitIp);
            _config.Slots.Add(created);
            NormalizeAndPersistLocked();
        }

        NotifyChanged();
        await SyncPolicyToServiceAsync();
        return created;
    }

    public async Task UpdateSlotLocationAsync(
        string slotId,
        string countryCode,
        string serverName,
        string city = "",
        string entryIp = "",
        string exitIp = "")
    {
        if (string.IsNullOrWhiteSpace(slotId) || string.IsNullOrWhiteSpace(countryCode))
        {
            return;
        }

        bool shouldReconnectSecondary = false;
        lock (_lock)
        {
            MultiTunnelSlotConfig? slot = _config.Slots.FirstOrDefault(s =>
                string.Equals(s.SlotId, slotId, StringComparison.OrdinalIgnoreCase));
            if (slot is null)
            {
                return;
            }

            slot.CountryCode = countryCode.Trim().ToUpperInvariant();
            slot.ServerName = string.IsNullOrWhiteSpace(serverName)
                ? $"{slot.CountryCode}#Fastest"
                : serverName.Trim();
            slot.City = city.Trim();
            slot.EntryIp = entryIp.Trim();
            slot.ExitIp = exitIp.Trim();

            shouldReconnectSecondary = slot.IsConnected &&
                !string.Equals(slot.SlotId, "T1", StringComparison.OrdinalIgnoreCase);

            NormalizeAndPersistLocked();
        }

        NotifyChanged();
        if (shouldReconnectSecondary)
        {
            await DisconnectSlotAsync(slotId);
            await ConnectSlotAsync(slotId);
            return;
        }

        await SyncPolicyToServiceAsync();
    }

    public async Task RemoveSlotAsync(string slotId)
    {
        if (string.IsNullOrWhiteSpace(slotId) || string.Equals(slotId, "T1", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        bool shouldDisconnectFirst;
        lock (_lock)
        {
            MultiTunnelSlotConfig? existing = _config.Slots.FirstOrDefault(s =>
                string.Equals(s.SlotId, slotId, StringComparison.OrdinalIgnoreCase));
            if (existing is null)
            {
                return;
            }

            shouldDisconnectFirst = existing.IsConnected || existing.IsConnecting;
        }

        if (shouldDisconnectFirst)
        {
            await DisconnectSlotAsync(slotId);
        }

        lock (_lock)
        {
            int removed = _config.Slots.RemoveAll(s => string.Equals(s.SlotId, slotId, StringComparison.OrdinalIgnoreCase));
            if (removed == 0)
            {
                return;
            }

            if (string.Equals(_config.DefaultTunnelId, slotId, StringComparison.OrdinalIgnoreCase))
            {
                _config.DefaultTunnelId = "T1";
            }

            NormalizeAndPersistLocked();
        }

        NotifyChanged();
        await SyncPolicyToServiceAsync();
    }

    public async Task<bool> ConnectSlotAsync(string slotId)
    {
        MultiTunnelSlotConfig? slot;
        string normalizedId;
        lock (_lock)
        {
            slot = _config.Slots.FirstOrDefault(s =>
                string.Equals(s.SlotId, slotId, StringComparison.OrdinalIgnoreCase));
            if (slot is null || string.IsNullOrWhiteSpace(slot.CountryCode))
            {
                return false;
            }

            normalizedId = slot.SlotId.ToUpperInvariant();
            if (!_busySlots.Add(normalizedId))
            {
                return false;
            }

            _disconnectRequestedSlots.Remove(normalizedId);
            slot.IsConnecting = true;
            slot.LastError = null;
        }

        NotifyChanged();

        Server? selectedServer = _serversLoader?.GetServers().FirstOrDefault(s =>
            string.Equals(s.ExitCountry, slot.CountryCode, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(s.Name, slot.ServerName, StringComparison.OrdinalIgnoreCase));
        IConnectionIntent intent = selectedServer is not null
            ? new ConnectionIntent(SingleServerLocationIntent.From(slot.CountryCode, ServerInfo.From(selectedServer.Id, selectedServer.Name)))
            : new ConnectionIntent(SingleCountryLocationIntent.From(slot.CountryCode));

        if (string.Equals(normalizedId, "T1", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                await _connectionManager.ConnectAsync(VpnTriggerDimension.CountriesCountry, intent);
                return true;
            }
            catch (Exception ex)
            {
                lock (_lock)
                {
                    if (_config.Slots.FirstOrDefault(s => string.Equals(s.SlotId, "T1", StringComparison.OrdinalIgnoreCase)) is { } t1)
                    {
                        t1.LastError = ex.Message;
                        t1.IsConnecting = false;
                    }
                    _busySlots.Remove(normalizedId);
                }
                NotifyChanged();
                return false;
            }
            finally
            {
                lock (_lock)
                {
                    _busySlots.Remove(normalizedId);
                    if (_config.Slots.FirstOrDefault(s => string.Equals(s.SlotId, "T1", StringComparison.OrdinalIgnoreCase)) is { } t1)
                    {
                        t1.IsConnecting = _connectionManager.IsConnecting;
                    }
                }
            }
        }

        if (_connectionRequestCreator is null)
        {
            _logger.Warn<ConnectionLog>($"MultiTunnelManager: Cannot connect secondary slot {normalizedId} without IConnectionRequestCreator.");
            lock (_lock)
            {
                _busySlots.Remove(normalizedId);
                if (_config.Slots.FirstOrDefault(s => string.Equals(s.SlotId, normalizedId, StringComparison.OrdinalIgnoreCase)) is { } target)
                {
                    target.IsConnecting = false;
                    target.LastError = "Connection request creator unavailable.";
                }
            }
            NotifyChanged();
            return false;
        }

        try
        {
            bool effectivePf = slot.ResolveEffectivePortForwarding(_settings.IsPortForwardingEnabled);
            ConnectionRequestIpcEntity vpnRequest = await _connectionRequestCreator.CreateAsync(intent);
            bool isP2PServer = PrioritizeServersForSlot(vpnRequest, slot, effectivePf);

            if (vpnRequest.Config is not null)
            {
                vpnRequest.Config.PortForwarding = effectivePf;
            }

            MultiTunnelSlotConnectionRequestIpcEntity slotRequest = new()
            {
                SlotId = slot.SlotId,
                SlotIndex = slot.SlotIndex,
                ClientIpv4Address = slot.ClientIpv4,
                ServerGatewayIpv4Address = slot.ServerGatewayIpv4,
                CountryCode = slot.CountryCode,
                ServerName = slot.ServerName,
                ConnectionRequest = vpnRequest,
                PortForwardingEnabled = effectivePf,
                IsP2PServer = isP2PServer,
            };

            Result<MultiTunnelSlotConnectionResultIpcEntity> ipcResult = await _vpnServiceCaller.ConnectMultiTunnelSlotAsync(slotRequest);

            bool cancelledByDisconnect;
            lock (_lock)
            {
                cancelledByDisconnect = _disconnectRequestedSlots.Remove(normalizedId);
            }

            if (cancelledByDisconnect)
            {
                try
                {
                    await _vpnServiceCaller.DisconnectMultiTunnelSlotAsync(normalizedId);
                }
                catch
                {
                }

                lock (_lock)
                {
                    if (_config.Slots.FirstOrDefault(s => string.Equals(s.SlotId, normalizedId, StringComparison.OrdinalIgnoreCase)) is { } cancelledTarget)
                    {
                        cancelledTarget.IsConnected = false;
                        cancelledTarget.LastError = null;
                        NormalizeAndPersistLocked();
                    }
                }
                return false;
            }

            if (!ipcResult.Success || ipcResult.Value is null || !ipcResult.Value.Success)
            {
                string errorMessage = ipcResult.Value?.ErrorMessage ?? "Failed to connect tunnel slot.";
                _logger.Warn<ConnectionLog>($"MultiTunnelManager: Failed to connect slot {normalizedId}: {errorMessage}");
                lock (_lock)
                {
                    if (_config.Slots.FirstOrDefault(s => string.Equals(s.SlotId, normalizedId, StringComparison.OrdinalIgnoreCase)) is { } target)
                    {
                        target.IsConnected = false;
                        target.LastError = errorMessage;
                    }
                }
                return false;
            }

            lock (_lock)
            {
                MultiTunnelSlotConfig? target = _config.Slots.FirstOrDefault(s =>
                    string.Equals(s.SlotId, normalizedId, StringComparison.OrdinalIgnoreCase));
                if (target is not null)
                {
                    target.IsConnected = true;
                    target.LastError = null;
                    if (!string.IsNullOrWhiteSpace(ipcResult.Value.ConnectedServerName))
                    {
                        target.ServerName = ResolveDisplayServerName(ipcResult.Value.ConnectedServerName, ipcResult.Value.ConnectedEntryIp)
                            ?? ipcResult.Value.ConnectedServerName;
                    }
                    if (!string.IsNullOrWhiteSpace(ipcResult.Value.ConnectedEntryIp))
                    {
                        target.EntryIp = ipcResult.Value.ConnectedEntryIp;
                        target.ExitIp = ipcResult.Value.ConnectedEntryIp;
                    }
                    target.IsP2PServer = ResolveIsP2PServer(
                        ipcResult.Value.ConnectedServerName,
                        ipcResult.Value.ConnectedEntryIp,
                        ipcResult.Value.IsP2PServer);

                    if (_portForwardingManager?.GetSlotState(normalizedId) is { } livePf)
                    {
                        target.ActiveForwardedPort = livePf.ActivePort;
                        target.PortForwardingStatus = livePf.Status;
                        target.HasPortForwardingError = livePf.HasError;
                        target.LastPortChangeTimeUtc = livePf.LastPortChangeTimeUtc;
                    }

                    NormalizeAndPersistLocked();
                }
            }

            await SyncPolicyToServiceAsync();
            return true;
        }
        catch (Exception ex)
        {
            _logger.Error<ConnectionLog>($"MultiTunnelManager: Error connecting slot {normalizedId}.", ex);
            lock (_lock)
            {
                if (_config.Slots.FirstOrDefault(s => string.Equals(s.SlotId, normalizedId, StringComparison.OrdinalIgnoreCase)) is { } target)
                {
                    target.IsConnected = false;
                    target.LastError = ex.Message;
                }
            }
            return false;
        }
        finally
        {
            lock (_lock)
            {
                _busySlots.Remove(normalizedId);
                if (_config.Slots.FirstOrDefault(s => string.Equals(s.SlotId, normalizedId, StringComparison.OrdinalIgnoreCase)) is { } target)
                {
                    target.IsConnecting = false;
                }
            }
            NotifyChanged();
        }
    }

    public async Task DisconnectSlotAsync(string slotId)
    {
        if (string.IsNullOrWhiteSpace(slotId))
        {
            return;
        }

        string normalizedId = slotId.Trim().ToUpperInvariant();
        if (string.Equals(normalizedId, "T1", StringComparison.OrdinalIgnoreCase))
        {
            await _connectionManager.DisconnectAsync(VpnTriggerDimension.ConnectionCard);
            return;
        }

        bool acquiredBusy;
        lock (_lock)
        {
            _disconnectRequestedSlots.Add(normalizedId);
            acquiredBusy = _busySlots.Add(normalizedId);
            if (_config.Slots.FirstOrDefault(s => string.Equals(s.SlotId, normalizedId, StringComparison.OrdinalIgnoreCase)) is { } target)
            {
                target.IsConnecting = true;
                target.LastError = null;
            }
        }
        NotifyChanged();

        try
        {
            await _vpnServiceCaller.DisconnectMultiTunnelSlotAsync(normalizedId);
        }
        catch (Exception ex)
        {
            _logger.Warn<ConnectionLog>($"MultiTunnelManager: Error disconnecting slot {normalizedId}: {ex.Message}");
        }
        finally
        {
            lock (_lock)
            {
                if (acquiredBusy)
                {
                    _busySlots.Remove(normalizedId);
                    _disconnectRequestedSlots.Remove(normalizedId);
                }
                MultiTunnelSlotConfig? target = _config.Slots.FirstOrDefault(s =>
                    string.Equals(s.SlotId, normalizedId, StringComparison.OrdinalIgnoreCase));
                if (target is not null)
                {
                    target.IsConnected = false;
                    target.IsConnecting = false;
                    target.IsP2PServer = false;
                    target.ActiveForwardedPort = null;
                    target.PortForwardingStatus = PortMappingStatus.Stopped;
                    target.HasPortForwardingError = false;
                    target.LastPortChangeTimeUtc = null;
                    NormalizeAndPersistLocked();
                }
            }

            NotifyChanged();
            await SyncPolicyToServiceAsync();
        }
    }

    public async Task ConnectAllSlotsAsync()
    {
        CancellationTokenSource cts = new();
        CancellationTokenSource? previousCts;
        List<string> slotIds;
        lock (_lock)
        {
            previousCts = _connectAllCts;
            _connectAllCts = cts;
            slotIds = _config.Slots
                .OrderBy(s => s.SlotIndex)
                .Select(s => s.SlotId)
                .ToList();
        }

        try
        {
            previousCts?.Cancel();
        }
        catch
        {
        }

        CancellationToken ct = cts.Token;
        try
        {
            foreach (string slotId in slotIds)
            {
                if (ct.IsCancellationRequested)
                {
                    break;
                }

                bool shouldConnect;
                lock (_lock)
                {
                    MultiTunnelSlotConfig? slot = _config.Slots.FirstOrDefault(s =>
                        string.Equals(s.SlotId, slotId, StringComparison.OrdinalIgnoreCase));
                    shouldConnect = slot is not null &&
                                    !slot.IsConnected &&
                                    !slot.IsConnecting &&
                                    !string.IsNullOrWhiteSpace(slot.CountryCode);
                }

                if (shouldConnect)
                {
                    await ConnectSlotAsync(slotId);
                }
            }
        }
        finally
        {
            lock (_lock)
            {
                if (ReferenceEquals(_connectAllCts, cts))
                {
                    _connectAllCts = null;
                }
            }
            cts.Dispose();
        }
    }

    public async Task DisconnectAllSlotsAsync()
    {
        CancellationTokenSource? connectCts;
        List<string> secondaryIds;
        bool disconnectT1;
        lock (_lock)
        {
            connectCts = _connectAllCts;
            _connectAllCts = null;
            secondaryIds = _config.Slots
                .Where(s => !string.Equals(s.SlotId, "T1", StringComparison.OrdinalIgnoreCase) && (s.IsConnected || s.IsConnecting))
                .OrderByDescending(s => s.SlotIndex)
                .Select(s => s.SlotId)
                .ToList();

            MultiTunnelSlotConfig? t1 = _config.Slots.FirstOrDefault(s =>
                string.Equals(s.SlotId, "T1", StringComparison.OrdinalIgnoreCase));
            disconnectT1 = (t1 is not null && (t1.IsConnected || t1.IsConnecting)) ||
                           _connectionManager.IsConnected ||
                           _connectionManager.IsConnecting;
        }

        try
        {
            connectCts?.Cancel();
        }
        catch
        {
        }

        foreach (string slotId in secondaryIds)
        {
            await DisconnectSlotAsync(slotId);
        }

        if (disconnectT1)
        {
            await DisconnectSlotAsync("T1");
        }

        NotifyChanged();
        await SyncPolicyToServiceAsync();
    }

    public async Task<string> HandleMapCountryClickAsync(string countryCode)
    {
        if (string.IsNullOrWhiteSpace(countryCode))
        {
            return string.Empty;
        }

        string normalizedCode = countryCode.Trim().ToUpperInvariant();

        if (!IsEnabled)
        {
            IConnectionIntent directIntent = new ConnectionIntent(SingleCountryLocationIntent.From(normalizedCode));
            await _connectionManager.ConnectAsync(VpnTriggerDimension.Map, directIntent);
            return string.Empty;
        }

        MultiTunnelSlotConfig? t1;
        MultiTunnelSlotConfig? existing;
        int slotCount;

        lock (_lock)
        {
            t1 = _config.Slots.FirstOrDefault(s => string.Equals(s.SlotId, "T1", StringComparison.OrdinalIgnoreCase));
            existing = _config.Slots.FirstOrDefault(s => string.Equals(s.CountryCode, normalizedCode, StringComparison.OrdinalIgnoreCase));
            slotCount = _config.Slots.Count;
        }

        if (t1 is null || (!t1.IsConnected && !t1.IsConnecting && !_connectionManager.IsConnected && !_connectionManager.IsConnecting))
        {
            IConnectionIntent t1Intent = new ConnectionIntent(SingleCountryLocationIntent.From(normalizedCode));
            await _connectionManager.ConnectAsync(VpnTriggerDimension.Map, t1Intent);
            return $"Connecting primary slot T1 to {normalizedCode}.";
        }

        if (existing is not null)
        {
            if (existing.IsConnected || existing.IsConnecting)
            {
                return $"{existing.SlotId} ({normalizedCode}) is already {(existing.IsConnected ? "connected" : "connecting")}.";
            }

            bool ok = await ConnectSlotAsync(existing.SlotId);
            return ok
                ? $"Connected {existing.SlotId} ({normalizedCode}) alongside T1."
                : (existing.LastError ?? $"Failed to connect {existing.SlotId} ({normalizedCode}).");
        }

        if (slotCount >= MultiTunnelSlotConfig.MaxSlots)
        {
            return $"All {MultiTunnelSlotConfig.MaxSlots} Multi-Tunnel slots are in use. Disconnect or remove a slot before adding {normalizedCode}.";
        }

        MultiTunnelSlotConfig? added = await AddSlotAsync(normalizedCode, $"{normalizedCode}#Fastest");
        if (added is null)
        {
            return $"Could not allocate a Multi-Tunnel slot for {normalizedCode}.";
        }

        bool connected = await ConnectSlotAsync(added.SlotId);
        return connected
            ? $"Added and connected {added.SlotId} ({normalizedCode}) alongside T1."
            : (added.LastError ?? $"Added {added.SlotId} ({normalizedCode}), but connection failed.");
    }

    public async Task AddRuleAsync(MultiTunnelRuleConfig rule)
    {
        if (rule is null)
        {
            return;
        }

        lock (_lock)
        {
            if (rule.Id == Guid.Empty)
            {
                rule.Id = Guid.NewGuid();
            }
            rule.PriorityOrder = _config.Rules.Count + 1;
            _config.Rules.Add(rule);
            NormalizeAndPersistLocked();
        }

        NotifyChanged();
        await SyncPolicyToServiceAsync();
    }

    public async Task<int> ApplyRoutingPresetsAsync(
        IEnumerable<RoutingRulePreset> presets,
        RoutingPresetApplyMode mode,
        RuleTargetTypeIpcEntity? targetTypeOverride = null,
        string? targetTunnelIdOverride = null,
        TunnelFallbackBehaviorIpcEntity? fallbackBehaviorOverride = null,
        string? fallbackTunnelIdOverride = null)
    {
        List<RoutingRulePreset> presetList = presets?.Where(p => p is not null).ToList() ?? [];
        if (presetList.Count == 0)
        {
            return 0;
        }

        int appliedCount;
        lock (_lock)
        {
            List<string> availableSlotIds = _config.Slots
                .OrderBy(s => s.SlotIndex)
                .Select(s => s.SlotId)
                .ToList();

            List<MultiTunnelRuleConfig> generated = presetList
                .Select(p => p.ToRuleConfig(
                    availableSlotIds,
                    targetTypeOverride,
                    targetTunnelIdOverride,
                    fallbackBehaviorOverride,
                    fallbackTunnelIdOverride))
                .ToList();

            if (mode == RoutingPresetApplyMode.Replace)
            {
                _config.Rules = generated;
            }
            else if (mode == RoutingPresetApplyMode.ReplaceTarget)
            {
                _config.Rules.RemoveAll(r =>
                {
                    if (presetList.Any(p => p.MatchesRule(r)))
                    {
                        return true;
                    }

                    if (targetTypeOverride.HasValue)
                    {
                        if (r.TargetType != targetTypeOverride.Value)
                        {
                            return false;
                        }

                        return targetTypeOverride.Value != RuleTargetTypeIpcEntity.Tunnel ||
                               string.Equals(
                                   r.TargetTunnelId,
                                   generated[0].TargetTunnelId,
                                   StringComparison.OrdinalIgnoreCase);
                    }

                    return generated.Any(g =>
                        r.TargetType == g.TargetType &&
                        (g.TargetType != RuleTargetTypeIpcEntity.Tunnel ||
                         string.Equals(r.TargetTunnelId, g.TargetTunnelId, StringComparison.OrdinalIgnoreCase)));
                });

                _config.Rules.InsertRange(0, generated);
            }
            else
            {
                _config.Rules.RemoveAll(r => presetList.Any(p => p.MatchesRule(r)));
                _config.Rules.InsertRange(0, generated);
            }

            appliedCount = generated.Count;
            NormalizeAndPersistLocked();
        }

        NotifyChanged();
        await SyncPolicyToServiceAsync();
        return appliedCount;
    }

    public async Task<bool> RemoveRoutingPresetAsync(RoutingRulePreset preset)
    {
        if (preset is null)
        {
            return false;
        }

        int removedCount;
        lock (_lock)
        {
            removedCount = _config.Rules.RemoveAll(r => preset.MatchesRule(r));
            if (removedCount > 0)
            {
                NormalizeAndPersistLocked();
            }
        }

        if (removedCount > 0)
        {
            NotifyChanged();
            await SyncPolicyToServiceAsync();
            return true;
        }

        return false;
    }

    public async Task UpdateRuleAsync(MultiTunnelRuleConfig rule)
    {
        if (rule is null)
        {
            return;
        }

        lock (_lock)
        {
            int idx = _config.Rules.FindIndex(r => r.Id == rule.Id);
            if (idx < 0)
            {
                return;
            }

            rule.PriorityOrder = _config.Rules[idx].PriorityOrder;
            _config.Rules[idx] = rule;
            NormalizeAndPersistLocked();
        }

        NotifyChanged();
        await SyncPolicyToServiceAsync();
    }

    public async Task SetRuleEnabledAsync(Guid ruleId, bool isEnabled)
    {
        lock (_lock)
        {
            MultiTunnelRuleConfig? rule = _config.Rules.FirstOrDefault(r => r.Id == ruleId);
            if (rule is null || rule.IsEnabled == isEnabled)
            {
                return;
            }

            rule.IsEnabled = isEnabled;
            NormalizeAndPersistLocked();
        }

        NotifyChanged();
        await SyncPolicyToServiceAsync();
    }

    public async Task DeleteRuleAsync(Guid ruleId)
    {
        lock (_lock)
        {
            int removed = _config.Rules.RemoveAll(r => r.Id == ruleId);
            if (removed == 0)
            {
                return;
            }

            NormalizeAndPersistLocked();
        }

        NotifyChanged();
        await SyncPolicyToServiceAsync();
    }

    public async Task MoveRuleAsync(Guid ruleId, int delta)
    {
        lock (_lock)
        {
            int idx = _config.Rules.FindIndex(r => r.Id == ruleId);
            if (idx < 0)
            {
                return;
            }

            int targetIdx = Math.Clamp(idx + delta, 0, _config.Rules.Count - 1);
            if (targetIdx == idx)
            {
                return;
            }

            MultiTunnelRuleConfig item = _config.Rules[idx];
            _config.Rules.RemoveAt(idx);
            _config.Rules.Insert(targetIdx, item);
            NormalizeAndPersistLocked();
        }

        NotifyChanged();
        await SyncPolicyToServiceAsync();
    }

    public async Task ResetDefaultRulesAsync()
    {
        lock (_lock)
        {
            _config.Rules = CreateDefaultRules();
            _config.HasInitializedDefaultRules = true;
            NormalizeAndPersistLocked();
        }

        NotifyChanged();
        await SyncPolicyToServiceAsync();
    }

    public async Task ReconcileWithServiceAsync()
    {
        try
        {
            Result<MultiTunnelPolicyIpcEntity> result = await _vpnServiceCaller.GetMultiTunnelPolicyAsync();
            if (result is not { Success: true, Value.TunnelSlots: not null })
            {
                return;
            }

            bool anyChanged = false;
            lock (_lock)
            {
                foreach (TunnelSlotStateIpcEntity svcSlot in result.Value.TunnelSlots)
                {
                    if (svcSlot is null ||
                        string.IsNullOrWhiteSpace(svcSlot.SlotId) ||
                        string.Equals(svcSlot.SlotId, "T1", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    MultiTunnelSlotConfig? localSlot = _config.Slots.FirstOrDefault(s =>
                        string.Equals(s.SlotId, svcSlot.SlotId, StringComparison.OrdinalIgnoreCase));
                    if (localSlot is null)
                    {
                        continue;
                    }

                    bool svcConnected = svcSlot.Status == VpnStatusIpcEntity.Connected;
                    if (localSlot.IsConnected != svcConnected)
                    {
                        localSlot.IsConnected = svcConnected;
                        anyChanged = true;
                    }

                    if (svcConnected)
                    {
                        if (!string.IsNullOrWhiteSpace(svcSlot.ServerName) && localSlot.ServerName != svcSlot.ServerName)
                        {
                            localSlot.ServerName = svcSlot.ServerName;
                            anyChanged = true;
                        }
                        if (!string.IsNullOrWhiteSpace(svcSlot.EntryIp) && localSlot.EntryIp != svcSlot.EntryIp)
                        {
                            localSlot.EntryIp = svcSlot.EntryIp;
                            anyChanged = true;
                        }
                        if (!string.IsNullOrWhiteSpace(svcSlot.ExitIp) && localSlot.ExitIp != svcSlot.ExitIp)
                        {
                            localSlot.ExitIp = svcSlot.ExitIp;
                            anyChanged = true;
                        }
                        if (localSlot.IsP2PServer != svcSlot.IsP2PServer)
                        {
                            localSlot.IsP2PServer = svcSlot.IsP2PServer;
                            anyChanged = true;
                        }
                        int? svcPort = svcSlot.ActiveForwardedPort > 0 ? svcSlot.ActiveForwardedPort : null;
                        if (localSlot.ActiveForwardedPort != svcPort)
                        {
                            localSlot.ActiveForwardedPort = svcPort;
                            anyChanged = true;
                        }
                        PortMappingStatus svcPfStatus = (PortMappingStatus)(int)svcSlot.PortForwardingStatus;
                        if (localSlot.PortForwardingStatus != svcPfStatus)
                        {
                            localSlot.PortForwardingStatus = svcPfStatus;
                            anyChanged = true;
                        }
                        if (localSlot.HasPortForwardingError != svcSlot.HasPortForwardingError)
                        {
                            localSlot.HasPortForwardingError = svcSlot.HasPortForwardingError;
                            anyChanged = true;
                        }
                    }
                }

                if (anyChanged)
                {
                    NormalizeAndPersistLocked();
                }
            }

            if (anyChanged)
            {
                NotifyChanged();
            }
        }
        catch (Exception ex)
        {
            _logger.Debug<ConnectionLog>($"MultiTunnelManager: Startup service reconciliation skipped: {ex.Message}");
        }
    }

    public async Task SyncPolicyToServiceAsync()
    {
        try
        {
            MultiTunnelPolicyIpcEntity policy = BuildIpcPolicy();
            await _vpnServiceCaller.ApplyMultiTunnelPolicyAsync(policy);
        }
        catch (Exception ex)
        {
            _logger.Warn<ConnectionLog>($"MultiTunnelManager: Failed to sync Multi-Tunnel policy to Service: {ex.Message}");
        }
    }

    public async Task<RoutingDecisionIpcEntity> EvaluateTrafficAsync(TrafficQueryIpcEntity query)
    {
        try
        {
            Result<RoutingDecisionIpcEntity> ipcResult = await _vpnServiceCaller.EvaluateMultiTunnelTrafficAsync(query);
            if (ipcResult.Success && ipcResult.Value is not null)
            {
                return ipcResult.Value;
            }
        }
        catch (Exception ex)
        {
            _logger.Debug<ConnectionLog>($"MultiTunnelManager: EvaluateMultiTunnelTraffic IPC unavailable ({ex.Message}); using local preview.");
        }

        RoutingDecisionIpcEntity preview = EvaluateLocalPreview(query);
        preview.Explanation += " [Local preview - Service offline]";
        return preview;
    }

    public MultiTunnelPolicyIpcEntity BuildIpcPolicy()
    {
        lock (_lock)
        {
            return new MultiTunnelPolicyIpcEntity
            {
                IsMultiTunnelEnabled = _config.IsMultiTunnelEnabled,
                DefaultTargetType = _config.DefaultTargetType,
                DefaultTunnelId = _config.DefaultTunnelId,
                TunnelSlots = _config.Slots
                    .OrderBy(s => s.SlotIndex)
                    .Select(s => new TunnelSlotStateIpcEntity
                    {
                        SlotId = s.SlotId,
                        SlotIndex = s.SlotIndex,
                        AdapterName = $"ProtonVPN-{s.SlotId}",
                        Status = s.IsConnected ? VpnStatusIpcEntity.Connected : VpnStatusIpcEntity.Disconnected,
                        ClientIpv4Address = s.ClientIpv4,
                        ServerGatewayIpv4Address = s.ServerGatewayIpv4,
                        ClientIpv6Address = null,
                        ServerCountryCode = s.CountryCode,
                        ServerName = s.ServerName,
                        EntryIp = s.EntryIp,
                        ExitIp = s.ExitIp,
                        PortForwardingEnabled = s.ResolveEffectivePortForwarding(_settings.IsPortForwardingEnabled),
                        ActiveForwardedPort = s.ActiveForwardedPort ?? 0,
                        PortForwardingStatus = (PortMappingStatusIpcEntity)(int)s.PortForwardingStatus,
                        IsP2PServer = s.IsP2PServer,
                        HasPortForwardingError = s.HasPortForwardingError,
                        IsDefaultRouteTunnel = s.IsDefaultRouteTunnel,
                    })
                    .ToList(),
                PriorityRules = _config.Rules
                    .OrderBy(r => r.PriorityOrder)
                    .Select(r => new SelectiveRoutingRuleIpcEntity
                    {
                        Id = r.Id,
                        PriorityOrder = r.PriorityOrder,
                        Name = r.Name,
                        IsEnabled = r.IsEnabled,
                        AppPattern = r.AppPattern,
                        DomainPattern = r.DomainPattern,
                        IpCidrPattern = r.IpCidrPattern,
                        PortPattern = r.PortPattern,
                        Protocol = r.Protocol,
                        TargetType = r.TargetType,
                        TargetTunnelId = r.TargetTunnelId,
                        FallbackBehavior = r.FallbackBehavior,
                        FallbackTunnelId = r.FallbackTunnelId,
                    })
                    .ToList(),
            };
        }
    }

    public void Receive(ConnectionStatusChangedMessage message)
    {
        UpdatePrimarySlotFromConnectionManager();
    }

    public void Receive(ConnectionDetailsChangedMessage message)
    {
        UpdatePrimarySlotFromConnectionManager();
    }

    public void Receive(SettingChangedMessage message)
    {
        if (message.PropertyName == nameof(ISettings.IsPortForwardingEnabled))
        {
            NotifyChanged();
            SyncPolicyToServiceAsync().FireAndForget();
        }
    }

    public void Receive(PortForwardingPortChangedMessage message)
    {
        UpdateSlotPortForwardingFromManager(message.SlotId);
    }

    public void Receive(PortForwardingStatusChangedMessage message)
    {
        UpdateSlotPortForwardingFromManager(message.SlotId);
    }

    private void UpdateSlotPortForwardingFromManager(string slotId)
    {
        if (string.IsNullOrWhiteSpace(slotId) || _portForwardingManager is null)
        {
            return;
        }

        string normalizedId = slotId.Trim().ToUpperInvariant();
        SlotPortForwardingState? pfState = _portForwardingManager.GetSlotState(normalizedId);
        if (pfState is null)
        {
            return;
        }

        bool changed = false;
        lock (_lock)
        {
            MultiTunnelSlotConfig? slot = _config.Slots.FirstOrDefault(s =>
                string.Equals(s.SlotId, normalizedId, StringComparison.OrdinalIgnoreCase));
            if (slot is null)
            {
                return;
            }

            if (slot.ActiveForwardedPort != pfState.ActivePort ||
                slot.PortForwardingStatus != pfState.Status ||
                slot.HasPortForwardingError != pfState.HasError ||
                slot.LastPortChangeTimeUtc != pfState.LastPortChangeTimeUtc)
            {
                slot.ActiveForwardedPort = pfState.ActivePort;
                slot.PortForwardingStatus = pfState.Status;
                slot.HasPortForwardingError = pfState.HasError;
                slot.LastPortChangeTimeUtc = pfState.LastPortChangeTimeUtc;
                changed = true;
            }
        }

        if (changed)
        {
            NotifyChanged();
        }
    }

    private void UpdatePrimarySlotFromConnectionManager()
    {
        bool shouldSync;
        lock (_lock)
        {
            MultiTunnelSlotConfig? t1 = _config.Slots.FirstOrDefault(s =>
                string.Equals(s.SlotId, "T1", StringComparison.OrdinalIgnoreCase));
            if (t1 is null)
            {
                return;
            }

            t1.IsConnecting = _connectionManager.IsConnecting;
            t1.IsConnected = _connectionManager.IsConnected;

            if (_connectionManager.IsConnected || _connectionManager.IsConnecting)
            {
                t1.LastError = null;
            }

            // Only update T1 endpoint metadata once the primary tunnel is actually connected.
            if (_connectionManager.IsConnected && _connectionManager.CurrentConnectionDetails is { } details)
            {
                t1.CountryCode = details.ExitCountryCode;
                t1.ServerName = details.ServerName;
                t1.City = details.City;
                t1.EntryIp = details.EntryIpAddress ?? string.Empty;
                t1.ExitIp = details.ServerIpAddress?.ToString() ?? string.Empty;
                t1.IsP2PServer = details.IsP2P;

                if (_portForwardingManager?.GetSlotState("T1") is { } pf)
                {
                    t1.ActiveForwardedPort = pf.ActivePort;
                    t1.PortForwardingStatus = pf.Status;
                    t1.HasPortForwardingError = pf.HasError;
                    t1.LastPortChangeTimeUtc = pf.LastPortChangeTimeUtc;
                }
            }
            else if (!_connectionManager.IsConnected)
            {
                t1.IsP2PServer = false;
                t1.ActiveForwardedPort = null;
                t1.PortForwardingStatus = PortMappingStatus.Stopped;
                t1.HasPortForwardingError = false;
                t1.LastPortChangeTimeUtc = null;
            }

            NormalizeAndPersistLocked();
            shouldSync = !_connectionManager.IsConnecting;
        }

        NotifyChanged();
        if (shouldSync)
        {
            SyncPolicyToServiceAsync().FireAndForget();
        }
    }

    private bool PrioritizeServersForSlot(ConnectionRequestIpcEntity vpnRequest, MultiTunnelSlotConfig slot, bool effectivePortForwarding)
    {
        if (vpnRequest.Servers is null || vpnRequest.Servers.Length == 0 || _serversLoader is null)
        {
            return false;
        }

        IReadOnlyList<Server> countryServers = _serversLoader.GetServers()
            .Where(s => string.Equals(s.ExitCountry, slot.CountryCode, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (!string.IsNullOrWhiteSpace(slot.ServerName) &&
            !slot.ServerName.Trim().EndsWith("#Fastest", StringComparison.OrdinalIgnoreCase))
        {
            Server? explicitServer = countryServers.FirstOrDefault(s =>
                string.Equals(s.Name, slot.ServerName.Trim(), StringComparison.OrdinalIgnoreCase));

            HashSet<string> preferredIps = new(StringComparer.OrdinalIgnoreCase);
            if (!string.IsNullOrWhiteSpace(slot.EntryIp))
            {
                preferredIps.Add(slot.EntryIp.Trim());
            }
            if (explicitServer is not null)
            {
                foreach (PhysicalServer ps in explicitServer.Servers)
                {
                    if (!string.IsNullOrWhiteSpace(ps.EntryIp))
                    {
                        preferredIps.Add(ps.EntryIp);
                    }
                }
            }

            if (preferredIps.Count > 0)
            {
                vpnRequest.Servers = vpnRequest.Servers
                    .OrderByDescending(s => !string.IsNullOrWhiteSpace(s.Ip) && preferredIps.Contains(s.Ip))
                    .ToArray();
            }

            if (explicitServer is not null)
            {
                return explicitServer.Features.IsSupported(ServerFeatures.P2P);
            }
        }

        if (effectivePortForwarding)
        {
            HashSet<string> p2pIps = countryServers
                .Where(s => s.Features.IsSupported(ServerFeatures.P2P))
                .SelectMany(s => s.Servers)
                .Select(ps => ps.EntryIp)
                .Where(ip => !string.IsNullOrWhiteSpace(ip))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            if (p2pIps.Count > 0)
            {
                vpnRequest.Servers = vpnRequest.Servers
                    .OrderByDescending(s => !string.IsNullOrWhiteSpace(s.Ip) && p2pIps.Contains(s.Ip))
                    .ToArray();
            }
        }

        VpnServerIpcEntity firstServer = vpnRequest.Servers[0];
        return ResolveIsP2PServer(firstServer.Name, firstServer.Ip, defaultValue: false);
    }

    private bool ResolveIsP2PServer(string? serverNameOrDomain, string? entryIp, bool defaultValue)
    {
        if (_serversLoader is null)
        {
            return defaultValue;
        }

        Server? matched = FindLogicalServer(serverNameOrDomain, entryIp);
        return matched is not null ? matched.Features.IsSupported(ServerFeatures.P2P) : defaultValue;
    }

    private string? ResolveDisplayServerName(string? serverNameOrDomain, string? entryIp)
    {
        return FindLogicalServer(serverNameOrDomain, entryIp)?.Name;
    }

    private Server? FindLogicalServer(string? serverNameOrDomain, string? entryIp)
    {
        if (_serversLoader is null)
        {
            return null;
        }

        IEnumerable<Server> servers = _serversLoader.GetServers();

        if (!string.IsNullOrWhiteSpace(serverNameOrDomain))
        {
            string trimmed = serverNameOrDomain.Trim();
            Server? byName = servers.FirstOrDefault(s =>
                string.Equals(s.Name, trimmed, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(s.Domain, trimmed, StringComparison.OrdinalIgnoreCase) ||
                s.Servers.Any(ps => string.Equals(ps.Domain, trimmed, StringComparison.OrdinalIgnoreCase)));
            if (byName is not null)
            {
                return byName;
            }
        }

        return string.IsNullOrWhiteSpace(entryIp) ? null : servers.FirstOrDefault(s =>
            s.Servers.Any(ps => string.Equals(ps.EntryIp, entryIp, StringComparison.OrdinalIgnoreCase)));
    }

    private void LoadFromSettings()
    {
        lock (_lock)
        {
            MultiTunnelPolicyConfig? loaded = null;
            string rawJson = _settings.MultiTunnelPolicyJson;
            if (!string.IsNullOrWhiteSpace(rawJson))
            {
                try
                {
                    loaded = JsonSerializer.Deserialize<MultiTunnelPolicyConfig>(rawJson, JsonOptions);
                }
                catch
                {
                    loaded = null;
                }
            }

            if (loaded is not null)
            {
                _config = loaded;
                if (_config.Rules.Count > 0)
                {
                    _config.HasInitializedDefaultRules = true;
                }
            }
            else
            {
                _config = new MultiTunnelPolicyConfig
                {
                    IsMultiTunnelEnabled = _settings.IsMultiTunnelEnabled,
                    HasInitializedDefaultRules = true,
                    DefaultTargetType = RuleTargetTypeIpcEntity.Direct,
                    DefaultTunnelId = "T1",
                    Slots = [MultiTunnelSlotConfig.CreateDefault(0, "SG", "SG#Fastest", "Singapore")],
                    Rules = CreateDefaultRules(),
                };
            }

            _config.IsMultiTunnelEnabled = _settings.IsMultiTunnelEnabled;

            if (_config.Slots.Count == 0 || !_config.Slots.Any(s => string.Equals(s.SlotId, "T1", StringComparison.OrdinalIgnoreCase)))
            {
                _config.Slots.Insert(0, MultiTunnelSlotConfig.CreateDefault(0, "SG", "SG#Fastest", "Singapore"));
            }

            foreach (MultiTunnelSlotConfig slot in _config.Slots)
            {
                slot.IsConnected = false;
                slot.IsConnecting = false;
                slot.LastError = null;
            }

            if (!_config.HasInitializedDefaultRules && _config.Rules.Count == 0)
            {
                _config.Rules = CreateDefaultRules();
                _config.HasInitializedDefaultRules = true;
            }
            else
            {
                _config.HasInitializedDefaultRules = true;
                _config.Rules = _config.Rules.OrderBy(r => r.PriorityOrder).ToList();
            }

            NormalizeAndPersistLocked();
        }
    }

    private void NormalizeAndPersistLocked()
    {
        _config.Slots = _config.Slots
            .OrderBy(s => s.SlotIndex)
            .Take(MultiTunnelSlotConfig.MaxSlots)
            .ToList();

        for (int i = 0; i < _config.Rules.Count; i++)
        {
            _config.Rules[i].PriorityOrder = i + 1;
        }

        _conflicts = DetectConflicts(_config.Rules);

        _settings.IsMultiTunnelEnabled = _config.IsMultiTunnelEnabled;
        _settings.MultiTunnelPolicyJson = JsonSerializer.Serialize(_config, JsonOptions);
    }

    private void NotifyChanged()
    {
        _eventMessageSender.Send(new MultiTunnelPolicyChangedMessage(IsEnabled, Slots.Count, EnabledRuleCount));
    }

    private RoutingDecisionIpcEntity EvaluateLocalPreview(TrafficQueryIpcEntity query)
    {
        lock (_lock)
        {
            Dictionary<string, MultiTunnelSlotConfig> slotMap = _config.Slots
                .ToDictionary(s => s.SlotId.ToUpperInvariant(), s => s, StringComparer.OrdinalIgnoreCase);

            foreach (MultiTunnelRuleConfig rule in _config.Rules.Where(r => r.IsEnabled && r.HasAnyCondition).OrderBy(r => r.PriorityOrder))
            {
                if (!MatchesRulePreview(rule, query))
                {
                    continue;
                }

                uint weight = (uint)Math.Clamp(14 - (Math.Max(1, rule.PriorityOrder) - 1), 2, 14);
                if (rule.TargetType == RuleTargetTypeIpcEntity.Direct)
                {
                    return new RoutingDecisionIpcEntity
                    {
                        EffectiveTargetType = RuleTargetTypeIpcEntity.Direct,
                        MatchedRuleId = rule.Id,
                        MatchedRulePriority = rule.PriorityOrder,
                        MatchedRuleName = rule.Name,
                        WfpFilterWeight = weight,
                        Explanation = $"Matched Rule #{rule.PriorityOrder} ('{rule.Name}') -> Direct physical connection.",
                    };
                }

                if (rule.TargetType == RuleTargetTypeIpcEntity.Block)
                {
                    return new RoutingDecisionIpcEntity
                    {
                        EffectiveTargetType = RuleTargetTypeIpcEntity.Block,
                        MatchedRuleId = rule.Id,
                        MatchedRulePriority = rule.PriorityOrder,
                        MatchedRuleName = rule.Name,
                        WfpFilterWeight = weight,
                        Explanation = $"Matched Rule #{rule.PriorityOrder} ('{rule.Name}') -> Explicit Block.",
                    };
                }

                string targetId = string.IsNullOrWhiteSpace(rule.TargetTunnelId) ? "T1" : rule.TargetTunnelId.ToUpperInvariant();
                if (slotMap.TryGetValue(targetId, out MultiTunnelSlotConfig? slot) && slot.IsConnected)
                {
                    return new RoutingDecisionIpcEntity
                    {
                        EffectiveTargetType = RuleTargetTypeIpcEntity.Tunnel,
                        EffectiveTunnelId = targetId,
                        MatchedRuleId = rule.Id,
                        MatchedRulePriority = rule.PriorityOrder,
                        MatchedRuleName = rule.Name,
                        WfpFilterWeight = weight,
                        Explanation = $"Matched Rule #{rule.PriorityOrder} ('{rule.Name}') -> Tunnel {targetId} ({slot.CountryCode}).",
                    };
                }

                if (rule.FallbackBehavior == TunnelFallbackBehaviorIpcEntity.FallbackToDirect)
                {
                    return new RoutingDecisionIpcEntity
                    {
                        EffectiveTargetType = RuleTargetTypeIpcEntity.Direct,
                        MatchedRuleId = rule.Id,
                        MatchedRulePriority = rule.PriorityOrder,
                        MatchedRuleName = rule.Name,
                        IsFallbackApplied = true,
                        WfpFilterWeight = weight,
                        Explanation = $"Matched Rule #{rule.PriorityOrder} ('{rule.Name}'): {targetId} is down -> Fallback to Direct.",
                    };
                }

                if (rule.FallbackBehavior == TunnelFallbackBehaviorIpcEntity.FallbackToTunnel &&
                    !string.IsNullOrWhiteSpace(rule.FallbackTunnelId) &&
                    slotMap.TryGetValue(rule.FallbackTunnelId.ToUpperInvariant(), out MultiTunnelSlotConfig? fbSlot) &&
                    fbSlot.IsConnected)
                {
                    return new RoutingDecisionIpcEntity
                    {
                        EffectiveTargetType = RuleTargetTypeIpcEntity.Tunnel,
                        EffectiveTunnelId = fbSlot.SlotId,
                        MatchedRuleId = rule.Id,
                        MatchedRulePriority = rule.PriorityOrder,
                        MatchedRuleName = rule.Name,
                        IsFallbackApplied = true,
                        WfpFilterWeight = weight,
                        Explanation = $"Matched Rule #{rule.PriorityOrder} ('{rule.Name}'): {targetId} is down -> Fallback to {fbSlot.SlotId}.",
                    };
                }

                return new RoutingDecisionIpcEntity
                {
                    EffectiveTargetType = RuleTargetTypeIpcEntity.Block,
                    MatchedRuleId = rule.Id,
                    MatchedRulePriority = rule.PriorityOrder,
                    MatchedRuleName = rule.Name,
                    IsKillSwitchBlocked = true,
                    WfpFilterWeight = weight,
                    Explanation = $"Matched Rule #{rule.PriorityOrder} ('{rule.Name}'): {targetId} is disconnected -> Per-Tunnel Kill-Switch Blocked.",
                };
            }

            if (_config.DefaultTargetType == RuleTargetTypeIpcEntity.Direct)
            {
                return new RoutingDecisionIpcEntity
                {
                    EffectiveTargetType = RuleTargetTypeIpcEntity.Direct,
                    WfpFilterWeight = 1,
                    Explanation = "No priority rule matched -> Default Policy: Direct physical connection.",
                };
            }

            if (_config.DefaultTargetType == RuleTargetTypeIpcEntity.Block)
            {
                return new RoutingDecisionIpcEntity
                {
                    EffectiveTargetType = RuleTargetTypeIpcEntity.Block,
                    WfpFilterWeight = 1,
                    Explanation = "No priority rule matched -> Default Policy: Block all unmatched traffic.",
                };
            }

            string defId = string.IsNullOrWhiteSpace(_config.DefaultTunnelId) ? "T1" : _config.DefaultTunnelId.ToUpperInvariant();
            if (slotMap.TryGetValue(defId, out MultiTunnelSlotConfig? defSlot) && defSlot.IsConnected)
            {
                return new RoutingDecisionIpcEntity
                {
                    EffectiveTargetType = RuleTargetTypeIpcEntity.Tunnel,
                    EffectiveTunnelId = defId,
                    WfpFilterWeight = 1,
                    Explanation = $"No priority rule matched -> Default Tunnel {defId} ({defSlot.CountryCode}).",
                };
            }

            return new RoutingDecisionIpcEntity
            {
                EffectiveTargetType = RuleTargetTypeIpcEntity.Block,
                IsKillSwitchBlocked = true,
                WfpFilterWeight = 1,
                Explanation = $"No priority rule matched and Default Tunnel {defId} is disconnected -> Blocked by Kill-Switch.",
            };
        }
    }

    private static bool MatchesRulePreview(MultiTunnelRuleConfig rule, TrafficQueryIpcEntity query)
    {
        if (!string.IsNullOrWhiteSpace(rule.AppPattern))
        {
            string? exe = Path.GetFileNameWithoutExtension(query.ProcessName ?? query.AppPath ?? string.Empty)?.Trim().ToLowerInvariant();
            if (string.IsNullOrEmpty(exe))
            {
                return false;
            }

            bool matchedApp = SplitTokens(rule.AppPattern).Any(tok =>
            {
                string cleanTok = Path.GetFileNameWithoutExtension(tok.Trim().Trim('"')).ToLowerInvariant();
                return string.Equals(cleanTok, exe, StringComparison.OrdinalIgnoreCase);
            });
            if (!matchedApp)
            {
                return false;
            }
        }

        if (!string.IsNullOrWhiteSpace(rule.DomainPattern))
        {
            string domain = (query.Domain ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
            if (string.IsNullOrEmpty(domain))
            {
                return false;
            }

            bool matchedDomain = SplitTokens(rule.DomainPattern).Any(rawTok =>
            {
                string tok = rawTok.Trim().ToLowerInvariant();
                if (tok.StartsWith("*.", StringComparison.Ordinal))
                {
                    string suffix = tok[2..];
                    return domain == suffix || domain.EndsWith("." + suffix, StringComparison.Ordinal);
                }
                return domain == tok;
            });
            if (!matchedDomain)
            {
                return false;
            }
        }

        if (!string.IsNullOrWhiteSpace(rule.IpCidrPattern))
        {
            if (!IPAddress.TryParse(query.RemoteIp?.Trim(), out IPAddress? ip))
            {
                return false;
            }

            bool matchedIp = SplitTokens(rule.IpCidrPattern).Any(cidr => IsIpInCidrPreview(ip, cidr));
            if (!matchedIp)
            {
                return false;
            }
        }

        if (!string.IsNullOrWhiteSpace(rule.PortPattern) || rule.Protocol != RuleProtocolIpcEntity.Any)
        {
            if (rule.Protocol != RuleProtocolIpcEntity.Any && query.Protocol != RuleProtocolIpcEntity.Any && rule.Protocol != query.Protocol)
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(rule.PortPattern))
            {
                if (!query.RemotePort.HasValue)
                {
                    return false;
                }

                int port = query.RemotePort.Value;
                bool matchedPort = SplitTokens(rule.PortPattern).Any(tok =>
                {
                    int dash = tok.IndexOf('-');
                    if (dash > 0 &&
                        int.TryParse(tok[..dash].Trim(), out int s) &&
                        int.TryParse(tok[(dash + 1)..].Trim(), out int e))
                    {
                        return port >= Math.Min(s, e) && port <= Math.Max(s, e);
                    }
                    return int.TryParse(tok.Trim(), out int p) && p == port;
                });
                if (!matchedPort)
                {
                    return false;
                }
            }
        }

        return true;
    }

    private static bool IsIpInCidrPreview(IPAddress ip, string cidrToken)
    {
        int slash = cidrToken.IndexOf('/');
        string addrPart = slash >= 0 ? cidrToken[..slash].Trim() : cidrToken.Trim();
        if (!IPAddress.TryParse(addrPart, out IPAddress? baseIp) || baseIp.AddressFamily != ip.AddressFamily)
        {
            return false;
        }

        byte[] ipBytes = ip.GetAddressBytes();
        byte[] baseBytes = baseIp.GetAddressBytes();
        int maxBits = ipBytes.Length * 8;
        int prefix = slash >= 0 && int.TryParse(cidrToken[(slash + 1)..], out int parsed)
            ? Math.Clamp(parsed, 0, maxBits)
            : maxBits;

        int fullBytes = prefix / 8;
        int remBits = prefix % 8;
        for (int i = 0; i < fullBytes; i++)
        {
            if (ipBytes[i] != baseBytes[i])
            {
                return false;
            }
        }

        if (remBits > 0)
        {
            int mask = 0xFF << (8 - remBits);
            if ((ipBytes[fullBytes] & mask) != (baseBytes[fullBytes] & mask))
            {
                return false;
            }
        }

        return true;
    }

    private static List<MultiTunnelRuleConflict> DetectConflicts(IReadOnlyList<MultiTunnelRuleConfig> rules)
    {
        List<MultiTunnelRuleConfig> ordered = rules
            .Where(r => r.IsEnabled && r.HasAnyCondition)
            .OrderBy(r => r.PriorityOrder)
            .ToList();

        List<MultiTunnelRuleConflict> warnings = [];
        for (int i = 0; i < ordered.Count; i++)
        {
            MultiTunnelRuleConfig upper = ordered[i];
            for (int j = i + 1; j < ordered.Count; j++)
            {
                MultiTunnelRuleConfig lower = ordered[j];
                bool upperBroaderOrEqual =
                    ConditionCoversTokens(upper.AppPattern, lower.AppPattern) &&
                    ConditionCoversTokens(upper.DomainPattern, lower.DomainPattern) &&
                    ConditionCoversTokens(upper.IpCidrPattern, lower.IpCidrPattern) &&
                    ConditionCoversTokens(upper.PortPattern, lower.PortPattern) &&
                    (upper.Protocol == RuleProtocolIpcEntity.Any || upper.Protocol == lower.Protocol);

                if (upperBroaderOrEqual)
                {
                    warnings.Add(new MultiTunnelRuleConflict(
                        upper.PriorityOrder,
                        upper.Name,
                        lower.PriorityOrder,
                        lower.Name,
                        $"Rule #{lower.PriorityOrder} ('{lower.Name}') may be shadowed by Rule #{upper.PriorityOrder} ('{upper.Name}')."));
                }
            }
        }

        return warnings;
    }

    private static bool ConditionCoversTokens(string? upperPattern, string? lowerPattern)
    {
        if (string.IsNullOrWhiteSpace(upperPattern))
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(lowerPattern))
        {
            return false;
        }

        HashSet<string> upperTokens = SplitTokens(upperPattern)
            .Select(t => t.ToLowerInvariant())
            .ToHashSet();

        return SplitTokens(lowerPattern)
            .All(t => upperTokens.Contains(t.ToLowerInvariant()));
    }

    private static IEnumerable<string> SplitTokens(string raw)
        => raw.Split([',', ';', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    public static List<MultiTunnelRuleConfig> CreateDefaultRules()
    {
        return
        [
            new MultiTunnelRuleConfig
            {
                PriorityOrder = 1,
                Name = "Banking & Local Services (.vn)",
                IsEnabled = true,
                DomainPattern = "*.vietcombank.com.vn, *.techcombank.com.vn, *.vneid.gov.vn, *.vn",
                TargetType = RuleTargetTypeIpcEntity.Direct,
            },
            new MultiTunnelRuleConfig
            {
                PriorityOrder = 2,
                Name = "Private LAN & Corporate Subnets",
                IsEnabled = true,
                IpCidrPattern = "192.168.0.0/16, 10.100.0.0/16, 172.16.0.0/12",
                TargetType = RuleTargetTypeIpcEntity.Direct,
            },
            new MultiTunnelRuleConfig
            {
                PriorityOrder = 3,
                Name = "AI & International Streaming",
                IsEnabled = true,
                DomainPattern = "*.openai.com, *.chatgpt.com, *.claude.ai, *.anthropic.com, *.netflix.com",
                TargetType = RuleTargetTypeIpcEntity.Tunnel,
                TargetTunnelId = "T1",
                FallbackBehavior = TunnelFallbackBehaviorIpcEntity.KillSwitchBlock,
            },
            new MultiTunnelRuleConfig
            {
                PriorityOrder = 4,
                Name = "P2P / BitTorrent (Strict Kill-Switch)",
                IsEnabled = true,
                AppPattern = "qbittorrent, transmission, deluge",
                TargetType = RuleTargetTypeIpcEntity.Tunnel,
                TargetTunnelId = "T1",
                FallbackBehavior = TunnelFallbackBehaviorIpcEntity.KillSwitchBlock,
            },
            new MultiTunnelRuleConfig
            {
                PriorityOrder = 5,
                Name = "Work Browsers & Messaging",
                IsEnabled = true,
                AppPattern = "chrome, firefox, msedge, telegram",
                TargetType = RuleTargetTypeIpcEntity.Tunnel,
                TargetTunnelId = "T1",
                FallbackBehavior = TunnelFallbackBehaviorIpcEntity.FallbackToDirect,
            },
            new MultiTunnelRuleConfig
            {
                PriorityOrder = 6,
                Name = "Low-Latency Meetings & Gaming UDP",
                IsEnabled = true,
                AppPattern = "zoom, discord, steam",
                PortPattern = "3478-3481",
                Protocol = RuleProtocolIpcEntity.Udp,
                TargetType = RuleTargetTypeIpcEntity.Direct,
            },
        ];
    }
}
