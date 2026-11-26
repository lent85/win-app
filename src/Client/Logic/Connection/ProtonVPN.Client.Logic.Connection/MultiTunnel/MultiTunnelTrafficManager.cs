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

using System.Timers;
using ProtonVPN.Client.EventMessaging.Contracts;
using ProtonVPN.Client.Logic.Connection.Contracts;
using ProtonVPN.Client.Logic.Connection.Contracts.History;
using ProtonVPN.Client.Logic.Connection.Contracts.Messages;
using ProtonVPN.Client.Logic.Connection.Contracts.MultiTunnel;
using ProtonVPN.Client.Logic.Services.Contracts;
using ProtonVPN.Common.Core.Extensions;
using ProtonVPN.Common.Core.Networking;
using ProtonVPN.Common.Core.Queues;
using ProtonVPN.Common.Legacy.Abstract;
using ProtonVPN.ProcessCommunication.Contracts.Entities.MultiTunnel;
using Timer = System.Timers.Timer;

namespace ProtonVPN.Client.Logic.Connection.MultiTunnel;

public sealed class MultiTunnelTrafficManager : IMultiTunnelTrafficManager,
    IDisposable,
    IEventMessageReceiver<MultiTunnelPolicyChangedMessage>,
    IEventMessageReceiver<ConnectionStatusChangedMessage>
{
    private const int HISTORY_LENGTH_IN_SECONDS = 60;

    private sealed class SlotTracker
    {
        public string SlotId { get; }
        public FixedSizeQueue<NetworkTraffic> SpeedHistory { get; } = new(HISTORY_LENGTH_IN_SECONDS, NetworkTraffic.Zero);
        public NetworkTraffic? LastVolume { get; set; }
        public NetworkTraffic LastSpeed { get; set; } = NetworkTraffic.Zero;
        public NetworkTraffic CurrentVolume { get; set; } = NetworkTraffic.Zero;

        public SlotTracker(string slotId)
        {
            SlotId = slotId;
        }

        public void Reset()
        {
            SpeedHistory.Reset();
            LastVolume = null;
            LastSpeed = NetworkTraffic.Zero;
            CurrentVolume = NetworkTraffic.Zero;
        }
    }

    private readonly IMultiTunnelManager _multiTunnelManager;
    private readonly IVpnServiceCaller _vpnServiceCaller;
    private readonly INetworkTrafficManager _primaryTrafficManager;
    private readonly IConnectionManager _connectionManager;
    private readonly IEventMessageSender _eventMessageSender;
    private readonly Timer _timer;
    private readonly object _lock = new();
    private readonly Dictionary<string, SlotTracker> _trackers = new(StringComparer.OrdinalIgnoreCase);

    private string _selectedMetricsSlotId = "ALL";
    private int _isPolling;

    public string SelectedMetricsSlotId
    {
        get { lock (_lock) { return _selectedMetricsSlotId; } }
    }

    public MultiTunnelTrafficManager(
        IMultiTunnelManager multiTunnelManager,
        IVpnServiceCaller vpnServiceCaller,
        INetworkTrafficManager primaryTrafficManager,
        IConnectionManager connectionManager,
        IEventMessageSender eventMessageSender)
    {
        _multiTunnelManager = multiTunnelManager;
        _vpnServiceCaller = vpnServiceCaller;
        _primaryTrafficManager = primaryTrafficManager;
        _connectionManager = connectionManager;
        _eventMessageSender = eventMessageSender;

        _timer = new Timer(TimeSpan.FromSeconds(1)) { AutoReset = true };
        _timer.Elapsed += OnTimerElapsed;

        UpdateTimerState();
    }

    public void Dispose()
    {
        _timer.Stop();
        _timer.Elapsed -= OnTimerElapsed;
        _timer.Dispose();
    }

    public void SelectMetricsSlot(string slotId)
    {
        string normalized = string.IsNullOrWhiteSpace(slotId) ? "ALL" : slotId.Trim().ToUpperInvariant();
        lock (_lock)
        {
            if (string.Equals(_selectedMetricsSlotId, normalized, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
            _selectedMetricsSlotId = normalized;
        }

        _eventMessageSender.Send(new MultiTunnelTrafficChangedMessage());
    }

    public SlotTrafficSnapshot? GetSlotTraffic(string slotId)
    {
        if (string.IsNullOrWhiteSpace(slotId))
        {
            return null;
        }

        MultiTunnelSlotConfig? slot = _multiTunnelManager.Slots.FirstOrDefault(s =>
            string.Equals(s.SlotId, slotId, StringComparison.OrdinalIgnoreCase));
        if (slot is null)
        {
            return null;
        }

        lock (_lock)
        {
            SlotTracker tracker = GetOrCreateTrackerLocked(slot.SlotId);
            return BuildSnapshotLocked(slot, tracker);
        }
    }

    public IReadOnlyList<SlotTrafficSnapshot> GetConnectedSlotTraffics()
    {
        IReadOnlyList<MultiTunnelSlotConfig> slots = _multiTunnelManager.Slots;
        List<SlotTrafficSnapshot> result = [];

        lock (_lock)
        {
            foreach (MultiTunnelSlotConfig slot in slots.Where(s => s.IsConnected).OrderBy(s => s.SlotIndex))
            {
                SlotTracker tracker = GetOrCreateTrackerLocked(slot.SlotId);
                result.Add(BuildSnapshotLocked(slot, tracker));
            }
        }

        return result;
    }

    public NetworkTraffic GetTotalSpeed()
    {
        IReadOnlyList<SlotTrafficSnapshot> connected = GetConnectedSlotTraffics();
        ulong rx = 0;
        ulong tx = 0;
        foreach (SlotTrafficSnapshot s in connected)
        {
            rx += s.Speed.BytesDownloaded;
            tx += s.Speed.BytesUploaded;
        }
        return new NetworkTraffic(rx, tx);
    }

    public NetworkTraffic GetTotalVolume()
    {
        IReadOnlyList<SlotTrafficSnapshot> connected = GetConnectedSlotTraffics();
        ulong rx = 0;
        ulong tx = 0;
        foreach (SlotTrafficSnapshot s in connected)
        {
            rx += s.Volume.BytesDownloaded;
            tx += s.Volume.BytesUploaded;
        }
        return new NetworkTraffic(rx, tx);
    }

    public void Receive(MultiTunnelPolicyChangedMessage message)
    {
        SyncDisconnectedTrackers();
        UpdateTimerState();
    }

    public void Receive(ConnectionStatusChangedMessage message)
    {
        SyncDisconnectedTrackers();
        UpdateTimerState();
    }

    private void UpdateTimerState()
    {
        bool shouldRun = _multiTunnelManager.IsEnabled && _multiTunnelManager.ConnectedSlotCount > 0;
        _timer.Enabled = shouldRun;
    }

    private void SyncDisconnectedTrackers()
    {
        IReadOnlyList<MultiTunnelSlotConfig> slots = _multiTunnelManager.Slots;
        bool resetSelected = false;

        lock (_lock)
        {
            HashSet<string> connectedIds = slots
                .Where(s => s.IsConnected)
                .Select(s => s.SlotId)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (KeyValuePair<string, SlotTracker> kvp in _trackers)
            {
                if (!connectedIds.Contains(kvp.Key))
                {
                    kvp.Value.Reset();
                }
            }

            if (!string.Equals(_selectedMetricsSlotId, "ALL", StringComparison.OrdinalIgnoreCase) &&
                !connectedIds.Contains(_selectedMetricsSlotId))
            {
                _selectedMetricsSlotId = "ALL";
                resetSelected = true;
            }
        }

        if (resetSelected)
        {
            _eventMessageSender.Send(new MultiTunnelTrafficChangedMessage());
        }
    }

    private void OnTimerElapsed(object? sender, ElapsedEventArgs e)
    {
        PollTrafficAsync().FireAndForget();
    }

    private async Task PollTrafficAsync()
    {
        if (Interlocked.Exchange(ref _isPolling, 1) == 1)
        {
            return;
        }

        try
        {
            MultiTunnelTrafficSnapshotIpcEntity? snapshot = null;
            bool ipcSucceeded = false;
            try
            {
                Result<MultiTunnelTrafficSnapshotIpcEntity> result = await _vpnServiceCaller.GetMultiTunnelNetworkTrafficAsync();
                if (result is { Success: true, Value: not null })
                {
                    snapshot = result.Value;
                    ipcSucceeded = true;
                }
            }
            catch
            {
            }

            DateTime now = DateTime.UtcNow;
            IReadOnlyList<MultiTunnelSlotConfig> slots = _multiTunnelManager.Slots;

            Dictionary<string, SlotNetworkTrafficIpcEntity> ipcBySlot = (snapshot?.Slots ?? [])
                .Where(s => !string.IsNullOrWhiteSpace(s.SlotId))
                .GroupBy(s => s.SlotId.ToUpperInvariant(), StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

            lock (_lock)
            {
                foreach (MultiTunnelSlotConfig slot in slots)
                {
                    SlotTracker tracker = GetOrCreateTrackerLocked(slot.SlotId);
                    if (!slot.IsConnected)
                    {
                        tracker.Reset();
                        continue;
                    }

                    bool hasSample = false;
                    NetworkTraffic volume = NetworkTraffic.Zero;
                    if (ipcSucceeded && ipcBySlot.TryGetValue(slot.SlotId, out SlotNetworkTrafficIpcEntity? ipcSlot))
                    {
                        volume = new NetworkTraffic(ipcSlot.BytesDownloaded, ipcSlot.BytesUploaded, now);
                        hasSample = true;
                    }

                    if (string.Equals(slot.SlotId, "T1", StringComparison.OrdinalIgnoreCase) &&
                        volume.Sum() == 0 &&
                        _connectionManager.IsConnected)
                    {
                        NetworkTraffic primaryVol = _primaryTrafficManager.GetVolume();
                        volume = new NetworkTraffic(primaryVol.BytesDownloaded, primaryVol.BytesUploaded, now);
                        hasSample = true;
                    }

                    if (!hasSample)
                    {
                        continue;
                    }

                    UpdateTrackerSampleLocked(tracker, volume, now);
                }
            }

            _eventMessageSender.Send(new MultiTunnelTrafficChangedMessage());
        }
        finally
        {
            Interlocked.Exchange(ref _isPolling, 0);
        }
    }

    private static void UpdateTrackerSampleLocked(SlotTracker tracker, NetworkTraffic volume, DateTime now)
    {
        if (tracker.LastVolume is null || volume.BytesDownloaded < tracker.LastVolume.Value.BytesDownloaded || volume.BytesUploaded < tracker.LastVolume.Value.BytesUploaded)
        {
            tracker.LastVolume = volume;
            tracker.CurrentVolume = volume;
            tracker.LastSpeed = NetworkTraffic.Zero;
            tracker.SpeedHistory.Enqueue(NetworkTraffic.Zero.Copy(now));
            return;
        }

        double seconds = (now - tracker.LastVolume.Value.UtcDate).TotalSeconds;
        if (seconds < 0.25)
        {
            return;
        }

        ulong rxDelta = volume.BytesDownloaded - tracker.LastVolume.Value.BytesDownloaded;
        ulong txDelta = volume.BytesUploaded - tracker.LastVolume.Value.BytesUploaded;
        NetworkTraffic speed = new((ulong)(rxDelta / seconds), (ulong)(txDelta / seconds), now);

        tracker.LastVolume = volume;
        tracker.CurrentVolume = volume;
        tracker.LastSpeed = speed;
        tracker.SpeedHistory.Enqueue(speed);
    }

    private SlotTracker GetOrCreateTrackerLocked(string slotId)
    {
        if (!_trackers.TryGetValue(slotId, out SlotTracker? tracker))
        {
            tracker = new SlotTracker(slotId.ToUpperInvariant());
            _trackers[slotId] = tracker;
        }
        return tracker;
    }

    private static SlotTrafficSnapshot BuildSnapshotLocked(MultiTunnelSlotConfig slot, SlotTracker tracker)
    {
        return new SlotTrafficSnapshot(
            SlotId: slot.SlotId,
            CountryCode: slot.CountryCode,
            ServerName: slot.ServerName,
            ColorHex: MultiTunnelSlotConfig.GetSlotColorHex(slot.SlotId),
            IsConnected: slot.IsConnected,
            Speed: tracker.LastSpeed,
            Volume: tracker.CurrentVolume,
            SpeedHistory: tracker.SpeedHistory.ToList());
    }
}
