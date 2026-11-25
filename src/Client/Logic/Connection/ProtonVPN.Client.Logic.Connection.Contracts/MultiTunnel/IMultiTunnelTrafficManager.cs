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

using ProtonVPN.Common.Core.Networking;

namespace ProtonVPN.Client.Logic.Connection.Contracts.MultiTunnel;

public sealed record SlotTrafficSnapshot(
    string SlotId,
    string CountryCode,
    string ServerName,
    string ColorHex,
    bool IsConnected,
    NetworkTraffic Speed,
    NetworkTraffic Volume,
    IReadOnlyList<NetworkTraffic> SpeedHistory);

public sealed record MultiTunnelTrafficChangedMessage;

public interface IMultiTunnelTrafficManager
{
    string SelectedMetricsSlotId { get; }
    void SelectMetricsSlot(string slotId);
    SlotTrafficSnapshot? GetSlotTraffic(string slotId);
    IReadOnlyList<SlotTrafficSnapshot> GetConnectedSlotTraffics();
    NetworkTraffic GetTotalSpeed();
    NetworkTraffic GetTotalVolume();
}
