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

using System.Threading;
using System.Threading.Tasks;
using ProtonVPN.Common.Core.Networking;
using ProtonVPN.ProcessCommunication.Contracts.Entities.MultiTunnel;

namespace ProtonVPN.Service.MultiTunnel;

public interface IMultiTunnelService
{
    bool IsEnabled { get; }
    void ApplyPolicy(MultiTunnelPolicyIpcEntity policy);
    MultiTunnelPolicyIpcEntity GetCurrentPolicy();
    RoutingDecisionIpcEntity EvaluateTraffic(TrafficQueryIpcEntity query);
    Task<MultiTunnelSlotConnectionResultIpcEntity> ConnectSlotAsync(MultiTunnelSlotConnectionRequestIpcEntity request, CancellationToken cancelToken);
    Task DisconnectSlotAsync(string slotId, CancellationToken cancelToken);
    MultiTunnelTrafficSnapshotIpcEntity GetTrafficSnapshot(NetworkTraffic primaryTraffic);
    void OnVpnConnected(VpnState state);
    void OnVpnDisconnected(VpnState state, bool isReconnecting);
    void OnServiceStop();
}
