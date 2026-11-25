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

using ProtonVPN.ProcessCommunication.Contracts.Entities.MultiTunnel;

namespace ProtonVPN.Client.Logic.Connection.Contracts.MultiTunnel;

public interface IMultiTunnelManager
{
    bool IsEnabled { get; }
    RuleTargetTypeIpcEntity DefaultTargetType { get; }
    string DefaultTunnelId { get; }
    IReadOnlyList<MultiTunnelSlotConfig> Slots { get; }
    IReadOnlyList<MultiTunnelRuleConfig> Rules { get; }
    IReadOnlyList<MultiTunnelRuleConflict> Conflicts { get; }
    int EnabledRuleCount { get; }
    int ConnectedSlotCount { get; }

    Task SetEnabledAsync(bool enabled);
    Task SetDefaultRoutingAsync(RuleTargetTypeIpcEntity defaultTargetType, string defaultTunnelId);
    Task<MultiTunnelSlotConfig?> AddSlotAsync(string countryCode, string serverName, string city = "", string entryIp = "", string exitIp = "");
    Task UpdateSlotLocationAsync(string slotId, string countryCode, string serverName, string city = "", string entryIp = "", string exitIp = "");
    Task RemoveSlotAsync(string slotId);
    Task<bool> ConnectSlotAsync(string slotId);
    Task DisconnectSlotAsync(string slotId);

    Task AddRuleAsync(MultiTunnelRuleConfig rule);
    Task UpdateRuleAsync(MultiTunnelRuleConfig rule);
    Task SetRuleEnabledAsync(Guid ruleId, bool isEnabled);
    Task DeleteRuleAsync(Guid ruleId);
    Task MoveRuleAsync(Guid ruleId, int delta);
    Task ResetDefaultRulesAsync();

    Task SyncPolicyToServiceAsync();
    Task<RoutingDecisionIpcEntity> EvaluateTrafficAsync(TrafficQueryIpcEntity query);
    MultiTunnelPolicyIpcEntity BuildIpcPolicy();
}
