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
using System.Runtime.Serialization;
using ProtonVPN.ProcessCommunication.Contracts.Entities.Vpn;

namespace ProtonVPN.ProcessCommunication.Contracts.Entities.MultiTunnel;

[DataContract]
public enum RuleTargetTypeIpcEntity
{
    [EnumMember] Tunnel = 0,
    [EnumMember] Direct = 1,
    [EnumMember] Block = 2,
}

[DataContract]
public enum TunnelFallbackBehaviorIpcEntity
{
    [EnumMember] KillSwitchBlock = 0,
    [EnumMember] FallbackToTunnel = 1,
    [EnumMember] FallbackToDirect = 2,
}

[DataContract]
public enum RuleProtocolIpcEntity
{
    [EnumMember] Any = 0,
    [EnumMember] Tcp = 1,
    [EnumMember] Udp = 2,
}

[DataContract]
public class SelectiveRoutingRuleIpcEntity
{
    [DataMember(Order = 1)] public Guid Id { get; set; } = Guid.NewGuid();
    [DataMember(Order = 2)] public int PriorityOrder { get; set; }
    [DataMember(Order = 3)] public string Name { get; set; } = string.Empty;
    [DataMember(Order = 4)] public bool IsEnabled { get; set; } = true;
    [DataMember(Order = 5)] public string? AppPattern { get; set; }
    [DataMember(Order = 6)] public string? AppSha256 { get; set; }
    [DataMember(Order = 7)] public bool IncludeChildProcesses { get; set; } = true;
    [DataMember(Order = 8)] public string? DomainPattern { get; set; }
    [DataMember(Order = 9)] public string? IpCidrPattern { get; set; }
    [DataMember(Order = 10)] public string? PortPattern { get; set; }
    [DataMember(Order = 11)] public RuleProtocolIpcEntity Protocol { get; set; } = RuleProtocolIpcEntity.Any;
    [DataMember(Order = 12)] public RuleTargetTypeIpcEntity TargetType { get; set; } = RuleTargetTypeIpcEntity.Tunnel;
    [DataMember(Order = 13)] public string TargetTunnelId { get; set; } = "T1";
    [DataMember(Order = 14)] public TunnelFallbackBehaviorIpcEntity FallbackBehavior { get; set; } = TunnelFallbackBehaviorIpcEntity.KillSwitchBlock;
    [DataMember(Order = 15)] public string? FallbackTunnelId { get; set; }
}

[DataContract]
public class TunnelSlotStateIpcEntity
{
    [DataMember(Order = 1)] public string SlotId { get; set; } = "T1";
    [DataMember(Order = 2)] public int SlotIndex { get; set; }
    [DataMember(Order = 3)] public string AdapterName { get; set; } = "ProtonVPN-T1";
    [DataMember(Order = 4)] public VpnStatusIpcEntity Status { get; set; } = VpnStatusIpcEntity.Disconnected;
    [DataMember(Order = 5)] public string ClientIpv4Address { get; set; } = "10.2.0.2";
    [DataMember(Order = 6)] public string ServerGatewayIpv4Address { get; set; } = "10.2.0.1";
    [DataMember(Order = 7)] public string? ClientIpv6Address { get; set; } = "2a07:b944::2:2";
    [DataMember(Order = 8)] public string ServerCountryCode { get; set; } = string.Empty;
    [DataMember(Order = 9)] public string ServerName { get; set; } = string.Empty;
    [DataMember(Order = 10)] public string EntryIp { get; set; } = string.Empty;
    [DataMember(Order = 11)] public string ExitIp { get; set; } = string.Empty;
    [DataMember(Order = 12)] public string BouncingLabel { get; set; } = string.Empty;
    [DataMember(Order = 13)] public VpnProtocolIpcEntity Protocol { get; set; } = VpnProtocolIpcEntity.WireGuardUdp;
    [DataMember(Order = 14)] public int NetShieldMode { get; set; } = 2;
    [DataMember(Order = 15)] public bool PortForwardingEnabled { get; set; }
    [DataMember(Order = 16)] public int ActiveForwardedPort { get; set; }
    [DataMember(Order = 17)] public bool IsDefaultRouteTunnel { get; set; }
}

[DataContract]
public class MultiTunnelPolicyIpcEntity
{
    [DataMember(Order = 1)] public bool IsMultiTunnelEnabled { get; set; }
    [DataMember(Order = 2)] public RuleTargetTypeIpcEntity DefaultTargetType { get; set; } = RuleTargetTypeIpcEntity.Direct;
    [DataMember(Order = 3)] public string DefaultTunnelId { get; set; } = "T1";
    [DataMember(Order = 4)] public List<TunnelSlotStateIpcEntity> TunnelSlots { get; set; } = [];
    [DataMember(Order = 5)] public List<SelectiveRoutingRuleIpcEntity> PriorityRules { get; set; } = [];
}

[DataContract]
public class TrafficQueryIpcEntity
{
    [DataMember(Order = 1)] public string? AppPath { get; set; }
    [DataMember(Order = 2)] public string? ProcessName { get; set; }
    [DataMember(Order = 3)] public string? ActualAppSha256 { get; set; }
    [DataMember(Order = 4)] public string? Domain { get; set; }
    [DataMember(Order = 5)] public string? RemoteIp { get; set; }
    [DataMember(Order = 6)] public int? RemotePort { get; set; }
    [DataMember(Order = 7)] public RuleProtocolIpcEntity Protocol { get; set; } = RuleProtocolIpcEntity.Any;
}

[DataContract]
public class RoutingDecisionIpcEntity
{
    [DataMember(Order = 1)] public RuleTargetTypeIpcEntity EffectiveTargetType { get; set; }
    [DataMember(Order = 2)] public string? EffectiveTunnelId { get; set; }
    [DataMember(Order = 3)] public Guid? MatchedRuleId { get; set; }
    [DataMember(Order = 4)] public int MatchedRulePriority { get; set; }
    [DataMember(Order = 5)] public string MatchedRuleName { get; set; } = string.Empty;
    [DataMember(Order = 6)] public bool IsFallbackApplied { get; set; }
    [DataMember(Order = 7)] public bool IsKillSwitchBlocked { get; set; }
    [DataMember(Order = 8)] public bool IsHashMismatchBlocked { get; set; }
    [DataMember(Order = 9)] public uint WfpFilterWeight { get; set; }
    [DataMember(Order = 10)] public string Explanation { get; set; } = string.Empty;
}

[DataContract]
public class MultiTunnelSlotConnectionRequestIpcEntity
{
    [DataMember(Order = 1)] public string SlotId { get; set; } = string.Empty;
    [DataMember(Order = 2)] public int SlotIndex { get; set; }
    [DataMember(Order = 3)] public string ClientIpv4Address { get; set; } = "10.3.0.2";
    [DataMember(Order = 4)] public string ServerGatewayIpv4Address { get; set; } = "10.3.0.1";
    [DataMember(Order = 5)] public string CountryCode { get; set; } = string.Empty;
    [DataMember(Order = 6)] public string ServerName { get; set; } = string.Empty;
    [DataMember(Order = 7)] public ConnectionRequestIpcEntity? ConnectionRequest { get; set; }
}

[DataContract]
public class MultiTunnelSlotConnectionResultIpcEntity
{
    [DataMember(Order = 1)] public bool Success { get; set; }
    [DataMember(Order = 2)] public string SlotId { get; set; } = string.Empty;
    [DataMember(Order = 3)] public string ConnectedServerName { get; set; } = string.Empty;
    [DataMember(Order = 4)] public string ConnectedEntryIp { get; set; } = string.Empty;
    [DataMember(Order = 5)] public string ErrorMessage { get; set; } = string.Empty;
}

[DataContract]
public class MultiTunnelSlotDisconnectionRequestIpcEntity
{
    [DataMember(Order = 1)] public string SlotId { get; set; } = string.Empty;
}

[DataContract]
public class SlotNetworkTrafficIpcEntity
{
    [DataMember(Order = 1)] public string SlotId { get; set; } = string.Empty;
    [DataMember(Order = 2)] public ulong BytesDownloaded { get; set; }
    [DataMember(Order = 3)] public ulong BytesUploaded { get; set; }
    [DataMember(Order = 4)] public bool IsConnected { get; set; }
}

[DataContract]
public class MultiTunnelTrafficSnapshotIpcEntity
{
    [DataMember(Order = 1)] public List<SlotNetworkTrafficIpcEntity> Slots { get; set; } = [];
}
