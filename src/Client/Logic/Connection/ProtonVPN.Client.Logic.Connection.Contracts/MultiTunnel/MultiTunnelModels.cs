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

using System.Text.Json.Serialization;
using ProtonVPN.ProcessCommunication.Contracts.Entities.MultiTunnel;

namespace ProtonVPN.Client.Logic.Connection.Contracts.MultiTunnel;

public sealed class MultiTunnelSlotConfig
{
    public const int MaxSlots = 5;

    public string SlotId { get; set; } = "T1";
    public int SlotIndex { get; set; }
    public string CountryCode { get; set; } = string.Empty;
    public string ServerName { get; set; } = string.Empty;
    public string City { get; set; } = string.Empty;
    public string EntryIp { get; set; } = string.Empty;
    public string ExitIp { get; set; } = string.Empty;
    public string ClientIpv4 { get; set; } = "10.2.0.2";
    public string ServerGatewayIpv4 { get; set; } = "10.2.0.1";
    public bool IsConnected { get; set; }
    public bool IsDefaultRouteTunnel { get; set; }

    [JsonIgnore]
    public bool IsConnecting { get; set; }

    [JsonIgnore]
    public string? LastError { get; set; }

    public static string GetSlotColorHex(string? slotId) =>
        (slotId?.Trim().ToUpperInvariant()) switch
        {
            "T1" => "#1EA885",
            "T2" => "#38BDF8",
            "T3" => "#A78BFA",
            "T4" => "#F59E0B",
            "T5" => "#F43F5E",
            _ => "#1EA885",
        };

    public static MultiTunnelSlotConfig CreateDefault(
        int slotIndex,
        string countryCode,
        string serverName,
        string city = "",
        string entryIp = "",
        string exitIp = "")
    {
        return new MultiTunnelSlotConfig
        {
            SlotId = $"T{slotIndex + 1}",
            SlotIndex = slotIndex,
            CountryCode = countryCode.Trim().ToUpperInvariant(),
            ServerName = serverName.Trim(),
            City = city.Trim(),
            EntryIp = entryIp.Trim(),
            ExitIp = exitIp.Trim(),
            ClientIpv4 = $"10.{2 + slotIndex}.0.2",
            ServerGatewayIpv4 = $"10.{2 + slotIndex}.0.1",
            IsConnected = false,
            IsDefaultRouteTunnel = slotIndex == 0,
        };
    }
}

public sealed class MultiTunnelRuleConfig
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public int PriorityOrder { get; set; }
    public string Name { get; set; } = string.Empty;
    public bool IsEnabled { get; set; } = true;

    public string? AppPattern { get; set; }
    public string? DomainPattern { get; set; }
    public string? IpCidrPattern { get; set; }
    public string? PortPattern { get; set; }
    public RuleProtocolIpcEntity Protocol { get; set; } = RuleProtocolIpcEntity.Any;

    public RuleTargetTypeIpcEntity TargetType { get; set; } = RuleTargetTypeIpcEntity.Tunnel;
    public string TargetTunnelId { get; set; } = "T1";
    public TunnelFallbackBehaviorIpcEntity FallbackBehavior { get; set; } = TunnelFallbackBehaviorIpcEntity.KillSwitchBlock;
    public string? FallbackTunnelId { get; set; }

    public bool HasAnyCondition =>
        !string.IsNullOrWhiteSpace(AppPattern) ||
        !string.IsNullOrWhiteSpace(DomainPattern) ||
        !string.IsNullOrWhiteSpace(IpCidrPattern) ||
        !string.IsNullOrWhiteSpace(PortPattern) ||
        Protocol != RuleProtocolIpcEntity.Any;

    public string ConditionsSummary
    {
        get
        {
            List<string> parts = [];
            if (!string.IsNullOrWhiteSpace(AppPattern))
            {
                parts.Add($"App: {AppPattern}");
            }
            if (!string.IsNullOrWhiteSpace(DomainPattern))
            {
                parts.Add($"Domain: {DomainPattern}");
            }
            if (!string.IsNullOrWhiteSpace(IpCidrPattern))
            {
                parts.Add($"IP: {IpCidrPattern}");
            }
            if (!string.IsNullOrWhiteSpace(PortPattern) || Protocol != RuleProtocolIpcEntity.Any)
            {
                string port = string.IsNullOrWhiteSpace(PortPattern) ? "*" : PortPattern;
                parts.Add($"Port: {port}/{Protocol}");
            }
            return parts.Count > 0 ? string.Join("  •  ", parts) : "Any (inactive)";
        }
    }

    public string TargetSummary => TargetType switch
    {
        RuleTargetTypeIpcEntity.Direct => "Direct",
        RuleTargetTypeIpcEntity.Block => "Block",
        _ => string.IsNullOrWhiteSpace(TargetTunnelId) ? "Tunnel T1" : $"Tunnel {TargetTunnelId.ToUpperInvariant()}",
    };

    public string FallbackSummary => TargetType != RuleTargetTypeIpcEntity.Tunnel
        ? "—"
        : FallbackBehavior switch
        {
            TunnelFallbackBehaviorIpcEntity.FallbackToTunnel =>
                $"Fallback {(string.IsNullOrWhiteSpace(FallbackTunnelId) ? "T1" : FallbackTunnelId.ToUpperInvariant())}",
            TunnelFallbackBehaviorIpcEntity.FallbackToDirect => "Fallback Direct",
            _ => "Kill-Switch",
        };
}

public sealed class MultiTunnelPolicyConfig
{
    public bool IsMultiTunnelEnabled { get; set; }
    public RuleTargetTypeIpcEntity DefaultTargetType { get; set; } = RuleTargetTypeIpcEntity.Direct;
    public string DefaultTunnelId { get; set; } = "T1";
    public List<MultiTunnelSlotConfig> Slots { get; set; } = [];
    public List<MultiTunnelRuleConfig> Rules { get; set; } = [];
}

public sealed record MultiTunnelRuleConflict(
    int UpperPriorityOrder,
    string UpperRuleName,
    int LowerPriorityOrder,
    string LowerRuleName,
    string Description);

public sealed record MultiTunnelPolicyChangedMessage(bool IsEnabled, int SlotCount, int EnabledRuleCount);
