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
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Numerics;

namespace ProtonVPN.Service.MultiTunnel;

public enum RuleTargetType
{
    Tunnel = 0,
    Direct = 1,
    Block = 2,
}

public enum TunnelFallbackBehavior
{
    KillSwitchBlock = 0,
    FallbackToTunnel = 1,
    FallbackToDirect = 2,
}

public enum RuleProtocol
{
    Any = 0,
    Tcp = 1,
    Udp = 2,
}

public enum RuleConflictType
{
    DuplicateMatch = 0,
    ShadowedByBroaderRule = 1,
}

public sealed record TunnelSlotAllocation(
    string SlotId,
    int SlotIndex,
    string AdapterName,
    Guid AdapterGuid,
    IPAddress ClientIpv4,
    IPAddress ServerGatewayIpv4,
    IPAddress ClientIpv6,
    IPAddress ServerGatewayIpv6,
    uint BaseRouteMetric)
{
    public const int MaxTunnelSlots = 5;

    public static TunnelSlotAllocation ForSlot(int slotIndex, IReadOnlySet<byte>? reservedSecondOctets = null)
    {
        if (slotIndex is < 0 or >= MaxTunnelSlots)
        {
            throw new ArgumentOutOfRangeException(nameof(slotIndex), $"Slot index must be between 0 and {MaxTunnelSlots - 1}.");
        }

        byte targetOctet = (byte)(2 + slotIndex);
        if (reservedSecondOctets is not null)
        {
            byte candidate = 2;
            int found = 0;
            while (candidate < 254)
            {
                if (!reservedSecondOctets.Contains(candidate))
                {
                    if (found == slotIndex)
                    {
                        targetOctet = candidate;
                        break;
                    }
                    found++;
                }
                candidate++;
            }
        }

        string slotId = $"T{slotIndex + 1}";
        string adapterName = $"ProtonVPN-{slotId}";
        Guid adapterGuid = Guid.Parse($"{{9BEB3451-4026-4F8A-8762-8F608B124FE{slotIndex}}}");

        return new TunnelSlotAllocation(
            SlotId: slotId,
            SlotIndex: slotIndex,
            AdapterName: adapterName,
            AdapterGuid: adapterGuid,
            ClientIpv4: new IPAddress([10, targetOctet, 0, 2]),
            ServerGatewayIpv4: new IPAddress([10, targetOctet, 0, 1]),
            ClientIpv6: IPAddress.Parse($"2a07:b944::{targetOctet:x}:2"),
            ServerGatewayIpv6: IPAddress.Parse($"2a07:b944::{targetOctet:x}:1"),
            BaseRouteMetric: (uint)(10 + slotIndex));
    }
}

public sealed class TunnelSlotRuntimeState
{
    public required string SlotId { get; init; }
    public required int SlotIndex { get; init; }
    public bool IsConnected { get; set; }
    public IPAddress ClientIpv4 { get; set; } = IPAddress.Parse("10.2.0.2");
    public IPAddress ServerGatewayIpv4 { get; set; } = IPAddress.Parse("10.2.0.1");
    public IPAddress? ClientIpv6 { get; set; }
    public string CountryCode { get; set; } = string.Empty;
    public string ServerName { get; set; } = string.Empty;
    public string EntryIp { get; set; } = string.Empty;
    public string ExitIp { get; set; } = string.Empty;
    public uint InterfaceIndex { get; set; }
}

public sealed class SelectiveRoutingRule
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public int PriorityOrder { get; set; }
    public string Name { get; set; } = string.Empty;
    public bool IsEnabled { get; set; } = true;

    public string? AppPattern { get; set; }
    public string? ExpectedAppSha256 { get; set; }
    public bool IncludeChildProcesses { get; set; } = true;

    public string? DomainPattern { get; set; }
    public string? IpCidrPattern { get; set; }
    public string? PortPattern { get; set; }
    public RuleProtocol Protocol { get; set; } = RuleProtocol.Any;

    public RuleTargetType TargetType { get; set; } = RuleTargetType.Tunnel;
    public string TargetTunnelId { get; set; } = "T1";
    public TunnelFallbackBehavior FallbackBehavior { get; set; } = TunnelFallbackBehavior.KillSwitchBlock;
    public string? FallbackTunnelId { get; set; }

    public bool HasAppCondition => !string.IsNullOrWhiteSpace(AppPattern);
    public bool HasDomainCondition => !string.IsNullOrWhiteSpace(DomainPattern);
    public bool HasIpCondition => !string.IsNullOrWhiteSpace(IpCidrPattern);
    public bool HasPortCondition => !string.IsNullOrWhiteSpace(PortPattern) || Protocol != RuleProtocol.Any;
    public bool HasAnyCondition => HasAppCondition || HasDomainCondition || HasIpCondition || HasPortCondition;
}

public sealed record TrafficQuery(
    string? AppPath = null,
    string? ProcessName = null,
    string? ActualAppSha256 = null,
    string? Domain = null,
    string? RemoteIp = null,
    int? RemotePort = null,
    RuleProtocol Protocol = RuleProtocol.Any);

public sealed record RoutingDecision(
    RuleTargetType EffectiveTargetType,
    string? EffectiveTunnelId,
    SelectiveRoutingRule? MatchedRule,
    bool IsFallbackApplied,
    bool IsKillSwitchBlocked,
    bool IsHashMismatchBlocked,
    uint WfpFilterWeight,
    string Explanation);

public sealed record RuleConflictWarning(
    Guid UpperRuleId,
    int UpperPriorityOrder,
    string UpperRuleName,
    Guid LowerRuleId,
    int LowerPriorityOrder,
    string LowerRuleName,
    RuleConflictType ConflictType,
    string Description);

public static class PriorityRuleEngine
{
    public const uint MaxWfpPriorityWeight = 60000;
    public const uint WfpPriorityStep = 10;
    public const uint DefaultPolicyWfpWeight = 100;

    public static uint ComputeWfpWeight(int priorityOrder)
    {
        if (priorityOrder <= 0)
        {
            return MaxWfpPriorityWeight;
        }

        uint deduction = (uint)Math.Min(priorityOrder * (int)WfpPriorityStep, (int)(MaxWfpPriorityWeight - 1000));
        return MaxWfpPriorityWeight - deduction;
    }

    public static RoutingDecision Evaluate(
        TrafficQuery query,
        IEnumerable<SelectiveRoutingRule> rules,
        IReadOnlyDictionary<string, TunnelSlotRuntimeState> tunnelStates,
        RuleTargetType defaultTargetType = RuleTargetType.Direct,
        string defaultTunnelId = "T1")
    {
        List<SelectiveRoutingRule> orderedRules = rules
            .Where(r => r.IsEnabled && r.HasAnyCondition)
            .OrderBy(r => r.PriorityOrder)
            .ToList();

        foreach (SelectiveRoutingRule rule in orderedRules)
        {
            if (!MatchesRule(rule, query, out bool hashMismatch))
            {
                if (hashMismatch)
                {
                    return new RoutingDecision(
                        EffectiveTargetType: RuleTargetType.Block,
                        EffectiveTunnelId: null,
                        MatchedRule: rule,
                        IsFallbackApplied: false,
                        IsKillSwitchBlocked: true,
                        IsHashMismatchBlocked: true,
                        WfpFilterWeight: ComputeWfpWeight(rule.PriorityOrder),
                        Explanation: $"Blocked by SHA-256 binary integrity mismatch on rule #{rule.PriorityOrder} ('{rule.Name}').");
                }
                continue;
            }

            return ResolveTarget(rule, tunnelStates);
        }

        return ResolveDefaultTarget(defaultTargetType, defaultTunnelId, tunnelStates);
    }

    public static List<RuleConflictWarning> DetectConflicts(IEnumerable<SelectiveRoutingRule> rules)
    {
        List<SelectiveRoutingRule> ordered = rules
            .Where(r => r.IsEnabled && r.HasAnyCondition)
            .OrderBy(r => r.PriorityOrder)
            .ToList();

        List<RuleConflictWarning> warnings = [];

        for (int i = 0; i < ordered.Count; i++)
        {
            SelectiveRoutingRule upper = ordered[i];
            for (int j = i + 1; j < ordered.Count; j++)
            {
                SelectiveRoutingRule lower = ordered[j];

                if (IsIdenticalConditionSet(upper, lower))
                {
                    warnings.Add(new RuleConflictWarning(
                        upper.Id, upper.PriorityOrder, upper.Name,
                        lower.Id, lower.PriorityOrder, lower.Name,
                        RuleConflictType.DuplicateMatch,
                        $"Rule #{lower.PriorityOrder} ('{lower.Name}') has identical match conditions to higher-priority Rule #{upper.PriorityOrder} ('{upper.Name}')."));
                }
                else if (DoesUpperRuleShadowLowerRule(upper, lower))
                {
                    warnings.Add(new RuleConflictWarning(
                        upper.Id, upper.PriorityOrder, upper.Name,
                        lower.Id, lower.PriorityOrder, lower.Name,
                        RuleConflictType.ShadowedByBroaderRule,
                        $"Rule #{lower.PriorityOrder} ('{lower.Name}') is shadowed by broader higher-priority Rule #{upper.PriorityOrder} ('{upper.Name}'). Move Rule #{lower.PriorityOrder} above Rule #{upper.PriorityOrder}."));
                }
            }
        }

        return warnings;
    }

    public static void NormalizePriorities(IList<SelectiveRoutingRule> rules)
    {
        for (int i = 0; i < rules.Count; i++)
        {
            rules[i].PriorityOrder = i + 1;
        }
    }

    private static RoutingDecision ResolveTarget(
        SelectiveRoutingRule rule,
        IReadOnlyDictionary<string, TunnelSlotRuntimeState> tunnelStates)
    {
        uint weight = ComputeWfpWeight(rule.PriorityOrder);

        if (rule.TargetType == RuleTargetType.Direct)
        {
            return new RoutingDecision(
                EffectiveTargetType: RuleTargetType.Direct,
                EffectiveTunnelId: null,
                MatchedRule: rule,
                IsFallbackApplied: false,
                IsKillSwitchBlocked: false,
                IsHashMismatchBlocked: false,
                WfpFilterWeight: weight,
                Explanation: $"Matched Rule #{rule.PriorityOrder} ('{rule.Name}') -> Direct physical connection.");
        }

        if (rule.TargetType == RuleTargetType.Block)
        {
            return new RoutingDecision(
                EffectiveTargetType: RuleTargetType.Block,
                EffectiveTunnelId: null,
                MatchedRule: rule,
                IsFallbackApplied: false,
                IsKillSwitchBlocked: false,
                IsHashMismatchBlocked: false,
                WfpFilterWeight: weight,
                Explanation: $"Matched Rule #{rule.PriorityOrder} ('{rule.Name}') -> Explicit Block.");
        }

        string targetId = string.IsNullOrWhiteSpace(rule.TargetTunnelId) ? "T1" : rule.TargetTunnelId.ToUpperInvariant();
        if (tunnelStates.TryGetValue(targetId, out TunnelSlotRuntimeState? slot) && slot.IsConnected)
        {
            return new RoutingDecision(
                EffectiveTargetType: RuleTargetType.Tunnel,
                EffectiveTunnelId: targetId,
                MatchedRule: rule,
                IsFallbackApplied: false,
                IsKillSwitchBlocked: false,
                IsHashMismatchBlocked: false,
                WfpFilterWeight: weight,
                Explanation: $"Matched Rule #{rule.PriorityOrder} ('{rule.Name}') -> Tunnel {targetId} ({slot.CountryCode} · {slot.ClientIpv4}).");
        }

        // Target tunnel is disconnected -> evaluate FallbackBehavior
        switch (rule.FallbackBehavior)
        {
            case TunnelFallbackBehavior.FallbackToTunnel:
                string? fallbackId = rule.FallbackTunnelId?.ToUpperInvariant();
                if (!string.IsNullOrWhiteSpace(fallbackId) &&
                    tunnelStates.TryGetValue(fallbackId, out TunnelSlotRuntimeState? fbSlot) &&
                    fbSlot.IsConnected)
                {
                    return new RoutingDecision(
                        EffectiveTargetType: RuleTargetType.Tunnel,
                        EffectiveTunnelId: fallbackId,
                        MatchedRule: rule,
                        IsFallbackApplied: true,
                        IsKillSwitchBlocked: false,
                        IsHashMismatchBlocked: false,
                        WfpFilterWeight: weight,
                        Explanation: $"Matched Rule #{rule.PriorityOrder} ('{rule.Name}'): primary {targetId} is down -> Fallback to {fallbackId} ({fbSlot.CountryCode}).");
                }

                return new RoutingDecision(
                    EffectiveTargetType: RuleTargetType.Block,
                    EffectiveTunnelId: null,
                    MatchedRule: rule,
                    IsFallbackApplied: true,
                    IsKillSwitchBlocked: true,
                    IsHashMismatchBlocked: false,
                    WfpFilterWeight: weight,
                    Explanation: $"Matched Rule #{rule.PriorityOrder} ('{rule.Name}'): both primary {targetId} and fallback {fallbackId ?? "N/A"} are disconnected -> Per-Tunnel Kill-Switch Blocked.");

            case TunnelFallbackBehavior.FallbackToDirect:
                return new RoutingDecision(
                    EffectiveTargetType: RuleTargetType.Direct,
                    EffectiveTunnelId: null,
                    MatchedRule: rule,
                    IsFallbackApplied: true,
                    IsKillSwitchBlocked: false,
                    IsHashMismatchBlocked: false,
                    WfpFilterWeight: weight,
                    Explanation: $"Matched Rule #{rule.PriorityOrder} ('{rule.Name}'): {targetId} is disconnected -> Fallback to Direct connection.");

            default:
                return new RoutingDecision(
                    EffectiveTargetType: RuleTargetType.Block,
                    EffectiveTunnelId: null,
                    MatchedRule: rule,
                    IsFallbackApplied: false,
                    IsKillSwitchBlocked: true,
                    IsHashMismatchBlocked: false,
                    WfpFilterWeight: weight,
                    Explanation: $"Matched Rule #{rule.PriorityOrder} ('{rule.Name}'): {targetId} is disconnected -> Per-Tunnel Kill-Switch Blocked.");
        }
    }

    private static RoutingDecision ResolveDefaultTarget(
        RuleTargetType defaultTargetType,
        string defaultTunnelId,
        IReadOnlyDictionary<string, TunnelSlotRuntimeState> tunnelStates)
    {
        if (defaultTargetType == RuleTargetType.Direct)
        {
            return new RoutingDecision(
                RuleTargetType.Direct, null, null, false, false, false, DefaultPolicyWfpWeight,
                "No priority rule matched -> Default Policy: Direct physical connection.");
        }

        if (defaultTargetType == RuleTargetType.Block)
        {
            return new RoutingDecision(
                RuleTargetType.Block, null, null, false, false, false, DefaultPolicyWfpWeight,
                "No priority rule matched -> Default Policy: Block all unmatched traffic.");
        }

        string targetId = string.IsNullOrWhiteSpace(defaultTunnelId) ? "T1" : defaultTunnelId.ToUpperInvariant();
        if (tunnelStates.TryGetValue(targetId, out TunnelSlotRuntimeState? slot) && slot.IsConnected)
        {
            return new RoutingDecision(
                RuleTargetType.Tunnel, targetId, null, false, false, false, DefaultPolicyWfpWeight,
                $"No priority rule matched -> Default Tunnel {targetId} ({slot.CountryCode}).");
        }

        return new RoutingDecision(
            RuleTargetType.Block, null, null, false, true, false, DefaultPolicyWfpWeight,
            $"No priority rule matched and Default Tunnel {targetId} is disconnected -> Blocked by Kill-Switch.");
    }

    private static bool MatchesRule(SelectiveRoutingRule rule, TrafficQuery query, out bool hashMismatch)
    {
        hashMismatch = false;

        if (rule.HasAppCondition)
        {
            if (!MatchesAppPattern(rule.AppPattern!, query.AppPath, query.ProcessName))
            {
                return false;
            }

            if (!string.IsNullOrWhiteSpace(rule.ExpectedAppSha256) &&
                !string.IsNullOrWhiteSpace(query.ActualAppSha256) &&
                !string.Equals(rule.ExpectedAppSha256.Trim(), query.ActualAppSha256.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                hashMismatch = true;
                return false;
            }
        }

        if (rule.HasDomainCondition && !MatchesDomainPattern(rule.DomainPattern!, query.Domain))
        {
            return false;
        }

        if (rule.HasIpCondition && !MatchesIpCidrPattern(rule.IpCidrPattern!, query.RemoteIp))
        {
            return false;
        }

        if (rule.HasPortCondition && !MatchesPortAndProtocol(rule.PortPattern, rule.Protocol, query.RemotePort, query.Protocol))
        {
            return false;
        }

        return true;
    }

    public static bool MatchesAppPattern(string patternList, string? appPath, string? processName)
    {
        string normalizedPath = NormalizePath(appPath);
        string normalizedExe = NormalizeProcessName(processName);
        if (string.IsNullOrEmpty(normalizedExe) && !string.IsNullOrEmpty(normalizedPath))
        {
            normalizedExe = NormalizeProcessName(Path.GetFileName(normalizedPath));
        }

        if (string.IsNullOrEmpty(normalizedPath) && string.IsNullOrEmpty(normalizedExe))
        {
            return false;
        }

        foreach (string rawToken in SplitTokens(patternList))
        {
            string tokenPath = NormalizePath(rawToken);
            string tokenExe = NormalizeProcessName(Path.GetFileName(tokenPath));

            if (!string.IsNullOrEmpty(normalizedPath) &&
                string.Equals(normalizedPath, tokenPath, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (!string.IsNullOrEmpty(normalizedExe) &&
                !string.IsNullOrEmpty(tokenExe) &&
                string.Equals(normalizedExe, tokenExe, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    public static bool MatchesDomainPattern(string patternList, string? rawDomain)
    {
        string domain = NormalizeDomain(rawDomain);
        if (string.IsNullOrEmpty(domain))
        {
            return false;
        }

        foreach (string rawToken in SplitTokens(patternList))
        {
            string token = rawToken.Trim().ToLowerInvariant();
            if (token.StartsWith("keyword:", StringComparison.Ordinal))
            {
                string kw = token["keyword:".Length..].Trim();
                if (!string.IsNullOrEmpty(kw) && domain.Contains(kw, StringComparison.Ordinal))
                {
                    return true;
                }
                continue;
            }

            string cleanPattern = NormalizeDomain(token, preserveLeadingWildcard: true);
            if (string.IsNullOrEmpty(cleanPattern))
            {
                continue;
            }

            if (cleanPattern == "*")
            {
                return true;
            }

            if (cleanPattern.StartsWith("*.", StringComparison.Ordinal))
            {
                string suffix = cleanPattern[2..];
                if (string.Equals(domain, suffix, StringComparison.Ordinal) ||
                    domain.EndsWith("." + suffix, StringComparison.Ordinal))
                {
                    return true;
                }
            }
            else if (cleanPattern.StartsWith(".", StringComparison.Ordinal))
            {
                string suffix = cleanPattern[1..];
                if (string.Equals(domain, suffix, StringComparison.Ordinal) ||
                    domain.EndsWith("." + suffix, StringComparison.Ordinal))
                {
                    return true;
                }
            }
            else if (string.Equals(domain, cleanPattern, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    public static bool MatchesIpCidrPattern(string patternList, string? remoteIpString)
    {
        if (string.IsNullOrWhiteSpace(remoteIpString) || !IPAddress.TryParse(remoteIpString.Trim(), out IPAddress? remoteIp))
        {
            return false;
        }

        foreach (string token in SplitTokens(patternList))
        {
            if (IsIpInCidr(remoteIp, token))
            {
                return true;
            }
        }

        return false;
    }

    public static bool MatchesPortAndProtocol(string? portPatternList, RuleProtocol ruleProto, int? queryPort, RuleProtocol queryProto)
    {
        if (ruleProto != RuleProtocol.Any && queryProto != RuleProtocol.Any && ruleProto != queryProto)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(portPatternList))
        {
            return true;
        }

        if (!queryPort.HasValue || queryPort.Value is <= 0 or > 65535)
        {
            return false;
        }

        int port = queryPort.Value;
        foreach (string token in SplitTokens(portPatternList))
        {
            int dashIdx = token.IndexOf('-');
            if (dashIdx > 0)
            {
                if (int.TryParse(token[..dashIdx].Trim(), out int startPort) &&
                    int.TryParse(token[(dashIdx + 1)..].Trim(), out int endPort))
                {
                    if (startPort > endPort)
                    {
                        (startPort, endPort) = (endPort, startPort);
                    }

                    if (port >= startPort && port <= endPort)
                    {
                        return true;
                    }
                }
            }
            else if (int.TryParse(token.Trim(), out int singlePort) && port == singlePort)
            {
                return true;
            }
        }

        return false;
    }

    public static bool IsIpInCidr(IPAddress ip, string cidrOrIp)
    {
        string trimmed = cidrOrIp.Trim();
        int slashIdx = trimmed.IndexOf('/');
        string networkPart = slashIdx >= 0 ? trimmed[..slashIdx].Trim() : trimmed;

        if (!IPAddress.TryParse(networkPart, out IPAddress? networkIp) ||
            networkIp.AddressFamily != ip.AddressFamily)
        {
            return false;
        }

        byte[] ipBytes = ip.GetAddressBytes();
        byte[] netBytes = networkIp.GetAddressBytes();
        int maxBits = ipBytes.Length * 8;
        int prefixLength = maxBits;

        if (slashIdx >= 0 && (!int.TryParse(trimmed[(slashIdx + 1)..].Trim(), out prefixLength) || prefixLength < 0 || prefixLength > maxBits))
        {
            return false;
        }

        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;

        for (int i = 0; i < fullBytes; i++)
        {
            if (ipBytes[i] != netBytes[i])
            {
                return false;
            }
        }

        if (remainingBits > 0)
        {
            byte mask = (byte)(0xFF << (8 - remainingBits));
            if ((ipBytes[fullBytes] & mask) != (netBytes[fullBytes] & mask))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsIdenticalConditionSet(SelectiveRoutingRule a, SelectiveRoutingRule b)
    {
        return NormalizeConditionTokenSet(a.AppPattern) == NormalizeConditionTokenSet(b.AppPattern) &&
               NormalizeConditionTokenSet(a.DomainPattern) == NormalizeConditionTokenSet(b.DomainPattern) &&
               NormalizeConditionTokenSet(a.IpCidrPattern) == NormalizeConditionTokenSet(b.IpCidrPattern) &&
               NormalizeConditionTokenSet(a.PortPattern) == NormalizeConditionTokenSet(b.PortPattern) &&
               a.Protocol == b.Protocol;
    }

    private static bool DoesUpperRuleShadowLowerRule(SelectiveRoutingRule upper, SelectiveRoutingRule lower)
    {
        if (!ConditionCoversApp(upper.AppPattern, lower.AppPattern))
        {
            return false;
        }

        if (!ConditionCoversDomain(upper.DomainPattern, lower.DomainPattern))
        {
            return false;
        }

        if (!ConditionCoversIpCidr(upper.IpCidrPattern, lower.IpCidrPattern))
        {
            return false;
        }

        if (!ConditionCoversPorts(upper.PortPattern, lower.PortPattern))
        {
            return false;
        }

        if (upper.Protocol != RuleProtocol.Any && upper.Protocol != lower.Protocol)
        {
            return false;
        }

        return true;
    }

    private static bool ConditionCoversApp(string? upperPattern, string? lowerPattern)
    {
        if (string.IsNullOrWhiteSpace(upperPattern))
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(lowerPattern))
        {
            return false;
        }

        string[] upperTokens = SplitTokens(upperPattern);
        string[] lowerTokens = SplitTokens(lowerPattern);
        HashSet<string> upperSet = upperTokens.Select(t => t.ToLowerInvariant()).ToHashSet();

        return lowerTokens.All(lt => upperSet.Contains(lt.ToLowerInvariant()) ||
                                     upperTokens.Any(ut => MatchesAppPattern(ut, lt, lt)));
    }

    private static bool ConditionCoversDomain(string? upperPattern, string? lowerPattern)
    {
        if (string.IsNullOrWhiteSpace(upperPattern))
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(lowerPattern))
        {
            return false;
        }

        string[] lowerTokens = SplitTokens(lowerPattern);
        return lowerTokens.All(lt =>
        {
            string sample = lt.StartsWith("*.", StringComparison.Ordinal) ? "sub." + lt[2..] : lt;
            return MatchesDomainPattern(upperPattern, sample);
        });
    }

    private static bool ConditionCoversIpCidr(string? upperPattern, string? lowerPattern)
    {
        if (string.IsNullOrWhiteSpace(upperPattern))
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(lowerPattern))
        {
            return false;
        }

        List<(IPAddress Network, int Prefix, string Raw)> upperCidrs = [];
        foreach (string t in SplitTokens(upperPattern))
        {
            if (TryParseCidr(t, out IPAddress? ip, out int p) && ip is not null)
            {
                upperCidrs.Add((ip, p, t));
            }
        }

        string[] lowerTokens = SplitTokens(lowerPattern);
        if (upperCidrs.Count == 0 || lowerTokens.Length == 0)
        {
            return false;
        }

        foreach (string lt in lowerTokens)
        {
            if (!TryParseCidr(lt, out IPAddress? lowerIp, out int lowerPrefix) || lowerIp is null)
            {
                return false;
            }

            bool covered = upperCidrs.Any(uc =>
                uc.Network.AddressFamily == lowerIp.AddressFamily &&
                uc.Prefix <= lowerPrefix &&
                IsIpInCidr(lowerIp, uc.Raw));

            if (!covered)
            {
                return false;
            }
        }

        return true;
    }

    private static bool ConditionCoversPorts(string? upperPattern, string? lowerPattern)
    {
        if (string.IsNullOrWhiteSpace(upperPattern))
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(lowerPattern))
        {
            return false;
        }

        List<(int Start, int End)> upperIntervals = ParseMergedPortIntervals(upperPattern);
        List<(int Start, int End)> lowerIntervals = ParseMergedPortIntervals(lowerPattern);
        if (upperIntervals.Count == 0 || lowerIntervals.Count == 0)
        {
            return false;
        }

        return lowerIntervals.All(li => upperIntervals.Any(ui => ui.Start <= li.Start && ui.End >= li.End));
    }

    private static bool TryParseCidr(string cidrOrIp, out IPAddress? ip, out int prefixLength)
    {
        ip = null;
        prefixLength = 0;
        string trimmed = cidrOrIp.Trim();
        int slashIdx = trimmed.IndexOf('/');
        string ipPart = slashIdx >= 0 ? trimmed[..slashIdx].Trim() : trimmed;

        if (!IPAddress.TryParse(ipPart, out IPAddress? parsed))
        {
            return false;
        }

        int maxBits = parsed.GetAddressBytes().Length * 8;
        prefixLength = maxBits;
        if (slashIdx >= 0 && (!int.TryParse(trimmed[(slashIdx + 1)..].Trim(), out prefixLength) || prefixLength < 0 || prefixLength > maxBits))
        {
            return false;
        }

        ip = parsed;
        return true;
    }

    private static List<(int Start, int End)> ParseMergedPortIntervals(string patternList)
    {
        List<(int Start, int End)> raw = [];
        foreach (string token in SplitTokens(patternList))
        {
            int dashIdx = token.IndexOf('-');
            if (dashIdx > 0)
            {
                if (int.TryParse(token[..dashIdx].Trim(), out int s) &&
                    int.TryParse(token[(dashIdx + 1)..].Trim(), out int e))
                {
                    if (s > e)
                    {
                        (s, e) = (e, s);
                    }
                    raw.Add((Math.Clamp(s, 1, 65535), Math.Clamp(e, 1, 65535)));
                }
            }
            else if (int.TryParse(token.Trim(), out int single) && single is >= 1 and <= 65535)
            {
                raw.Add((single, single));
            }
        }

        if (raw.Count == 0)
        {
            return raw;
        }

        raw.Sort((a, b) => a.Start != b.Start ? a.Start.CompareTo(b.Start) : a.End.CompareTo(b.End));
        List<(int Start, int End)> merged = [raw[0]];
        for (int i = 1; i < raw.Count; i++)
        {
            var last = merged[^1];
            var cur = raw[i];
            if (cur.Start <= last.End + 1)
            {
                merged[^1] = (last.Start, Math.Max(last.End, cur.End));
            }
            else
            {
                merged.Add(cur);
            }
        }

        return merged;
    }

    private static string NormalizeConditionTokenSet(string? pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern))
        {
            return string.Empty;
        }

        return string.Join(",", SplitTokens(pattern).Select(t => t.ToLowerInvariant()).OrderBy(t => t));
    }

    private static string[] SplitTokens(string patternList)
    {
        return patternList
            .Split([',', ';', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static string NormalizePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        return path.Trim().Replace('\\', '/');
    }

    private static string NormalizeProcessName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return string.Empty;
        }

        string clean = name.Trim().ToLowerInvariant();
        if (clean.EndsWith(".exe", StringComparison.Ordinal))
        {
            clean = clean[..^4];
        }

        return clean;
    }

    private static string NormalizeDomain(string? raw, bool preserveLeadingWildcard = false)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return string.Empty;
        }

        string s = raw.Trim().ToLowerInvariant();
        int schemeIdx = s.IndexOf("://", StringComparison.Ordinal);
        if (schemeIdx >= 0)
        {
            s = s[(schemeIdx + 3)..];
        }

        int slashIdx = s.IndexOf('/');
        if (slashIdx >= 0)
        {
            s = s[..slashIdx];
        }

        int colonIdx = s.IndexOf(':');
        if (colonIdx >= 0)
        {
            s = s[..colonIdx];
        }

        s = s.TrimEnd('.');
        if (!preserveLeadingWildcard && s.StartsWith("*.", StringComparison.Ordinal))
        {
            s = s[2..];
        }

        return s;
    }
}
