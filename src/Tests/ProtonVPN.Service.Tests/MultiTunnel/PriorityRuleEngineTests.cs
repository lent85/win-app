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
using System.Net;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using ProtonVPN.Service.MultiTunnel;

namespace ProtonVPN.Service.Tests.MultiTunnel;

[TestClass]
public class PriorityRuleEngineTests
{
    private static Dictionary<string, TunnelSlotRuntimeState> CreateDefaultSlots(bool t1Connected = true, bool t2Connected = false)
    {
        return new Dictionary<string, TunnelSlotRuntimeState>(StringComparer.OrdinalIgnoreCase)
        {
            ["T1"] = new()
            {
                SlotId = "T1",
                SlotIndex = 0,
                IsConnected = t1Connected,
                CountryCode = "SG",
                ClientIpv4 = IPAddress.Parse("10.2.0.2"),
                ServerGatewayIpv4 = IPAddress.Parse("10.2.0.1"),
            },
            ["T2"] = new()
            {
                SlotId = "T2",
                SlotIndex = 1,
                IsConnected = t2Connected,
                CountryCode = "US",
                ClientIpv4 = IPAddress.Parse("10.3.0.2"),
                ServerGatewayIpv4 = IPAddress.Parse("10.3.0.1"),
            },
        };
    }

    [TestMethod]
    public void Evaluate_RespectsTopDownPriorityOrderAndWfpWeights()
    {
        List<SelectiveRoutingRule> rules =
        [
            new()
            {
                PriorityOrder = 1,
                Name = "Banking Direct",
                IsEnabled = true,
                DomainPattern = "*.vietcombank.com.vn, *.vn",
                TargetType = RuleTargetType.Direct,
            },
            new()
            {
                PriorityOrder = 2,
                Name = "Chrome Tunnel",
                IsEnabled = true,
                AppPattern = "chrome",
                TargetType = RuleTargetType.Tunnel,
                TargetTunnelId = "T1",
            },
        ];

        RoutingDecision decision = PriorityRuleEngine.Evaluate(
            new TrafficQuery(ProcessName: "chrome.exe", Domain: "ebank.vietcombank.com.vn"),
            rules,
            CreateDefaultSlots());

        decision.EffectiveTargetType.Should().Be(RuleTargetType.Direct);
        decision.MatchedRule!.PriorityOrder.Should().Be(1);
        PriorityRuleEngine.ComputeWfpWeight(1).Should().BeGreaterThan(PriorityRuleEngine.ComputeWfpWeight(2));
        PriorityRuleEngine.ComputeWfpWeight(2).Should().BeGreaterThan(PriorityRuleEngine.DefaultPolicyWfpWeight);
    }

    [TestMethod]
    public void MatchesDomainPattern_HandlesWildcardsWithoutFalsePrefixMatch()
    {
        PriorityRuleEngine.MatchesDomainPattern("*.openai.com", "api.openai.com").Should().BeTrue();
        PriorityRuleEngine.MatchesDomainPattern("*.openai.com", "openai.com").Should().BeTrue();
        PriorityRuleEngine.MatchesDomainPattern("*.openai.com", "evilopenai.com").Should().BeFalse();
    }

    [TestMethod]
    public void MatchesIpCidrPattern_MatchesIpv4AndIpv6Subnets()
    {
        PriorityRuleEngine.MatchesIpCidrPattern("192.168.0.0/16, 10.100.0.0/16", "192.168.42.5").Should().BeTrue();
        PriorityRuleEngine.MatchesIpCidrPattern("192.168.0.0/16, 10.100.0.0/16", "8.8.8.8").Should().BeFalse();
        PriorityRuleEngine.MatchesIpCidrPattern("fe80::/10", "fe80::1").Should().BeTrue();
    }

    [TestMethod]
    public void MatchesPortAndProtocol_RespectsRangesAndProtocol()
    {
        PriorityRuleEngine.MatchesPortAndProtocol("3478-3481", RuleProtocol.Udp, 3479, RuleProtocol.Udp).Should().BeTrue();
        PriorityRuleEngine.MatchesPortAndProtocol("3478-3481", RuleProtocol.Udp, 3479, RuleProtocol.Tcp).Should().BeFalse();
        PriorityRuleEngine.MatchesPortAndProtocol("3478-3481", RuleProtocol.Udp, 443, RuleProtocol.Udp).Should().BeFalse();
    }

    [TestMethod]
    public void Evaluate_BlocksOnExpectedSha256Mismatch()
    {
        List<SelectiveRoutingRule> rules =
        [
            new()
            {
                PriorityOrder = 1,
                Name = "Verified Curl",
                IsEnabled = true,
                AppPattern = "curl.exe",
                ExpectedAppSha256 = "aaaa",
                TargetType = RuleTargetType.Tunnel,
                TargetTunnelId = "T1",
            },
        ];

        RoutingDecision decision = PriorityRuleEngine.Evaluate(
            new TrafficQuery(ProcessName: "curl.exe", ActualAppSha256: "bbbb"),
            rules,
            CreateDefaultSlots());

        decision.EffectiveTargetType.Should().Be(RuleTargetType.Block);
        decision.IsHashMismatchBlocked.Should().BeTrue();
        decision.IsKillSwitchBlocked.Should().BeTrue();
    }

    [TestMethod]
    public void Evaluate_HandlesFallbackAndKillSwitchWhenTargetTunnelDisconnected()
    {
        List<SelectiveRoutingRule> killSwitchRule =
        [
            new()
            {
                PriorityOrder = 1,
                Name = "P2P KillSwitch",
                IsEnabled = true,
                AppPattern = "qbittorrent",
                TargetType = RuleTargetType.Tunnel,
                TargetTunnelId = "T2",
                FallbackBehavior = TunnelFallbackBehavior.KillSwitchBlock,
            },
        ];

        RoutingDecision blocked = PriorityRuleEngine.Evaluate(
            new TrafficQuery(ProcessName: "qbittorrent.exe"),
            killSwitchRule,
            CreateDefaultSlots(t1Connected: true, t2Connected: false));

        blocked.EffectiveTargetType.Should().Be(RuleTargetType.Block);
        blocked.IsKillSwitchBlocked.Should().BeTrue();

        killSwitchRule[0].FallbackBehavior = TunnelFallbackBehavior.FallbackToTunnel;
        killSwitchRule[0].FallbackTunnelId = "T1";

        RoutingDecision failover = PriorityRuleEngine.Evaluate(
            new TrafficQuery(ProcessName: "qbittorrent.exe"),
            killSwitchRule,
            CreateDefaultSlots(t1Connected: true, t2Connected: false));

        failover.EffectiveTargetType.Should().Be(RuleTargetType.Tunnel);
        failover.EffectiveTunnelId.Should().Be("T1");
        failover.IsFallbackApplied.Should().BeTrue();

        killSwitchRule[0].FallbackBehavior = TunnelFallbackBehavior.FallbackToDirect;
        RoutingDecision directFailover = PriorityRuleEngine.Evaluate(
            new TrafficQuery(ProcessName: "qbittorrent.exe"),
            killSwitchRule,
            CreateDefaultSlots(t1Connected: true, t2Connected: false));

        directFailover.EffectiveTargetType.Should().Be(RuleTargetType.Direct);
        directFailover.IsFallbackApplied.Should().BeTrue();
    }

    [TestMethod]
    public void DetectConflicts_FlagsBroaderShadowingRule()
    {
        List<SelectiveRoutingRule> rules =
        [
            new()
            {
                PriorityOrder = 1,
                Name = "All Chrome",
                IsEnabled = true,
                AppPattern = "chrome",
                TargetType = RuleTargetType.Direct,
            },
            new()
            {
                PriorityOrder = 2,
                Name = "Chrome ChatGPT",
                IsEnabled = true,
                AppPattern = "chrome",
                DomainPattern = "*.openai.com",
                TargetType = RuleTargetType.Tunnel,
                TargetTunnelId = "T1",
            },
        ];

        List<RuleConflictWarning> conflicts = PriorityRuleEngine.DetectConflicts(rules);

        conflicts.Should().ContainSingle();
        conflicts[0].ConflictType.Should().Be(RuleConflictType.ShadowedByBroaderRule);
        conflicts[0].UpperPriorityOrder.Should().Be(1);
        conflicts[0].LowerPriorityOrder.Should().Be(2);
    }

    [TestMethod]
    public void TunnelSlotAllocation_AllocatesDistinctNonOverlappingSubnetsAndSkipsReservedOctets()
    {
        TunnelSlotAllocation t1 = TunnelSlotAllocation.ForSlot(0);
        TunnelSlotAllocation t5 = TunnelSlotAllocation.ForSlot(4);
        t1.ClientIpv4.ToString().Should().Be("10.2.0.2");
        t5.ClientIpv4.ToString().Should().Be("10.6.0.2");

        HashSet<byte> reserved = [2];
        TunnelSlotAllocation shifted = TunnelSlotAllocation.ForSlot(0, reserved);
        shifted.ClientIpv4.ToString().Should().Be("10.3.0.2");
    }
}
