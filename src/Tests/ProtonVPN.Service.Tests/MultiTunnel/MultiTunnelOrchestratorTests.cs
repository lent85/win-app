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
public class MultiTunnelOrchestratorTests
{
    [TestMethod]
    public void ActivateAndDeactivateSlot_RefCountsSharedEndpointRoutes()
    {
        MultiTunnelOrchestrator orchestrator = new();

        bool createFirst = orchestrator.ActivateSlot("T1", "SG", "SG#1", "185.159.1.10", "185.159.1.10", 10);
        bool createSecond = orchestrator.ActivateSlot("T2", "SG", "SG#2", "185.159.1.10", "185.159.1.11", 11);

        createFirst.Should().BeTrue();
        createSecond.Should().BeFalse();
        orchestrator.GetEndpointRouteOwnerCount("185.159.1.10").Should().Be(2);

        bool removeFirst = orchestrator.DeactivateSlot("T1", out string released1);
        removeFirst.Should().BeFalse();
        released1.Should().Be("185.159.1.10");
        orchestrator.GetEndpointRouteOwnerCount("185.159.1.10").Should().Be(1);

        bool removeSecond = orchestrator.DeactivateSlot("T2", out string released2);
        removeSecond.Should().BeTrue();
        released2.Should().Be("185.159.1.10");
        orchestrator.GetEndpointRouteOwnerCount("185.159.1.10").Should().Be(0);
    }

    [TestMethod]
    public void MoveRulePriority_ReordersAndNormalizesPriorityNumbers()
    {
        MultiTunnelOrchestrator orchestrator = new();
        SelectiveRoutingRule r1 = new() { PriorityOrder = 1, Name = "First", DomainPattern = "*.vn" };
        SelectiveRoutingRule r2 = new() { PriorityOrder = 2, Name = "Second", AppPattern = "chrome" };

        orchestrator.SetPriorityRules([r1, r2], RuleTargetType.Direct, "T1");
        bool moved = orchestrator.MoveRulePriority(r2.Id, -1);

        moved.Should().BeTrue();
        IReadOnlyList<SelectiveRoutingRule> ordered = orchestrator.GetPriorityRules();
        ordered[0].Id.Should().Be(r2.Id);
        ordered[0].PriorityOrder.Should().Be(1);
        ordered[1].Id.Should().Be(r1.Id);
        ordered[1].PriorityOrder.Should().Be(2);
    }

    [TestMethod]
    public void DnsRoutingTable_ParsesQueryAndAnswersAndPrunesExpiredEntries()
    {
        // Minimal DNS query packet for "api.openai.com" (txId = 0x1234, qdCount = 1, qType = A (1))
        byte[] queryPacket =
        [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            3, (byte)'a', (byte)'p', (byte)'i',
            6, (byte)'o', (byte)'p', (byte)'e', (byte)'n', (byte)'a', (byte)'i',
            3, (byte)'c', (byte)'o', (byte)'m',
            0,
            0x00, 0x01, 0x00, 0x01,
        ];

        MultiTunnelDnsRoutingTable.TryParseQueryDomain(queryPacket, out DnsQuestionInfo q).Should().BeTrue();
        q.QueryDomain.Should().Be("api.openai.com");
        q.TransactionId.Should().Be(0x1234);
        q.QueryType.Should().Be(1);

        MultiTunnelDnsRoutingTable table = new();
        DateTime now = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        SelectiveRoutingRule rule = new() { PriorityOrder = 2, Name = "AI" };
        RoutingDecision decision = new(RuleTargetType.Tunnel, "T1", rule, false, false, false, 59980, "AI");
        List<DnsResolvedRecord> records = [new(IPAddress.Parse("104.18.6.192"), 30)];

        table.RegisterResolvedAddresses("api.openai.com", decision, records, now);
        table.GetActiveAddressesByRule(now).Should().ContainKey(rule.Id);

        // Min TTL 30s + 30s grace = 60s
        table.PruneExpired(now.AddSeconds(61)).Should().Be(1);
        table.GetActiveAddressesByRule(now.AddSeconds(62)).Should().BeEmpty();
    }
}
