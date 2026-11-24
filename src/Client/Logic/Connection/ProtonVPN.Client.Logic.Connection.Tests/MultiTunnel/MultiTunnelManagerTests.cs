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

using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute;
using ProtonVPN.Client.EventMessaging.Contracts;
using ProtonVPN.Client.Logic.Connection.Contracts;
using ProtonVPN.Client.Logic.Connection.Contracts.MultiTunnel;
using ProtonVPN.Client.Logic.Connection.MultiTunnel;
using ProtonVPN.Client.Logic.Services.Contracts;
using ProtonVPN.Client.Settings.Contracts;
using ProtonVPN.Common.Legacy.Abstract;
using ProtonVPN.Logging.Contracts;
using ProtonVPN.ProcessCommunication.Contracts.Entities.MultiTunnel;
using ProtonVPN.ProcessCommunication.Contracts.Entities.Vpn;

namespace ProtonVPN.Client.Logic.Connection.Tests.MultiTunnel;

[TestClass]
public class MultiTunnelManagerTests
{
    private ILogger _logger = null!;
    private ISettings _settings = null!;
    private IVpnServiceCaller _vpnServiceCaller = null!;
    private IConnectionManager _connectionManager = null!;
    private IEventMessageSender _eventMessageSender = null!;
    private bool _storedEnabled;
    private string _storedJson = string.Empty;

    [TestInitialize]
    public void Setup()
    {
        _logger = Substitute.For<ILogger>();
        _settings = Substitute.For<ISettings>();
        _vpnServiceCaller = Substitute.For<IVpnServiceCaller>();
        _connectionManager = Substitute.For<IConnectionManager>();
        _eventMessageSender = Substitute.For<IEventMessageSender>();

        _storedEnabled = false;
        _storedJson = string.Empty;

        _settings.IsMultiTunnelEnabled.Returns(_ => _storedEnabled);
        _settings.When(s => s.IsMultiTunnelEnabled = Arg.Any<bool>()).Do(ci => _storedEnabled = ci.Arg<bool>());
        _settings.MultiTunnelPolicyJson.Returns(_ => _storedJson);
        _settings.When(s => s.MultiTunnelPolicyJson = Arg.Any<string>()).Do(ci => _storedJson = ci.Arg<string>());

        _vpnServiceCaller.ApplyMultiTunnelPolicyAsync(Arg.Any<MultiTunnelPolicyIpcEntity>())
            .Returns(Task.CompletedTask);
    }

    private MultiTunnelManager CreateManager() => new(
        _logger,
        _settings,
        _vpnServiceCaller,
        _connectionManager,
        _eventMessageSender);

    [TestMethod]
    public void Constructor_InitializesPrimarySlotAndSixDefaultRules()
    {
        MultiTunnelManager manager = CreateManager();

        Assert.AreEqual(1, manager.Slots.Count);
        Assert.AreEqual("T1", manager.Slots[0].SlotId);
        Assert.AreEqual(6, manager.Rules.Count);
        Assert.AreEqual(6, manager.EnabledRuleCount);
        Assert.IsFalse(string.IsNullOrWhiteSpace(_storedJson));
    }

    [TestMethod]
    public async Task AddSlotAsync_RequiresExplicitCountryAndRespectsMaxFiveSlots()
    {
        MultiTunnelManager manager = CreateManager();

        MultiTunnelSlotConfig? rejected = await manager.AddSlotAsync("", "Invalid");
        Assert.IsNull(rejected);

        MultiTunnelSlotConfig? t2 = await manager.AddSlotAsync("JP", "Tokyo #1", "Tokyo");
        MultiTunnelSlotConfig? t3 = await manager.AddSlotAsync("US", "Dallas #2", "Dallas");
        MultiTunnelSlotConfig? t4 = await manager.AddSlotAsync("CH", "Zurich #3", "Zurich");
        MultiTunnelSlotConfig? t5 = await manager.AddSlotAsync("DE", "Frankfurt #4", "Frankfurt");
        MultiTunnelSlotConfig? overflow = await manager.AddSlotAsync("NL", "Amsterdam #5", "Amsterdam");

        Assert.IsNotNull(t2);
        Assert.AreEqual("T2", t2.SlotId);
        Assert.AreEqual("JP", t2.CountryCode);
        Assert.AreEqual("10.3.0.2", t2.ClientIpv4);
        Assert.AreEqual("T5", t5!.SlotId);
        Assert.IsNull(overflow);
        Assert.AreEqual(5, manager.Slots.Count);
    }

    [TestMethod]
    public async Task RemoveSlotAsync_BlocksT1AndAllowsSecondarySlots()
    {
        MultiTunnelManager manager = CreateManager();
        await manager.AddSlotAsync("US", "US#1");

        await manager.RemoveSlotAsync("T1");
        Assert.AreEqual(2, manager.Slots.Count);

        await manager.RemoveSlotAsync("T2");
        Assert.AreEqual(1, manager.Slots.Count);
        Assert.AreEqual("T1", manager.Slots[0].SlotId);
    }

    [TestMethod]
    public async Task RuleCrudAndMove_PersistsSyncsAndDetectsConflicts()
    {
        MultiTunnelManager manager = CreateManager();

        await manager.SetEnabledAsync(true);
        Assert.IsTrue(_storedEnabled);

        MultiTunnelRuleConfig broadRule = new()
        {
            Name = "Broad Browsers",
            IsEnabled = true,
            AppPattern = "chrome, firefox, msedge, telegram",
            TargetType = RuleTargetTypeIpcEntity.Direct,
        };
        await manager.AddRuleAsync(broadRule);
        Assert.AreEqual(7, manager.Rules.Count);

        await manager.MoveRuleAsync(broadRule.Id, -6);
        Assert.AreEqual(broadRule.Id, manager.Rules[0].Id);
        Assert.AreEqual(1, manager.Rules[0].PriorityOrder);
        Assert.IsTrue(manager.Conflicts.Any());

        await manager.SetRuleEnabledAsync(broadRule.Id, false);
        Assert.AreEqual(6, manager.EnabledRuleCount);

        await manager.DeleteRuleAsync(broadRule.Id);
        Assert.AreEqual(6, manager.Rules.Count);

        await _vpnServiceCaller.Received().ApplyMultiTunnelPolicyAsync(Arg.Is<MultiTunnelPolicyIpcEntity>(p => p.IsMultiTunnelEnabled));
    }

    [TestMethod]
    public async Task EvaluateTrafficAsync_UsesIpcWhenAvailableAndFallsBackLocallyWhenOffline()
    {
        MultiTunnelManager manager = CreateManager();
        TrafficQueryIpcEntity query = new() { ProcessName = "chrome", Domain = "api.openai.com" };

        _vpnServiceCaller.EvaluateMultiTunnelTrafficAsync(Arg.Any<TrafficQueryIpcEntity>())
            .Returns(Result.Ok(new RoutingDecisionIpcEntity
            {
                EffectiveTargetType = RuleTargetTypeIpcEntity.Tunnel,
                EffectiveTunnelId = "T1",
                MatchedRulePriority = 3,
                Explanation = "IPC response",
            }));

        RoutingDecisionIpcEntity ipcDecision = await manager.EvaluateTrafficAsync(query);
        Assert.AreEqual("IPC response", ipcDecision.Explanation);

        _vpnServiceCaller.EvaluateMultiTunnelTrafficAsync(Arg.Any<TrafficQueryIpcEntity>())
            .Returns(Result.Fail<RoutingDecisionIpcEntity>("Service offline"));

        RoutingDecisionIpcEntity previewDecision = await manager.EvaluateTrafficAsync(query);
        Assert.IsTrue(previewDecision.Explanation.Contains("Local preview"));
        Assert.AreEqual(3, previewDecision.MatchedRulePriority);
    }
}
