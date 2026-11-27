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
using ProtonVPN.Client.Logic.Connection.Contracts.Messages;
using ProtonVPN.Client.Logic.Connection.Contracts.MultiTunnel;
using ProtonVPN.Client.Logic.Connection.MultiTunnel;
using ProtonVPN.Client.Logic.Services.Contracts;
using ProtonVPN.Client.Settings.Contracts;
using ProtonVPN.Common.Legacy.Abstract;
using ProtonVPN.Common.Legacy.PortForwarding;
using ProtonVPN.EntityMapping.Contracts;
using ProtonVPN.Logging.Contracts;
using ProtonVPN.ProcessCommunication.Contracts.Entities.MultiTunnel;
using ProtonVPN.ProcessCommunication.Contracts.Entities.PortForwarding;
using ProtonVPN.ProcessCommunication.Contracts.Entities.Vpn;
using ProtonVPN.StatisticalEvents.Contracts.Dimensions;

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

    [TestMethod]
    public void MultiTunnelRoutingPresetCatalog_ContainsExpectedServicePresetsWithValidPatterns()
    {
        IReadOnlyList<RoutingRulePreset> all = MultiTunnelRoutingPresetCatalog.All;
        Assert.IsTrue(all.Count >= 16);
        Assert.AreEqual(all.Count, all.Select(p => p.Id).Distinct(System.StringComparer.OrdinalIgnoreCase).Count());

        RoutingRulePreset? google = MultiTunnelRoutingPresetCatalog.FindById("google-services");
        RoutingRulePreset? facebook = MultiTunnelRoutingPresetCatalog.FindById("facebook-services");
        Assert.IsNotNull(google);
        Assert.IsNotNull(facebook);
        Assert.IsTrue(google.DomainPattern!.Contains("*.google.com"));
        Assert.IsTrue(facebook.DomainPattern!.Contains("*.facebook.com"));

        foreach (RoutingRulePreset preset in all)
        {
            MultiTunnelRuleConfig rule = preset.ToRuleConfig(["T1", "T2", "T3"]);
            Assert.IsTrue(rule.HasAnyCondition, $"Preset '{preset.Id}' produced a rule with no condition.");
            Assert.IsFalse(string.IsNullOrWhiteSpace(rule.Name));
        }
    }

    [TestMethod]
    public async Task ApplyRoutingPresetsAsync_AddMode_InsertsAtTopPreservesExistingAndRoutesGoogleAndFacebook()
    {
        MultiTunnelManager manager = CreateManager();
        MultiTunnelSlotConfig? t2 = await manager.AddSlotAsync("US", "US#1");
        Assert.IsNotNull(t2);
        int initialCount = manager.Rules.Count;

        RoutingRulePreset google = MultiTunnelRoutingPresetCatalog.FindById("google-services")!;
        RoutingRulePreset facebook = MultiTunnelRoutingPresetCatalog.FindById("facebook-services")!;

        int applied = await manager.ApplyRoutingPresetsAsync(
            [google, facebook],
            RoutingPresetApplyMode.Add,
            RuleTargetTypeIpcEntity.Tunnel,
            "T2",
            TunnelFallbackBehaviorIpcEntity.FallbackToDirect);

        Assert.AreEqual(2, applied);
        Assert.AreEqual(initialCount + 2, manager.Rules.Count);
        Assert.AreEqual("Google Services", manager.Rules[0].Name);
        Assert.AreEqual(1, manager.Rules[0].PriorityOrder);
        Assert.AreEqual("T2", manager.Rules[0].TargetTunnelId);
        Assert.AreEqual(TunnelFallbackBehaviorIpcEntity.FallbackToDirect, manager.Rules[0].FallbackBehavior);
        Assert.AreEqual("Facebook / Meta Services", manager.Rules[1].Name);
        Assert.AreEqual(2, manager.Rules[1].PriorityOrder);

        _vpnServiceCaller.EvaluateMultiTunnelTrafficAsync(Arg.Any<TrafficQueryIpcEntity>())
            .Returns(Result.Fail<RoutingDecisionIpcEntity>("Offline"));

        RoutingDecisionIpcEntity googleDecision = await manager.EvaluateTrafficAsync(new TrafficQueryIpcEntity
        {
            ProcessName = "chrome",
            Domain = "mail.google.com",
            RemotePort = 443,
            Protocol = RuleProtocolIpcEntity.Tcp,
        });
        Assert.AreEqual(1, googleDecision.MatchedRulePriority);
        Assert.AreEqual("Google Services", googleDecision.MatchedRuleName);

        RoutingDecisionIpcEntity fbDecision = await manager.EvaluateTrafficAsync(new TrafficQueryIpcEntity
        {
            ProcessName = "chrome",
            Domain = "www.facebook.com",
            RemotePort = 443,
            Protocol = RuleProtocolIpcEntity.Tcp,
        });
        Assert.AreEqual(2, fbDecision.MatchedRulePriority);
        Assert.AreEqual("Facebook / Meta Services", fbDecision.MatchedRuleName);
    }

    [TestMethod]
    public async Task ApplyRoutingPresetsAsync_ReplaceMode_ReplacesAllExistingRulesAndRespectsOverrides()
    {
        MultiTunnelManager manager = CreateManager();

        RoutingRulePreset ai = MultiTunnelRoutingPresetCatalog.FindById("ai-assistants")!;
        RoutingRulePreset lan = MultiTunnelRoutingPresetCatalog.FindById("private-lan")!;

        // Only T1 exists on manager, so ai-assistants (default T2) must safely resolve to T1
        int applied = await manager.ApplyRoutingPresetsAsync([ai, lan], RoutingPresetApplyMode.Replace);

        Assert.AreEqual(2, applied);
        Assert.AreEqual(2, manager.Rules.Count);
        Assert.AreEqual(1, manager.Rules[0].PriorityOrder);
        Assert.AreEqual("AI Assistants (OpenAI, Claude, Gemini)", manager.Rules[0].Name);
        Assert.AreEqual(RuleTargetTypeIpcEntity.Tunnel, manager.Rules[0].TargetType);
        Assert.AreEqual("T1", manager.Rules[0].TargetTunnelId);
        Assert.AreEqual(2, manager.Rules[1].PriorityOrder);
        Assert.AreEqual(RuleTargetTypeIpcEntity.Direct, manager.Rules[1].TargetType);

        // Override all selected templates to Direct
        RoutingRulePreset google = MultiTunnelRoutingPresetCatalog.FindById("google-services")!;
        int replacedDirect = await manager.ApplyRoutingPresetsAsync(
            [google],
            RoutingPresetApplyMode.Replace,
            RuleTargetTypeIpcEntity.Direct);

        Assert.AreEqual(1, replacedDirect);
        Assert.AreEqual(1, manager.Rules.Count);
        Assert.AreEqual(RuleTargetTypeIpcEntity.Direct, manager.Rules[0].TargetType);
    }

    [TestMethod]
    public async Task ConnectAllAndDisconnectAllSlotsAsync_ConnectsAndDisconnectsAllSlotsCleanly()
    {
        _vpnServiceCaller.ConnectMultiTunnelSlotAsync(Arg.Any<MultiTunnelSlotConnectionRequestIpcEntity>())
            .Returns(ci => Result.Ok(new MultiTunnelSlotConnectionResultIpcEntity
            {
                Success = true,
                SlotId = ci.Arg<MultiTunnelSlotConnectionRequestIpcEntity>().SlotId,
                ConnectedServerName = "US#1",
                ConnectedEntryIp = "185.159.158.10",
            }));
        _vpnServiceCaller.DisconnectMultiTunnelSlotAsync(Arg.Any<string>())
            .Returns(Task.CompletedTask);

        ProtonVPN.Client.Logic.Connection.Contracts.RequestCreators.IConnectionRequestCreator requestCreator =
            Substitute.For<ProtonVPN.Client.Logic.Connection.Contracts.RequestCreators.IConnectionRequestCreator>();
        requestCreator.CreateAsync(Arg.Any<ProtonVPN.Client.Logic.Connection.Contracts.Models.Intents.IConnectionIntent>())
            .Returns(new ConnectionRequestIpcEntity());

        MultiTunnelManager manager = new(
            _logger,
            _settings,
            _vpnServiceCaller,
            _connectionManager,
            _eventMessageSender,
            requestCreator);

        await manager.SetEnabledAsync(true);
        await manager.AddSlotAsync("US", "US#1");
        await manager.AddSlotAsync("CH", "CH#1");
        Assert.AreEqual(3, manager.Slots.Count);
        Assert.IsFalse(manager.IsAnySlotConnecting);

        await manager.ConnectAllSlotsAsync();

        await _connectionManager.Received(1).ConnectAsync(
            VpnTriggerDimension.CountriesCountry,
            Arg.Any<ProtonVPN.Client.Logic.Connection.Contracts.Models.Intents.IConnectionIntent>());
        await _vpnServiceCaller.Received(1).ConnectMultiTunnelSlotAsync(
            Arg.Is<MultiTunnelSlotConnectionRequestIpcEntity>(r => r.SlotId == "T2"));
        await _vpnServiceCaller.Received(1).ConnectMultiTunnelSlotAsync(
            Arg.Is<MultiTunnelSlotConnectionRequestIpcEntity>(r => r.SlotId == "T3"));
        Assert.IsTrue(manager.Slots.First(s => s.SlotId == "T2").IsConnected);
        Assert.IsTrue(manager.Slots.First(s => s.SlotId == "T3").IsConnected);

        _connectionManager.IsConnected.Returns(true);
        await manager.DisconnectAllSlotsAsync();

        await _vpnServiceCaller.Received(1).DisconnectMultiTunnelSlotAsync("T3");
        await _vpnServiceCaller.Received(1).DisconnectMultiTunnelSlotAsync("T2");
        await _connectionManager.Received(1).DisconnectAsync(VpnTriggerDimension.ConnectionCard);
        Assert.IsFalse(manager.Slots.First(s => s.SlotId == "T2").IsConnected);
        Assert.IsFalse(manager.Slots.First(s => s.SlotId == "T3").IsConnected);
    }

    [TestMethod]
    public async Task ApplyRoutingPresetsAsync_UpsertAndReplaceTarget_MovesWithoutDuplicatesAndPreservesOtherSlots()
    {
        MultiTunnelManager manager = CreateManager();
        await manager.AddSlotAsync("SG", "SG#1");

        RoutingRulePreset google = MultiTunnelRoutingPresetCatalog.FindById("google-services")!;
        RoutingRulePreset facebook = MultiTunnelRoutingPresetCatalog.FindById("facebook-services")!;
        RoutingRulePreset youtube = MultiTunnelRoutingPresetCatalog.FindById("youtube-media")!;
        RoutingRulePreset ai = MultiTunnelRoutingPresetCatalog.FindById("ai-assistants")!;
        RoutingRulePreset lan = MultiTunnelRoutingPresetCatalog.FindById("private-lan")!;

        await manager.ApplyRoutingPresetsAsync([ai], RoutingPresetApplyMode.Replace, RuleTargetTypeIpcEntity.Tunnel, "T1");
        await manager.ApplyRoutingPresetsAsync([lan], RoutingPresetApplyMode.Add, RuleTargetTypeIpcEntity.Direct);
        await manager.ApplyRoutingPresetsAsync([google], RoutingPresetApplyMode.Add, RuleTargetTypeIpcEntity.Tunnel, "T1");
        await manager.ApplyRoutingPresetsAsync([facebook], RoutingPresetApplyMode.Add, RuleTargetTypeIpcEntity.Tunnel, "T2");

        // Moving google-services from T1 -> T2 via Add must upsert cleanly without duplicates
        await manager.ApplyRoutingPresetsAsync([google], RoutingPresetApplyMode.Add, RuleTargetTypeIpcEntity.Tunnel, "T2");
        Assert.AreEqual(1, manager.Rules.Count(r => google.MatchesRule(r)));
        Assert.AreEqual("T2", manager.Rules.First(r => google.MatchesRule(r)).TargetTunnelId);

        // ReplaceTarget on T2 replaces T2 rules (google + facebook) with youtube, while preserving T1 (ai) & Direct (lan)
        await manager.ApplyRoutingPresetsAsync([youtube], RoutingPresetApplyMode.ReplaceTarget, RuleTargetTypeIpcEntity.Tunnel, "T2");
        Assert.AreEqual(3, manager.Rules.Count);
        Assert.IsTrue(manager.Rules.Any(r => youtube.MatchesRule(r) && r.TargetTunnelId == "T2"));
        Assert.IsTrue(manager.Rules.Any(r => ai.MatchesRule(r) && r.TargetTunnelId == "T1"));
        Assert.IsTrue(manager.Rules.Any(r => lan.MatchesRule(r) && r.TargetType == RuleTargetTypeIpcEntity.Direct));
        Assert.IsFalse(manager.Rules.Any(r => google.MatchesRule(r) || facebook.MatchesRule(r)));

        // RemoveRoutingPresetAsync cleanly removes youtube rule
        bool removed = await manager.RemoveRoutingPresetAsync(youtube);
        Assert.IsTrue(removed);
        Assert.AreEqual(2, manager.Rules.Count);
    }

    [TestMethod]
    public async Task RemoveSlotAndDisable_DisconnectsConnectedSecondarySlots()
    {
        _vpnServiceCaller.ConnectMultiTunnelSlotAsync(Arg.Any<MultiTunnelSlotConnectionRequestIpcEntity>())
            .Returns(ci => Result.Ok(new MultiTunnelSlotConnectionResultIpcEntity
            {
                Success = true,
                SlotId = ci.Arg<MultiTunnelSlotConnectionRequestIpcEntity>().SlotId,
                ConnectedServerName = "US#1",
                ConnectedEntryIp = "185.159.158.10",
            }));
        _vpnServiceCaller.DisconnectMultiTunnelSlotAsync(Arg.Any<string>()).Returns(Task.CompletedTask);

        ProtonVPN.Client.Logic.Connection.Contracts.RequestCreators.IConnectionRequestCreator requestCreator =
            Substitute.For<ProtonVPN.Client.Logic.Connection.Contracts.RequestCreators.IConnectionRequestCreator>();
        requestCreator.CreateAsync(Arg.Any<ProtonVPN.Client.Logic.Connection.Contracts.Models.Intents.IConnectionIntent>())
            .Returns(new ConnectionRequestIpcEntity());

        MultiTunnelManager manager = new(
            _logger,
            _settings,
            _vpnServiceCaller,
            _connectionManager,
            _eventMessageSender,
            requestCreator);

        await manager.SetEnabledAsync(true);
        await manager.AddSlotAsync("US", "US#1");
        await manager.AddSlotAsync("JP", "JP#1");
        Assert.IsTrue(await manager.ConnectSlotAsync("T2"));
        Assert.IsTrue(await manager.ConnectSlotAsync("T3"));

        await manager.RemoveSlotAsync("T2");
        await _vpnServiceCaller.Received(1).DisconnectMultiTunnelSlotAsync("T2");
        Assert.IsFalse(manager.Slots.Any(s => s.SlotId == "T2"));

        await manager.SetEnabledAsync(false);
        await _vpnServiceCaller.Received(1).DisconnectMultiTunnelSlotAsync("T3");
        await _connectionManager.DidNotReceive().DisconnectAsync(Arg.Any<VpnTriggerDimension>());
    }

    [TestMethod]
    public async Task DeletingAllRules_PersistsEmptyRulesAcrossReload()
    {
        MultiTunnelManager manager = CreateManager();
        foreach (Guid id in manager.Rules.Select(r => r.Id).ToList())
        {
            await manager.DeleteRuleAsync(id);
        }

        Assert.AreEqual(0, manager.Rules.Count);

        MultiTunnelManager reloaded = CreateManager();
        Assert.AreEqual(0, reloaded.Rules.Count);
    }

    [TestMethod]
    public async Task ReconcileWithServiceAsync_RestoresConnectedSecondarySlotState()
    {
        MultiTunnelManager manager = CreateManager();
        await manager.AddSlotAsync("US", "US#Fastest");

        _vpnServiceCaller.GetMultiTunnelPolicyAsync().Returns(Result.Ok(new MultiTunnelPolicyIpcEntity
        {
            IsMultiTunnelEnabled = true,
            TunnelSlots =
            [
                new TunnelSlotStateIpcEntity
                {
                    SlotId = "T2",
                    Status = VpnStatusIpcEntity.Connected,
                    ServerName = "US-NY#10",
                    EntryIp = "185.159.158.10",
                    ExitIp = "185.159.158.10",
                },
            ],
        }));

        await manager.ReconcileWithServiceAsync();

        MultiTunnelSlotConfig t2 = manager.Slots.First(s => s.SlotId == "T2");
        Assert.IsTrue(t2.IsConnected);
        Assert.AreEqual("US-NY#10", t2.ServerName);
        Assert.AreEqual("185.159.158.10", t2.EntryIp);
    }

    [TestMethod]
    public async Task SetSlotPortForwardingOverrideAsync_ResolvesGlobalAndPerSlotOverridesInPolicy()
    {
        _settings.IsPortForwardingEnabled.Returns(true);
        MultiTunnelManager manager = CreateManager();
        await manager.AddSlotAsync("NL", "NL#Fastest");

        Assert.IsTrue(manager.IsSlotPortForwardingEnabled("T1"));
        Assert.IsTrue(manager.IsSlotPortForwardingEnabled("T2"));

        await manager.SetSlotPortForwardingOverrideAsync("T2", false);
        Assert.IsTrue(manager.IsSlotPortForwardingEnabled("T1"));
        Assert.IsFalse(manager.IsSlotPortForwardingEnabled("T2"));

        MultiTunnelPolicyIpcEntity policy = manager.BuildIpcPolicy();
        Assert.IsTrue(policy.TunnelSlots.First(s => s.SlotId == "T1").PortForwardingEnabled);
        Assert.IsFalse(policy.TunnelSlots.First(s => s.SlotId == "T2").PortForwardingEnabled);

        MultiTunnelManager reloaded = CreateManager();
        Assert.IsFalse(reloaded.IsSlotPortForwardingEnabled("T2"));
    }

    [TestMethod]
    public void PortForwardingManager_TracksIndependentPortsPerSlot()
    {
        IEntityMapper mapper = Substitute.For<IEntityMapper>();
        mapper.Map<PortForwardingStateIpcEntity, PortForwardingState>(Arg.Any<PortForwardingStateIpcEntity>())
            .Returns(ci =>
            {
                PortForwardingStateIpcEntity src = ci.Arg<PortForwardingStateIpcEntity>();
                return new PortForwardingState
                {
                    Status = (PortMappingStatus)(int)src.Status,
                    MappedPort = src.MappedPort is null
                        ? null
                        : new TemporaryMappedPort
                        {
                            MappedPort = new MappedPort(src.MappedPort.InternalPort, src.MappedPort.ExternalPort),
                            Lifetime = src.MappedPort.Lifetime,
                            ExpirationDateUtc = src.MappedPort.ExpirationDateUtc,
                        },
                };
            });

        _connectionManager.IsConnected.Returns(true);
        PortForwardingManager pfManager = new(_eventMessageSender, mapper, _logger, _connectionManager);

        pfManager.Receive(new PortForwardingStateIpcEntity
        {
            SlotId = "T2",
            Status = PortMappingStatusIpcEntity.SleepingUntilRefresh,
            MappedPort = new TemporaryMappedPortIpcEntity { InternalPort = 41234, ExternalPort = 41234 },
        });
        pfManager.Receive(new PortForwardingStateIpcEntity
        {
            SlotId = "T3",
            Status = PortMappingStatusIpcEntity.SleepingUntilRefresh,
            MappedPort = new TemporaryMappedPortIpcEntity { InternalPort = 52345, ExternalPort = 52345 },
        });

        Assert.AreEqual(41234, pfManager.GetActivePort("T2"));
        Assert.AreEqual(52345, pfManager.GetActivePort("T3"));
        Assert.IsNull(pfManager.ActivePort);

        _eventMessageSender.Received().Send(Arg.Is<PortForwardingPortChangedMessage>(m => m.SlotId == "T2" && m.ActivePort == 41234));
        _eventMessageSender.Received().Send(Arg.Is<PortForwardingPortChangedMessage>(m => m.SlotId == "T3" && m.ActivePort == 52345));
    }
}
