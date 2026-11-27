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

using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute;
using ProtonVPN.Client.EventMessaging.Contracts;
using ProtonVPN.Client.Logic.Connection.Contracts;
using ProtonVPN.Client.Logic.Connection.Contracts.Messages;
using ProtonVPN.Client.Logic.Connection.Contracts.Models;
using ProtonVPN.Client.Logic.Connection.Contracts.Models.Intents;
using ProtonVPN.Client.Logic.Connection.Contracts.Models.Intents.Locations.Servers;
using ProtonVPN.Client.Logic.Connection.Contracts.MultiTunnel;
using ProtonVPN.Client.Logic.Connection.Contracts.RequestCreators;
using ProtonVPN.Client.Logic.Connection.MultiTunnel;
using ProtonVPN.Client.Logic.Connection.RequestCreators;
using ProtonVPN.Client.Logic.Profiles.Contracts.Models;
using ProtonVPN.Client.Logic.Servers.Contracts;
using ProtonVPN.Client.Logic.Servers.Contracts.Enums;
using ProtonVPN.Client.Logic.Servers.Contracts.Models;
using ProtonVPN.Client.Logic.Services.Contracts;
using ProtonVPN.Client.Settings.Contracts;
using ProtonVPN.Common.Core.Networking;
using ProtonVPN.Common.Legacy.Abstract;
using ProtonVPN.Common.Legacy.PortForwarding;
using ProtonVPN.EntityMapping.Contracts;
using ProtonVPN.Logging.Contracts;
using ProtonVPN.ProcessCommunication.Contracts.Entities.MultiTunnel;
using ProtonVPN.ProcessCommunication.Contracts.Entities.PortForwarding;
using ProtonVPN.ProcessCommunication.Contracts.Entities.Settings;
using ProtonVPN.StatisticalEvents.Contracts.Dimensions;

namespace ProtonVPN.Client.Logic.Connection.Tests.MultiTunnel;

[TestClass]
public class MultiTunnelPortForwardingRegressionTests
{
    [TestMethod]
    public void PrimaryPortNotification_SeesCompleteUpdatedState()
    {
        IEventMessageSender sender = Substitute.For<IEventMessageSender>();
        IEntityMapper mapper = Substitute.For<IEntityMapper>();
        mapper.Map<PortForwardingStateIpcEntity, PortForwardingState>(Arg.Any<PortForwardingStateIpcEntity>())
            .Returns(new PortForwardingState
            {
                Status = PortMappingStatus.SleepingUntilRefresh,
                MappedPort = new TemporaryMappedPort { MappedPort = new MappedPort(43210, 43210) },
            });
        IConnectionManager connection = Substitute.For<IConnectionManager>();
        connection.IsConnected.Returns(true);
        Server server = CreateServer("NL#1", "nl-01.protonvpn.net", "185.159.158.10");
        connection.CurrentConnectionDetails.Returns(new ConnectionDetails(
            ConnectionIntent.Default, server, server.Servers[0], VpnProtocol.WireGuardUdp, 51820));
        PortForwardingManager manager = new(sender, mapper, Substitute.For<ILogger>(), connection);
        int? portSeenByReceiver = null;
        sender.When(s => s.Send(Arg.Any<PortForwardingPortChangedMessage>()))
            .Do(_ => portSeenByReceiver = manager.GetActivePort("T1"));

        manager.Receive(new PortForwardingStateIpcEntity { SlotId = "T1" });

        Assert.AreEqual(43210, portSeenByReceiver);
    }

    [TestMethod]
    public void SecondaryErrorFlagChange_NotifiesEvenWhenStatusAndPortStayTheSame()
    {
        IEventMessageSender sender = Substitute.For<IEventMessageSender>();
        IEntityMapper mapper = Substitute.For<IEntityMapper>();
        mapper.Map<PortForwardingStateIpcEntity, PortForwardingState>(Arg.Any<PortForwardingStateIpcEntity>())
            .Returns(new PortForwardingState { Status = PortMappingStatus.Stopped });
        PortForwardingManager manager = new(sender, mapper, Substitute.For<ILogger>(), Substitute.For<IConnectionManager>());
        manager.Receive(new PortForwardingStateIpcEntity { SlotId = "T2" });
        sender.ClearReceivedCalls();

        manager.Receive(new PortForwardingStateIpcEntity { SlotId = "T2", HasPortForwardingError = true });

        Assert.IsTrue(manager.GetSlotState("T2")!.HasError);
        sender.Received(1).Send(Arg.Is<PortForwardingStatusChangedMessage>(m => m.SlotId == "T2"));
    }

    [TestMethod]
    public async Task EnableDisableMultiTunnel_ReappliesAndRestoresPrimaryPortForwarding()
    {
        ISettings settings = Substitute.For<ISettings>();
        string json = string.Empty;
        bool enabled = false;
        settings.MultiTunnelPolicyJson.Returns(_ => json);
        settings.When(s => s.MultiTunnelPolicyJson = Arg.Any<string>()).Do(c => json = c.Arg<string>());
        settings.IsMultiTunnelEnabled.Returns(_ => enabled);
        settings.When(s => s.IsMultiTunnelEnabled = Arg.Any<bool>()).Do(c => enabled = c.Arg<bool>());
        IConnectionManager connection = Substitute.For<IConnectionManager>();
        connection.IsConnected.Returns(true);
        IVpnServiceCaller caller = Substitute.For<IVpnServiceCaller>();
        MainSettingsRequestCreator creator = new(settings, Substitute.For<IEntityMapper>());
        MultiTunnelManager manager = new(Substitute.For<ILogger>(), settings, caller, connection,
            Substitute.For<IEventMessageSender>(), mainSettingsRequestCreator: creator);

        // Editing a saved override while disabled must not affect the active single tunnel.
        await manager.SetSlotPortForwardingOverrideAsync("T1", true);
        await caller.DidNotReceive().ApplySettingsAsync(Arg.Any<MainSettingsIpcEntity>());
        await manager.SetEnabledAsync(true);
        await caller.Received().ApplySettingsAsync(Arg.Is<MainSettingsIpcEntity>(s => s.PortForwarding));
        caller.ClearReceivedCalls();

        await manager.SetEnabledAsync(false);

        await caller.Received().ApplySettingsAsync(Arg.Is<MainSettingsIpcEntity>(s => !s.PortForwarding));
    }

    [TestMethod]
    [DataRow(true, false)]
    [DataRow(false, true)]
    public void PrimaryOverride_TakesPrecedenceOverProfile(bool overrideValue, bool profileValue)
    {
        ISettings settings = Substitute.For<ISettings>();
        settings.IsMultiTunnelEnabled.Returns(true);
        settings.MultiTunnelPolicyJson.Returns(JsonSerializer.Serialize(new MultiTunnelPolicyConfig
        {
            Slots = [new MultiTunnelSlotConfig { SlotId = "T1", PortForwardingOverride = overrideValue }],
        }));
        IConnectionProfile profile = Substitute.For<IConnectionProfile>();
        profile.Settings.Returns(new ProfileSettings { IsPortForwardingEnabled = profileValue });
        MainSettingsRequestCreator creator = new(settings, Substitute.For<IEntityMapper>());

        Assert.AreEqual(overrideValue, creator.Create(profile).PortForwarding);
        settings.IsMultiTunnelEnabled.Returns(false);
        Assert.AreEqual(profileValue, creator.Create(profile).PortForwarding);
    }

    [TestMethod]
    public async Task ExplicitServerSelection_UsesServerIntentForPrimaryAndSecondarySlots()
    {
        ISettings settings = Substitute.For<ISettings>();
        IConnectionManager connection = Substitute.For<IConnectionManager>();
        IVpnServiceCaller caller = Substitute.For<IVpnServiceCaller>();
        IConnectionRequestCreator creator = Substitute.For<IConnectionRequestCreator>();
        creator.CreateAsync(Arg.Any<IConnectionIntent>()).Returns(new ProtonVPN.ProcessCommunication.Contracts.Entities.Vpn.ConnectionRequestIpcEntity());
        caller.ConnectMultiTunnelSlotAsync(Arg.Any<MultiTunnelSlotConnectionRequestIpcEntity>())
            .Returns(Result.Ok(new MultiTunnelSlotConnectionResultIpcEntity { Success = true, SlotId = "T2" }));
        IServersLoader loader = Substitute.For<IServersLoader>();
        Server server = CreateServer("NL#2", "nl-02.protonvpn.net", "185.159.158.20");
        loader.GetServers().Returns([server]);
        MultiTunnelManager manager = new(Substitute.For<ILogger>(), settings, caller, connection,
            Substitute.For<IEventMessageSender>(), creator, loader);
        await manager.SetEnabledAsync(true);
        await manager.AddSlotAsync("NL", "NL#2");

        Assert.IsTrue(await manager.ConnectSlotAsync("T2"));
        await creator.Received().CreateAsync(Arg.Is<IConnectionIntent>(i =>
            i.Location is SingleServerLocationIntent && ((SingleServerLocationIntent)i.Location).Server.Id == server.Id));
        await manager.UpdateSlotLocationAsync("T1", "NL", "NL#2");
        Assert.IsTrue(await manager.ConnectSlotAsync("T1"));
        await connection.Received().ConnectAsync(Arg.Any<VpnTriggerDimension>(), Arg.Is<IConnectionIntent>(i =>
            i.Location is SingleServerLocationIntent && ((SingleServerLocationIntent)i.Location).Server.Id == server.Id));
    }

    private static Server CreateServer(string name, string domain, string ip) => new()
    {
        Id = name, Name = name, Domain = domain, ExitCountry = "NL", EntryCountry = "NL", HostCountry = "NL",
        City = "", State = "", GatewayName = "", StatusReference = default!, EntryLocation = default!, ExitLocation = default!,
        Features = ServerFeatures.P2P, Status = 1,
        Servers = [new PhysicalServer
        {
            Id = domain, Domain = domain, EntryIp = ip, ExitIp = ip, Label = "", Status = 1,
            X25519PublicKey = "", Signature = "",
        }],
    };
}
