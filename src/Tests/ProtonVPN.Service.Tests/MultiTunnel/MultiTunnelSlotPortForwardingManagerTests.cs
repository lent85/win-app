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
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute;
using ProtonVPN.Common.Core.Networking;
using ProtonVPN.Common.Legacy.PortForwarding;
using ProtonVPN.Common.Legacy.Vpn;
using ProtonVPN.Configurations.Contracts;
using ProtonVPN.Crypto.Contracts;
using ProtonVPN.IssueReporting.Contracts;
using ProtonVPN.Logging.Contracts;
using ProtonVPN.Service.MultiTunnel;
using ProtonVPN.Vpn.PortMapping.Serializers.Common;

namespace ProtonVPN.Service.Tests.MultiTunnel;

[TestClass]
public class MultiTunnelSlotPortForwardingManagerTests
{
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task StartupFailure_PublishesErrorAndClearsItOnStop(bool hasCertificate)
    {
        MultiTunnelSlotPortForwardingManager manager = CreateManager();
        List<MultiTunnelSlotPortForwardingState> events = [];
        manager.SlotStateChanged += (_, state) => events.Add(state);

        await StartAsync(manager, hasCertificate);

        MultiTunnelSlotPortForwardingState state = manager.GetSlotState("t2");
        Assert.IsNotNull(state);
        Assert.IsTrue(state.HasPortForwardingError);
        Assert.AreEqual(PortMappingStatus.Error, state.State.Status);
        Assert.IsNull(state.State.MappedPort);

        await manager.StopSlotAsync("T2");
        Assert.IsNull(manager.GetSlotState("T2"));
        Assert.AreEqual(PortMappingStatus.Stopped, events[^1].State.Status);
        Assert.IsFalse(events[^1].HasPortForwardingError);
    }

    [TestMethod]
    public async Task UpdateAfterWorkerFailure_ReportsErrorWhenEnabledAndClearsWhenDisabled()
    {
        MultiTunnelSlotPortForwardingManager manager = CreateManager();
        await StartAsync(manager, hasCertificate: true);

        await manager.UpdateSlotFeaturesAsync("T2", false, 2, true, false);
        Assert.IsFalse(manager.GetSlotState("T2").HasPortForwardingError);
        Assert.AreEqual(PortMappingStatus.Stopped, manager.GetSlotState("T2").State.Status);
        await manager.UpdateSlotFeaturesAsync("T2", true, 2, true, false);
        Assert.IsTrue(manager.GetSlotState("T2").HasPortForwardingError);
        Assert.AreEqual(PortMappingStatus.Error, manager.GetSlotState("T2").State.Status);
        await manager.StopAllAsync();
    }

    [TestMethod]
    public async Task CancelledStart_DoesNotCreateSession()
    {
        MultiTunnelSlotPortForwardingManager manager = CreateManager();
        using CancellationTokenSource cancellation = new();
        cancellation.Cancel();

        await Assert.ThrowsExactlyAsync<TaskCanceledException>(() => StartAsync(manager, true, cancellation.Token));

        Assert.AreEqual(0, manager.GetAllSlotStates().Count);
    }

    private static MultiTunnelSlotPortForwardingManager CreateManager()
    {
        IStaticConfiguration config = Substitute.For<IStaticConfiguration>();
        config.ServiceExePath.Returns("missing-local-agent-worker.exe");
        return new MultiTunnelSlotPortForwardingManager(Substitute.For<ILogger>(), config,
            Substitute.For<IMessageSerializerProxy>(), Substitute.For<IIssueReporter>());
    }

    private static Task StartAsync(MultiTunnelSlotPortForwardingManager manager, bool hasCertificate, CancellationToken token = default)
    {
        const string key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        VpnCredentials credentials = new(hasCertificate ? "CERT" : "", DateTime.UtcNow.AddDays(1),
            new AsymmetricKeyPair(new SecretKey(key, KeyAlgorithm.Ed25519), new PublicKey(key, KeyAlgorithm.Ed25519)), "", "");
        return manager.StartSlotAsync("T2", IPAddress.Loopback, IPAddress.Loopback, default, credentials,
            new VpnConfig(new VpnConfigParameters()), true, true, token);
    }
}
