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
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute;
using ProtonVPN.Common.Core.Networking;
using ProtonVPN.Common.Legacy.Threading;
using ProtonVPN.Configurations.Contracts;
using ProtonVPN.EntityMapping.Contracts;
using ProtonVPN.Logging.Contracts;
using ProtonVPN.OperatingSystems.Network.Contracts;
using ProtonVPN.ProcessCommunication.Contracts.Entities.MultiTunnel;
using ProtonVPN.ProcessCommunication.Contracts.Entities.Vpn;
using ProtonVPN.Service.ControllerRetries;
using ProtonVPN.Service.Driver;
using ProtonVPN.Service.MultiTunnel;
using ProtonVPN.Service.ProcessCommunication;
using ProtonVPN.Service.Settings;
using ProtonVPN.Service.StateMachine;
using ProtonVPN.Service.Vpn;
using ProtonVPN.Vpn.Connection;
using ProtonVPN.Vpn.LocalAgent;
using ProtonVPN.Vpn.PortMapping;

namespace ProtonVPN.Service.Tests.MultiTunnel;

[TestClass]
public class MultiTunnelServiceTests
{
    private ILogger _logger;
    private MultiTunnelOrchestrator _orchestrator;
    private IMultiTunnelWfpManager _wfpManager;
    private ICalloutDriver _calloutDriver;
    private INetworkUtilities _networkUtilities;
    private ISystemNetworkInterfaces _networkInterfaces;
    private IConfiguration _config;
    private IServiceSettings _serviceSettings;

    [TestInitialize]
    public void Setup()
    {
        _logger = Substitute.For<ILogger>();
        _orchestrator = new MultiTunnelOrchestrator();
        _wfpManager = Substitute.For<IMultiTunnelWfpManager>();
        _calloutDriver = Substitute.For<ICalloutDriver>();
        _networkUtilities = Substitute.For<INetworkUtilities>();
        _networkInterfaces = Substitute.For<ISystemNetworkInterfaces>();
        _config = Substitute.For<IConfiguration>();
        _serviceSettings = Substitute.For<IServiceSettings>();

        _serviceSettings.OpenVpnAdapter.Returns(OpenVpnAdapter.Tun);
        _config.GetHardwareId(Arg.Any<VpnProtocol>(), Arg.Any<OpenVpnAdapter>()).Returns("ProtonVPN-Tun");
        _networkUtilities.GetBestInterfaceIPv4Address("ProtonVPN-Tun").Returns(IPAddress.Parse("192.168.1.100"));
        INetworkInterface nic = Substitute.For<INetworkInterface>();
        nic.Id.Returns(string.Empty);
        _networkInterfaces.GetBestInterfaceExcludingHardwareId("ProtonVPN-Tun").Returns(nic);
    }

    private MultiTunnelService CreateService() => new(
        _logger,
        _orchestrator,
        _wfpManager,
        _calloutDriver,
        _networkUtilities,
        _networkInterfaces,
        _config,
        _serviceSettings);

    [TestMethod]
    public void ApplyPolicy_WhenEnabledAndVpnConnected_StartsCalloutDriverAndAppliesWfp()
    {
        MultiTunnelService service = CreateService();
        service.OnVpnConnected(new VpnState(
            VpnStatus.Connected,
            VpnError.None,
            localIp: "10.2.0.2",
            remoteIp: "185.159.1.10",
            endpointPort: 51820,
            vpnProtocol: VpnProtocol.WireGuardUdp));

        MultiTunnelPolicyIpcEntity policy = new()
        {
            IsMultiTunnelEnabled = true,
            DefaultTargetType = RuleTargetTypeIpcEntity.Direct,
            DefaultTunnelId = "T1",
            PriorityRules =
            [
                new SelectiveRoutingRuleIpcEntity
                {
                    PriorityOrder = 1,
                    Name = "LAN Direct",
                    IsEnabled = true,
                    IpCidrPattern = "192.168.0.0/16",
                    TargetType = RuleTargetTypeIpcEntity.Direct,
                },
            ],
        };

        service.ApplyPolicy(policy);

        _calloutDriver.Received(1).Start();
        _wfpManager.Received(1).ApplyMultiTunnelPolicy(
            Arg.Is<IReadOnlyDictionary<string, TunnelSlotRuntimeState>>(d => d["T1"].IsConnected),
            Arg.Is<IReadOnlyList<SelectiveRoutingRule>>(r => r.Count == 1 && r[0].Name == "LAN Direct"),
            Arg.Any<IReadOnlyDictionary<Guid, IReadOnlyList<IPAddress>>>(),
            IPAddress.Parse("192.168.1.100"),
            null);
    }

    [TestMethod]
    public void OnVpnDisconnected_PreservesWfpDuringReconnectAndDisablesOnFullDisconnect()
    {
        MultiTunnelService service = CreateService();
        service.ApplyPolicy(new MultiTunnelPolicyIpcEntity { IsMultiTunnelEnabled = true });

        VpnState connectedState = new(VpnStatus.Connected, VpnError.None, "10.2.0.2", "185.159.1.10", 51820, VpnProtocol.WireGuardUdp);
        service.OnVpnConnected(connectedState);
        _wfpManager.ClearReceivedCalls();

        service.OnVpnDisconnected(new VpnState(VpnStatus.Disconnected, VpnProtocol.WireGuardUdp), isReconnecting: true);
        _wfpManager.DidNotReceive().Disable();

        service.OnVpnDisconnected(new VpnState(VpnStatus.Disconnected, VpnProtocol.WireGuardUdp), isReconnecting: false);
        _wfpManager.Received(1).Disable();
    }

    [TestMethod]
    public async Task VpnController_DelegatesMultiTunnelIpcCallsToMultiTunnelService()
    {
        IMultiTunnelService mtService = Substitute.For<IMultiTunnelService>();
        MultiTunnelPolicyIpcEntity expectedPolicy = new() { IsMultiTunnelEnabled = true };
        RoutingDecisionIpcEntity expectedDecision = new() { EffectiveTargetType = RuleTargetTypeIpcEntity.Direct };
        mtService.GetCurrentPolicy().Returns(expectedPolicy);
        mtService.EvaluateTraffic(Arg.Any<TrafficQueryIpcEntity>()).Returns(expectedDecision);

        VpnController controller = new(
            _logger,
            _serviceSettings,
            Substitute.For<ITaskQueue>(),
            Substitute.For<IPortMappingProtocolClient>(),
            Substitute.For<IClientControllerSender>(),
            Substitute.For<IEntityMapper>(),
            Substitute.For<ILocalAgentTlsCredentialsCache>(),
            Substitute.For<IControllerRetryManager>(),
            Substitute.For<IVpnConnectionStateMachine>(),
            Substitute.For<ITunnelOrchestrator>(),
            Substitute.For<ILocalAgent>(),
            Substitute.For<ILocalAgentEventReceiver>(),
            mtService);

        await controller.ApplyMultiTunnelPolicy(expectedPolicy, CancellationToken.None);
        MultiTunnelPolicyIpcEntity actualPolicy = await controller.GetMultiTunnelPolicy(CancellationToken.None);
        RoutingDecisionIpcEntity actualDecision = await controller.EvaluateMultiTunnelTraffic(new TrafficQueryIpcEntity(), CancellationToken.None);

        mtService.Received(1).ApplyPolicy(expectedPolicy);
        actualPolicy.Should().BeSameAs(expectedPolicy);
        actualDecision.Should().BeSameAs(expectedDecision);
    }
}
