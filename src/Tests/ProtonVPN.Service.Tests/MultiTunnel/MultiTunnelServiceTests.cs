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
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute;
using ProtonVPN.Common.Core.Networking;
using ProtonVPN.Common.Legacy.Threading;
using ProtonVPN.Common.Legacy.Vpn;
using ProtonVPN.Configurations.Contracts;
using ProtonVPN.Configurations.Contracts.Entities;
using ProtonVPN.Crypto.Contracts;
using ProtonVPN.EntityMapping.Contracts;
using ProtonVPN.Logging.Contracts;
using ProtonVPN.OperatingSystems.Network.Contracts;
using ProtonVPN.OperatingSystems.Network.Contracts.Routing;
using ProtonVPN.OperatingSystems.Services.Contracts;
using ProtonVPN.ProcessCommunication.Contracts.Entities.Crypto;
using ProtonVPN.ProcessCommunication.Contracts.Entities.MultiTunnel;
using ProtonVPN.ProcessCommunication.Contracts.Entities.Vpn;
using ProtonVPN.Service.ControllerRetries;
using ProtonVPN.Service.Driver;
using ProtonVPN.Service.Firewall;
using ProtonVPN.Service.MultiTunnel;
using ProtonVPN.Service.ProcessCommunication;
using ProtonVPN.Service.Settings;
using ProtonVPN.Service.StateMachine;
using ProtonVPN.Service.Vpn;
using ProtonVPN.Vpn.Common;
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

    private MultiTunnelService CreateService(bool enableBackgroundDns = false) => new(
        _logger,
        _orchestrator,
        _wfpManager,
        _calloutDriver,
        _networkUtilities,
        _networkInterfaces,
        _config,
        _serviceSettings)
    {
        EnableBackgroundDnsResolution = enableBackgroundDns,
    };

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
            null,
            RuleTargetType.Direct,
            "T1");
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

    [TestMethod]
    public void ApplyPolicy_DeduplicatesUnchangedPolicyFingerprint_AvoidingRedundantWfpFlaps()
    {
        MultiTunnelService service = CreateService();
        service.OnVpnConnected(new VpnState(
            VpnStatus.Connected,
            VpnError.None,
            localIp: "10.2.0.2",
            remoteIp: "185.159.1.10",
            endpointPort: 51820,
            vpnProtocol: VpnProtocol.WireGuardUdp));

        Guid ruleId = Guid.NewGuid();
        MultiTunnelPolicyIpcEntity policy = new()
        {
            IsMultiTunnelEnabled = true,
            DefaultTargetType = RuleTargetTypeIpcEntity.Direct,
            DefaultTunnelId = "T1",
            PriorityRules =
            [
                new SelectiveRoutingRuleIpcEntity
                {
                    Id = ruleId,
                    PriorityOrder = 1,
                    Name = "LAN Direct",
                    IsEnabled = true,
                    IpCidrPattern = "192.168.0.0/16",
                    TargetType = RuleTargetTypeIpcEntity.Direct,
                },
            ],
        };

        service.ApplyPolicy(policy);
        service.ApplyPolicy(policy);

        _wfpManager.Received(1).ApplyMultiTunnelPolicy(
            Arg.Any<IReadOnlyDictionary<string, TunnelSlotRuntimeState>>(),
            Arg.Any<IReadOnlyList<SelectiveRoutingRule>>(),
            Arg.Any<IReadOnlyDictionary<Guid, IReadOnlyList<IPAddress>>>(),
            IPAddress.Parse("192.168.1.100"),
            null,
            RuleTargetType.Direct,
            "T1");
    }

    [TestMethod]
    public void ReapplyWfpPolicy_SkipsVpnTunnelInterfacesWhenResolvingPhysicalIpv4()
    {
        INetworkInterface vpnNic = Substitute.For<INetworkInterface>();
        vpnNic.Name.Returns("ProtonVPN-T2");
        vpnNic.Description.Returns("WireGuard Tunnel");
        vpnNic.Index.Returns(42u);
        vpnNic.IsActive.Returns(true);
        vpnNic.DefaultGateway.Returns(IPAddress.Parse("10.3.0.1"));
        vpnNic.GetUnicastAddresses().Returns([new NetworkAddress(IPAddress.Parse("10.3.0.2"))]);

        INetworkInterface ethNic = Substitute.For<INetworkInterface>();
        ethNic.Name.Returns("Ethernet");
        ethNic.Description.Returns("Intel Ethernet");
        ethNic.Index.Returns(7u);
        ethNic.IsActive.Returns(true);
        ethNic.DefaultGateway.Returns(IPAddress.Parse("192.168.50.1"));
        ethNic.GetUnicastAddresses().Returns([new NetworkAddress(IPAddress.Parse("192.168.50.25"))]);

        _networkInterfaces.GetInterfaces().Returns([vpnNic, ethNic]);
        IRoutingTableHelper routingHelper = Substitute.For<IRoutingTableHelper>();
        routingHelper.GetInterfaceMetric(7u, false).Returns(25u);

        MultiTunnelService service = new(
            _logger,
            _orchestrator,
            _wfpManager,
            _calloutDriver,
            _networkUtilities,
            _networkInterfaces,
            _config,
            _serviceSettings,
            routingTableHelper: routingHelper)
        {
            EnableBackgroundDnsResolution = false,
        };

        service.OnVpnConnected(new VpnState(
            VpnStatus.Connected,
            VpnError.None,
            localIp: "10.2.0.2",
            remoteIp: "185.159.1.10",
            endpointPort: 51820,
            vpnProtocol: VpnProtocol.WireGuardUdp));

        service.ApplyPolicy(new MultiTunnelPolicyIpcEntity { IsMultiTunnelEnabled = true });

        _wfpManager.Received(1).ApplyMultiTunnelPolicy(
            Arg.Any<IReadOnlyDictionary<string, TunnelSlotRuntimeState>>(),
            Arg.Any<IReadOnlyList<SelectiveRoutingRule>>(),
            Arg.Any<IReadOnlyDictionary<Guid, IReadOnlyList<IPAddress>>>(),
            IPAddress.Parse("192.168.50.25"),
            null,
            RuleTargetType.Direct,
            "T1");
    }

    [TestMethod]
    public async Task MultiTunnelSlotRunner_ConfiguresHighMetricSlotRouteAndCleansUpOnDisconnect()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), $"pvpn-slotrunner-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        try
        {
            IStaticConfiguration staticConfig = Substitute.For<IStaticConfiguration>();
            IWireGuardConfigurations wgConfig = Substitute.For<IWireGuardConfigurations>();
            wgConfig.ConfigFilePath.Returns(Path.Combine(tempDir, "ProtonVPN.conf"));
            wgConfig.ServicePath.Returns("C:\\Program Files\\Proton\\WireGuardService.exe");
            wgConfig.ServiceName.Returns("ProtonVPN WireGuard");
            staticConfig.WireGuard.Returns(wgConfig);
            staticConfig.GetWireGuardHardwareId().Returns("ProtonVPN-WG");

            IEntityMapper mapper = Substitute.For<IEntityMapper>();
            mapper.Map<VpnServerIpcEntity, VpnHost>(Arg.Any<VpnServerIpcEntity[]>())
                .Returns([new VpnHost("us-01.protonvpn.net", "185.159.158.10", string.Empty, new PublicKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", KeyAlgorithm.X25519), string.Empty, false, null)]);
            mapper.Map<VpnCredentialsIpcEntity, VpnCredentials>(Arg.Any<VpnCredentialsIpcEntity>())
                .Returns(new VpnCredentials(
                    new AsymmetricKeyPair(
                        new SecretKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", KeyAlgorithm.Ed25519),
                        new PublicKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", KeyAlgorithm.Ed25519))));
            mapper.Map<VpnConfigIpcEntity, VpnConfig>(Arg.Any<VpnConfigIpcEntity>())
                .Returns(new VpnConfig(new VpnConfigParameters()));

            IX25519KeyGenerator x25519 = Substitute.For<IX25519KeyGenerator>();
            x25519.FromEd25519SecretKey(Arg.Any<SecretKey>())
                .Returns(new SecretKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", KeyAlgorithm.X25519));

            IService slotService = Substitute.For<IService>();
            slotService.IsCreated().Returns(false);
            slotService.IsRunning().Returns(true);
            slotService.IsStopped().Returns(false);
            slotService.StartAsync(Arg.Any<CancellationToken>()).Returns(true);
            slotService.StopAsync(Arg.Any<CancellationToken>()).Returns(true);

            IServiceFactory serviceFactory = Substitute.For<IServiceFactory>();
            serviceFactory.Get("ProtonVPN WireGuard T2").Returns(slotService);

            IRoutingTableHelper routingHelper = Substitute.For<IRoutingTableHelper>();
            IIpv4GatewayResolver gatewayResolver = Substitute.For<IIpv4GatewayResolver>();

            INetworkInterface ethNic = Substitute.For<INetworkInterface>();
            ethNic.Name.Returns("Ethernet");
            ethNic.Description.Returns("Intel Ethernet");
            ethNic.Index.Returns(7u);
            ethNic.IsActive.Returns(true);
            ethNic.DefaultGateway.Returns(IPAddress.Parse("192.168.1.1"));
            ethNic.GetUnicastAddresses().Returns([new NetworkAddress(IPAddress.Parse("192.168.1.50"))]);

            INetworkInterface t2Nic = Substitute.For<INetworkInterface>();
            t2Nic.Name.Returns("ProtonVPN-T2");
            t2Nic.Description.Returns("ProtonVPN-T2");
            t2Nic.Index.Returns(99u);
            t2Nic.IsActive.Returns(true);
            t2Nic.GetUnicastAddresses().Returns([new NetworkAddress(IPAddress.Parse("10.3.0.2"))]);

            ISystemNetworkInterfaces networkInterfaces = Substitute.For<ISystemNetworkInterfaces>();
            networkInterfaces.GetInterfaces().Returns([ethNic, t2Nic]);

            IPermittedRemoteAddress permittedRemote = Substitute.For<IPermittedRemoteAddress>();

            MultiTunnelSlotRunner runner = new(
                _logger,
                staticConfig,
                mapper,
                x25519,
                serviceFactory,
                routingHelper,
                gatewayResolver,
                _orchestrator,
                permittedRemote,
                networkInterfaces);

            MultiTunnelSlotConnectionRequestIpcEntity req = new()
            {
                SlotId = "T2",
                SlotIndex = 1,
                ClientIpv4Address = "10.3.0.2",
                ServerGatewayIpv4Address = "10.3.0.1",
                CountryCode = "US",
                ConnectionRequest = new ConnectionRequestIpcEntity
                {
                    Servers = [new VpnServerIpcEntity { Name = "us-01.protonvpn.net", Ip = "185.159.158.10" }],
                    Credentials = new VpnCredentialsIpcEntity
                    {
                        ClientKeyPair = new AsymmetricKeyPairIpcEntity
                        {
                            SecretKey = new SecretKeyIpcEntity { Bytes = new byte[32], Base64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
                            PublicKey = new PublicKeyIpcEntity { Bytes = new byte[32], Base64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
                        },
                    },
                    Config = new VpnConfigIpcEntity(),
                },
            };

            MultiTunnelSlotConnectionResultIpcEntity result = await runner.ConnectSlotAsync(req, CancellationToken.None);

            result.Success.Should().BeTrue();
            _orchestrator.GetSlotStates()["T2"].InterfaceIndex.Should().Be(99u);
            routingHelper.Received().CreateRoute(Arg.Is<RouteConfiguration>(r =>
                r.InterfaceIndex == 99u && r.Metric == 32001u && r.Destination.Ip.Equals(IPAddress.Any)));
            routingHelper.Received().CreateRoute(Arg.Is<RouteConfiguration>(r =>
                r.InterfaceIndex == 99u && r.Metric == 32001u && r.Destination.Ip.Equals(IPAddress.Parse("10.3.0.1"))));

            string writtenConf = File.ReadAllText(Path.Combine(tempDir, "ProtonVPN-T2.conf"));
            writtenConf.Should().Contain("Table = off");
            writtenConf.Should().NotContain("DNS =");

            await runner.DisconnectSlotAsync("T2", CancellationToken.None);

            routingHelper.Received().DeleteRoute(Arg.Is<RouteConfiguration>(r =>
                r.InterfaceIndex == 99u && r.Destination.Ip.Equals(IPAddress.Any)));
            routingHelper.Received().DeleteRoute("185.159.158.10", false);
        }
        finally
        {
            try { Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }
}
