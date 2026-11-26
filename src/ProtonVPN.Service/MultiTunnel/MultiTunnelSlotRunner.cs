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
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ProtonVPN.Common.Core.Networking;
using ProtonVPN.Common.Legacy.Vpn;
using ProtonVPN.Configurations.Contracts;
using ProtonVPN.Crypto.Contracts;
using ProtonVPN.EntityMapping.Contracts;
using ProtonVPN.Logging.Contracts;
using ProtonVPN.Logging.Contracts.Events.ConnectLogs;
using ProtonVPN.Logging.Contracts.Events.DisconnectLogs;
using ProtonVPN.OperatingSystems.Network.Contracts;
using ProtonVPN.OperatingSystems.Network.Contracts.Routing;
using ProtonVPN.OperatingSystems.Services.Contracts;
using ProtonVPN.ProcessCommunication.Contracts.Entities.MultiTunnel;
using ProtonVPN.ProcessCommunication.Contracts.Entities.Vpn;
using ProtonVPN.Service.Firewall;
using ProtonVPN.Vpn.Common;
using ProtonVPN.WireGuardDriver;
using FilterAction = ProtonVPN.NetworkFilter.Action;

namespace ProtonVPN.Service.MultiTunnel;

public interface IMultiTunnelSlotRunner
{
    Task<MultiTunnelSlotConnectionResultIpcEntity> ConnectSlotAsync(
        MultiTunnelSlotConnectionRequestIpcEntity request,
        CancellationToken cancellationToken);

    Task DisconnectSlotAsync(string slotId, CancellationToken cancellationToken);

    Task DisconnectAllAsync();

    IReadOnlyList<SlotNetworkTrafficIpcEntity> GetSlotTrafficSnapshot();
}

public sealed class MultiTunnelSlotRunner : IMultiTunnelSlotRunner
{
    private const int DEFAULT_WIREGUARD_PORT = 51820;

    private readonly ILogger _logger;
    private readonly IStaticConfiguration _staticConfig;
    private readonly IEntityMapper _entityMapper;
    private readonly IX25519KeyGenerator _x25519KeyGenerator;
    private readonly IServiceFactory _serviceFactory;
    private readonly IRoutingTableHelper _routingTableHelper;
    private readonly IIpv4GatewayResolver _ipv4GatewayResolver;
    private readonly MultiTunnelOrchestrator _orchestrator;
    private readonly IPermittedRemoteAddress? _permittedRemoteAddress;
    private readonly ISystemNetworkInterfaces? _networkInterfaces;

    public MultiTunnelSlotRunner(
        ILogger logger,
        IStaticConfiguration staticConfig,
        IEntityMapper entityMapper,
        IX25519KeyGenerator x25519KeyGenerator,
        IServiceFactory serviceFactory,
        IRoutingTableHelper routingTableHelper,
        IIpv4GatewayResolver ipv4GatewayResolver,
        MultiTunnelOrchestrator orchestrator,
        IPermittedRemoteAddress? permittedRemoteAddress = null,
        ISystemNetworkInterfaces? networkInterfaces = null)
    {
        _logger = logger;
        _staticConfig = staticConfig;
        _entityMapper = entityMapper;
        _x25519KeyGenerator = x25519KeyGenerator;
        _serviceFactory = serviceFactory;
        _routingTableHelper = routingTableHelper;
        _ipv4GatewayResolver = ipv4GatewayResolver;
        _orchestrator = orchestrator;
        _permittedRemoteAddress = permittedRemoteAddress;
        _networkInterfaces = networkInterfaces;
    }

    public async Task<MultiTunnelSlotConnectionResultIpcEntity> ConnectSlotAsync(
        MultiTunnelSlotConnectionRequestIpcEntity request,
        CancellationToken cancellationToken)
    {
        string slotId = request.SlotId?.Trim().ToUpperInvariant() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(slotId) || string.Equals(slotId, "T1", StringComparison.OrdinalIgnoreCase))
        {
            return new MultiTunnelSlotConnectionResultIpcEntity
            {
                Success = false,
                SlotId = slotId,
                ErrorMessage = "Primary slot T1 is managed by the main VPN connection.",
            };
        }

        if (request.ConnectionRequest is null ||
            request.ConnectionRequest.Servers is null ||
            request.ConnectionRequest.Servers.Length == 0 ||
            request.ConnectionRequest.Credentials?.ClientKeyPair?.SecretKey is null)
        {
            return new MultiTunnelSlotConnectionResultIpcEntity
            {
                Success = false,
                SlotId = slotId,
                ErrorMessage = "Missing server list or WireGuard client credentials.",
            };
        }

        try
        {
            IReadOnlyList<VpnHost> endpoints = _entityMapper.Map<VpnServerIpcEntity, VpnHost>(request.ConnectionRequest.Servers);
            VpnCredentials credentials = _entityMapper.Map<VpnCredentialsIpcEntity, VpnCredentials>(request.ConnectionRequest.Credentials);
            VpnConfig vpnConfig = _entityMapper.Map<VpnConfigIpcEntity, VpnConfig>(request.ConnectionRequest.Config);

            VpnHost endpoint = endpoints.FirstOrDefault(e => e.X25519PublicKey is not null && !string.IsNullOrWhiteSpace(e.Ip));
            if (endpoint.X25519PublicKey is null || string.IsNullOrWhiteSpace(endpoint.Ip))
            {
                return new MultiTunnelSlotConnectionResultIpcEntity
                {
                    Success = false,
                    SlotId = slotId,
                    ErrorMessage = "No WireGuard-capable server available for this slot.",
                };
            }

            int port = vpnConfig.Ports.TryGetValue(VpnProtocol.WireGuardUdp, out IReadOnlyCollection<int>? udpPorts) && udpPorts.Count > 0
                ? udpPorts.First()
                : DEFAULT_WIREGUARD_PORT;

            await StopSlotServiceAsync(slotId).ConfigureAwait(false);

            string configPath = GetSlotConfigPath(slotId);
            string? configDir = Path.GetDirectoryName(configPath);
            if (!string.IsNullOrEmpty(configDir))
            {
                Directory.CreateDirectory(configDir);
            }

            string privateKeyBase64 = _x25519KeyGenerator.FromEd25519SecretKey(credentials.ClientKeyPair.SecretKey).Base64;
            string clientIpv4 = string.IsNullOrWhiteSpace(request.ClientIpv4Address)
                ? $"10.{2 + request.SlotIndex}.0.2"
                : request.ClientIpv4Address.Trim();
            string gatewayIpv4 = string.IsNullOrWhiteSpace(request.ServerGatewayIpv4Address)
                ? $"10.{2 + request.SlotIndex}.0.1"
                : request.ServerGatewayIpv4Address.Trim();

            string configContent = new StringBuilder()
                .AppendLine("[Interface]")
                .AppendLine($"PrivateKey = {privateKeyBase64}")
                .AppendLine($"Address = {clientIpv4}/32")
                .AppendLine("Table = off")
                .AppendLine("[Peer]")
                .AppendLine($"PublicKey = {endpoint.X25519PublicKey.Base64}")
                .AppendLine("AllowedIPs = 0.0.0.0/0")
                .AppendLine($"Endpoint = {endpoint.Ip}:{port}")
                .AppendLine("PersistentKeepalive = 25")
                .ToString();

            File.WriteAllText(configPath, configContent);

            bool shouldCreateRoute = _orchestrator.ActivateSlot(
                slotId,
                request.CountryCode ?? string.Empty,
                endpoint.Name,
                endpoint.Ip,
                endpoint.Ip,
                interfaceIndex: 0);

            if (_orchestrator.GetSlotStates().TryGetValue(slotId, out TunnelSlotRuntimeState? runtimeSlot))
            {
                if (IPAddress.TryParse(clientIpv4, out IPAddress? parsedClient))
                {
                    runtimeSlot.ClientIpv4 = parsedClient;
                }
                if (IPAddress.TryParse(gatewayIpv4, out IPAddress? parsedGateway))
                {
                    runtimeSlot.ServerGatewayIpv4 = parsedGateway;
                }
            }

            _permittedRemoteAddress?.Add([endpoint.Ip], FilterAction.HardPermit);

            if (shouldCreateRoute && NetworkAddress.TryParse(endpoint.Ip, out NetworkAddress endpointAddress))
            {
                CreatePhysicalEndpointRoute(endpoint.Ip, endpointAddress);
            }

            IService service = _serviceFactory.Get(GetSlotServiceName(slotId));
            string commandLine = $"\"{_staticConfig.WireGuard.ServicePath}\" \"{configPath}\" \"udp\"";
            if (!service.IsCreated())
            {
                service.Create(new ServiceCreationOptions(
                    pathAndArguments: commandLine,
                    isUnrestricted: true,
                    dependencies: ["Nsi", "TcpIp"]));
            }
            else
            {
                if (!service.IsEnabled())
                {
                    service.Enable();
                }

                string? existingPath = service.GetBinaryPath();
                if (!string.Equals(existingPath, commandLine, StringComparison.Ordinal))
                {
                    service.UpdatePathAndArgs(commandLine);
                }
            }

            bool started = await service.StartAsync(cancellationToken).ConfigureAwait(false);
            if (!started && !service.IsRunning())
            {
                bool removedLast = _orchestrator.DeactivateSlot(slotId, out string failedIp);
                if (removedLast && !string.IsNullOrWhiteSpace(failedIp))
                {
                    _routingTableHelper.DeleteRoute(failedIp, isIpv6: false);
                    _permittedRemoteAddress?.Remove(failedIp);
                }

                return new MultiTunnelSlotConnectionResultIpcEntity
                {
                    Success = false,
                    SlotId = slotId,
                    ErrorMessage = $"Failed to start WireGuard service for {slotId}.",
                };
            }

            uint resolvedInterfaceIndex = await WaitForSlotInterfaceIndexAsync(
                slotId,
                clientIpv4,
                cancellationToken).ConfigureAwait(false);

            if (_orchestrator.GetSlotStates().TryGetValue(slotId, out TunnelSlotRuntimeState? liveSlot))
            {
                liveSlot.InterfaceIndex = resolvedInterfaceIndex;
            }

            if (resolvedInterfaceIndex > 0 &&
                IPAddress.TryParse(clientIpv4, out IPAddress? parsedClientIp) &&
                IPAddress.TryParse(gatewayIpv4, out IPAddress? parsedGatewayIp))
            {
                ConfigureSlotInterfaceRoutes(resolvedInterfaceIndex, request.SlotIndex, parsedClientIp, parsedGatewayIp);
            }

            _logger.Info<ConnectLog>($"MultiTunnelSlotRunner: Connected slot {slotId} -> {endpoint.Name} ({endpoint.Ip}:{port}, local {clientIpv4}, ifIdx {resolvedInterfaceIndex}).");

            return new MultiTunnelSlotConnectionResultIpcEntity
            {
                Success = true,
                SlotId = slotId,
                ConnectedServerName = endpoint.Name,
                ConnectedEntryIp = endpoint.Ip,
            };
        }
        catch (Exception ex)
        {
            _logger.Error<ConnectLog>($"MultiTunnelSlotRunner: Failed to connect slot {slotId}.", ex);
            bool removedLast = _orchestrator.DeactivateSlot(slotId, out string cleanupIp);
            if (removedLast && !string.IsNullOrWhiteSpace(cleanupIp))
            {
                _routingTableHelper.DeleteRoute(cleanupIp, isIpv6: false);
                _permittedRemoteAddress?.Remove(cleanupIp);
            }

            return new MultiTunnelSlotConnectionResultIpcEntity
            {
                Success = false,
                SlotId = slotId,
                ErrorMessage = ex.Message,
            };
        }
    }

    public async Task DisconnectSlotAsync(string slotId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(slotId) || string.Equals(slotId, "T1", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        string normalizedId = slotId.Trim().ToUpperInvariant();
        uint interfaceIndex = 0;
        IPAddress? clientIp = null;
        IPAddress? gatewayIp = null;
        if (_orchestrator.GetSlotStates().TryGetValue(normalizedId, out TunnelSlotRuntimeState? runtimeSlot))
        {
            interfaceIndex = runtimeSlot.InterfaceIndex;
            clientIp = runtimeSlot.ClientIpv4;
            gatewayIp = runtimeSlot.ServerGatewayIpv4;
        }

        if (interfaceIndex > 0 && clientIp is not null && gatewayIp is not null)
        {
            CleanupSlotInterfaceRoutes(interfaceIndex, clientIp, gatewayIp);
        }

        await StopSlotServiceAsync(normalizedId).ConfigureAwait(false);

        string configPath = GetSlotConfigPath(normalizedId);
        if (File.Exists(configPath))
        {
            try
            {
                File.Delete(configPath);
            }
            catch (Exception ex)
            {
                _logger.Warn<DisconnectLog>($"MultiTunnelSlotRunner: Could not delete {configPath}: {ex.Message}");
            }
        }

        bool shouldDeleteRoute = _orchestrator.DeactivateSlot(normalizedId, out string releasedEntryIp);
        if (shouldDeleteRoute && !string.IsNullOrWhiteSpace(releasedEntryIp))
        {
            _routingTableHelper.DeleteRoute(releasedEntryIp, isIpv6: false);
            _permittedRemoteAddress?.Remove(releasedEntryIp);
        }

        _logger.Info<DisconnectLog>($"MultiTunnelSlotRunner: Disconnected slot {normalizedId}.");
    }

    public async Task DisconnectAllAsync()
    {
        for (int i = 1; i < TunnelSlotAllocation.MaxTunnelSlots; i++)
        {
            await DisconnectSlotAsync($"T{i + 1}", CancellationToken.None).ConfigureAwait(false);
        }
    }

    public IReadOnlyList<SlotNetworkTrafficIpcEntity> GetSlotTrafficSnapshot()
    {
        List<SlotNetworkTrafficIpcEntity> results = [];
        IReadOnlyDictionary<string, TunnelSlotRuntimeState> states = _orchestrator.GetSlotStates();

        for (int i = 1; i < TunnelSlotAllocation.MaxTunnelSlots; i++)
        {
            string slotId = $"T{i + 1}";
            if (!states.TryGetValue(slotId, out TunnelSlotRuntimeState? state) || !state.IsConnected)
            {
                continue;
            }

            (ulong rx, ulong tx) = ReadAdapterTraffic(slotId);
            results.Add(new SlotNetworkTrafficIpcEntity
            {
                SlotId = slotId,
                BytesDownloaded = rx,
                BytesUploaded = tx,
                IsConnected = true,
            });
        }

        return results;
    }

    private static (ulong Rx, ulong Tx) ReadAdapterTraffic(string slotId)
    {
        string adapterName = $"ProtonVPN-{slotId}";
        try
        {
            using Adapter adapter = new(adapterName);
            Interface iface = adapter.GetConfiguration();
            ulong rx = 0;
            ulong tx = 0;
            foreach (Peer peer in iface.Peers)
            {
                rx += peer.RxBytes;
                tx += peer.TxBytes;
            }
            return (rx, tx);
        }
        catch (Win32Exception)
        {
            // Fallback to OS interface statistics if WireGuardNT adapter handle is unavailable
        }
        catch
        {
        }

        try
        {
            NetworkInterface? nic = NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(n => string.Equals(n.Name, adapterName, StringComparison.OrdinalIgnoreCase));
            if (nic is not null)
            {
                IPInterfaceStatistics stats = nic.GetIPStatistics();
                return ((ulong)Math.Max(0, stats.BytesReceived), (ulong)Math.Max(0, stats.BytesSent));
            }
        }
        catch
        {
        }

        return (0, 0);
    }

    private async Task StopSlotServiceAsync(string slotId)
    {
        IService service = _serviceFactory.Get(GetSlotServiceName(slotId));
        if (!service.IsCreated() || service.IsStopped())
        {
            return;
        }

        for (int attempt = 0; attempt < 3; attempt++)
        {
            if (await service.StopAsync(CancellationToken.None).ConfigureAwait(false))
            {
                return;
            }
            await Task.Delay(100).ConfigureAwait(false);
        }

        service.Kill();
    }

    private string GetSlotConfigPath(string slotId)
    {
        string baseDir = Path.GetDirectoryName(_staticConfig.WireGuard.ConfigFilePath) ?? string.Empty;
        return Path.Combine(baseDir, $"ProtonVPN-{slotId}.conf");
    }

    private string GetSlotServiceName(string slotId) => $"{_staticConfig.WireGuard.ServiceName} {slotId}";

    private void CreatePhysicalEndpointRoute(string endpointIp, NetworkAddress endpointAddress)
    {
        NetworkAddress? gatewayAddr = null;
        uint interfaceIndex = 0;
        uint metric = 0;

        if (MultiTunnelNetworkHelper.TryResolvePhysicalInterface(
                _networkInterfaces,
                _routingTableHelper,
                out INetworkInterface? physIface,
                out _,
                out _,
                out IPAddress? physGw,
                out uint physMetric) &&
            physIface is not null &&
            physGw is not null &&
            NetworkAddress.TryParse(physGw.ToString(), out NetworkAddress parsedPhysGw))
        {
            gatewayAddr = parsedPhysGw;
            interfaceIndex = physIface.Index;
            metric = physMetric;
        }
        else if (_ipv4GatewayResolver.TryGetBestIpv4Gateway(_staticConfig.GetWireGuardHardwareId(), out Ipv4GatewayInfo? gatewayInfo) &&
                 gatewayInfo is not null &&
                 !MultiTunnelNetworkHelper.IsTunnelSubnetIpv4(gatewayInfo.GatewayAddress.Ip))
        {
            gatewayAddr = gatewayInfo.GatewayAddress;
            interfaceIndex = gatewayInfo.Interface.Index;
            metric = gatewayInfo.InterfaceMetric;
        }

        if (gatewayAddr is null || interfaceIndex == 0)
        {
            _logger.Warn<ConnectLog>($"MultiTunnelSlotRunner: Physical gateway unavailable for endpoint {endpointIp}; skipping /32 route.");
            return;
        }

        _routingTableHelper.DeleteRoute(endpointIp, isIpv6: false);
        _routingTableHelper.CreateRoute(new RouteConfiguration
        {
            Destination = endpointAddress,
            Gateway = gatewayAddr.Value,
            InterfaceIndex = interfaceIndex,
            Metric = metric,
            IsIpv6 = endpointAddress.IsIpV6,
        });
    }

    private async Task<uint> WaitForSlotInterfaceIndexAsync(string slotId, string clientIpv4, CancellationToken cancellationToken)
    {
        if (_networkInterfaces is null)
        {
            return 0;
        }

        string expectedAdapterName = $"ProtonVPN-{slotId}";
        IPAddress.TryParse(clientIpv4, out IPAddress? parsedClient);

        for (int attempt = 0; attempt < 30; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                INetworkInterface[] interfaces = _networkInterfaces.GetInterfaces();
                INetworkInterface? match = interfaces.FirstOrDefault(i =>
                    i.Index > 0 &&
                    (string.Equals(i.Name, expectedAdapterName, StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(i.Description, expectedAdapterName, StringComparison.OrdinalIgnoreCase) ||
                     (parsedClient is not null && i.GetUnicastAddresses().Any(a => !a.IsIpV6 && a.Ip.Equals(parsedClient)))));

                if (match is not null)
                {
                    return match.Index;
                }
            }
            catch
            {
            }

            await Task.Delay(150, cancellationToken).ConfigureAwait(false);
        }

        return 0;
    }

    private void ConfigureSlotInterfaceRoutes(uint interfaceIndex, int slotIndex, IPAddress clientIp, IPAddress gatewayIp)
    {
        if (interfaceIndex == 0 ||
            !NetworkAddress.TryParse("0.0.0.0/0", out NetworkAddress defaultIpv4) ||
            !NetworkAddress.TryParse("0.0.0.0/1", out NetworkAddress splitLow) ||
            !NetworkAddress.TryParse("128.0.0.0/1", out NetworkAddress splitHigh) ||
            !NetworkAddress.TryParse(clientIp.ToString(), out NetworkAddress clientNet) ||
            !NetworkAddress.TryParse($"{gatewayIp}/32", out NetworkAddress gatewayHost))
        {
            return;
        }

        // Remove any competing low-metric routes scoped specifically to this slot adapter
        _routingTableHelper.DeleteRoute(new RouteConfiguration { Destination = defaultIpv4, Gateway = clientNet, InterfaceIndex = interfaceIndex, IsIpv6 = false });
        _routingTableHelper.DeleteRoute(new RouteConfiguration { Destination = splitLow, Gateway = clientNet, InterfaceIndex = interfaceIndex, IsIpv6 = false });
        _routingTableHelper.DeleteRoute(new RouteConfiguration { Destination = splitHigh, Gateway = clientNet, InterfaceIndex = interfaceIndex, IsIpv6 = false });

        uint highMetric = 32000u + (uint)Math.Max(0, slotIndex);

        _routingTableHelper.CreateRoute(new RouteConfiguration
        {
            Destination = defaultIpv4,
            Gateway = clientNet,
            InterfaceIndex = interfaceIndex,
            Metric = highMetric,
            IsIpv6 = false,
        });

        _routingTableHelper.CreateRoute(new RouteConfiguration
        {
            Destination = gatewayHost,
            Gateway = clientNet,
            InterfaceIndex = interfaceIndex,
            Metric = highMetric,
            IsIpv6 = false,
        });
    }

    private void CleanupSlotInterfaceRoutes(uint interfaceIndex, IPAddress clientIp, IPAddress gatewayIp)
    {
        if (interfaceIndex == 0 ||
            !NetworkAddress.TryParse("0.0.0.0/0", out NetworkAddress defaultIpv4) ||
            !NetworkAddress.TryParse(clientIp.ToString(), out NetworkAddress clientNet) ||
            !NetworkAddress.TryParse($"{gatewayIp}/32", out NetworkAddress gatewayHost))
        {
            return;
        }

        try
        {
            _routingTableHelper.DeleteRoute(new RouteConfiguration { Destination = defaultIpv4, Gateway = clientNet, InterfaceIndex = interfaceIndex, IsIpv6 = false });
            _routingTableHelper.DeleteRoute(new RouteConfiguration { Destination = gatewayHost, Gateway = clientNet, InterfaceIndex = interfaceIndex, IsIpv6 = false });
        }
        catch (Exception ex)
        {
            _logger.Warn<DisconnectLog>($"MultiTunnelSlotRunner: Failed to clean routes on interface {interfaceIndex}: {ex.Message}");
        }
    }
}
