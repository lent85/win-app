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

    public MultiTunnelSlotRunner(
        ILogger logger,
        IStaticConfiguration staticConfig,
        IEntityMapper entityMapper,
        IX25519KeyGenerator x25519KeyGenerator,
        IServiceFactory serviceFactory,
        IRoutingTableHelper routingTableHelper,
        IIpv4GatewayResolver ipv4GatewayResolver,
        MultiTunnelOrchestrator orchestrator,
        IPermittedRemoteAddress? permittedRemoteAddress = null)
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
                .AppendLine($"DNS = {gatewayIpv4}")
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

            if (shouldCreateRoute &&
                NetworkAddress.TryParse(endpoint.Ip, out NetworkAddress endpointAddress) &&
                _ipv4GatewayResolver.TryGetBestIpv4Gateway(_staticConfig.GetWireGuardHardwareId(), out Ipv4GatewayInfo? gatewayInfo) &&
                gatewayInfo is not null)
            {
                _routingTableHelper.DeleteRoute(endpoint.Ip, isIpv6: false);
                _routingTableHelper.CreateRoute(new RouteConfiguration
                {
                    Destination = endpointAddress,
                    Gateway = gatewayInfo.GatewayAddress,
                    InterfaceIndex = gatewayInfo.Interface.Index,
                    Metric = gatewayInfo.InterfaceMetric,
                    IsIpv6 = endpointAddress.IsIpV6,
                });
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

            _logger.Info<ConnectLog>($"MultiTunnelSlotRunner: Connected slot {slotId} -> {endpoint.Name} ({endpoint.Ip}:{port}, local {clientIpv4}).");

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
}
