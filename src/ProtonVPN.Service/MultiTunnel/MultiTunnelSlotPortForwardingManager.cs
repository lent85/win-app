/*
 * Copyright (c) 2026 Proton AG
 *
 * This file is part of ProtonVPN.
 *
 * ProtonVPN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ProtonVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ProtonVPN.Common.Core.Extensions;
using ProtonVPN.Common.Core.Networking;
using ProtonVPN.Common.Legacy;
using ProtonVPN.Common.Legacy.PortForwarding;
using ProtonVPN.Common.Legacy.Vpn;
using ProtonVPN.Configurations.Contracts;
using ProtonVPN.IssueReporting.Contracts;
using ProtonVPN.Logging.Contracts;
using ProtonVPN.Logging.Contracts.Events.ConnectLogs;
using ProtonVPN.Logging.Contracts.Events.LocalAgentLogs;
using ProtonVPN.Vpn.Gateways;
using ProtonVPN.Vpn.LocalAgent.Contracts;
using ProtonVPN.Vpn.PortMapping;
using ProtonVPN.Vpn.PortMapping.Serializers.Common;
using ProtonVPN.Vpn.PortMapping.UdpClients;

namespace ProtonVPN.Service.MultiTunnel;

public sealed record MultiTunnelSlotPortForwardingState(
    string SlotId,
    bool PortForwardingEnabled,
    bool IsP2PServer,
    bool HasPortForwardingError,
    PortForwardingState State);

public interface IMultiTunnelSlotPortForwardingManager
{
    event EventHandler<MultiTunnelSlotPortForwardingState>? SlotStateChanged;

    Task StartSlotAsync(
        string slotId,
        IPAddress clientIpv4,
        IPAddress gatewayIpv4,
        VpnHost endpoint,
        VpnCredentials credentials,
        VpnConfig vpnConfig,
        bool portForwardingEnabled,
        bool isP2PServer,
        CancellationToken cancellationToken);

    Task UpdateSlotFeaturesAsync(
        string slotId,
        bool portForwardingEnabled,
        int netShieldMode,
        bool splitTcp,
        bool moderateNat);

    Task StopSlotAsync(string slotId);

    Task StopAllAsync();

    MultiTunnelSlotPortForwardingState? GetSlotState(string slotId);

    IReadOnlyList<MultiTunnelSlotPortForwardingState> GetAllSlotStates();

    void RepeatAllStates();
}

public sealed class MultiTunnelSlotPortForwardingManager : IMultiTunnelSlotPortForwardingManager
{
    private const int LOCAL_AGENT_PORT = 65432;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private readonly ILogger _logger;
    private readonly IStaticConfiguration _staticConfig;
    private readonly IMessageSerializerProxy _messageSerializerProxy;
    private readonly IIssueReporter _issueReporter;

    private readonly object _lock = new();
    private readonly SemaphoreSlim _lifecycleLock = new(1, 1);
    private readonly Dictionary<string, SlotSession> _sessions = new(StringComparer.OrdinalIgnoreCase);

    public event EventHandler<MultiTunnelSlotPortForwardingState>? SlotStateChanged;

    public MultiTunnelSlotPortForwardingManager(
        ILogger logger,
        IStaticConfiguration staticConfig,
        IMessageSerializerProxy messageSerializerProxy,
        IIssueReporter issueReporter)
    {
        _logger = logger;
        _staticConfig = staticConfig;
        _messageSerializerProxy = messageSerializerProxy;
        _issueReporter = issueReporter;
    }

    public async Task StartSlotAsync(
        string slotId,
        IPAddress clientIpv4,
        IPAddress gatewayIpv4,
        VpnHost endpoint,
        VpnCredentials credentials,
        VpnConfig vpnConfig,
        bool portForwardingEnabled,
        bool isP2PServer,
        CancellationToken cancellationToken)
    {
        await _lifecycleLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await StartSlotCoreAsync(slotId, clientIpv4, gatewayIpv4, endpoint, credentials,
                vpnConfig, portForwardingEnabled, isP2PServer, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    private async Task StartSlotCoreAsync(
        string slotId,
        IPAddress clientIpv4,
        IPAddress gatewayIpv4,
        VpnHost endpoint,
        VpnCredentials credentials,
        VpnConfig vpnConfig,
        bool portForwardingEnabled,
        bool isP2PServer,
        CancellationToken cancellationToken)
    {
        if (!MultiTunnelSlotRunner.IsValidSecondarySlotId(slotId))
        {
            return;
        }

        string normalizedId = slotId.Trim().ToUpperInvariant();
        await StopSlotCoreAsync(normalizedId).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        string clientCertPem = credentials.ClientCertPem;
        string? clientSecretPem = credentials.ClientKeyPair?.SecretKey?.Pem;
        PortMappingProtocolClient portMappingClient = new(
            _logger,
            new UdpClientWrapper(clientIpv4),
            _messageSerializerProxy,
            new FixedGatewayCache(gatewayIpv4),
            _issueReporter);

        SlotSession session = new(
            normalizedId,
            portMappingClient,
            portForwardingEnabled,
            isP2PServer,
            vpnConfig.NetShieldMode,
            vpnConfig.SplitTcp,
            vpnConfig.ModerateNat);

        portMappingClient.StateChanged += (_, e) => OnSlotNatPmpStateChanged(session, e.Data);

        lock (_lock)
        {
            _sessions[normalizedId] = session;
        }

        RaiseStateChanged(session);

        try
        {
            if (string.IsNullOrWhiteSpace(clientCertPem) || string.IsNullOrWhiteSpace(clientSecretPem))
            {
                throw new InvalidOperationException("Missing LocalAgent certificate/key.");
            }

            string? exePath = _staticConfig.ServiceExePath;

            if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
            {
                throw new FileNotFoundException("Service executable not found for LocalAgent worker.");
            }

            ProcessStartInfo psi = new()
            {
                FileName = exePath,
                Arguments = "--local-agent-worker",
                WorkingDirectory = AppContext.BaseDirectory,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            Process? process = Process.Start(psi);
            if (process is null)
            {
                throw new InvalidOperationException("Failed to launch LocalAgent worker process.");
            }

            session.WorkerProcess = process;
            // Drain stderr so a native failure cannot fill its pipe and stall the worker.
            process.ErrorDataReceived += (_, _) => { };
            process.BeginErrorReadLine();
            session.ReadLoopTask = Task.Run(() => ReadWorkerOutputAsync(session), CancellationToken.None);

            string connectJson = JsonSerializer.Serialize(new
            {
                cmd = "connect",
                clientCertPem,
                clientKeyPem = clientSecretPem,
                host = $"{gatewayIpv4}:{LOCAL_AGENT_PORT}",
                certServerName = endpoint.Name,
                bouncing = endpoint.Label ?? string.Empty,
                splitTcp = vpnConfig.SplitTcp,
                netShieldLevel = vpnConfig.NetShieldMode,
                portForwarding = portForwardingEnabled,
                moderateNat = vpnConfig.ModerateNat,
            });

            await session.WriteCommandAsync(connectJson).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.Error<LocalAgentLog>($"MultiTunnelSlotPF[{normalizedId}]: Failed to start LocalAgent worker.", ex);
            await HandleWorkerFailureAsync(session).ConfigureAwait(false);
        }
    }

    public async Task UpdateSlotFeaturesAsync(
        string slotId,
        bool portForwardingEnabled,
        int netShieldMode,
        bool splitTcp,
        bool moderateNat)
    {
        await _lifecycleLock.WaitAsync().ConfigureAwait(false);
        try
        {
            await UpdateSlotFeaturesCoreAsync(slotId, portForwardingEnabled, netShieldMode, splitTcp, moderateNat).ConfigureAwait(false);
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    private async Task UpdateSlotFeaturesCoreAsync(
        string slotId,
        bool portForwardingEnabled,
        int netShieldMode,
        bool splitTcp,
        bool moderateNat)
    {
        if (string.IsNullOrWhiteSpace(slotId))
        {
            return;
        }

        string normalizedId = slotId.Trim().ToUpperInvariant();
        SlotSession? session;
        lock (_lock)
        {
            _sessions.TryGetValue(normalizedId, out session);
        }

        if (session is null)
        {
            return;
        }

        bool pfChanged = session.PortForwardingEnabled != portForwardingEnabled;
        session.PortForwardingEnabled = portForwardingEnabled;
        session.NetShieldMode = netShieldMode;
        session.SplitTcp = splitTcp;
        session.ModerateNat = moderateNat;

        if (!portForwardingEnabled)
        {
            session.HasPortForwardingError = false;
            await session.PortMappingClient.StopAsync().ConfigureAwait(false);
            session.LastPortForwardingState = PortForwardingState.Default;
            RaiseStateChanged(session);
        }
        else if (pfChanged)
        {
            session.HasPortForwardingError = false;
        }

        string setFeaturesJson = JsonSerializer.Serialize(new
        {
            cmd = "set_features",
            splitTcp,
            netShieldLevel = netShieldMode,
            portForwarding = portForwardingEnabled,
            moderateNat,
        });

        try
        {
            await session.WriteCommandAsync(setFeaturesJson).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.Warn<LocalAgentLog>($"MultiTunnelSlotPF[{session.SlotId}]: Failed to update worker features: {ex.Message}");
            await HandleWorkerFailureAsync(session).ConfigureAwait(false);
            return;
        }

        if (portForwardingEnabled && session.IsLocalAgentConnected && !session.HasPortForwardingError)
        {
            session.PortMappingClient.StartAsync().FireAndForget();
        }
        else
        {
            RaiseStateChanged(session);
        }
    }

    public async Task StopSlotAsync(string slotId)
    {
        await _lifecycleLock.WaitAsync().ConfigureAwait(false);
        try
        {
            await StopSlotCoreAsync(slotId).ConfigureAwait(false);
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    private async Task StopSlotCoreAsync(string slotId)
    {
        if (string.IsNullOrWhiteSpace(slotId))
        {
            return;
        }

        string normalizedId = slotId.Trim().ToUpperInvariant();
        SlotSession? session;
        lock (_lock)
        {
            if (!_sessions.TryGetValue(normalizedId, out session))
            {
                return;
            }
            _sessions.Remove(normalizedId);
        }

        await DisposeSessionAsync(session).ConfigureAwait(false);
        session.LastPortForwardingState = PortForwardingState.Default;
        session.HasPortForwardingError = false;
        RaiseStateChanged(session);
    }

    public async Task StopAllAsync()
    {
        await _lifecycleLock.WaitAsync().ConfigureAwait(false);
        try
        {
            List<string> slotIds;
            lock (_lock)
            {
                slotIds = _sessions.Keys.ToList();
            }

            foreach (string slotId in slotIds)
            {
                await StopSlotCoreAsync(slotId).ConfigureAwait(false);
            }
        }
        finally
        {
            _lifecycleLock.Release();
        }
    }

    public MultiTunnelSlotPortForwardingState? GetSlotState(string slotId)
    {
        if (string.IsNullOrWhiteSpace(slotId))
        {
            return null;
        }

        lock (_lock)
        {
            return _sessions.TryGetValue(slotId.Trim().ToUpperInvariant(), out SlotSession? session)
                ? ToSnapshot(session)
                : null;
        }
    }

    public IReadOnlyList<MultiTunnelSlotPortForwardingState> GetAllSlotStates()
    {
        lock (_lock)
        {
            return _sessions.Values.Select(ToSnapshot).ToList();
        }
    }

    public void RepeatAllStates()
    {
        List<SlotSession> snapshot;
        lock (_lock)
        {
            snapshot = _sessions.Values.ToList();
        }

        foreach (SlotSession session in snapshot)
        {
            RaiseStateChanged(session);
        }
    }

    private async Task ReadWorkerOutputAsync(SlotSession session)
    {
        Process? process = session.WorkerProcess;
        if (process is null)
        {
            return;
        }

        try
        {
            while (!session.IsDisposed)
            {
                string? line = await process.StandardOutput.ReadLineAsync().ConfigureAwait(false);
                if (line is null)
                {
                    break;
                }

                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                await HandleWorkerLineAsync(session, line).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            if (!session.IsDisposed)
            {
                _logger.Debug<LocalAgentLog>($"MultiTunnelSlotPF[{session.SlotId}]: Worker stdout reader ended: {ex.Message}");
            }
        }
        finally
        {
            await HandleWorkerFailureAsync(session).ConfigureAwait(false);
        }
    }

    private async Task HandleWorkerFailureAsync(SlotSession session)
    {
        if (session.IsDisposed)
        {
            return;
        }

        session.IsLocalAgentConnected = false;
        await session.PortMappingClient.StopAsync().ConfigureAwait(false);
        if (session.IsDisposed)
        {
            return;
        }

        session.HasPortForwardingError = session.PortForwardingEnabled;
        session.LastPortForwardingState = new PortForwardingState
        {
            Status = session.PortForwardingEnabled ? PortMappingStatus.Error : PortMappingStatus.Stopped,
        };
        RaiseStateChanged(session);
    }

    private async Task HandleWorkerLineAsync(SlotSession session, string line)
    {
        if (session.IsDisposed)
        {
            return;
        }
        try
        {
            using JsonDocument doc = JsonDocument.Parse(line);
            if (!doc.RootElement.TryGetProperty("type", out JsonElement typeProp))
            {
                return;
            }

            string? type = typeProp.GetString();
            if (string.Equals(type, "connect_result", StringComparison.OrdinalIgnoreCase))
            {
                string? err = doc.RootElement.TryGetProperty("error", out JsonElement errProp) ? errProp.GetString() : null;
                if (!string.IsNullOrEmpty(err))
                {
                    _logger.Warn<LocalAgentLog>($"MultiTunnelSlotPF[{session.SlotId}]: LocalAgent Connect failed: {err}");
                    await HandleWorkerFailureAsync(session).ConfigureAwait(false);
                }
                else
                {
                    _logger.Info<LocalAgentLog>($"MultiTunnelSlotPF[{session.SlotId}]: LocalAgent TLS channel opened.");
                }
                return;
            }

            if (!string.Equals(type, "event", StringComparison.OrdinalIgnoreCase) ||
                !doc.RootElement.TryGetProperty("raw", out JsonElement rawProp))
            {
                return;
            }

            string? raw = rawProp.GetString();
            if (string.IsNullOrWhiteSpace(raw))
            {
                return;
            }

            LocalAgentEvent? ev = JsonSerializer.Deserialize<LocalAgentEvent>(raw, JsonOptions);
            if (ev is null)
            {
                return;
            }

            if (string.Equals(ev.EventType, "state", StringComparison.OrdinalIgnoreCase))
            {
                if (string.Equals(ev.State, "Connected", StringComparison.OrdinalIgnoreCase))
                {
                    session.IsLocalAgentConnected = true;
                    if (session.PortForwardingEnabled && !session.HasPortForwardingError && !session.IsDisposed)
                    {
                        _logger.Debug<ConnectLog>($"MultiTunnelSlotPF[{session.SlotId}]: Starting NAT-PMP client.");
                        session.PortMappingClient.StartAsync().FireAndForget();
                    }
                }
                else if (string.Equals(ev.State, "Disconnected", StringComparison.OrdinalIgnoreCase))
                {
                    session.IsLocalAgentConnected = false;
                    await session.PortMappingClient.StopAsync().ConfigureAwait(false);
                }
            }
            else if (string.Equals(ev.EventType, "error", StringComparison.OrdinalIgnoreCase))
            {
                _logger.Warn<LocalAgentLog>($"MultiTunnelSlotPF[{session.SlotId}]: LocalAgent error code {ev.Code}: {ev.Desc}");
                if (ev.Code == (int)VpnError.PortForwardingNotSupported)
                {
                    await session.PortMappingClient.StopAsync().ConfigureAwait(false);
                    if (session.IsDisposed)
                    {
                        return;
                    }
                    session.HasPortForwardingError = true;
                    session.LastPortForwardingState = new PortForwardingState
                    {
                        MappedPort = null,
                        Status = PortMappingStatus.Error,
                    };
                    RaiseStateChanged(session);
                }
            }
            else if (string.Equals(ev.EventType, "log", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(ev.Log))
            {
                _logger.Debug<LocalAgentLog>($"MultiTunnelSlotPF[{session.SlotId}]: {ev.Log}");
            }
        }
        catch (Exception ex)
        {
            _logger.Debug<LocalAgentLog>($"MultiTunnelSlotPF[{session.SlotId}]: Failed to parse worker message: {ex.Message}");
        }
    }

    private void OnSlotNatPmpStateChanged(SlotSession session, PortForwardingState state)
    {
        if (session.IsDisposed)
        {
            return;
        }

        session.LastPortForwardingState = state ?? PortForwardingState.Default;
        if (session.LastPortForwardingState.Status == PortMappingStatus.Error)
        {
            session.HasPortForwardingError = true;
        }
        else if (session.LastPortForwardingState.Status is PortMappingStatus.PortMappingCommunication or PortMappingStatus.SleepingUntilRefresh)
        {
            session.HasPortForwardingError = false;
        }

        RaiseStateChanged(session);
    }

    private void RaiseStateChanged(SlotSession session)
    {
        SlotStateChanged?.Invoke(this, ToSnapshot(session));
    }

    private static MultiTunnelSlotPortForwardingState ToSnapshot(SlotSession session)
    {
        return new MultiTunnelSlotPortForwardingState(
            SlotId: session.SlotId,
            PortForwardingEnabled: session.PortForwardingEnabled,
            IsP2PServer: session.IsP2PServer,
            HasPortForwardingError: session.HasPortForwardingError,
            State: session.LastPortForwardingState);
    }

    private static async Task DisposeSessionAsync(SlotSession session)
    {
        session.IsDisposed = true;

        try
        {
            await session.PortMappingClient.StopAsync().ConfigureAwait(false);
        }
        catch
        {
        }

        Process? proc = session.WorkerProcess;
        if (proc is not null)
        {
            try
            {
                await session.WriteCommandAsync("{\"cmd\":\"close\"}").ConfigureAwait(false);
                proc.StandardInput.Close();
            }
            catch
            {
            }

            try
            {
                using CancellationTokenSource waitCts = new(TimeSpan.FromMilliseconds(1500));
                await proc.WaitForExitAsync(waitCts.Token).ConfigureAwait(false);
            }
            catch
            {
                try
                {
                    if (!proc.HasExited)
                    {
                        proc.Kill(entireProcessTree: true);
                    }
                }
                catch
                {
                }
            }
            finally
            {
                proc.Dispose();
            }
        }
    }

    private sealed class FixedGatewayCache : IGatewayCache
    {
        private readonly IPAddress _gateway;

        public FixedGatewayCache(IPAddress gateway)
        {
            _gateway = gateway;
        }

        public void Save(IPAddress gatewayIPAddress) { }
        public void Clear() { }
        public IPAddress? Get() => _gateway;
    }

    private sealed class SlotSession
    {
        private readonly SemaphoreSlim _stdinLock = new(1, 1);

        public string SlotId { get; }
        public PortMappingProtocolClient PortMappingClient { get; }
        public bool PortForwardingEnabled { get; set; }
        public bool IsP2PServer { get; }
        public int NetShieldMode { get; set; }
        public bool SplitTcp { get; set; }
        public bool ModerateNat { get; set; }
        public bool IsLocalAgentConnected { get; set; }
        public bool HasPortForwardingError { get; set; }
        public bool IsDisposed { get; set; }
        public Process? WorkerProcess { get; set; }
        public Task? ReadLoopTask { get; set; }
        public PortForwardingState LastPortForwardingState { get; set; } = PortForwardingState.Default;

        public SlotSession(
            string slotId,
            PortMappingProtocolClient portMappingClient,
            bool portForwardingEnabled,
            bool isP2PServer,
            int netShieldMode,
            bool splitTcp,
            bool moderateNat)
        {
            SlotId = slotId;
            PortMappingClient = portMappingClient;
            PortForwardingEnabled = portForwardingEnabled;
            IsP2PServer = isP2PServer;
            NetShieldMode = netShieldMode;
            SplitTcp = splitTcp;
            ModerateNat = moderateNat;
        }

        public async Task WriteCommandAsync(string jsonLine)
        {
            Process? proc = WorkerProcess;
            if (proc is null || proc.HasExited)
            {
                throw new IOException("LocalAgent worker is unavailable.");
            }

            await _stdinLock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (proc.HasExited)
                {
                    throw new IOException("LocalAgent worker has exited.");
                }
                await proc.StandardInput.WriteLineAsync(jsonLine).ConfigureAwait(false);
                await proc.StandardInput.FlushAsync().ConfigureAwait(false);
            }
            finally
            {
                _stdinLock.Release();
            }
        }
    }
}
