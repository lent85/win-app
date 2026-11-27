/*
 * Copyright (c) 2023 Proton AG
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

using ProtonVPN.Client.EventMessaging.Contracts;
using ProtonVPN.Client.Logic.Connection.Contracts;
using ProtonVPN.Client.Logic.Connection.Contracts.Messages;
using ProtonVPN.Common.Legacy.PortForwarding;
using ProtonVPN.EntityMapping.Contracts;
using ProtonVPN.Logging.Contracts;
using ProtonVPN.Logging.Contracts.Events.AppLogs;
using ProtonVPN.ProcessCommunication.Contracts.Entities.PortForwarding;

namespace ProtonVPN.Client.Logic.Connection;

public class PortForwardingManager : IPortForwardingManager, IEventMessageReceiver<PortForwardingStateIpcEntity>
{
    private readonly IEventMessageSender _eventMessageSender;
    private readonly IEntityMapper _entityMapper;
    private readonly ILogger _logger;
    private readonly IConnectionManager _connectionManager;

    private readonly object _lock = new();
    private readonly Dictionary<string, int?> _portsBySlot = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, PortMappingStatus> _statusBySlot = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, bool> _hasErrorBySlot = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _lastPortChangeBySlot = new(StringComparer.OrdinalIgnoreCase);

    private DateTime _lastPortChangeTimeUtc;
    private int? _port;
    private PortMappingStatus _status;

    protected bool IsConnectedToP2PServer => _connectionManager.IsConnected && _connectionManager.CurrentConnectionDetails?.IsP2P == true;

    public bool IsFetchingPort =>
        IsConnectedToP2PServer &&
        _status is not PortMappingStatus.Stopped
               and not PortMappingStatus.Error
               and not PortMappingStatus.DestroyPortMappingCommunication;

    public bool HasError => _status is PortMappingStatus.Error;

    protected bool IsConnectedToNonP2PServer => _connectionManager.IsConnected && _connectionManager.CurrentConnectionDetails?.IsP2P != true;

    public int? ActivePort => IsConnectedToP2PServer && (_status is PortMappingStatus.PortMappingCommunication or PortMappingStatus.SleepingUntilRefresh)
            ? _port
            : null;

    public DateTime? LastPortChangeTimeUtc => ActivePort.HasValue ? _lastPortChangeTimeUtc : null;

    public IReadOnlyDictionary<string, SlotPortForwardingState> SlotStates
    {
        get
        {
            lock (_lock)
            {
                Dictionary<string, SlotPortForwardingState> result = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["T1"] = new SlotPortForwardingState(
                        "T1",
                        ActivePort,
                        _status,
                        IsFetchingPort,
                        HasError,
                        LastPortChangeTimeUtc)
                };

                foreach (string slotId in _statusBySlot.Keys.Union(_portsBySlot.Keys, StringComparer.OrdinalIgnoreCase))
                {
                    if (string.Equals(slotId, "T1", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    result[slotId] = BuildSecondarySlotStateLocked(slotId);
                }

                return result;
            }
        }
    }

    public PortForwardingManager(
        IEventMessageSender eventMessageSender,
        IEntityMapper entityMapper, 
        ILogger logger,
        IConnectionManager connectionManager)
    {
        _eventMessageSender = eventMessageSender;
        _entityMapper = entityMapper;
        _logger = logger;
        _connectionManager = connectionManager;
    }

    public SlotPortForwardingState? GetSlotState(string slotId)
    {
        if (string.IsNullOrWhiteSpace(slotId))
        {
            return null;
        }

        string normalized = slotId.Trim().ToUpperInvariant();
        if (string.Equals(normalized, "T1", StringComparison.OrdinalIgnoreCase))
        {
            return new SlotPortForwardingState(
                "T1",
                ActivePort,
                _status,
                IsFetchingPort,
                HasError,
                LastPortChangeTimeUtc);
        }

        lock (_lock)
        {
            if (!_statusBySlot.ContainsKey(normalized) && !_portsBySlot.ContainsKey(normalized))
            {
                return null;
            }

            return BuildSecondarySlotStateLocked(normalized);
        }
    }

    public int? GetActivePort(string slotId)
    {
        return GetSlotState(slotId)?.ActivePort;
    }

    public void Receive(PortForwardingStateIpcEntity message)
    {
        PortForwardingState portForwardingState = _entityMapper.Map<PortForwardingStateIpcEntity, PortForwardingState>(message);
        string slotId = string.IsNullOrWhiteSpace(message.SlotId) ? "T1" : message.SlotId.Trim().ToUpperInvariant();

        int? newPort = portForwardingState.MappedPort?.MappedPort?.ExternalPort;
        PortMappingStatus newStatus = portForwardingState.Status;

        if (string.Equals(slotId, "T1", StringComparison.OrdinalIgnoreCase))
        {
            bool primaryPortChanged;
            bool primaryStatusChanged;
            lock (_lock)
            {
                primaryPortChanged = _port != newPort;
                primaryStatusChanged = _status != newStatus;
                _port = newPort;
                _status = newStatus;
                if (primaryPortChanged)
                {
                    _lastPortChangeTimeUtc = DateTime.UtcNow;
                }
            }

            // Receivers query the manager synchronously, so publish only after the full state is saved.
            if (primaryPortChanged)
            {
                _logger.Info<AppLog>($"Port forwarding port changed to '{newPort}'.");
                NotifyPortChange(newPort, "T1");
            }

            if (primaryStatusChanged)
            {
                _logger.Info<AppLog>($"Port forwarding status changed to '{newStatus}'.");
                NotifyStatusChange(newStatus, "T1");
            }

            return;
        }

        bool portChanged;
        bool statusChanged;
        lock (_lock)
        {
            _portsBySlot.TryGetValue(slotId, out int? prevPort);
            portChanged = prevPort != newPort;
            if (portChanged)
            {
                _portsBySlot[slotId] = newPort;
                _lastPortChangeBySlot[slotId] = DateTime.UtcNow;
            }

            _statusBySlot.TryGetValue(slotId, out PortMappingStatus prevStatus);
            _hasErrorBySlot.TryGetValue(slotId, out bool previousError);
            bool hasError = message.HasPortForwardingError || newStatus == PortMappingStatus.Error;
            statusChanged = !_statusBySlot.ContainsKey(slotId) || prevStatus != newStatus || previousError != hasError;
            _statusBySlot[slotId] = newStatus;
            _hasErrorBySlot[slotId] = hasError;
        }

        if (portChanged)
        {
            _logger.Info<AppLog>($"Port forwarding [{slotId}] port changed to '{newPort}'.");
            NotifyPortChange(newPort, slotId);
        }

        if (statusChanged)
        {
            _logger.Info<AppLog>($"Port forwarding [{slotId}] status changed to '{newStatus}'.");
            NotifyStatusChange(newStatus, slotId);
        }
    }

    private SlotPortForwardingState BuildSecondarySlotStateLocked(string slotId)
    {
        _portsBySlot.TryGetValue(slotId, out int? rawPort);
        _statusBySlot.TryGetValue(slotId, out PortMappingStatus status);
        _hasErrorBySlot.TryGetValue(slotId, out bool hasExplicitError);
        _lastPortChangeBySlot.TryGetValue(slotId, out DateTime lastChange);

        int? activePort = status is PortMappingStatus.PortMappingCommunication or PortMappingStatus.SleepingUntilRefresh
            ? rawPort
            : null;
        bool isFetching = status is not PortMappingStatus.Stopped
            and not PortMappingStatus.Error
            and not PortMappingStatus.DestroyPortMappingCommunication;
        bool hasError = hasExplicitError || status is PortMappingStatus.Error;

        return new SlotPortForwardingState(
            slotId,
            activePort,
            status,
            isFetching,
            hasError,
            activePort.HasValue && lastChange != default ? lastChange : null);
    }

    private void NotifyPortChange(int? newPort, string slotId)
    {
        _eventMessageSender.Send(new PortForwardingPortChangedMessage(newPort, slotId));
    }

    private void NotifyStatusChange(PortMappingStatus newStatus, string slotId)
    {
        _eventMessageSender.Send(new PortForwardingStatusChangedMessage(newStatus, slotId));
    }
}
