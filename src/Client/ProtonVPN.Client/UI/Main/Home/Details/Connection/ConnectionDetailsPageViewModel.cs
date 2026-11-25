/*
 * Copyright (c) 2024 Proton AG
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

using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using ProtonVPN.Client.Core.Bases;
using ProtonVPN.Client.Core.Bases.ViewModels;
using ProtonVPN.Client.Core.Services.Navigation;
using ProtonVPN.Client.EventMessaging.Contracts;
using ProtonVPN.Client.Localization.Extensions;
using ProtonVPN.Client.Logic.Connection.Contracts;
using ProtonVPN.Client.Logic.Connection.Contracts.History;
using ProtonVPN.Client.Logic.Connection.Contracts.Messages;
using ProtonVPN.Client.Logic.Connection.Contracts.Models;
using ProtonVPN.Client.Logic.Connection.Contracts.MultiTunnel;
using ProtonVPN.Client.Settings.Contracts;
using ProtonVPN.Common.Core.Networking;

namespace ProtonVPN.Client.UI.Main.Home.Details.Connection;

public sealed class ConnectionMetricSlotTab
{
    public required string SlotId { get; init; }
    public required string Label { get; init; }
    public required SolidColorBrush DotBrush { get; init; }
    public required bool ShowDot { get; init; }
    public required bool IsSelected { get; init; }
    public Thickness SelectedBorderThickness => IsSelected ? new Thickness(2) : new Thickness(1);
}

public partial class ConnectionDetailsPageViewModel : PageViewModelBase<IDetailsViewNavigator>,
    IEventMessageReceiver<ConnectionDetailsChangedMessage>,
    IEventMessageReceiver<NetworkTrafficChangedMessage>,
    IEventMessageReceiver<MultiTunnelTrafficChangedMessage>,
    IEventMessageReceiver<MultiTunnelPolicyChangedMessage>
{
    private readonly ISettings _settings;
    private readonly IConnectionManager _connectionManager;
    private readonly INetworkTrafficManager _networkTrafficManager;
    private readonly IMultiTunnelManager _multiTunnelManager;
    private readonly IMultiTunnelTrafficManager _multiTunnelTrafficManager;

    [ObservableProperty]
    private string? _serverIpAddress;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FormattedVolume))]
    private long? _volume;

    [ObservableProperty]
    private double _serverLoad;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FormattedProtocol))]
    private VpnProtocol? _protocol;

    [ObservableProperty]
    private string? _protocolOverrideText;

    [ObservableProperty]
    private bool _isMultiTunnelMetricsBarVisible;

    public ObservableCollection<ConnectionMetricSlotTab> MetricSlotTabs { get; } = [];

    public string FormattedVolume => Localizer.GetFormattedSize(Volume);

    public string FormattedProtocol => string.IsNullOrWhiteSpace(ProtocolOverrideText)
        ? Localizer.GetVpnProtocol(Protocol)
        : ProtocolOverrideText;

    public ConnectionDetailsPageViewModel(
        ISettings settings,
        IConnectionManager connectionManager,
        INetworkTrafficManager networkTrafficManager,
        IMultiTunnelManager multiTunnelManager,
        IMultiTunnelTrafficManager multiTunnelTrafficManager,
        IDetailsViewNavigator viewNavigator,
        IViewModelHelper viewModelHelper)
        : base(viewNavigator, viewModelHelper)
    {
        _settings = settings;
        _connectionManager = connectionManager;
        _networkTrafficManager = networkTrafficManager;
        _multiTunnelManager = multiTunnelManager;
        _multiTunnelTrafficManager = multiTunnelTrafficManager;
    }

    public void Receive(ConnectionDetailsChangedMessage message)
    {
        if (IsActive)
        {
            ExecuteOnUIThread(SetDetails);
        }
    }

    public void Receive(NetworkTrafficChangedMessage message)
    {
        if (IsActive)
        {
            ExecuteOnUIThread(SetDetails);
        }
    }

    public void Receive(MultiTunnelTrafficChangedMessage message)
    {
        if (IsActive)
        {
            ExecuteOnUIThread(SetDetails);
        }
    }

    public void Receive(MultiTunnelPolicyChangedMessage message)
    {
        if (IsActive)
        {
            ExecuteOnUIThread(SetDetails);
        }
    }

    public void SelectMetricSlot(string slotId)
    {
        _multiTunnelTrafficManager.SelectMetricsSlot(slotId);
        SetDetails();
    }

    protected override void OnLanguageChanged()
    {
        base.OnLanguageChanged();

        OnPropertyChanged(nameof(FormattedVolume));
        OnPropertyChanged(nameof(FormattedProtocol));
    }

    protected override void OnActivated()
    {
        base.OnActivated();

        SetDetails();
    }

    partial void OnProtocolOverrideTextChanged(string? value)
    {
        OnPropertyChanged(nameof(FormattedProtocol));
    }

    private void SetDetails()
    {
        List<MultiTunnelSlotConfig> connectedSlots = _multiTunnelManager.IsEnabled
            ? _multiTunnelManager.Slots.Where(s => s.IsConnected).OrderBy(s => s.SlotIndex).ToList()
            : [];

        IsMultiTunnelMetricsBarVisible = connectedSlots.Count > 0;

        if (!IsMultiTunnelMetricsBarVisible)
        {
            MetricSlotTabs.Clear();
            ProtocolOverrideText = null;
            ConnectionDetails? details = _connectionManager.CurrentConnectionDetails;
            ServerIpAddress = EmptyValueExtensions.GetValueOrDefault(details?.ServerIpAddress?.Ipv4Address);
            ServerLoad = details?.ServerLoad ?? 0;
            Protocol = details?.Protocol;
            Volume = (long)_networkTrafficManager.GetVolume().Sum();
            return;
        }

        string selectedSlotId = _multiTunnelTrafficManager.SelectedMetricsSlotId;
        if (!string.Equals(selectedSlotId, "ALL", StringComparison.OrdinalIgnoreCase) &&
            !connectedSlots.Any(s => string.Equals(s.SlotId, selectedSlotId, StringComparison.OrdinalIgnoreCase)))
        {
            selectedSlotId = "ALL";
        }

        MetricSlotTabs.Clear();
        MetricSlotTabs.Add(new ConnectionMetricSlotTab
        {
            SlotId = "ALL",
            Label = $"All ({connectedSlots.Count})",
            DotBrush = SlotColorBrushHelper.ToBrush("#FFFFFF"),
            ShowDot = false,
            IsSelected = string.Equals(selectedSlotId, "ALL", StringComparison.OrdinalIgnoreCase),
        });

        foreach (MultiTunnelSlotConfig slot in connectedSlots)
        {
            string label = string.IsNullOrWhiteSpace(slot.CountryCode)
                ? slot.SlotId
                : $"{slot.SlotId} · {slot.CountryCode}";

            MetricSlotTabs.Add(new ConnectionMetricSlotTab
            {
                SlotId = slot.SlotId,
                Label = label,
                DotBrush = SlotColorBrushHelper.ToBrush(MultiTunnelSlotConfig.GetSlotColorHex(slot.SlotId)),
                ShowDot = true,
                IsSelected = string.Equals(selectedSlotId, slot.SlotId, StringComparison.OrdinalIgnoreCase),
            });
        }

        if (string.Equals(selectedSlotId, "ALL", StringComparison.OrdinalIgnoreCase))
        {
            ProtocolOverrideText = $"WireGuard ({connectedSlots.Count}x)";
            ServerIpAddress = string.Join(", ", connectedSlots
                .Select(s => string.IsNullOrWhiteSpace(s.ExitIp) ? s.EntryIp : s.ExitIp)
                .Where(ip => !string.IsNullOrWhiteSpace(ip)));
            if (string.IsNullOrWhiteSpace(ServerIpAddress))
            {
                ServerIpAddress = EmptyValueExtensions.GetValueOrDefault(_connectionManager.CurrentConnectionDetails?.ServerIpAddress?.Ipv4Address);
            }
            ServerLoad = _connectionManager.CurrentConnectionDetails?.ServerLoad ?? 0;
            Protocol = _connectionManager.CurrentConnectionDetails?.Protocol ?? VpnProtocol.WireGuardUdp;
            Volume = (long)_multiTunnelTrafficManager.GetTotalVolume().Sum();
            return;
        }

        MultiTunnelSlotConfig selectedSlot = connectedSlots.First(s =>
            string.Equals(s.SlotId, selectedSlotId, StringComparison.OrdinalIgnoreCase));
        SlotTrafficSnapshot? slotTraffic = _multiTunnelTrafficManager.GetSlotTraffic(selectedSlot.SlotId);

        if (string.Equals(selectedSlot.SlotId, "T1", StringComparison.OrdinalIgnoreCase))
        {
            ProtocolOverrideText = null;
            ConnectionDetails? details = _connectionManager.CurrentConnectionDetails;
            ServerIpAddress = EmptyValueExtensions.GetValueOrDefault(details?.ServerIpAddress?.Ipv4Address);
            ServerLoad = details?.ServerLoad ?? 0;
            Protocol = details?.Protocol;
            Volume = (long)(slotTraffic?.Volume.Sum() ?? _networkTrafficManager.GetVolume().Sum());
        }
        else
        {
            ProtocolOverrideText = $"{selectedSlot.SlotId} · WireGuard";
            string ip = !string.IsNullOrWhiteSpace(selectedSlot.ExitIp) ? selectedSlot.ExitIp : selectedSlot.EntryIp;
            ServerIpAddress = string.IsNullOrWhiteSpace(ip) ? selectedSlot.ClientIpv4 : ip;
            ServerLoad = 0;
            Protocol = VpnProtocol.WireGuardUdp;
            Volume = (long)(slotTraffic?.Volume.Sum() ?? 0);
        }
    }
}
