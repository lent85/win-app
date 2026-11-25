/*
 * Copyright (c) 2025 Proton AG
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
using Microsoft.UI.Xaml.Media;
using ProtonVPN.Client.Common.Enums;
using ProtonVPN.Client.Common.Helpers;
using ProtonVPN.Client.Contracts.Messages;
using ProtonVPN.Client.Core.Bases;
using ProtonVPN.Client.Core.Bases.ViewModels;
using ProtonVPN.Client.Core.Services.Activation;
using ProtonVPN.Client.EventMessaging.Contracts;
using ProtonVPN.Client.Localization.Extensions;
using ProtonVPN.Client.Logic.Connection.Contracts.History;
using ProtonVPN.Client.Logic.Connection.Contracts.Messages;
using ProtonVPN.Client.Logic.Connection.Contracts.MultiTunnel;
using ProtonVPN.Common.Core.Networking;

namespace ProtonVPN.Client.UI.Main.Home.Details.Connection;

public sealed class SlotTrafficLegendItem
{
    public required string SlotId { get; init; }
    public required string Label { get; init; }
    public required SolidColorBrush ColorBrush { get; init; }
    public required string DownloadText { get; init; }
    public required string UploadText { get; init; }
}

public partial class SpeedChartComponentViewModel : ActivatableViewModelBase,
    IEventMessageReceiver<NetworkTrafficChangedMessage>,
    IEventMessageReceiver<MultiTunnelTrafficChangedMessage>,
    IEventMessageReceiver<MultiTunnelPolicyChangedMessage>,
    IEventMessageReceiver<MainWindowVisibilityChangedMessage>
{
    private const double Y_AXIS_BUFFER = 1.1;

    private readonly INetworkTrafficManager _networkTrafficManager;
    private readonly IMultiTunnelManager _multiTunnelManager;
    private readonly IMultiTunnelTrafficManager _multiTunnelTrafficManager;
    private readonly IMainWindowActivator _mainWindowActivator;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FormattedDownloadSpeed))]
    private long _downloadSpeed;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FormattedUploadSpeed))]
    private long _uploadSpeed;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FormattedDownloadVolume))]
    [NotifyPropertyChangedFor(nameof(FormattedTotalVolume))]
    private long _downloadVolume;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FormattedUploadVolume))]
    [NotifyPropertyChangedFor(nameof(FormattedTotalVolume))]
    private long _uploadVolume;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(SpeedUnit))]
    private ByteMetrics _metric;

    public string FormattedDownloadSpeed => Localizer.GetFormattedSpeed(DownloadSpeed);

    public string FormattedUploadSpeed => Localizer.GetFormattedSpeed(UploadSpeed);

    public string FormattedDownloadVolume => Localizer.GetFormattedSize(DownloadVolume);

    public string FormattedUploadVolume => Localizer.GetFormattedSize(UploadVolume);

    public string FormattedTotalVolume => Localizer.GetFormattedSize(DownloadVolume + UploadVolume);

    public string SpeedUnit => Localizer.GetFormat("Format_SpeedUnit", Localizer.GetSpeedUnit(Metric));

    [ObservableProperty]
    private IReadOnlyList<double> _downloadSpeedHistory = [];

    [ObservableProperty]
    private IReadOnlyList<double> _uploadSpeedHistory = [];

    [ObservableProperty]
    private IReadOnlyList<SlotSpeedChartSeries> _slotSeries = [];

    [ObservableProperty]
    private bool _isMultiTunnelChartActive;

    public ObservableCollection<SlotTrafficLegendItem> SlotLegends { get; } = [];

    [ObservableProperty]
    private double _lowerBound;

    [ObservableProperty]
    private double _midpoint;

    [ObservableProperty]
    private double _upperBound;

    public SpeedChartComponentViewModel(
        INetworkTrafficManager networkTrafficManager,
        IMultiTunnelManager multiTunnelManager,
        IMultiTunnelTrafficManager multiTunnelTrafficManager,
        IMainWindowActivator mainWindowActivator,
        IViewModelHelper viewModelHelper)
        : base(viewModelHelper)
    {
        _networkTrafficManager = networkTrafficManager;
        _multiTunnelManager = multiTunnelManager;
        _multiTunnelTrafficManager = multiTunnelTrafficManager;
        _mainWindowActivator = mainWindowActivator;
    }

    public void Receive(NetworkTrafficChangedMessage message)
    {
        ExecuteOnUIThread(InvalidateAll);
    }

    public void Receive(MultiTunnelTrafficChangedMessage message)
    {
        ExecuteOnUIThread(InvalidateAll);
    }

    public void Receive(MultiTunnelPolicyChangedMessage message)
    {
        ExecuteOnUIThread(InvalidateAll);
    }

    public void Receive(MainWindowVisibilityChangedMessage message)
    {
        ExecuteOnUIThread(InvalidateAll);
    }

    protected override void OnActivated()
    {
        base.OnActivated();

        InvalidateAll();
    }

    protected override void OnLanguageChanged()
    {
        base.OnLanguageChanged();

        OnPropertyChanged(nameof(FormattedDownloadSpeed));
        OnPropertyChanged(nameof(FormattedUploadSpeed));
        OnPropertyChanged(nameof(FormattedDownloadVolume));
        OnPropertyChanged(nameof(FormattedUploadVolume));
        OnPropertyChanged(nameof(FormattedTotalVolume));
        OnPropertyChanged(nameof(SpeedUnit));
    }

    private void InvalidateAll()
    {
        if (!IsActive || !_mainWindowActivator.IsWindowVisible)
        {
            return;
        }

        IReadOnlyList<SlotTrafficSnapshot> connectedSlots = _multiTunnelManager.IsEnabled
            ? _multiTunnelTrafficManager.GetConnectedSlotTraffics()
            : [];

        if (connectedSlots.Count > 0)
        {
            IsMultiTunnelChartActive = true;
            InvalidateMultiTunnelChart(connectedSlots);
            return;
        }

        IsMultiTunnelChartActive = false;
        SlotSeries = [];
        SlotLegends.Clear();

        NetworkTraffic speed = _networkTrafficManager.GetSpeed();
        NetworkTraffic volume = _networkTrafficManager.GetVolume();

        DownloadSpeed = (long)speed.BytesDownloaded;
        UploadSpeed = (long)speed.BytesUploaded;

        DownloadVolume = (long)volume.BytesDownloaded;
        UploadVolume = (long)volume.BytesUploaded;

        InvalidateSpeedGraph();
    }

    private void InvalidateMultiTunnelChart(IReadOnlyList<SlotTrafficSnapshot> connectedSlots)
    {
        string selectedSlotId = _multiTunnelTrafficManager.SelectedMetricsSlotId;
        bool isAll = string.Equals(selectedSlotId, "ALL", StringComparison.OrdinalIgnoreCase);

        IReadOnlyList<SlotTrafficSnapshot> displayedSlots = isAll
            ? connectedSlots
            : connectedSlots.Where(s => string.Equals(s.SlotId, selectedSlotId, StringComparison.OrdinalIgnoreCase)).ToList();

        if (displayedSlots.Count == 0)
        {
            displayedSlots = connectedSlots;
            isAll = true;
        }

        if (isAll)
        {
            NetworkTraffic totalSpeed = _multiTunnelTrafficManager.GetTotalSpeed();
            NetworkTraffic totalVolume = _multiTunnelTrafficManager.GetTotalVolume();
            DownloadSpeed = (long)totalSpeed.BytesDownloaded;
            UploadSpeed = (long)totalSpeed.BytesUploaded;
            DownloadVolume = (long)totalVolume.BytesDownloaded;
            UploadVolume = (long)totalVolume.BytesUploaded;
        }
        else
        {
            SlotTrafficSnapshot selected = displayedSlots[0];
            DownloadSpeed = (long)selected.Speed.BytesDownloaded;
            UploadSpeed = (long)selected.Speed.BytesUploaded;
            DownloadVolume = (long)selected.Volume.BytesDownloaded;
            UploadVolume = (long)selected.Volume.BytesUploaded;
        }

        long maxSpeed = 0;
        foreach (SlotTrafficSnapshot slot in displayedSlots)
        {
            foreach (NetworkTraffic point in slot.SpeedHistory)
            {
                if ((long)point.BytesDownloaded > maxSpeed)
                {
                    maxSpeed = (long)point.BytesDownloaded;
                }
                if ((long)point.BytesUploaded > maxSpeed)
                {
                    maxSpeed = (long)point.BytesUploaded;
                }
            }
        }

        (double scaledMaxSpeed, ByteMetrics metric) = ByteConversionHelper.CalculateSize(maxSpeed);
        Metric = metric;
        double scaleFactor = ByteConversionHelper.GetScaleFactor(Metric);
        double roundedScaledMaxSpeed = CalculateYAxisLimit(scaledMaxSpeed);

        LowerBound = 0.0;
        Midpoint = roundedScaledMaxSpeed / 2.0;
        UpperBound = roundedScaledMaxSpeed;

        List<SlotSpeedChartSeries> seriesList = [];
        SlotLegends.Clear();

        foreach (SlotTrafficSnapshot slot in displayedSlots)
        {
            IReadOnlyList<double> dl = slot.SpeedHistory.Select(nt => GetScaledDataPoint((long)nt.BytesDownloaded, scaleFactor)).ToList();
            IReadOnlyList<double> ul = slot.SpeedHistory.Select(nt => GetScaledDataPoint((long)nt.BytesUploaded, scaleFactor)).ToList();
            seriesList.Add(new SlotSpeedChartSeries(slot.SlotId, slot.ColorHex, dl, ul));

            string countryTag = string.IsNullOrWhiteSpace(slot.CountryCode) ? slot.SlotId : $"{slot.SlotId}·{slot.CountryCode}";
            SlotLegends.Add(new SlotTrafficLegendItem
            {
                SlotId = slot.SlotId,
                Label = countryTag,
                ColorBrush = SlotColorBrushHelper.ToBrush(slot.ColorHex),
                DownloadText = $"↓ {Localizer.GetFormattedSpeed((long)slot.Speed.BytesDownloaded)}",
                UploadText = $"↑ {Localizer.GetFormattedSpeed((long)slot.Speed.BytesUploaded)}",
            });
        }

        SlotSeries = seriesList;
        DownloadSpeedHistory = [];
        UploadSpeedHistory = [];
    }

    private void InvalidateSpeedGraph()
    {
        IReadOnlyList<NetworkTraffic> speedHistory = _networkTrafficManager.GetSpeedHistory();
        IEnumerable<long> downloadHistory = speedHistory.Select(nt => (long)nt.BytesDownloaded);
        IEnumerable<long> uploadHistory = speedHistory.Select(nt => (long)nt.BytesUploaded);

        long maxSpeed = Math.Max(downloadHistory.DefaultIfEmpty(0).Max(), uploadHistory.DefaultIfEmpty(0).Max());
        (double scaledMaxSpeed, ByteMetrics metric) = ByteConversionHelper.CalculateSize(maxSpeed);

        Metric = metric;
        double scaleFactor = ByteConversionHelper.GetScaleFactor(Metric);

        double roundedScaledMaxSpeed = CalculateYAxisLimit(scaledMaxSpeed);

        LowerBound = 0.0;
        Midpoint = roundedScaledMaxSpeed / 2.0;
        UpperBound = roundedScaledMaxSpeed;

        DownloadSpeedHistory = downloadHistory.Select(n => GetScaledDataPoint(n, scaleFactor)).ToList();
        UploadSpeedHistory = uploadHistory.Select(n => GetScaledDataPoint(n, scaleFactor)).ToList();
    }

    private double GetScaledDataPoint(long number, double scaleFactor)
    {
        return Math.Round(number / scaleFactor, 1);
    }

    private double CalculateYAxisLimit(double maxValue)
    {
        if (maxValue <= 0)
        {
            return 10;
        }

        maxValue *= Y_AXIS_BUFFER;

        double roundedLimit;

        if (maxValue < 1)
        {
            roundedLimit = Math.Ceiling(maxValue * 5) / 5;
        }
        else if (maxValue <= 5)
        {
            roundedLimit = Math.Ceiling(maxValue);
        }
        else if (maxValue <= 20)
        {
            roundedLimit = Math.Ceiling(maxValue / 2) * 2;
        }
        else
        {
            double scale = Math.Pow(10, Math.Floor(Math.Log10(maxValue)));
            roundedLimit = Math.Ceiling(maxValue / scale) * scale;
        }

        return roundedLimit;
    }
}
