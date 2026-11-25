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

using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.Input;
using ProtonVPN.Client.Contracts.Profiles;
using ProtonVPN.Client.Core.Bases;
using ProtonVPN.Client.Core.Bases.ViewModels;
using ProtonVPN.Client.Core.Enums;
using ProtonVPN.Client.Core.Services.Activation;
using ProtonVPN.Client.Core.Services.Navigation;
using ProtonVPN.Client.EventMessaging.Contracts;
using ProtonVPN.Client.Localization.Extensions;
using ProtonVPN.Client.Logic.Connection.Contracts;
using ProtonVPN.Client.Logic.Connection.Contracts.Models.Intents;
using ProtonVPN.Client.Logic.Connection.Contracts.Models.Intents.Locations.Countries;
using ProtonVPN.Client.Logic.Connection.Contracts.MultiTunnel;
using ProtonVPN.Client.Settings.Contracts;
using ProtonVPN.Client.Settings.Contracts.Conflicts.Bases;
using ProtonVPN.Client.Settings.Contracts.RequiredReconnections;
using ProtonVPN.Client.UI.Main.Features.Bases;
using ProtonVPN.Client.UI.Main.Settings.Pages.Connection;
using ProtonVPN.ProcessCommunication.Contracts.Entities.MultiTunnel;
using ProtonVPN.StatisticalEvents.Contracts.Dimensions;

namespace ProtonVPN.Client.UI.Main.Features.MultiTunnel;

public partial class MultiTunnelWidgetViewModel : FeatureWidgetViewModelBase,
    IEventMessageReceiver<MultiTunnelPolicyChangedMessage>
{
    private readonly IMultiTunnelManager _multiTunnelManager;
    private bool _isRefreshing;
    private bool _isMultiTunnelEnabled;
    private string? _selectedDefaultTargetType = "Direct";
    private string? _selectedDefaultTunnelId = "T1";

    public override string Header => "Multi-Tunnel";

    public override bool IsRestricted => false;

    public bool IsMultiTunnelEnabled
    {
        get => _isMultiTunnelEnabled;
        set
        {
            if (SetProperty(ref _isMultiTunnelEnabled, value) && !_isRefreshing)
            {
                _ = _multiTunnelManager.SetEnabledAsync(value);
            }
        }
    }

    public string? SelectedDefaultTargetType
    {
        get => _selectedDefaultTargetType;
        set
        {
            if (SetProperty(ref _selectedDefaultTargetType, value))
            {
                OnPropertyChanged(nameof(IsDefaultTargetTunnel));
                if (!_isRefreshing && !string.IsNullOrWhiteSpace(value) &&
                    Enum.TryParse(value, out RuleTargetTypeIpcEntity target))
                {
                    _ = _multiTunnelManager.SetDefaultRoutingAsync(target, SelectedDefaultTunnelId ?? "T1");
                }
            }
        }
    }

    public string? SelectedDefaultTunnelId
    {
        get => _selectedDefaultTunnelId;
        set
        {
            if (SetProperty(ref _selectedDefaultTunnelId, value) &&
                !_isRefreshing &&
                !string.IsNullOrWhiteSpace(value) &&
                Enum.TryParse(SelectedDefaultTargetType, out RuleTargetTypeIpcEntity target))
            {
                _ = _multiTunnelManager.SetDefaultRoutingAsync(target, value);
            }
        }
    }

    public bool IsDefaultTargetTunnel =>
        string.Equals(SelectedDefaultTargetType, "Tunnel", StringComparison.OrdinalIgnoreCase);

    public string SummaryText =>
        $"{_multiTunnelManager.ConnectedSlotCount}/{_multiTunnelManager.Slots.Count} slots  •  " +
        $"{_multiTunnelManager.EnabledRuleCount}/{_multiTunnelManager.Rules.Count} rules";

    public IReadOnlyList<string> TargetTypeOptions { get; } = ["Direct", "Tunnel", "Block"];
    public IReadOnlyList<string> SlotIdOptions { get; } = ["T1", "T2", "T3", "T4", "T5"];
    public ObservableCollection<MultiTunnelSlotItem> Slots { get; } = [];

    public MultiTunnelWidgetViewModel(
        IViewModelHelper viewModelHelper,
        IMainViewNavigator mainViewNavigator,
        ISettingsViewNavigator settingsViewNavigator,
        IMainWindowOverlayActivator mainWindowOverlayActivator,
        ISettings settings,
        IConnectionManager connectionManager,
        IUpsellCarouselWindowActivator upsellCarouselWindowActivator,
        IRequiredReconnectionSettings requiredReconnectionSettings,
        ISettingsConflictResolver settingsConflictResolver,
        IProfileEditor profileEditor,
        IMultiTunnelManager multiTunnelManager)
        : base(viewModelHelper,
               mainViewNavigator,
               settingsViewNavigator,
               mainWindowOverlayActivator,
               settings,
               connectionManager,
               upsellCarouselWindowActivator,
               requiredReconnectionSettings,
               settingsConflictResolver,
               profileEditor,
               ConnectionFeature.MultiTunnel)
    {
        _multiTunnelManager = multiTunnelManager;
    }

    public void Receive(MultiTunnelPolicyChangedMessage message)
    {
        ExecuteOnUIThread(RefreshState);
    }

    protected override void OnActivated()
    {
        base.OnActivated();
        RefreshState();
    }

    protected override void OnFeatureFlyoutOpened()
    {
        base.OnFeatureFlyoutOpened();
        RefreshState();
    }

    protected override IEnumerable<string> GetSettingsChangedForUpdate()
    {
        yield return nameof(ISettings.IsMultiTunnelEnabled);
        yield return nameof(ISettings.MultiTunnelPolicyJson);
    }

    protected override string GetFeatureStatus()
    {
        return _multiTunnelManager.IsEnabled
            ? $"On ({_multiTunnelManager.Slots.Count}/5)"
            : "Off";
    }

    protected override bool IsOnFeaturePage(PageViewModelBase? currentPageContext)
    {
        return currentPageContext is MultiTunnelPageViewModel;
    }

    protected override void OnSettingsChanged()
    {
        RefreshState();
    }

    protected override void OnConnectionStatusChanged()
    {
        RefreshState();
    }

    [RelayCommand]
    private async Task OpenFullSettingsAsync()
    {
        await InvokeAsync();
    }

    public async Task ConnectSlotAsync(string slotId)
    {
        MultiTunnelSlotConfig? slot = _multiTunnelManager.Slots.FirstOrDefault(s =>
            string.Equals(s.SlotId, slotId, StringComparison.OrdinalIgnoreCase));
        if (slot is null || string.IsNullOrWhiteSpace(slot.CountryCode))
        {
            return;
        }

        IConnectionIntent intent = new ConnectionIntent(SingleCountryLocationIntent.From(slot.CountryCode));
        await ConnectionManager.ConnectAsync(VpnTriggerDimension.CountriesCountry, intent);
    }

    private void RefreshState()
    {
        _isRefreshing = true;
        try
        {
            IsMultiTunnelEnabled = _multiTunnelManager.IsEnabled;
            SelectedDefaultTargetType = _multiTunnelManager.DefaultTargetType.ToString();
            SelectedDefaultTunnelId = _multiTunnelManager.DefaultTunnelId;

            Slots.Clear();
            foreach (MultiTunnelSlotConfig slot in _multiTunnelManager.Slots)
            {
                string countryDisplay = string.IsNullOrWhiteSpace(slot.CountryCode)
                    ? "Unassigned"
                    : Localizer.GetCountryName(slot.CountryCode);
                if (string.IsNullOrWhiteSpace(countryDisplay) || countryDisplay == slot.CountryCode)
                {
                    countryDisplay = slot.CountryCode;
                }

                Slots.Add(new MultiTunnelSlotItem
                {
                    SlotId = slot.SlotId,
                    CountryCode = slot.CountryCode,
                    ServerName = slot.ServerName,
                    City = slot.City,
                    ClientIpv4 = slot.ClientIpv4,
                    StatusText = slot.IsConnected ? "Connected" : "Ready",
                    IsConnected = slot.IsConnected,
                    CanRemove = !string.Equals(slot.SlotId, "T1", StringComparison.OrdinalIgnoreCase),
                    SlotSummary = $"{countryDisplay} ({slot.CountryCode}) • {slot.ServerName}",
                });
            }

            OnPropertyChanged(nameof(Status));
            OnPropertyChanged(nameof(SummaryText));
            OnPropertyChanged(nameof(IsDefaultTargetTunnel));
        }
        finally
        {
            _isRefreshing = false;
        }
    }
}
