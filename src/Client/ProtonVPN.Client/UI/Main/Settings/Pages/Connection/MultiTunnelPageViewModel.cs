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
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Xaml.Media;
using ProtonVPN.Client.Core.Bases;
using ProtonVPN.Client.Core.Extensions;
using ProtonVPN.Client.Core.Models;
using ProtonVPN.Client.Core.Services.Activation;
using ProtonVPN.Client.Core.Services.Navigation;
using ProtonVPN.Client.EventMessaging.Contracts;
using ProtonVPN.Client.Localization.Extensions;
using ProtonVPN.Client.Logic.Connection.Contracts;
using ProtonVPN.Client.Logic.Connection.Contracts.Models.Intents;
using ProtonVPN.Client.Logic.Connection.Contracts.Models.Intents.Locations.Countries;
using ProtonVPN.Client.Logic.Connection.Contracts.MultiTunnel;
using ProtonVPN.Client.Logic.Connection.Contracts.Messages;
using ProtonVPN.Client.Logic.Servers.Contracts;
using ProtonVPN.Client.Logic.Servers.Contracts.Enums;
using ProtonVPN.Client.Logic.Servers.Contracts.Extensions;
using ProtonVPN.Client.Logic.Servers.Contracts.Messages;
using ProtonVPN.Client.Logic.Servers.Contracts.Models;
using ProtonVPN.Client.Services.PortForwarding;
using ProtonVPN.Client.Settings.Contracts;
using ProtonVPN.Client.Settings.Contracts.RequiredReconnections;
using ProtonVPN.Client.UI.Main.Home.Details.Connection;
using ProtonVPN.Client.UI.Main.Settings.Bases;
using ProtonVPN.Common.Core.Extensions;
using ProtonVPN.Common.Legacy.PortForwarding;
using ProtonVPN.ProcessCommunication.Contracts.Entities.MultiTunnel;
using ProtonVPN.StatisticalEvents.Contracts.Dimensions;

namespace ProtonVPN.Client.UI.Main.Settings.Pages.Connection;

public sealed record SlotCountryOption(string CountryCode, string DisplayName)
{
    public override string ToString() => DisplayName;
}

public sealed record SlotServerOption(string ServerId, string ServerName, string City, string EntryIp, string DisplayName)
{
    public override string ToString() => DisplayName;
}

public sealed class MultiTunnelSlotItem
{
    public required string SlotId { get; init; }
    public required string CountryCode { get; init; }
    public required string ServerName { get; init; }
    public required string City { get; init; }
    public required string ClientIpv4 { get; init; }
    public required string StatusText { get; init; }
    public bool IsConnected { get; init; }
    public bool IsConnecting { get; init; }
    public string? LastError { get; init; }
    public SolidColorBrush? SlotColorBrush { get; init; }
    public bool CanToggleConnection => !IsConnecting;
    public string ConnectButtonText => IsConnecting ? "Connecting..." : (IsConnected ? "Disconnect" : "Connect");
    public required bool CanRemove { get; init; }
    public required string SlotSummary { get; init; }
    public int RuleCount { get; init; }
    public string RuleCountBadge => RuleCount == 1 ? "1 rule" : $"{RuleCount} rules";

    public bool IsPortForwardingEnabled { get; init; }
    public bool? PortForwardingOverride { get; init; }
    public int? ActiveForwardedPort { get; init; }
    public bool HasActiveForwardedPort => ActiveForwardedPort is > 0;
    public bool HasPortForwardingWarning { get; init; }
    public string PortForwardingBadgeText { get; init; } = string.Empty;
    public bool ShowPortForwardingBadge => !string.IsNullOrEmpty(PortForwardingBadgeText);
    public string PortForwardingToggleText { get; init; } = "PF";
    public string PortForwardingTooltip { get; init; } = string.Empty;

    public static MultiTunnelSlotItem Create(
        MultiTunnelSlotConfig slot,
        string countryDisplay,
        int ruleCount,
        bool globalPortForwardingEnabled,
        SlotPortForwardingState? pfState,
        string? summaryOverride = null)
    {
        bool effectivePf = slot.ResolveEffectivePortForwarding(globalPortForwardingEnabled);
        int? activePort = slot.IsConnected && effectivePf
            ? (pfState is not null ? pfState.ActivePort : slot.ActiveForwardedPort)
            : null;
        bool isFetching = pfState?.IsFetchingPort ?? (slot.PortForwardingStatus is not PortMappingStatus.Stopped and not PortMappingStatus.Error and not PortMappingStatus.DestroyPortMappingCommunication);
        bool hasError = pfState?.HasError ?? slot.HasPortForwardingError;

        string badgeText = string.Empty;
        bool hasWarning = false;
        string tooltip = effectivePf
            ? "Port Forwarding enabled for this tunnel"
            : "Port Forwarding disabled for this tunnel";

        if (effectivePf && slot.IsConnected)
        {
            if (!slot.IsP2PServer)
            {
                badgeText = "PF: Non-P2P";
                hasWarning = true;
                tooltip = "Connected server does not support P2P Port Forwarding";
            }
            else if (activePort is > 0)
            {
                badgeText = $"PF: {activePort}";
                tooltip = $"Active forwarded port {activePort} — click to copy";
            }
            else if (hasError)
            {
                badgeText = "PF: Err";
                hasWarning = true;
                tooltip = "Port Forwarding error on this tunnel";
            }
            else if (isFetching)
            {
                badgeText = "PF: ...";
                tooltip = "Negotiating forwarded port via LocalAgent / NAT-PMP...";
            }
            else
            {
                badgeText = "PF: On";
            }
        }
        else if (effectivePf)
        {
            badgeText = "PF: On";
        }

        string toggleText = slot.PortForwardingOverride switch
        {
            true => "PF: On",
            false => "PF: Off",
            null => effectivePf ? "PF: Auto (On)" : "PF: Auto (Off)",
        };

        return new MultiTunnelSlotItem
        {
            SlotId = slot.SlotId,
            CountryCode = slot.CountryCode,
            ServerName = slot.ServerName,
            City = slot.City,
            ClientIpv4 = slot.ClientIpv4,
            StatusText = slot.IsConnecting ? "Connecting..." : (slot.IsConnected ? "Connected" : "Ready"),
            IsConnected = slot.IsConnected,
            IsConnecting = slot.IsConnecting,
            LastError = slot.LastError,
            SlotColorBrush = SlotColorBrushHelper.ToBrush(MultiTunnelSlotConfig.GetSlotColorHex(slot.SlotId)),
            CanRemove = !string.Equals(slot.SlotId, "T1", StringComparison.OrdinalIgnoreCase),
            SlotSummary = summaryOverride ?? $"{countryDisplay} ({slot.CountryCode}) • {slot.ServerName} • {slot.ClientIpv4}",
            RuleCount = ruleCount,
            IsPortForwardingEnabled = effectivePf,
            PortForwardingOverride = slot.PortForwardingOverride,
            ActiveForwardedPort = activePort,
            HasPortForwardingWarning = hasWarning,
            PortForwardingBadgeText = badgeText,
            PortForwardingToggleText = toggleText,
            PortForwardingTooltip = tooltip,
        };
    }
}

public sealed class MultiTunnelRuleItem
{
    public required Guid Id { get; init; }
    public required string PriorityBadge { get; init; }
    public required string Name { get; init; }
    public required bool IsEnabled { get; init; }
    public required string TargetBadge { get; init; }
    public required string FallbackBadge { get; init; }
    public required string CriteriaSummary { get; init; }

    public static string FormatFallbackBadge(
        MultiTunnelRuleConfig rule,
        IReadOnlyDictionary<string, MultiTunnelSlotConfig> slotsById)
    {
        if (!rule.IsEnabled || rule.TargetType != RuleTargetTypeIpcEntity.Tunnel)
        {
            return rule.FallbackSummary;
        }

        string targetId = string.IsNullOrWhiteSpace(rule.TargetTunnelId) ? "T1" : rule.TargetTunnelId.Trim().ToUpperInvariant();
        if (slotsById.TryGetValue(targetId, out MultiTunnelSlotConfig? targetSlot) && targetSlot.IsConnected)
        {
            return rule.FallbackSummary;
        }

        return rule.FallbackBehavior switch
        {
            TunnelFallbackBehaviorIpcEntity.FallbackToDirect => "Fallback Direct (Active)",
            TunnelFallbackBehaviorIpcEntity.FallbackToTunnel =>
                !string.IsNullOrWhiteSpace(rule.FallbackTunnelId) &&
                slotsById.TryGetValue(rule.FallbackTunnelId.Trim().ToUpperInvariant(), out MultiTunnelSlotConfig? fbSlot) &&
                fbSlot.IsConnected
                    ? $"Fallback {fbSlot.SlotId} (Active)"
                    : "Kill-Switch (Offline · Blocking)",
            _ => "Kill-Switch (Offline · Blocking)",
        };
    }
}

public partial class PresetTargetOption : ObservableObject
{
    public required string Key { get; init; }
    public required string ShortLabel { get; init; }
    public required string DisplayLabel { get; init; }
    public required string RuleCountText { get; init; }
    public bool HasRuleCount => !string.IsNullOrEmpty(RuleCountText);
    public required string ColorHex { get; init; }
    public required SolidColorBrush DotBrush { get; init; }

    [ObservableProperty]
    private bool _isSelected;

    public SolidColorBrush ChipBorderBrush => IsSelected
        ? DotBrush
        : SlotColorBrushHelper.ToBrush("#4A4A62");

    public SolidColorBrush ChipBackgroundBrush => IsSelected
        ? SlotColorBrushHelper.ToBrush(ColorHex, alpha: 42)
        : SlotColorBrushHelper.ToBrush("#232332");

    partial void OnIsSelectedChanged(bool value)
    {
        OnPropertyChanged(nameof(ChipBorderBrush));
        OnPropertyChanged(nameof(ChipBackgroundBrush));
    }
}

public partial class MultiTunnelPresetItem : ObservableObject
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required string Category { get; init; }
    public required string Description { get; init; }
    public required string ConditionPreview { get; init; }
    public required string RecommendedTargetLabel { get; init; }

    [ObservableProperty]
    private bool _isSelected;

    [ObservableProperty]
    private bool _isCurrentlyAssigned;

    [ObservableProperty]
    private string _currentRouteLabel = string.Empty;

    [ObservableProperty]
    private SolidColorBrush? _currentRouteBrush;

    [ObservableProperty]
    private bool _isAssignedToSelectedTarget;

    [ObservableProperty]
    private string _quickActionText = "+ T1";
}

public partial class MultiTunnelPageViewModel : SettingsPageViewModelBase,
    IEventMessageReceiver<MultiTunnelPolicyChangedMessage>,
    IEventMessageReceiver<ServerListChangedMessage>,
    IEventMessageReceiver<PortForwardingPortChangedMessage>,
    IEventMessageReceiver<PortForwardingStatusChangedMessage>
{
    private readonly IMultiTunnelManager _multiTunnelManager;
    private readonly IServersLoader _serversLoader;
    private readonly IMainWindowActivator _mainWindowActivator;
    private readonly IPortForwardingManager _portForwardingManager;
    private readonly IPortForwardingClipboardService _portForwardingClipboardService;
    private readonly List<MultiTunnelPresetItem> _allPresets = [];
    private IReadOnlyList<DiscoveredAppItem> _allDiscoveredApps = [];
    private bool _isRefreshing;

    [ObservableProperty]
    private bool _isAppPickerOpen;

    [ObservableProperty]
    private string _appPickerSearchQuery = string.Empty;

    [ObservableProperty]
    private string? _selectedPresetCategory = "All";

    [ObservableProperty]
    private string _presetSearchQuery = string.Empty;

    [ObservableProperty]
    private string _selectedPresetTargetKey = "T1";

    [ObservableProperty]
    private string? _selectedPresetFallbackBehavior = "Preset Default";

    [ObservableProperty]
    private string? _selectedPresetFallbackTunnelId = "T1";

    [ObservableProperty]
    private string _presetStatusText = string.Empty;

    [ObservableProperty]
    private string _selectedPresetCountText = "0 selected";

    [ObservableProperty]
    private bool _hasSelectedPresets;

    [ObservableProperty]
    private bool _isMultiTunnelEnabled;

    [ObservableProperty]
    private string _summaryText = string.Empty;

    [ObservableProperty]
    private string? _selectedDefaultTargetType = "Direct";

    [ObservableProperty]
    private string? _selectedDefaultTunnelId = "T1";

    [ObservableProperty]
    private SlotCountryOption? _selectedPickerCountry;

    [ObservableProperty]
    private SlotServerOption? _selectedPickerServer;

    [ObservableProperty]
    private string? _selectedEditSlotId = "NEW";

    [ObservableProperty]
    private string _slotPickerStatus = string.Empty;

    [ObservableProperty]
    private bool _hasConflicts;

    [ObservableProperty]
    private Guid? _editingRuleId;

    [ObservableProperty]
    private string _ruleEditorTitle = "Add New Priority Rule";

    [ObservableProperty]
    private string _ruleName = string.Empty;

    [ObservableProperty]
    private string _ruleAppPattern = string.Empty;

    [ObservableProperty]
    private string _ruleDomainPattern = string.Empty;

    [ObservableProperty]
    private string _ruleIpCidrPattern = string.Empty;

    [ObservableProperty]
    private string _rulePortPattern = string.Empty;

    [ObservableProperty]
    private string? _ruleProtocol = "Any";

    [ObservableProperty]
    private string? _ruleTargetType = "Tunnel";

    [ObservableProperty]
    private string? _ruleTargetTunnelId = "T1";

    [ObservableProperty]
    private string? _ruleFallbackBehavior = "KillSwitchBlock";

    [ObservableProperty]
    private string? _ruleFallbackTunnelId = "T1";

    [ObservableProperty]
    private string _simApp = "chrome";

    [ObservableProperty]
    private string _simDomain = "api.openai.com";

    [ObservableProperty]
    private string _simRemoteIp = string.Empty;

    [ObservableProperty]
    private string _simPort = "443";

    [ObservableProperty]
    private string? _simProtocol = "Tcp";

    [ObservableProperty]
    private string _simResultSummary = string.Empty;

    [ObservableProperty]
    private string _simResultDetails = string.Empty;

    [ObservableProperty]
    private bool _hasSimResult;

    public override string Title => "Multi-Tunnel & Priority Routing";

    public bool IsDefaultTargetTunnel => string.Equals(SelectedDefaultTargetType, "Tunnel", StringComparison.OrdinalIgnoreCase);

    public bool IsRuleTargetTunnel => string.Equals(RuleTargetType, "Tunnel", StringComparison.OrdinalIgnoreCase);

    public bool IsRuleFallbackTunnel => IsRuleTargetTunnel &&
                                        string.Equals(RuleFallbackBehavior, "FallbackToTunnel", StringComparison.OrdinalIgnoreCase);

    public bool IsPresetFallbackAllowed =>
        !string.Equals(SelectedPresetTargetKey, "DIRECT", StringComparison.OrdinalIgnoreCase) &&
        !string.Equals(SelectedPresetTargetKey, "BLOCK", StringComparison.OrdinalIgnoreCase);

    public bool IsPresetFallbackTunnel => IsPresetFallbackAllowed &&
                                          string.Equals(SelectedPresetFallbackBehavior, "FallbackToTunnel", StringComparison.OrdinalIgnoreCase);

    public bool IsSpecificPresetTargetSelected =>
        !string.Equals(SelectedPresetTargetKey, "PRESET_DEFAULT", StringComparison.OrdinalIgnoreCase);

    public string SelectedTargetShortLabel => GetShortRouteLabel(SelectedPresetTargetKey);

    public string AssignSelectedButtonText
    {
        get
        {
            int count = _allPresets.Count(p => p.IsSelected);
            string target = SelectedTargetShortLabel;
            return count > 0 ? $"+ Assign {count} to {target}" : $"+ Assign to {target}";
        }
    }

    public string ReplaceTargetButtonText => $"Replace {SelectedTargetShortLabel}";

    public bool HasPresetStatus => !string.IsNullOrWhiteSpace(PresetStatusText);

    public bool CanAddSlot => Slots.Count < MultiTunnelSlotConfig.MaxSlots;

    public IReadOnlyList<string> TargetTypeOptions { get; } = ["Direct", "Tunnel", "Block"];
    public IReadOnlyList<string> ProtocolOptions { get; } = ["Any", "Tcp", "Udp"];
    public IReadOnlyList<string> FallbackOptions { get; } = ["KillSwitchBlock", "FallbackToTunnel", "FallbackToDirect"];
    public IReadOnlyList<string> PresetCategoryOptions { get; } = ["All", "BigTech", "Social", "AiDev", "MediaGaming", "Network"];
    public IReadOnlyList<string> PresetFallbackOptions { get; } = ["Preset Default", "KillSwitchBlock", "FallbackToTunnel", "FallbackToDirect"];

    public ObservableCollection<string> SlotIdOptions { get; } = ["T1", "T2", "T3", "T4", "T5"];
    public ObservableCollection<string> SlotPickerTargets { get; } = ["NEW", "T1"];
    public ObservableCollection<SlotCountryOption> AvailableCountries { get; } = [];
    public ObservableCollection<SlotServerOption> AvailableServers { get; } = [];
    public ObservableCollection<MultiTunnelSlotItem> Slots { get; } = [];
    public ObservableCollection<MultiTunnelRuleItem> Rules { get; } = [];
    public ObservableCollection<PresetTargetOption> PresetTargetOptions { get; } = [];
    public ObservableCollection<MultiTunnelPresetItem> FilteredPresets { get; } = [];
    public ObservableCollection<DiscoveredAppItem> FilteredDiscoveredApps { get; } = [];
    public ObservableCollection<string> ConflictMessages { get; } = [];

    public MultiTunnelPageViewModel(
        IRequiredReconnectionSettings requiredReconnectionSettings,
        IMainViewNavigator mainViewNavigator,
        ISettingsViewNavigator settingsViewNavigator,
        IMainWindowOverlayActivator mainWindowOverlayActivator,
        IMainWindowActivator mainWindowActivator,
        ISettings settings,
        ISettingsConflictResolver settingsConflictResolver,
        IConnectionManager connectionManager,
        IMultiTunnelManager multiTunnelManager,
        IServersLoader serversLoader,
        IPortForwardingManager portForwardingManager,
        IPortForwardingClipboardService portForwardingClipboardService,
        IViewModelHelper viewModelHelper)
        : base(requiredReconnectionSettings,
               mainViewNavigator,
               settingsViewNavigator,
               mainWindowOverlayActivator,
               settings,
               settingsConflictResolver,
               connectionManager,
               viewModelHelper)
    {
        _mainWindowActivator = mainWindowActivator;
        _multiTunnelManager = multiTunnelManager;
        _serversLoader = serversLoader;
        _portForwardingManager = portForwardingManager;
        _portForwardingClipboardService = portForwardingClipboardService;

        PageSettings = [];
        InitializePresets();
    }

    protected override void OnActivated()
    {
        base.OnActivated();
        LoadCountries();
        RefreshState();
    }

    protected override void OnRetrieveSettings()
    {
        LoadCountries();
        RefreshState();
    }

    public void Receive(MultiTunnelPolicyChangedMessage message)
    {
        ExecuteOnUIThreadIfActive(RefreshState);
    }

    public void Receive(ServerListChangedMessage message)
    {
        ExecuteOnUIThreadIfActive(LoadCountries);
    }

    public void Receive(PortForwardingPortChangedMessage message)
    {
        ExecuteOnUIThreadIfActive(RefreshState);
    }

    public void Receive(PortForwardingStatusChangedMessage message)
    {
        ExecuteOnUIThreadIfActive(RefreshState);
    }

    partial void OnIsMultiTunnelEnabledChanged(bool value)
    {
        if (!_isRefreshing)
        {
            _multiTunnelManager.SetEnabledAsync(value).FireAndForget();
        }
    }

    partial void OnSelectedDefaultTargetTypeChanged(string? value)
    {
        OnPropertyChanged(nameof(IsDefaultTargetTunnel));
        if (!_isRefreshing && !string.IsNullOrWhiteSpace(value) && Enum.TryParse(value, out RuleTargetTypeIpcEntity target))
        {
            _multiTunnelManager.SetDefaultRoutingAsync(target, SelectedDefaultTunnelId ?? "T1").FireAndForget();
        }
    }

    partial void OnSelectedDefaultTunnelIdChanged(string? value)
    {
        if (!_isRefreshing && !string.IsNullOrWhiteSpace(value) &&
            Enum.TryParse(SelectedDefaultTargetType, out RuleTargetTypeIpcEntity target))
        {
            _multiTunnelManager.SetDefaultRoutingAsync(target, value).FireAndForget();
        }
    }

    partial void OnSelectedPickerCountryChanged(SlotCountryOption? value)
    {
        PopulateServersForCountry(value?.CountryCode);
    }

    partial void OnRuleTargetTypeChanged(string? value)
    {
        OnPropertyChanged(nameof(IsRuleTargetTunnel));
        OnPropertyChanged(nameof(IsRuleFallbackTunnel));
    }

    partial void OnRuleFallbackBehaviorChanged(string? value)
    {
        OnPropertyChanged(nameof(IsRuleFallbackTunnel));
    }

    partial void OnSelectedPresetCategoryChanged(string? value)
    {
        RefreshFilteredPresets();
    }

    partial void OnPresetSearchQueryChanged(string value)
    {
        RefreshFilteredPresets();
    }

    partial void OnSelectedPresetTargetKeyChanged(string value)
    {
        OnPropertyChanged(nameof(IsPresetFallbackAllowed));
        OnPropertyChanged(nameof(IsPresetFallbackTunnel));
        OnPropertyChanged(nameof(IsSpecificPresetTargetSelected));
        OnPropertyChanged(nameof(SelectedTargetShortLabel));
        OnPropertyChanged(nameof(AssignSelectedButtonText));
        OnPropertyChanged(nameof(ReplaceTargetButtonText));

        foreach (PresetTargetOption opt in PresetTargetOptions)
        {
            opt.IsSelected = string.Equals(opt.Key, value, StringComparison.OrdinalIgnoreCase);
        }

        RefreshPresetAssignmentStates();
    }

    partial void OnSelectedPresetFallbackBehaviorChanged(string? value)
    {
        OnPropertyChanged(nameof(IsPresetFallbackTunnel));
    }

    partial void OnPresetStatusTextChanged(string value)
    {
        OnPropertyChanged(nameof(HasPresetStatus));
    }

    public void SelectPresetTarget(string targetKey)
    {
        if (string.IsNullOrWhiteSpace(targetKey))
        {
            return;
        }

        string normalized = targetKey.Trim().ToUpperInvariant();
        if (!PresetTargetOptions.Any(o => string.Equals(o.Key, normalized, StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        SelectedPresetTargetKey = normalized;
        PresetTargetOption? selected = PresetTargetOptions.FirstOrDefault(o =>
            string.Equals(o.Key, normalized, StringComparison.OrdinalIgnoreCase));
        if (selected is not null)
        {
            PresetStatusText = $"Target set to {selected.DisplayLabel} — click + on any template or check multiple to assign.";
        }
    }

    public void SetPresetSelected(string presetId, bool isSelected)
    {
        MultiTunnelPresetItem? item = _allPresets.FirstOrDefault(p =>
            string.Equals(p.Id, presetId, StringComparison.OrdinalIgnoreCase));
        if (item is not null)
        {
            item.IsSelected = isSelected;
            UpdatePresetSelectionState();
        }
    }

    [RelayCommand]
    public void SelectAllVisiblePresets()
    {
        foreach (MultiTunnelPresetItem item in FilteredPresets)
        {
            item.IsSelected = true;
        }
        UpdatePresetSelectionState();
    }

    [RelayCommand]
    public void ClearSelectedPresets()
    {
        foreach (MultiTunnelPresetItem item in _allPresets)
        {
            item.IsSelected = false;
        }
        UpdatePresetSelectionState();
    }

    [RelayCommand]
    public Task AddSelectedPresetsAsync() => ApplySelectedPresetsAsync(RoutingPresetApplyMode.Add);

    [RelayCommand]
    public Task ReplaceTargetWithSelectedPresetsAsync() => ApplySelectedPresetsAsync(RoutingPresetApplyMode.ReplaceTarget);

    [RelayCommand]
    public Task ReplaceWithSelectedPresetsAsync() => ApplySelectedPresetsAsync(RoutingPresetApplyMode.Replace);

    public async Task QuickTogglePresetForTargetAsync(string presetId)
    {
        RoutingRulePreset? preset = MultiTunnelRoutingPresetCatalog.FindById(presetId);
        MultiTunnelPresetItem? item = _allPresets.FirstOrDefault(p =>
            string.Equals(p.Id, presetId, StringComparison.OrdinalIgnoreCase));
        if (preset is null || item is null)
        {
            return;
        }

        if (item.IsAssignedToSelectedTarget)
        {
            bool removed = await _multiTunnelManager.RemoveRoutingPresetAsync(preset);
            PresetStatusText = removed
                ? $"Removed '{preset.Name}' from {SelectedTargetShortLabel}."
                : $"Could not remove '{preset.Name}'.";
            return;
        }

        (RuleTargetTypeIpcEntity? targetTypeOverride, string? targetTunnelOverride, TunnelFallbackBehaviorIpcEntity? fbOverride, string? fbTunnelOverride) = ParsePresetOverrides();
        await _multiTunnelManager.ApplyRoutingPresetsAsync(
            [preset],
            RoutingPresetApplyMode.Add,
            targetTypeOverride,
            targetTunnelOverride,
            fbOverride,
            fbTunnelOverride);

        PresetStatusText = $"Assigned '{preset.Name}' -> {SelectedTargetShortLabel}.";
    }

    [RelayCommand]
    public void FillEditorFromSelectedPreset()
    {
        MultiTunnelPresetItem? selectedItem = _allPresets.FirstOrDefault(p => p.IsSelected) ?? FilteredPresets.FirstOrDefault();
        RoutingRulePreset? preset = MultiTunnelRoutingPresetCatalog.FindById(selectedItem?.Id);
        if (preset is null)
        {
            PresetStatusText = "Select a preset template first.";
            return;
        }

        IReadOnlyCollection<string> slotIds = _multiTunnelManager.Slots.Count > 0
            ? _multiTunnelManager.Slots.Select(s => s.SlotId).ToList()
            : ["T1"];
        (RuleTargetTypeIpcEntity? targetTypeOverride, string? targetTunnelOverride, TunnelFallbackBehaviorIpcEntity? fbOverride, string? fbTunnelOverride) = ParsePresetOverrides();
        MultiTunnelRuleConfig draft = preset.ToRuleConfig(slotIds, targetTypeOverride, targetTunnelOverride, fbOverride, fbTunnelOverride);

        EditingRuleId = null;
        RuleEditorTitle = $"New Rule from Template: {preset.Name}";
        RuleName = draft.Name;
        RuleAppPattern = draft.AppPattern ?? string.Empty;
        RuleDomainPattern = draft.DomainPattern ?? string.Empty;
        RuleIpCidrPattern = draft.IpCidrPattern ?? string.Empty;
        RulePortPattern = draft.PortPattern ?? string.Empty;
        RuleProtocol = draft.Protocol.ToString();
        RuleTargetType = draft.TargetType.ToString();
        RuleTargetTunnelId = draft.TargetTunnelId;
        RuleFallbackBehavior = draft.FallbackBehavior.ToString();
        RuleFallbackTunnelId = string.IsNullOrWhiteSpace(draft.FallbackTunnelId) ? "T1" : draft.FallbackTunnelId;
        PresetStatusText = $"Loaded '{preset.Name}' into the rule editor below.";
    }

    private async Task ApplySelectedPresetsAsync(RoutingPresetApplyMode mode)
    {
        List<RoutingRulePreset> selected = _allPresets
            .Where(i => i.IsSelected)
            .Select(i => MultiTunnelRoutingPresetCatalog.FindById(i.Id))
            .Where(p => p is not null)
            .Cast<RoutingRulePreset>()
            .ToList();

        if (selected.Count == 0)
        {
            PresetStatusText = "Check one or more service templates, or click + on any template row.";
            return;
        }

        (RuleTargetTypeIpcEntity? targetTypeOverride, string? targetTunnelOverride, TunnelFallbackBehaviorIpcEntity? fbOverride, string? fbTunnelOverride) = ParsePresetOverrides();
        int applied = await _multiTunnelManager.ApplyRoutingPresetsAsync(
            selected,
            mode,
            targetTypeOverride,
            targetTunnelOverride,
            fbOverride,
            fbTunnelOverride);

        PresetStatusText = mode switch
        {
            RoutingPresetApplyMode.Replace => $"Replaced all routing rules with {applied} template(s).",
            RoutingPresetApplyMode.ReplaceTarget => $"Replaced {SelectedTargetShortLabel} rules with {applied} template(s).",
            _ => $"Assigned {applied} template(s) -> {SelectedTargetShortLabel}.",
        };
        ClearSelectedPresets();
    }

    private (RuleTargetTypeIpcEntity? TargetType, string? TargetTunnelId, TunnelFallbackBehaviorIpcEntity? Fallback, string? FallbackTunnelId) ParsePresetOverrides()
    {
        RuleTargetTypeIpcEntity? targetType = null;
        string? targetTunnelId = null;
        TunnelFallbackBehaviorIpcEntity? fallbackBehavior = null;
        string? fallbackTunnelId = null;

        string key = SelectedPresetTargetKey?.Trim().ToUpperInvariant() ?? "PRESET_DEFAULT";
        if (!string.Equals(key, "PRESET_DEFAULT", StringComparison.OrdinalIgnoreCase))
        {
            if (string.Equals(key, "DIRECT", StringComparison.OrdinalIgnoreCase))
            {
                targetType = RuleTargetTypeIpcEntity.Direct;
            }
            else if (string.Equals(key, "BLOCK", StringComparison.OrdinalIgnoreCase))
            {
                targetType = RuleTargetTypeIpcEntity.Block;
            }
            else
            {
                targetType = RuleTargetTypeIpcEntity.Tunnel;
                targetTunnelId = key;
            }
        }

        if ((!targetType.HasValue || targetType == RuleTargetTypeIpcEntity.Tunnel) &&
            !string.Equals(SelectedPresetFallbackBehavior, "Preset Default", StringComparison.OrdinalIgnoreCase) &&
            Enum.TryParse(SelectedPresetFallbackBehavior, out TunnelFallbackBehaviorIpcEntity parsedFb))
        {
            fallbackBehavior = parsedFb;
            if (parsedFb == TunnelFallbackBehaviorIpcEntity.FallbackToTunnel)
            {
                fallbackTunnelId = string.IsNullOrWhiteSpace(SelectedPresetFallbackTunnelId) ? "T1" : SelectedPresetFallbackTunnelId;
            }
        }

        return (targetType, targetTunnelId, fallbackBehavior, fallbackTunnelId);
    }

    private void InitializePresets()
    {
        _allPresets.Clear();
        foreach (RoutingRulePreset preset in MultiTunnelRoutingPresetCatalog.All)
        {
            _allPresets.Add(new MultiTunnelPresetItem
            {
                Id = preset.Id,
                Name = preset.Name,
                Category = preset.Category,
                Description = preset.Description,
                ConditionPreview = preset.ConditionPreview,
                RecommendedTargetLabel = preset.RecommendedTargetLabel,
            });
        }
        RefreshFilteredPresets();
        UpdatePresetSelectionState();
        RefreshPresetAssignmentStates();
    }

    private void RefreshFilteredPresets()
    {
        FilteredPresets.Clear();
        foreach (MultiTunnelPresetItem item in _allPresets)
        {
            RoutingRulePreset? preset = MultiTunnelRoutingPresetCatalog.FindById(item.Id);
            if (preset is null)
            {
                continue;
            }

            bool categoryMatch = string.IsNullOrWhiteSpace(SelectedPresetCategory) ||
                                 string.Equals(SelectedPresetCategory, "All", StringComparison.OrdinalIgnoreCase) ||
                                 string.Equals(item.Category, SelectedPresetCategory, StringComparison.OrdinalIgnoreCase);

            if (categoryMatch && preset.MatchesSearch(PresetSearchQuery))
            {
                FilteredPresets.Add(item);
            }
        }
    }

    private void UpdatePresetSelectionState()
    {
        int count = _allPresets.Count(p => p.IsSelected);
        HasSelectedPresets = count > 0;
        SelectedPresetCountText = $"{count} selected";
        OnPropertyChanged(nameof(AssignSelectedButtonText));
    }

    private void RefreshPresetAssignmentStates()
    {
        IReadOnlyList<MultiTunnelRuleConfig> currentRules = _multiTunnelManager.Rules;
        foreach (MultiTunnelPresetItem item in _allPresets)
        {
            RoutingRulePreset? preset = MultiTunnelRoutingPresetCatalog.FindById(item.Id);
            if (preset is null)
            {
                continue;
            }

            MultiTunnelRuleConfig? matched = currentRules.FirstOrDefault(r => r.IsEnabled && preset.MatchesRule(r))
                ?? currentRules.FirstOrDefault(r => preset.MatchesRule(r));

            string? matchedRouteKey = null;
            if (matched is not null)
            {
                matchedRouteKey = matched.TargetType switch
                {
                    RuleTargetTypeIpcEntity.Direct => "DIRECT",
                    RuleTargetTypeIpcEntity.Block => "BLOCK",
                    _ => string.IsNullOrWhiteSpace(matched.TargetTunnelId) ? "T1" : matched.TargetTunnelId.ToUpperInvariant(),
                };
                item.IsCurrentlyAssigned = true;
                item.CurrentRouteLabel = matched.TargetSummary;
                item.CurrentRouteBrush = GetRouteBrush(matchedRouteKey);
            }
            else
            {
                item.IsCurrentlyAssigned = false;
                item.CurrentRouteLabel = string.Empty;
                item.CurrentRouteBrush = null;
            }

            string effectiveTarget = ResolveEffectiveTargetKey(preset);
            string shortTarget = GetShortRouteLabel(effectiveTarget);
            item.IsAssignedToSelectedTarget = matchedRouteKey is not null &&
                                              string.Equals(matchedRouteKey, effectiveTarget, StringComparison.OrdinalIgnoreCase);
            item.QuickActionText = item.IsAssignedToSelectedTarget
                ? $"✓ {shortTarget}"
                : (item.IsCurrentlyAssigned ? $"→ {shortTarget}" : $"+ {shortTarget}");
        }
    }

    private string ResolveEffectiveTargetKey(RoutingRulePreset preset)
    {
        string key = SelectedPresetTargetKey?.Trim().ToUpperInvariant() ?? "PRESET_DEFAULT";
        if (!string.Equals(key, "PRESET_DEFAULT", StringComparison.OrdinalIgnoreCase))
        {
            return key;
        }

        return preset.DefaultTargetType switch
        {
            RuleTargetTypeIpcEntity.Direct => "DIRECT",
            RuleTargetTypeIpcEntity.Block => "BLOCK",
            _ => string.IsNullOrWhiteSpace(preset.DefaultTargetTunnelId)
                ? "T1"
                : preset.DefaultTargetTunnelId.Trim().ToUpperInvariant(),
        };
    }

    private string GetShortRouteLabel(string? routeKey)
    {
        string key = routeKey?.Trim().ToUpperInvariant() ?? "PRESET_DEFAULT";
        if (key == "PRESET_DEFAULT")
        {
            return "Auto";
        }
        if (key == "DIRECT")
        {
            return "Direct";
        }
        if (key == "BLOCK")
        {
            return "Block";
        }

        MultiTunnelSlotConfig? slot = _multiTunnelManager.Slots.FirstOrDefault(s =>
            string.Equals(s.SlotId, key, StringComparison.OrdinalIgnoreCase));
        return slot is not null && !string.IsNullOrWhiteSpace(slot.CountryCode)
            ? $"{key} ({slot.CountryCode})"
            : key;
    }

    private static SolidColorBrush GetRouteBrush(string routeKey)
    {
        string colorHex = routeKey.ToUpperInvariant() switch
        {
            "DIRECT" => "#38BDF8",
            "BLOCK" => "#F7607B",
            "PRESET_DEFAULT" => "#8A6EFF",
            _ => MultiTunnelSlotConfig.GetSlotColorHex(routeKey),
        };
        return SlotColorBrushHelper.ToBrush(colorHex);
    }

    [RelayCommand]
    public async Task AddOrUpdateSlotAsync()
    {
        if (SelectedPickerCountry is null)
        {
            SlotPickerStatus = "Select a country from the list first.";
            return;
        }

        string countryCode = SelectedPickerCountry.CountryCode;
        string serverName = SelectedPickerServer is not null && !string.IsNullOrWhiteSpace(SelectedPickerServer.ServerName)
            ? SelectedPickerServer.ServerName
            : $"{countryCode}#Fastest";
        string city = SelectedPickerServer?.City ?? string.Empty;
        string entryIp = SelectedPickerServer?.EntryIp ?? string.Empty;

        string targetSlot = SelectedEditSlotId ?? "NEW";
        if (string.Equals(targetSlot, "NEW", StringComparison.OrdinalIgnoreCase))
        {
            MultiTunnelSlotConfig? added = await _multiTunnelManager.AddSlotAsync(countryCode, serverName, city, entryIp);
            SlotPickerStatus = added is null
                ? $"Maximum {MultiTunnelSlotConfig.MaxSlots} tunnel slots (T1-T5) reached."
                : $"Added slot {added.SlotId} -> {SelectedPickerCountry.DisplayName} ({serverName}).";
        }
        else
        {
            await _multiTunnelManager.UpdateSlotLocationAsync(targetSlot, countryCode, serverName, city, entryIp);
            SlotPickerStatus = $"Updated slot {targetSlot} -> {SelectedPickerCountry.DisplayName} ({serverName}).";
        }
    }

    public async Task ConnectSlotAsync(string slotId)
    {
        MultiTunnelSlotConfig? slot = _multiTunnelManager.Slots.FirstOrDefault(s =>
            string.Equals(s.SlotId, slotId, StringComparison.OrdinalIgnoreCase));
        if (slot is null)
        {
            return;
        }

        if (slot.IsConnected)
        {
            await _multiTunnelManager.DisconnectSlotAsync(slot.SlotId);
        }
        else
        {
            await _multiTunnelManager.ConnectSlotAsync(slot.SlotId);
        }
    }

    public Task RemoveSlotAsync(string slotId)
    {
        return _multiTunnelManager.RemoveSlotAsync(slotId);
    }

    public async Task ToggleSlotPortForwardingAsync(string slotId)
    {
        MultiTunnelSlotConfig? slot = _multiTunnelManager.Slots.FirstOrDefault(s =>
            string.Equals(s.SlotId, slotId, StringComparison.OrdinalIgnoreCase));
        if (slot is null)
        {
            return;
        }

        bool currentEffective = slot.ResolveEffectivePortForwarding(Settings.IsPortForwardingEnabled);
        bool nextDesired = !currentEffective;
        bool? nextOverride = nextDesired == Settings.IsPortForwardingEnabled ? null : nextDesired;
        await _multiTunnelManager.SetSlotPortForwardingOverrideAsync(slot.SlotId, nextOverride);
    }

    public async Task CopySlotPortAsync(string slotId)
    {
        await _portForwardingClipboardService.CopyActivePortToClipboardAsync(slotId);
    }

    [RelayCommand]
    public async Task SaveRuleAsync()
    {
        string name = string.IsNullOrWhiteSpace(RuleName) ? "Custom Priority Rule" : RuleName.Trim();
        RuleProtocolIpcEntity proto = Enum.TryParse(RuleProtocol, out RuleProtocolIpcEntity parsedProto)
            ? parsedProto
            : RuleProtocolIpcEntity.Any;
        RuleTargetTypeIpcEntity target = Enum.TryParse(RuleTargetType, out RuleTargetTypeIpcEntity parsedTarget)
            ? parsedTarget
            : RuleTargetTypeIpcEntity.Tunnel;
        TunnelFallbackBehaviorIpcEntity fallback = Enum.TryParse(RuleFallbackBehavior, out TunnelFallbackBehaviorIpcEntity parsedFb)
            ? parsedFb
            : TunnelFallbackBehaviorIpcEntity.KillSwitchBlock;

        MultiTunnelRuleConfig? existingRule = EditingRuleId.HasValue
            ? _multiTunnelManager.Rules.FirstOrDefault(r => r.Id == EditingRuleId.Value)
            : null;

        MultiTunnelRuleConfig rule = new()
        {
            Id = EditingRuleId ?? Guid.NewGuid(),
            Name = name,
            IsEnabled = existingRule?.IsEnabled ?? true,
            AppPattern = NullIfBlank(RuleAppPattern),
            DomainPattern = NullIfBlank(RuleDomainPattern),
            IpCidrPattern = NullIfBlank(RuleIpCidrPattern),
            PortPattern = NullIfBlank(RulePortPattern),
            Protocol = proto,
            TargetType = target,
            TargetTunnelId = string.IsNullOrWhiteSpace(RuleTargetTunnelId) ? "T1" : RuleTargetTunnelId,
            FallbackBehavior = fallback,
            FallbackTunnelId = string.IsNullOrWhiteSpace(RuleFallbackTunnelId) ? "T1" : RuleFallbackTunnelId,
        };

        if (!rule.HasAnyCondition)
        {
            SlotPickerStatus = "Provide at least one match condition (App, Domain, IP/CIDR, or Port/Protocol).";
            return;
        }

        if (EditingRuleId.HasValue)
        {
            await _multiTunnelManager.UpdateRuleAsync(rule);
        }
        else
        {
            await _multiTunnelManager.AddRuleAsync(rule);
        }

        CancelEditRule();
    }

    partial void OnAppPickerSearchQueryChanged(string value)
    {
        RefreshFilteredDiscoveredApps();
    }

    [RelayCommand]
    public async Task ToggleAppPickerAsync()
    {
        IsAppPickerOpen = !IsAppPickerOpen;
        if (IsAppPickerOpen)
        {
            await RefreshDiscoveredAppsAsync();
        }
    }

    [RelayCommand]
    public async Task RefreshDiscoveredAppsAsync()
    {
        IReadOnlyList<DiscoveredAppItem> apps = await Task.Run(WindowsAppDiscoveryHelper.DiscoverApps);
        _allDiscoveredApps = apps;
        RefreshFilteredDiscoveredApps();
    }

    public void PickDiscoveredApp(string executablePath)
    {
        AppendRuleAppEntry(executablePath);
        SlotPickerStatus = $"Added application: {Path.GetFileName(executablePath)}";
    }

    [RelayCommand]
    public async Task BrowseAppExecutableAsync()
    {
        if (_mainWindowActivator.Window == null)
        {
            return;
        }

        string filePath = await _mainWindowActivator.Window.PickSingleFileAsync(
            Localizer.Get("Settings_Connection_SplitTunneling_Apps_FilesFilterName"),
            [ExternalApp.EXE_FILE_EXTENSION]);

        if (!string.IsNullOrWhiteSpace(filePath))
        {
            AppendRuleAppEntry(filePath);
            SlotPickerStatus = $"Added executable: {filePath}";
        }
    }

    private void RefreshFilteredDiscoveredApps()
    {
        FilteredDiscoveredApps.Clear();
        string q = AppPickerSearchQuery?.Trim() ?? string.Empty;
        foreach (DiscoveredAppItem app in _allDiscoveredApps)
        {
            bool match = string.IsNullOrEmpty(q) ||
                         app.DisplayName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                         app.ProcessName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                         app.ExecutablePath.Contains(q, StringComparison.OrdinalIgnoreCase);
            if (match)
            {
                FilteredDiscoveredApps.Add(app);
            }
        }
    }

    private void AppendRuleAppEntry(string entry)
    {
        string trimmed = entry.Trim();
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return;
        }

        List<string> existing = RuleAppPattern
            .Split([',', ';', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();

        if (!existing.Contains(trimmed, StringComparer.OrdinalIgnoreCase))
        {
            existing.Add(trimmed);
            RuleAppPattern = string.Join(", ", existing);
        }
    }

    [RelayCommand]
    public void CancelEditRule()
    {
        EditingRuleId = null;
        RuleEditorTitle = "Add New Priority Rule";
        RuleName = string.Empty;
        RuleAppPattern = string.Empty;
        RuleDomainPattern = string.Empty;
        RuleIpCidrPattern = string.Empty;
        RulePortPattern = string.Empty;
        RuleProtocol = "Any";
        RuleTargetType = "Tunnel";
        RuleTargetTunnelId = "T1";
        RuleFallbackBehavior = "KillSwitchBlock";
        RuleFallbackTunnelId = "T1";
    }

    public void BeginEditRule(Guid ruleId)
    {
        MultiTunnelRuleConfig? rule = _multiTunnelManager.Rules.FirstOrDefault(r => r.Id == ruleId);
        if (rule is null)
        {
            return;
        }

        EditingRuleId = rule.Id;
        RuleEditorTitle = $"Editing Rule #{rule.PriorityOrder}: {rule.Name}";
        RuleName = rule.Name;
        RuleAppPattern = rule.AppPattern ?? string.Empty;
        RuleDomainPattern = rule.DomainPattern ?? string.Empty;
        RuleIpCidrPattern = rule.IpCidrPattern ?? string.Empty;
        RulePortPattern = rule.PortPattern ?? string.Empty;
        RuleProtocol = rule.Protocol.ToString();
        RuleTargetType = rule.TargetType.ToString();
        RuleTargetTunnelId = rule.TargetTunnelId;
        RuleFallbackBehavior = rule.FallbackBehavior.ToString();
        RuleFallbackTunnelId = string.IsNullOrWhiteSpace(rule.FallbackTunnelId) ? "T1" : rule.FallbackTunnelId;
    }

    public Task SetRuleEnabledAsync(Guid ruleId, bool isEnabled)
    {
        return _multiTunnelManager.SetRuleEnabledAsync(ruleId, isEnabled);
    }

    public Task MoveRuleUpAsync(Guid ruleId)
    {
        return _multiTunnelManager.MoveRuleAsync(ruleId, -1);
    }

    public Task MoveRuleDownAsync(Guid ruleId)
    {
        return _multiTunnelManager.MoveRuleAsync(ruleId, +1);
    }

    public Task DeleteRuleAsync(Guid ruleId)
    {
        if (EditingRuleId == ruleId)
        {
            CancelEditRule();
        }
        return _multiTunnelManager.DeleteRuleAsync(ruleId);
    }

    [RelayCommand]
    public Task ResetDefaultRulesAsync()
    {
        CancelEditRule();
        return _multiTunnelManager.ResetDefaultRulesAsync();
    }

    [RelayCommand]
    public async Task RunSimulationAsync()
    {
        int? parsedPort = int.TryParse(SimPort?.Trim(), out int p) && p is >= 1 and <= 65535 ? p : null;
        RuleProtocolIpcEntity proto = Enum.TryParse(SimProtocol, out RuleProtocolIpcEntity parsedProto)
            ? parsedProto
            : RuleProtocolIpcEntity.Any;

        TrafficQueryIpcEntity query = new()
        {
            AppPath = NullIfBlank(SimApp),
            ProcessName = NullIfBlank(SimApp),
            Domain = NullIfBlank(SimDomain),
            RemoteIp = NullIfBlank(SimRemoteIp),
            RemotePort = parsedPort,
            Protocol = proto,
        };

        RoutingDecisionIpcEntity decision = await _multiTunnelManager.EvaluateTrafficAsync(query);

        string targetLabel = decision.EffectiveTargetType switch
        {
            RuleTargetTypeIpcEntity.Direct => "DIRECT (Physical NIC)",
            RuleTargetTypeIpcEntity.Block => decision.IsKillSwitchBlocked ? "BLOCKED (Kill-Switch)" : "BLOCKED",
            _ => $"TUNNEL {decision.EffectiveTunnelId ?? "T1"}",
        };

        SimResultSummary = $"{targetLabel}  •  WFP Weight: {decision.WfpFilterWeight}";
        SimResultDetails = decision.Explanation;
        HasSimResult = true;
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
            SlotPickerTargets.Clear();
            SlotPickerTargets.Add("NEW");

            Dictionary<string, int> ruleCountsBySlot = new(StringComparer.OrdinalIgnoreCase);
            int directCount = 0;
            int blockCount = 0;
            foreach (MultiTunnelRuleConfig r in _multiTunnelManager.Rules)
            {
                if (!r.IsEnabled)
                {
                    continue;
                }

                switch (r.TargetType)
                {
                    case RuleTargetTypeIpcEntity.Direct:
                        directCount++;
                        break;
                    case RuleTargetTypeIpcEntity.Block:
                        blockCount++;
                        break;
                    default:
                        string tid = string.IsNullOrWhiteSpace(r.TargetTunnelId) ? "T1" : r.TargetTunnelId.Trim().ToUpperInvariant();
                        ruleCountsBySlot[tid] = ruleCountsBySlot.GetValueOrDefault(tid, 0) + 1;
                        break;
                }
            }

            foreach (MultiTunnelSlotConfig slot in _multiTunnelManager.Slots)
            {
                string countryDisplay = string.IsNullOrWhiteSpace(slot.CountryCode)
                    ? "Unassigned"
                    : Localizer.GetCountryName(slot.CountryCode);
                if (string.IsNullOrWhiteSpace(countryDisplay) || countryDisplay == slot.CountryCode)
                {
                    countryDisplay = slot.CountryCode;
                }

                Slots.Add(MultiTunnelSlotItem.Create(
                    slot,
                    countryDisplay,
                    ruleCountsBySlot.GetValueOrDefault(slot.SlotId, 0),
                    Settings.IsPortForwardingEnabled,
                    _portForwardingManager.GetSlotState(slot.SlotId)));

                SlotPickerTargets.Add(slot.SlotId);
            }

            if (string.IsNullOrWhiteSpace(SelectedEditSlotId) || !SlotPickerTargets.Contains(SelectedEditSlotId))
            {
                SelectedEditSlotId = "NEW";
            }

            List<string> validPresetTargets = _multiTunnelManager.Slots.Select(s => s.SlotId).ToList();
            validPresetTargets.Add("DIRECT");
            validPresetTargets.Add("BLOCK");
            validPresetTargets.Add("PRESET_DEFAULT");

            if (string.IsNullOrWhiteSpace(SelectedPresetTargetKey) ||
                !validPresetTargets.Contains(SelectedPresetTargetKey, StringComparer.OrdinalIgnoreCase))
            {
                SelectedPresetTargetKey = _multiTunnelManager.Slots.FirstOrDefault()?.SlotId ?? "T1";
            }

            PresetTargetOptions.Clear();
            foreach (MultiTunnelSlotConfig slot in _multiTunnelManager.Slots)
            {
                string colorHex = MultiTunnelSlotConfig.GetSlotColorHex(slot.SlotId);
                string countryCode = string.IsNullOrWhiteSpace(slot.CountryCode) ? "Auto" : slot.CountryCode;
                PresetTargetOptions.Add(new PresetTargetOption
                {
                    Key = slot.SlotId,
                    ShortLabel = GetShortRouteLabel(slot.SlotId),
                    DisplayLabel = $"{slot.SlotId} · {countryCode}",
                    RuleCountText = ruleCountsBySlot.GetValueOrDefault(slot.SlotId, 0).ToString(),
                    ColorHex = colorHex,
                    DotBrush = SlotColorBrushHelper.ToBrush(colorHex),
                    IsSelected = string.Equals(SelectedPresetTargetKey, slot.SlotId, StringComparison.OrdinalIgnoreCase),
                });
            }

            PresetTargetOptions.Add(new PresetTargetOption
            {
                Key = "DIRECT",
                ShortLabel = "Direct",
                DisplayLabel = "Direct",
                RuleCountText = directCount.ToString(),
                ColorHex = "#38BDF8",
                DotBrush = SlotColorBrushHelper.ToBrush("#38BDF8"),
                IsSelected = string.Equals(SelectedPresetTargetKey, "DIRECT", StringComparison.OrdinalIgnoreCase),
            });

            PresetTargetOptions.Add(new PresetTargetOption
            {
                Key = "BLOCK",
                ShortLabel = "Block",
                DisplayLabel = "Block",
                RuleCountText = blockCount.ToString(),
                ColorHex = "#F7607B",
                DotBrush = SlotColorBrushHelper.ToBrush("#F7607B"),
                IsSelected = string.Equals(SelectedPresetTargetKey, "BLOCK", StringComparison.OrdinalIgnoreCase),
            });

            PresetTargetOptions.Add(new PresetTargetOption
            {
                Key = "PRESET_DEFAULT",
                ShortLabel = "Auto",
                DisplayLabel = "Preset Default",
                RuleCountText = string.Empty,
                ColorHex = "#8A6EFF",
                DotBrush = SlotColorBrushHelper.ToBrush("#8A6EFF"),
                IsSelected = string.Equals(SelectedPresetTargetKey, "PRESET_DEFAULT", StringComparison.OrdinalIgnoreCase),
            });

            RefreshPresetAssignmentStates();
            OnPropertyChanged(nameof(SelectedTargetShortLabel));
            OnPropertyChanged(nameof(AssignSelectedButtonText));
            OnPropertyChanged(nameof(ReplaceTargetButtonText));
            OnPropertyChanged(nameof(IsPresetFallbackAllowed));
            OnPropertyChanged(nameof(IsPresetFallbackTunnel));
            OnPropertyChanged(nameof(IsSpecificPresetTargetSelected));

            Dictionary<string, MultiTunnelSlotConfig> slotsById = _multiTunnelManager.Slots
                .ToDictionary(s => s.SlotId.ToUpperInvariant(), s => s, StringComparer.OrdinalIgnoreCase);

            Rules.Clear();
            foreach (MultiTunnelRuleConfig rule in _multiTunnelManager.Rules)
            {
                Rules.Add(new MultiTunnelRuleItem
                {
                    Id = rule.Id,
                    PriorityBadge = $"#{rule.PriorityOrder}",
                    Name = rule.Name,
                    IsEnabled = rule.IsEnabled,
                    TargetBadge = rule.TargetSummary,
                    FallbackBadge = MultiTunnelRuleItem.FormatFallbackBadge(rule, slotsById),
                    CriteriaSummary = rule.ConditionsSummary,
                });
            }

            ConflictMessages.Clear();
            foreach (MultiTunnelRuleConflict conflict in _multiTunnelManager.Conflicts)
            {
                ConflictMessages.Add(conflict.Description);
            }
            HasConflicts = ConflictMessages.Count > 0;

            SummaryText =
                $"Status: {(IsMultiTunnelEnabled ? "ENABLED" : "DISABLED")}  •  " +
                $"Slots: {_multiTunnelManager.ConnectedSlotCount}/{Slots.Count} (max {MultiTunnelSlotConfig.MaxSlots})  •  " +
                $"Active Rules: {_multiTunnelManager.EnabledRuleCount}/{Rules.Count}  •  " +
                $"Conflicts: {ConflictMessages.Count}";

            OnPropertyChanged(nameof(CanAddSlot));
            OnPropertyChanged(nameof(IsDefaultTargetTunnel));
        }
        finally
        {
            _isRefreshing = false;
        }
    }

    private void LoadCountries()
    {
        string? previousCode = SelectedPickerCountry?.CountryCode;
        AvailableCountries.Clear();

        List<SlotCountryOption> options = _serversLoader.GetCountries()
            .Select(c =>
            {
                string localized = Localizer.GetCountryName(c.Code);
                string label = string.IsNullOrWhiteSpace(localized) || localized == c.Code
                    ? c.Code
                    : $"{localized} ({c.Code})";
                return new SlotCountryOption(c.Code, label);
            })
            .OrderBy(o => o.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (options.Count == 0)
        {
            options =
            [
                new("SG", "Singapore (SG)"),
                new("JP", "Japan (JP)"),
                new("US", "United States (US)"),
                new("CH", "Switzerland (CH)"),
                new("GB", "United Kingdom (GB)"),
                new("DE", "Germany (DE)"),
                new("NL", "Netherlands (NL)"),
                new("VN", "Vietnam (VN)"),
            ];
        }

        foreach (SlotCountryOption opt in options)
        {
            AvailableCountries.Add(opt);
        }

        SelectedPickerCountry = (!string.IsNullOrWhiteSpace(previousCode)
            ? AvailableCountries.FirstOrDefault(c => string.Equals(c.CountryCode, previousCode, StringComparison.OrdinalIgnoreCase))
            : null) ?? AvailableCountries.FirstOrDefault();
    }

    private void PopulateServersForCountry(string? countryCode)
    {
        AvailableServers.Clear();
        if (string.IsNullOrWhiteSpace(countryCode))
        {
            SelectedPickerServer = null;
            return;
        }

        AvailableServers.Add(new SlotServerOption(
            ServerId: string.Empty,
            ServerName: $"{countryCode}#Fastest",
            City: string.Empty,
            EntryIp: string.Empty,
            DisplayName: $"Fastest in {countryCode}"));

        IEnumerable<Server> matching = _serversLoader.GetServers()
            .Where(s => string.Equals(s.ExitCountry, countryCode, StringComparison.OrdinalIgnoreCase) && !s.IsUnderMaintenance());

        matching = Settings.IsPortForwardingEnabled
            ? matching.OrderByDescending(s => s.Features.IsSupported(ServerFeatures.P2P)).ThenByDescending(s => s.Score)
            : matching.OrderByDescending(s => s.Score);

        foreach (Server srv in matching.Take(25))
        {
            string entryIp = srv.Servers?.FirstOrDefault()?.EntryIp ?? string.Empty;
            string p2pTag = srv.Features.IsSupported(ServerFeatures.P2P) ? " [P2P]" : string.Empty;
            string label = string.IsNullOrWhiteSpace(srv.City)
                ? $"{srv.Name}{p2pTag} (Load {srv.Load}%)"
                : $"{srv.Name}{p2pTag} — {srv.City} ({srv.Load}%)";
            AvailableServers.Add(new SlotServerOption(srv.Id, srv.Name, srv.City, entryIp, label));
        }

        SelectedPickerServer = AvailableServers.FirstOrDefault();
    }

    private static string? NullIfBlank(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
