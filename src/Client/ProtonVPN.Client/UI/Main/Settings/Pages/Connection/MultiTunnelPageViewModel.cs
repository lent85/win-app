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
using ProtonVPN.Client.Core.Services.Activation;
using ProtonVPN.Client.Core.Services.Navigation;
using ProtonVPN.Client.EventMessaging.Contracts;
using ProtonVPN.Client.Localization.Extensions;
using ProtonVPN.Client.Logic.Connection.Contracts;
using ProtonVPN.Client.Logic.Connection.Contracts.Models.Intents;
using ProtonVPN.Client.Logic.Connection.Contracts.Models.Intents.Locations.Countries;
using ProtonVPN.Client.Logic.Connection.Contracts.MultiTunnel;
using ProtonVPN.Client.Logic.Servers.Contracts;
using ProtonVPN.Client.Logic.Servers.Contracts.Messages;
using ProtonVPN.Client.Logic.Servers.Contracts.Models;
using ProtonVPN.Client.Settings.Contracts;
using ProtonVPN.Client.Settings.Contracts.RequiredReconnections;
using ProtonVPN.Client.UI.Main.Home.Details.Connection;
using ProtonVPN.Client.UI.Main.Settings.Bases;
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
}

public partial class MultiTunnelPageViewModel : SettingsPageViewModelBase,
    IEventMessageReceiver<MultiTunnelPolicyChangedMessage>,
    IEventMessageReceiver<ServerListChangedMessage>
{
    private readonly IMultiTunnelManager _multiTunnelManager;
    private readonly IServersLoader _serversLoader;
    private readonly List<MultiTunnelPresetItem> _allPresets = [];
    private bool _isRefreshing;

    [ObservableProperty]
    private string? _selectedPresetCategory = "All";

    [ObservableProperty]
    private string _presetSearchQuery = string.Empty;

    [ObservableProperty]
    private string? _selectedPresetTargetType = "Preset Default";

    [ObservableProperty]
    private string? _selectedPresetTunnelId = "T1";

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

    public bool IsPresetTargetTunnel => string.Equals(SelectedPresetTargetType, "Tunnel", StringComparison.OrdinalIgnoreCase);

    public bool IsPresetFallbackAllowed =>
        !string.Equals(SelectedPresetTargetType, "Direct", StringComparison.OrdinalIgnoreCase) &&
        !string.Equals(SelectedPresetTargetType, "Block", StringComparison.OrdinalIgnoreCase);

    public bool IsPresetFallbackTunnel => IsPresetFallbackAllowed &&
                                          string.Equals(SelectedPresetFallbackBehavior, "FallbackToTunnel", StringComparison.OrdinalIgnoreCase);

    public bool HasPresetStatus => !string.IsNullOrWhiteSpace(PresetStatusText);

    public bool CanAddSlot => Slots.Count < MultiTunnelSlotConfig.MaxSlots;

    public IReadOnlyList<string> TargetTypeOptions { get; } = ["Direct", "Tunnel", "Block"];
    public IReadOnlyList<string> ProtocolOptions { get; } = ["Any", "Tcp", "Udp"];
    public IReadOnlyList<string> FallbackOptions { get; } = ["KillSwitchBlock", "FallbackToTunnel", "FallbackToDirect"];
    public IReadOnlyList<string> PresetCategoryOptions { get; } = ["All", "BigTech", "Social", "AiDev", "MediaGaming", "Network"];
    public IReadOnlyList<string> PresetTargetTypeOptions { get; } = ["Preset Default", "Direct", "Tunnel", "Block"];
    public IReadOnlyList<string> PresetFallbackOptions { get; } = ["Preset Default", "KillSwitchBlock", "FallbackToTunnel", "FallbackToDirect"];

    public ObservableCollection<string> SlotIdOptions { get; } = ["T1", "T2", "T3", "T4", "T5"];
    public ObservableCollection<string> SlotPickerTargets { get; } = ["NEW", "T1"];
    public ObservableCollection<SlotCountryOption> AvailableCountries { get; } = [];
    public ObservableCollection<SlotServerOption> AvailableServers { get; } = [];
    public ObservableCollection<MultiTunnelSlotItem> Slots { get; } = [];
    public ObservableCollection<MultiTunnelRuleItem> Rules { get; } = [];
    public ObservableCollection<MultiTunnelPresetItem> FilteredPresets { get; } = [];
    public ObservableCollection<string> ConflictMessages { get; } = [];

    public MultiTunnelPageViewModel(
        IRequiredReconnectionSettings requiredReconnectionSettings,
        IMainViewNavigator mainViewNavigator,
        ISettingsViewNavigator settingsViewNavigator,
        IMainWindowOverlayActivator mainWindowOverlayActivator,
        ISettings settings,
        ISettingsConflictResolver settingsConflictResolver,
        IConnectionManager connectionManager,
        IMultiTunnelManager multiTunnelManager,
        IServersLoader serversLoader,
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
        _multiTunnelManager = multiTunnelManager;
        _serversLoader = serversLoader;

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
        ExecuteOnUIThread(RefreshState);
    }

    public void Receive(ServerListChangedMessage message)
    {
        ExecuteOnUIThread(LoadCountries);
    }

    partial void OnIsMultiTunnelEnabledChanged(bool value)
    {
        if (!_isRefreshing)
        {
            _ = _multiTunnelManager.SetEnabledAsync(value);
        }
    }

    partial void OnSelectedDefaultTargetTypeChanged(string? value)
    {
        OnPropertyChanged(nameof(IsDefaultTargetTunnel));
        if (!_isRefreshing && !string.IsNullOrWhiteSpace(value) && Enum.TryParse(value, out RuleTargetTypeIpcEntity target))
        {
            _ = _multiTunnelManager.SetDefaultRoutingAsync(target, SelectedDefaultTunnelId ?? "T1");
        }
    }

    partial void OnSelectedDefaultTunnelIdChanged(string? value)
    {
        if (!_isRefreshing && !string.IsNullOrWhiteSpace(value) &&
            Enum.TryParse(SelectedDefaultTargetType, out RuleTargetTypeIpcEntity target))
        {
            _ = _multiTunnelManager.SetDefaultRoutingAsync(target, value);
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

    partial void OnSelectedPresetTargetTypeChanged(string? value)
    {
        OnPropertyChanged(nameof(IsPresetTargetTunnel));
        OnPropertyChanged(nameof(IsPresetFallbackAllowed));
        OnPropertyChanged(nameof(IsPresetFallbackTunnel));
    }

    partial void OnSelectedPresetFallbackBehaviorChanged(string? value)
    {
        OnPropertyChanged(nameof(IsPresetFallbackTunnel));
    }

    partial void OnPresetStatusTextChanged(string value)
    {
        OnPropertyChanged(nameof(HasPresetStatus));
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
    public Task ReplaceWithSelectedPresetsAsync() => ApplySelectedPresetsAsync(RoutingPresetApplyMode.Replace);

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
            PresetStatusText = "Select one or more service templates first.";
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

        PresetStatusText = mode == RoutingPresetApplyMode.Replace
            ? $"Replaced routing rules with {applied} template rule(s)."
            : $"Added {applied} template rule(s) to the top of the priority list.";
        ClearSelectedPresets();
    }

    private (RuleTargetTypeIpcEntity? TargetType, string? TargetTunnelId, TunnelFallbackBehaviorIpcEntity? Fallback, string? FallbackTunnelId) ParsePresetOverrides()
    {
        RuleTargetTypeIpcEntity? targetType = null;
        string? targetTunnelId = null;
        TunnelFallbackBehaviorIpcEntity? fallbackBehavior = null;
        string? fallbackTunnelId = null;

        if (!string.Equals(SelectedPresetTargetType, "Preset Default", StringComparison.OrdinalIgnoreCase) &&
            Enum.TryParse(SelectedPresetTargetType, out RuleTargetTypeIpcEntity parsedTarget))
        {
            targetType = parsedTarget;
            if (parsedTarget == RuleTargetTypeIpcEntity.Tunnel)
            {
                targetTunnelId = string.IsNullOrWhiteSpace(SelectedPresetTunnelId) ? "T1" : SelectedPresetTunnelId;
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

        MultiTunnelRuleConfig rule = new()
        {
            Id = EditingRuleId ?? Guid.NewGuid(),
            Name = name,
            IsEnabled = true,
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
                    StatusText = slot.IsConnecting ? "Connecting..." : (slot.IsConnected ? "Connected" : "Ready"),
                    IsConnected = slot.IsConnected,
                    IsConnecting = slot.IsConnecting,
                    LastError = slot.LastError,
                    SlotColorBrush = SlotColorBrushHelper.ToBrush(MultiTunnelSlotConfig.GetSlotColorHex(slot.SlotId)),
                    CanRemove = !string.Equals(slot.SlotId, "T1", StringComparison.OrdinalIgnoreCase),
                    SlotSummary = $"{countryDisplay} ({slot.CountryCode}) • {slot.ServerName} • {slot.ClientIpv4}",
                });

                SlotPickerTargets.Add(slot.SlotId);
            }

            if (string.IsNullOrWhiteSpace(SelectedEditSlotId) || !SlotPickerTargets.Contains(SelectedEditSlotId))
            {
                SelectedEditSlotId = "NEW";
            }

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
                    FallbackBadge = rule.FallbackSummary,
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
            .Where(s => string.Equals(s.ExitCountry, countryCode, StringComparison.OrdinalIgnoreCase) && !s.IsUnderMaintenance())
            .OrderByDescending(s => s.Score)
            .Take(25);

        foreach (Server srv in matching)
        {
            string entryIp = srv.Servers?.FirstOrDefault()?.EntryIp ?? string.Empty;
            string label = string.IsNullOrWhiteSpace(srv.City)
                ? $"{srv.Name} (Load {srv.Load}%)"
                : $"{srv.Name} — {srv.City} ({srv.Load}%)";
            AvailableServers.Add(new SlotServerOption(srv.Id, srv.Name, srv.City, entryIp, label));
        }

        SelectedPickerServer = AvailableServers.FirstOrDefault();
    }

    private static string? NullIfBlank(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
