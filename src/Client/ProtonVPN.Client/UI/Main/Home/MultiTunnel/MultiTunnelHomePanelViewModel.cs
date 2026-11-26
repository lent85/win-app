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
using ProtonVPN.Client.Core.Bases;
using ProtonVPN.Client.Core.Bases.ViewModels;
using ProtonVPN.Client.Core.Extensions;
using ProtonVPN.Client.Core.Models;
using ProtonVPN.Client.Core.Services.Activation;
using ProtonVPN.Client.Core.Services.Navigation;
using ProtonVPN.Client.EventMessaging.Contracts;
using ProtonVPN.Client.Localization.Extensions;
using ProtonVPN.Client.Logic.Connection.Contracts;
using ProtonVPN.Client.Logic.Connection.Contracts.Messages;
using ProtonVPN.Client.Logic.Connection.Contracts.Models.Intents;
using ProtonVPN.Client.Logic.Connection.Contracts.Models.Intents.Locations.Countries;
using ProtonVPN.Client.Logic.Connection.Contracts.MultiTunnel;
using ProtonVPN.Client.Logic.Servers.Contracts;
using ProtonVPN.Client.Logic.Servers.Contracts.Messages;
using ProtonVPN.Client.Logic.Servers.Contracts.Models;
using ProtonVPN.Client.UI.Main.Home.Details.Connection;
using ProtonVPN.Client.UI.Main.Settings.Pages.Connection;
using ProtonVPN.ProcessCommunication.Contracts.Entities.MultiTunnel;
using ProtonVPN.StatisticalEvents.Contracts.Dimensions;

namespace ProtonVPN.Client.UI.Main.Home.MultiTunnel;

public sealed record RoutingPresetOption(string Id, string DisplayName, string ConditionPreview)
{
    public override string ToString() => DisplayName;
}

public sealed record QuickRouteOption(string Key, string DisplayName)
{
    public override string ToString() => DisplayName;
}

public partial class MultiTunnelHomePanelViewModel : ActivatableViewModelBase,
    IEventMessageReceiver<MultiTunnelPolicyChangedMessage>,
    IEventMessageReceiver<ServerListChangedMessage>,
    IEventMessageReceiver<ConnectionStatusChangedMessage>
{
    private readonly IMultiTunnelManager _multiTunnelManager;
    private readonly IServersLoader _serversLoader;
    private readonly IConnectionManager _connectionManager;
    private readonly IMainViewNavigator _mainViewNavigator;
    private readonly ISettingsViewNavigator _settingsViewNavigator;
    private readonly IMainWindowActivator _mainWindowActivator;
    private bool _isRefreshing;

    private bool _isMultiTunnelEnabled;
    private bool _isExpanded = true;
    private bool _isPipelinesTabSelected = true;
    private bool _isRulesTabSelected;
    private bool _isSimulatorTabSelected;
    private string _summaryText = string.Empty;
    private string? _selectedDefaultTargetType = "Direct";
    private string? _selectedDefaultTunnelId = "T1";
    private SlotCountryOption? _selectedPickerCountry;
    private SlotServerOption? _selectedPickerServer;
    private string? _selectedEditSlotId = "NEW";
    private string _slotPickerStatus = string.Empty;
    private bool _hasConflicts;

    private Guid? _editingRuleId;
    private string _quickRuleName = string.Empty;
    private string _quickRuleApp = string.Empty;
    private string _quickRuleDomain = string.Empty;
    private string _quickRuleIpOrPort = string.Empty;
    private string? _quickRuleTargetType = "Tunnel";
    private string? _quickRuleTunnelId = "T1";
    private string _quickRuleStatus = string.Empty;

    private RoutingPresetOption? _selectedQuickPreset;
    private QuickRouteOption? _selectedQuickPresetRoute;

    private string _simApp = "chrome";
    private string _simDomain = "api.openai.com";
    private string _simRemoteIp = string.Empty;
    private string _simPort = "443";
    private string? _simProtocol = "Tcp";
    private string _simResultSummary = string.Empty;
    private string _simResultDetails = string.Empty;
    private bool _hasSimResult;

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

    public bool IsExpanded
    {
        get => _isExpanded;
        set
        {
            if (SetProperty(ref _isExpanded, value))
            {
                OnPropertyChanged(nameof(ExpandButtonGlyph));
            }
        }
    }

    public string ExpandButtonGlyph => IsExpanded ? "\uE70E" : "\uE70D";

    public bool IsPipelinesTabSelected
    {
        get => _isPipelinesTabSelected;
        set => SetProperty(ref _isPipelinesTabSelected, value);
    }

    public bool IsRulesTabSelected
    {
        get => _isRulesTabSelected;
        set => SetProperty(ref _isRulesTabSelected, value);
    }

    public bool IsSimulatorTabSelected
    {
        get => _isSimulatorTabSelected;
        set => SetProperty(ref _isSimulatorTabSelected, value);
    }

    public string PipelinesTabHeader => $"Pipelines ({Slots.Count}/{MultiTunnelSlotConfig.MaxSlots})";

    public string RulesTabHeader => $"Rules ({Rules.Count})";

    public string SummaryText
    {
        get => _summaryText;
        private set => SetProperty(ref _summaryText, value);
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

    public SlotCountryOption? SelectedPickerCountry
    {
        get => _selectedPickerCountry;
        set
        {
            if (SetProperty(ref _selectedPickerCountry, value))
            {
                PopulateServersForCountry(value?.CountryCode);
            }
        }
    }

    public SlotServerOption? SelectedPickerServer
    {
        get => _selectedPickerServer;
        set => SetProperty(ref _selectedPickerServer, value);
    }

    public string? SelectedEditSlotId
    {
        get => _selectedEditSlotId;
        set => SetProperty(ref _selectedEditSlotId, value);
    }

    public string SlotPickerStatus
    {
        get => _slotPickerStatus;
        private set
        {
            if (SetProperty(ref _slotPickerStatus, value))
            {
                OnPropertyChanged(nameof(HasSlotPickerStatus));
            }
        }
    }

    public bool HasSlotPickerStatus => !string.IsNullOrWhiteSpace(SlotPickerStatus);

    public bool HasConflicts
    {
        get => _hasConflicts;
        private set => SetProperty(ref _hasConflicts, value);
    }

    public bool IsEditingRule => _editingRuleId.HasValue;

    public string QuickRuleSaveButtonText => IsEditingRule ? "Save" : "+ Rule";

    public string QuickRuleName
    {
        get => _quickRuleName;
        set => SetProperty(ref _quickRuleName, value);
    }

    public string QuickRuleApp
    {
        get => _quickRuleApp;
        set => SetProperty(ref _quickRuleApp, value);
    }

    public string QuickRuleDomain
    {
        get => _quickRuleDomain;
        set => SetProperty(ref _quickRuleDomain, value);
    }

    public string QuickRuleIpOrPort
    {
        get => _quickRuleIpOrPort;
        set => SetProperty(ref _quickRuleIpOrPort, value);
    }

    public string? QuickRuleTargetType
    {
        get => _quickRuleTargetType;
        set
        {
            if (SetProperty(ref _quickRuleTargetType, value))
            {
                OnPropertyChanged(nameof(IsQuickRuleTargetTunnel));
            }
        }
    }

    public string? QuickRuleTunnelId
    {
        get => _quickRuleTunnelId;
        set => SetProperty(ref _quickRuleTunnelId, value);
    }

    public bool IsQuickRuleTargetTunnel =>
        string.Equals(QuickRuleTargetType, "Tunnel", StringComparison.OrdinalIgnoreCase);

    public string QuickRuleStatus
    {
        get => _quickRuleStatus;
        private set
        {
            if (SetProperty(ref _quickRuleStatus, value))
            {
                OnPropertyChanged(nameof(HasQuickRuleStatus));
            }
        }
    }

    public bool HasQuickRuleStatus => !string.IsNullOrWhiteSpace(QuickRuleStatus);

    public RoutingPresetOption? SelectedQuickPreset
    {
        get => _selectedQuickPreset;
        set => SetProperty(ref _selectedQuickPreset, value);
    }

    public QuickRouteOption? SelectedQuickPresetRoute
    {
        get => _selectedQuickPresetRoute;
        set => SetProperty(ref _selectedQuickPresetRoute, value);
    }

    public string SimApp
    {
        get => _simApp;
        set => SetProperty(ref _simApp, value);
    }

    public string SimDomain
    {
        get => _simDomain;
        set => SetProperty(ref _simDomain, value);
    }

    public string SimRemoteIp
    {
        get => _simRemoteIp;
        set => SetProperty(ref _simRemoteIp, value);
    }

    public string SimPort
    {
        get => _simPort;
        set => SetProperty(ref _simPort, value);
    }

    public string? SimProtocol
    {
        get => _simProtocol;
        set => SetProperty(ref _simProtocol, value);
    }

    public string SimResultSummary
    {
        get => _simResultSummary;
        private set => SetProperty(ref _simResultSummary, value);
    }

    public string SimResultDetails
    {
        get => _simResultDetails;
        private set => SetProperty(ref _simResultDetails, value);
    }

    public bool HasSimResult
    {
        get => _hasSimResult;
        private set => SetProperty(ref _hasSimResult, value);
    }

    public IReadOnlyList<string> TargetTypeOptions { get; } = ["Direct", "Tunnel", "Block"];
    public IReadOnlyList<string> ProtocolOptions { get; } = ["Any", "Tcp", "Udp"];
    public ObservableCollection<string> SlotIdOptions { get; } = ["T1", "T2", "T3", "T4", "T5"];
    public ObservableCollection<string> SlotPickerTargets { get; } = ["NEW", "T1"];
    public ObservableCollection<SlotCountryOption> AvailableCountries { get; } = [];
    public ObservableCollection<SlotServerOption> AvailableServers { get; } = [];
    public ObservableCollection<MultiTunnelSlotItem> Slots { get; } = [];
    public ObservableCollection<MultiTunnelRuleItem> Rules { get; } = [];
    public ObservableCollection<string> ConflictMessages { get; } = [];
    public ObservableCollection<RoutingPresetOption> AvailablePresets { get; } = [];
    public ObservableCollection<QuickRouteOption> QuickPresetRouteOptions { get; } = [];

    public MultiTunnelHomePanelViewModel(
        IMultiTunnelManager multiTunnelManager,
        IServersLoader serversLoader,
        IConnectionManager connectionManager,
        IMainViewNavigator mainViewNavigator,
        ISettingsViewNavigator settingsViewNavigator,
        IMainWindowActivator mainWindowActivator,
        IViewModelHelper viewModelHelper)
        : base(viewModelHelper)
    {
        _multiTunnelManager = multiTunnelManager;
        _serversLoader = serversLoader;
        _connectionManager = connectionManager;
        _mainViewNavigator = mainViewNavigator;
        _settingsViewNavigator = settingsViewNavigator;
        _mainWindowActivator = mainWindowActivator;

        foreach (RoutingRulePreset preset in MultiTunnelRoutingPresetCatalog.All)
        {
            AvailablePresets.Add(new RoutingPresetOption(preset.Id, preset.Name, preset.ConditionPreview));
        }
        SelectedQuickPreset = AvailablePresets.FirstOrDefault();
    }

    protected override void OnActivated()
    {
        base.OnActivated();
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

    public void Receive(ConnectionStatusChangedMessage message)
    {
        ExecuteOnUIThread(RefreshState);
    }

    [RelayCommand]
    private void ToggleExpanded()
    {
        IsExpanded = !IsExpanded;
    }

    [RelayCommand]
    private async Task OpenFullConfigAsync()
    {
        await _mainViewNavigator.NavigateToSettingsViewAsync();
        await _settingsViewNavigator.NavigateToMultiTunnelSettingsViewAsync(isDirectNavigation: true);
    }

    [RelayCommand]
    private async Task AddOrUpdateSlotAsync()
    {
        if (SelectedPickerCountry is null)
        {
            SlotPickerStatus = "Select a country first.";
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
                ? $"Max {MultiTunnelSlotConfig.MaxSlots} slots (T1-T5) reached."
                : $"Added {added.SlotId} -> {SelectedPickerCountry.DisplayName} ({serverName}).";
        }
        else
        {
            await _multiTunnelManager.UpdateSlotLocationAsync(targetSlot, countryCode, serverName, city, entryIp);
            SlotPickerStatus = $"Updated {targetSlot} -> {SelectedPickerCountry.DisplayName} ({serverName}).";
        }
    }

    [RelayCommand]
    private async Task SaveQuickRuleAsync()
    {
        string rawIpOrPort = QuickRuleIpOrPort.Trim();
        string? ipCidr = null;
        string? port = null;
        if (!string.IsNullOrWhiteSpace(rawIpOrPort))
        {
            if (rawIpOrPort.Contains('.') || rawIpOrPort.Contains(':') || rawIpOrPort.Contains('/'))
            {
                ipCidr = rawIpOrPort;
            }
            else
            {
                port = rawIpOrPort;
            }
        }

        RuleTargetTypeIpcEntity target = Enum.TryParse(QuickRuleTargetType, out RuleTargetTypeIpcEntity parsedTarget)
            ? parsedTarget
            : RuleTargetTypeIpcEntity.Tunnel;

        MultiTunnelRuleConfig? existing = _editingRuleId.HasValue
            ? _multiTunnelManager.Rules.FirstOrDefault(r => r.Id == _editingRuleId.Value)
            : null;

        MultiTunnelRuleConfig rule = new()
        {
            Id = existing?.Id ?? Guid.NewGuid(),
            PriorityOrder = existing?.PriorityOrder ?? 0,
            Name = string.IsNullOrWhiteSpace(QuickRuleName) ? "Quick Rule" : QuickRuleName.Trim(),
            IsEnabled = existing?.IsEnabled ?? true,
            AppPattern = NullIfBlank(QuickRuleApp),
            DomainPattern = NullIfBlank(QuickRuleDomain),
            IpCidrPattern = ipCidr,
            PortPattern = port,
            Protocol = existing?.Protocol ?? RuleProtocolIpcEntity.Any,
            TargetType = target,
            TargetTunnelId = string.IsNullOrWhiteSpace(QuickRuleTunnelId) ? "T1" : QuickRuleTunnelId,
            FallbackBehavior = existing?.FallbackBehavior ?? TunnelFallbackBehaviorIpcEntity.KillSwitchBlock,
            FallbackTunnelId = existing?.FallbackTunnelId,
        };

        if (!rule.HasAnyCondition)
        {
            QuickRuleStatus = "Enter at least one match (App, Domain, IP/CIDR, or Port).";
            return;
        }

        if (existing is not null)
        {
            await _multiTunnelManager.UpdateRuleAsync(rule);
            QuickRuleStatus = $"Updated rule '{rule.Name}' -> {rule.TargetSummary}.";
        }
        else
        {
            await _multiTunnelManager.AddRuleAsync(rule);
            QuickRuleStatus = $"Added rule '{rule.Name}' -> {rule.TargetSummary}.";
        }

        ResetQuickRuleEditorState();
    }

    [RelayCommand]
    private void CancelEditRule()
    {
        ResetQuickRuleEditorState();
        QuickRuleStatus = string.Empty;
    }

    [RelayCommand]
    private async Task BrowseQuickRuleAppAsync()
    {
        if (_mainWindowActivator.Window == null)
        {
            return;
        }

        string filePath = await _mainWindowActivator.Window.PickSingleFileAsync(
            Localizer.Get("Settings_Connection_SplitTunneling_Apps_FilesFilterName"),
            [ExternalApp.EXE_FILE_EXTENSION]);

        if (string.IsNullOrWhiteSpace(filePath))
        {
            return;
        }

        List<string> existing = QuickRuleApp
            .Split([',', ';', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();
        if (!existing.Contains(filePath, StringComparer.OrdinalIgnoreCase))
        {
            existing.Add(filePath);
            QuickRuleApp = string.Join(", ", existing);
        }

        QuickRuleStatus = $"Selected executable: {Path.GetFileName(filePath)}";
    }

    [RelayCommand]
    private Task AddSelectedPresetAsync() => ApplyQuickPresetAsync(RoutingPresetApplyMode.Add);

    [RelayCommand]
    private Task ReplaceWithSelectedPresetAsync()
    {
        string key = SelectedQuickPresetRoute?.Key ?? "PRESET_DEFAULT";
        RoutingPresetApplyMode mode = string.Equals(key, "PRESET_DEFAULT", StringComparison.OrdinalIgnoreCase)
            ? RoutingPresetApplyMode.Replace
            : RoutingPresetApplyMode.ReplaceTarget;
        return ApplyQuickPresetAsync(mode);
    }

    private async Task ApplyQuickPresetAsync(RoutingPresetApplyMode mode)
    {
        RoutingRulePreset? preset = MultiTunnelRoutingPresetCatalog.FindById(SelectedQuickPreset?.Id);
        if (preset is null)
        {
            QuickRuleStatus = "Select a service template first.";
            return;
        }

        RuleTargetTypeIpcEntity? targetTypeOverride = null;
        string? targetTunnelOverride = null;
        string routeChoice = SelectedQuickPresetRoute?.Key?.Trim() ?? "PRESET_DEFAULT";
        string targetDisplay = SelectedQuickPresetRoute?.DisplayName ?? "Preset Default";
        if (!string.Equals(routeChoice, "PRESET_DEFAULT", StringComparison.OrdinalIgnoreCase))
        {
            if (string.Equals(routeChoice, "DIRECT", StringComparison.OrdinalIgnoreCase))
            {
                targetTypeOverride = RuleTargetTypeIpcEntity.Direct;
            }
            else if (string.Equals(routeChoice, "BLOCK", StringComparison.OrdinalIgnoreCase))
            {
                targetTypeOverride = RuleTargetTypeIpcEntity.Block;
            }
            else
            {
                targetTypeOverride = RuleTargetTypeIpcEntity.Tunnel;
                targetTunnelOverride = routeChoice.ToUpperInvariant();
            }
        }

        await _multiTunnelManager.ApplyRoutingPresetsAsync([preset], mode, targetTypeOverride, targetTunnelOverride);
        QuickRuleStatus = mode switch
        {
            RoutingPresetApplyMode.Replace => $"Replaced all routing rules with '{preset.Name}'.",
            RoutingPresetApplyMode.ReplaceTarget => $"Replaced {targetDisplay} rules with '{preset.Name}'.",
            _ => $"Assigned '{preset.Name}' -> {targetDisplay}.",
        };
    }

    public void OpenTemplatesForSlot(string slotId)
    {
        QuickRouteOption? match = QuickPresetRouteOptions.FirstOrDefault(o =>
            string.Equals(o.Key, slotId, StringComparison.OrdinalIgnoreCase));
        if (match is not null)
        {
            SelectedQuickPresetRoute = match;
        }

        QuickRuleTargetType = "Tunnel";
        QuickRuleTunnelId = slotId;
        QuickRuleStatus = $"Pick a service template or add a rule -> {match?.DisplayName ?? slotId}.";

        IsPipelinesTabSelected = false;
        IsSimulatorTabSelected = false;
        IsRulesTabSelected = true;
    }

    [RelayCommand]
    private async Task RunSimulationAsync()
    {
        int? parsedPort = int.TryParse(SimPort, out int p) ? p : null;
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
            SlotPickerStatus = $"Disconnected {slot.SlotId}.";
        }
        else
        {
            bool ok = await _multiTunnelManager.ConnectSlotAsync(slot.SlotId);
            MultiTunnelSlotConfig? updated = _multiTunnelManager.Slots.FirstOrDefault(s =>
                string.Equals(s.SlotId, slot.SlotId, StringComparison.OrdinalIgnoreCase));
            SlotPickerStatus = ok
                ? string.Empty
                : (updated?.LastError ?? $"Failed to connect {slot.SlotId}.");
        }
    }

    public void SelectSlotForEdit(string slotId)
    {
        if (SlotPickerTargets.Contains(slotId))
        {
            SelectedEditSlotId = slotId;
        }

        MultiTunnelSlotConfig? slot = _multiTunnelManager.Slots.FirstOrDefault(s =>
            string.Equals(s.SlotId, slotId, StringComparison.OrdinalIgnoreCase));
        if (slot is not null)
        {
            SlotCountryOption? match = AvailableCountries.FirstOrDefault(c =>
                string.Equals(c.CountryCode, slot.CountryCode, StringComparison.OrdinalIgnoreCase));
            if (match is not null)
            {
                SelectedPickerCountry = match;
            }
            SlotPickerStatus = $"Editing {slotId} — pick country/server and click + Apply.";
        }
    }

    public void BeginEditRule(Guid ruleId)
    {
        MultiTunnelRuleConfig? rule = _multiTunnelManager.Rules.FirstOrDefault(r => r.Id == ruleId);
        if (rule is null)
        {
            return;
        }

        _editingRuleId = rule.Id;
        QuickRuleName = rule.Name;
        QuickRuleApp = rule.AppPattern ?? string.Empty;
        QuickRuleDomain = rule.DomainPattern ?? string.Empty;
        QuickRuleIpOrPort = !string.IsNullOrWhiteSpace(rule.IpCidrPattern)
            ? rule.IpCidrPattern
            : (rule.PortPattern ?? string.Empty);
        QuickRuleTargetType = rule.TargetType.ToString();
        QuickRuleTunnelId = string.IsNullOrWhiteSpace(rule.TargetTunnelId) ? "T1" : rule.TargetTunnelId;
        QuickRuleStatus = $"Editing '{rule.Name}' — click Save to apply.";

        IsPipelinesTabSelected = false;
        IsSimulatorTabSelected = false;
        IsRulesTabSelected = true;

        OnPropertyChanged(nameof(IsEditingRule));
        OnPropertyChanged(nameof(QuickRuleSaveButtonText));
    }

    public Task RemoveSlotAsync(string slotId) => _multiTunnelManager.RemoveSlotAsync(slotId);
    public Task SetRuleEnabledAsync(Guid ruleId, bool isEnabled) => _multiTunnelManager.SetRuleEnabledAsync(ruleId, isEnabled);
    public Task MoveRuleUpAsync(Guid ruleId) => _multiTunnelManager.MoveRuleAsync(ruleId, -1);
    public Task MoveRuleDownAsync(Guid ruleId) => _multiTunnelManager.MoveRuleAsync(ruleId, 1);

    public async Task DeleteRuleAsync(Guid ruleId)
    {
        if (_editingRuleId == ruleId)
        {
            ResetQuickRuleEditorState();
            QuickRuleStatus = string.Empty;
        }

        await _multiTunnelManager.DeleteRuleAsync(ruleId);
    }

    private void ResetQuickRuleEditorState()
    {
        _editingRuleId = null;
        QuickRuleName = string.Empty;
        QuickRuleApp = string.Empty;
        QuickRuleDomain = string.Empty;
        QuickRuleIpOrPort = string.Empty;
        QuickRuleTargetType = "Tunnel";
        QuickRuleTunnelId = "T1";
        OnPropertyChanged(nameof(IsEditingRule));
        OnPropertyChanged(nameof(QuickRuleSaveButtonText));
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

            Dictionary<string, int> ruleCountsBySlot = _multiTunnelManager.Rules
                .Where(r => r.IsEnabled && r.TargetType == RuleTargetTypeIpcEntity.Tunnel)
                .GroupBy(
                    r => string.IsNullOrWhiteSpace(r.TargetTunnelId) ? "T1" : r.TargetTunnelId.Trim().ToUpperInvariant(),
                    StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);

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
                    RuleCount = ruleCountsBySlot.GetValueOrDefault(slot.SlotId, 0),
                });

                SlotPickerTargets.Add(slot.SlotId);
            }

            if (string.IsNullOrWhiteSpace(SelectedEditSlotId) || !SlotPickerTargets.Contains(SelectedEditSlotId))
            {
                SelectedEditSlotId = "NEW";
            }

            string? prevQuickRouteKey = SelectedQuickPresetRoute?.Key;
            QuickPresetRouteOptions.Clear();
            foreach (MultiTunnelSlotConfig slot in _multiTunnelManager.Slots)
            {
                string cc = string.IsNullOrWhiteSpace(slot.CountryCode) ? "Auto" : slot.CountryCode;
                QuickPresetRouteOptions.Add(new QuickRouteOption(slot.SlotId, $"{slot.SlotId} · {cc}"));
            }
            QuickPresetRouteOptions.Add(new QuickRouteOption("DIRECT", "Direct"));
            QuickPresetRouteOptions.Add(new QuickRouteOption("BLOCK", "Block"));
            QuickPresetRouteOptions.Add(new QuickRouteOption("PRESET_DEFAULT", "Preset Default"));

            SelectedQuickPresetRoute = (!string.IsNullOrWhiteSpace(prevQuickRouteKey)
                ? QuickPresetRouteOptions.FirstOrDefault(o => string.Equals(o.Key, prevQuickRouteKey, StringComparison.OrdinalIgnoreCase))
                : null) ?? QuickPresetRouteOptions.FirstOrDefault();

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
                $"{_multiTunnelManager.ConnectedSlotCount}/{Slots.Count} slots  •  " +
                $"{_multiTunnelManager.EnabledRuleCount}/{Rules.Count} rules" +
                (HasConflicts ? $"  •  {ConflictMessages.Count} conflict(s)" : string.Empty);

            OnPropertyChanged(nameof(IsDefaultTargetTunnel));
            OnPropertyChanged(nameof(PipelinesTabHeader));
            OnPropertyChanged(nameof(RulesTabHeader));
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
