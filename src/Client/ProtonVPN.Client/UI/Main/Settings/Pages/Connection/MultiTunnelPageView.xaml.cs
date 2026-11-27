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

using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using ProtonVPN.Client.Core.Bases;

namespace ProtonVPN.Client.UI.Main.Settings.Pages.Connection;

public sealed partial class MultiTunnelPageView : IContextAware
{
    public MultiTunnelPageViewModel ViewModel { get; }

    public MultiTunnelPageView()
    {
        ViewModel = App.GetService<MultiTunnelPageViewModel>();

        InitializeComponent();

        Loaded += OnLoaded;
        Unloaded += OnUnloaded;

        ViewModel.ResetContentScrollRequested += OnResetContentScrollRequested;
    }

    public object GetContext()
    {
        return ViewModel;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        ViewModel.Activate();
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        ViewModel.Deactivate();
    }

    private void OnResetContentScrollRequested(object? sender, EventArgs e)
    {
        PageContentHost.ResetContentScroll();
    }

    private static async void RunSafeAsync(Func<Task> action)
    {
        try
        {
            await action();
        }
        catch
        {
        }
    }

    private void OnConnectSlotClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string slotId })
        {
            RunSafeAsync(() => ViewModel.ConnectSlotAsync(slotId));
        }
    }

    private void OnRemoveSlotClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string slotId })
        {
            RunSafeAsync(() => ViewModel.RemoveSlotAsync(slotId));
        }
    }

    private void OnCopySlotPortClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string slotId })
        {
            RunSafeAsync(() => ViewModel.CopySlotPortAsync(slotId));
        }
    }

    private void OnToggleSlotPortForwardingClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string slotId })
        {
            RunSafeAsync(() => ViewModel.ToggleSlotPortForwardingAsync(slotId));
        }
    }

    private void OnAssignTemplatesToSlotClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string slotId })
        {
            ViewModel.SelectPresetTarget(slotId);
            PresetSectionBorder.StartBringIntoView();
        }
    }

    private void OnSelectPresetTargetClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string targetKey })
        {
            ViewModel.SelectPresetTarget(targetKey);
        }
    }

    private void OnQuickAssignPresetClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string presetId })
        {
            RunSafeAsync(() => ViewModel.QuickTogglePresetForTargetAsync(presetId));
        }
    }

    private void OnPickDiscoveredAppClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string executablePath })
        {
            ViewModel.PickDiscoveredApp(executablePath);
        }
    }

    private void OnRuleEnabledClick(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox { Tag: Guid ruleId } cb)
        {
            bool isEnabled = cb.IsChecked == true;
            RunSafeAsync(() => ViewModel.SetRuleEnabledAsync(ruleId, isEnabled));
        }
    }

    private void OnMoveRuleUpClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: Guid ruleId })
        {
            RunSafeAsync(() => ViewModel.MoveRuleUpAsync(ruleId));
        }
    }

    private void OnMoveRuleDownClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: Guid ruleId })
        {
            RunSafeAsync(() => ViewModel.MoveRuleDownAsync(ruleId));
        }
    }

    private void OnEditRuleClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: Guid ruleId })
        {
            ViewModel.BeginEditRule(ruleId);
        }
    }

    private void OnDeleteRuleClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: Guid ruleId })
        {
            RunSafeAsync(() => ViewModel.DeleteRuleAsync(ruleId));
        }
    }

    private void OnPresetCheckClick(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox { Tag: string presetId } cb)
        {
            ViewModel.SetPresetSelected(presetId, cb.IsChecked == true);
        }
    }
}
