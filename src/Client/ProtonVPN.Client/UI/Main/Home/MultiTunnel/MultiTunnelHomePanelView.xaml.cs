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

namespace ProtonVPN.Client.UI.Main.Home.MultiTunnel;

public sealed partial class MultiTunnelHomePanelView : IContextAware
{
    public MultiTunnelHomePanelViewModel ViewModel { get; }

    public MultiTunnelHomePanelView()
    {
        ViewModel = App.GetService<MultiTunnelHomePanelViewModel>();

        InitializeComponent();

        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
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

    private async void OnConnectSlotClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string slotId })
        {
            await ViewModel.ConnectSlotAsync(slotId);
        }
    }

    private void OnEditSlotClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string slotId })
        {
            ViewModel.SelectSlotForEdit(slotId);
        }
    }

    private async void OnRemoveSlotClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string slotId })
        {
            await ViewModel.RemoveSlotAsync(slotId);
        }
    }

    private async void OnRuleEnabledClick(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox { Tag: Guid ruleId } cb)
        {
            await ViewModel.SetRuleEnabledAsync(ruleId, cb.IsChecked == true);
        }
    }

    private async void OnMoveRuleUpClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: Guid ruleId })
        {
            await ViewModel.MoveRuleUpAsync(ruleId);
        }
    }

    private async void OnMoveRuleDownClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: Guid ruleId })
        {
            await ViewModel.MoveRuleDownAsync(ruleId);
        }
    }

    private void OnEditRuleClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: Guid ruleId })
        {
            ViewModel.BeginEditRule(ruleId);
        }
    }

    private async void OnDeleteRuleClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: Guid ruleId })
        {
            await ViewModel.DeleteRuleAsync(ruleId);
        }
    }
}
