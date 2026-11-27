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
    private const double CompactTableWidthThreshold = 700;
    private const double IconOnlyButtonsWidthThreshold = 560;

    public static readonly DependencyProperty IsMergedTableLayoutProperty =
        DependencyProperty.Register(
            nameof(IsMergedTableLayout),
            typeof(bool),
            typeof(MultiTunnelHomePanelView),
            new PropertyMetadata(false));

    public static readonly DependencyProperty IsIconOnlyButtonsProperty =
        DependencyProperty.Register(
            nameof(IsIconOnlyButtons),
            typeof(bool),
            typeof(MultiTunnelHomePanelView),
            new PropertyMetadata(false));

    public bool IsMergedTableLayout
    {
        get => (bool)GetValue(IsMergedTableLayoutProperty);
        private set => SetValue(IsMergedTableLayoutProperty, value);
    }

    public bool IsIconOnlyButtons
    {
        get => (bool)GetValue(IsIconOnlyButtonsProperty);
        private set => SetValue(IsIconOnlyButtonsProperty, value);
    }

    public MultiTunnelHomePanelViewModel ViewModel { get; }

    public MultiTunnelHomePanelView()
    {
        ViewModel = App.GetService<MultiTunnelHomePanelViewModel>();

        InitializeComponent();

        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        SizeChanged += OnSizeChanged;
    }

    public object GetContext()
    {
        return ViewModel;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        ViewModel.Activate();
        UpdateResponsiveState(ActualWidth);
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        ViewModel.Deactivate();
    }

    private void OnSizeChanged(object sender, SizeChangedEventArgs e)
    {
        UpdateResponsiveState(e.NewSize.Width);
    }

    private void UpdateResponsiveState(double width)
    {
        if (width <= 0)
        {
            return;
        }

        bool isMerged = width < CompactTableWidthThreshold;
        bool isIconOnly = width < IconOnlyButtonsWidthThreshold;

        if (IsMergedTableLayout != isMerged)
        {
            IsMergedTableLayout = isMerged;
        }

        if (IsIconOnlyButtons != isIconOnly)
        {
            IsIconOnlyButtons = isIconOnly;
        }

        string stateName = isIconOnly
            ? "NarrowIconOnlyState"
            : isMerged
                ? "CompactTableState"
                : "WideState";

        VisualStateManager.GoToState(this, stateName, false);
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

    private void OnEditSlotClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string slotId })
        {
            ViewModel.SelectSlotForEdit(slotId);
        }
    }

    private void OnSlotTemplatesClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string slotId })
        {
            ViewModel.OpenTemplatesForSlot(slotId);
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
}
