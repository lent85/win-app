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
using ProtonVPN.Client.Core.Bases;

namespace ProtonVPN.Client.UI.Main.Features.MultiTunnel;

public sealed partial class MultiTunnelWidgetView : IContextAware
{
    public MultiTunnelWidgetViewModel ViewModel { get; }

    public MultiTunnelWidgetView()
    {
        ViewModel = App.GetService<MultiTunnelWidgetViewModel>();

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

    private void OnWidgetFlyoutOpened(object sender, object e)
    {
        ViewModel.IsFeatureFlyoutOpened = true;
    }

    private void OnWidgetFlyoutClosed(object sender, object e)
    {
        ViewModel.IsFeatureFlyoutOpened = false;
    }

    private async void OnConnectSlotClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string slotId })
        {
            await ViewModel.ConnectSlotAsync(slotId);
        }
    }

    private async void OnCopySlotPortClick(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string slotId })
        {
            await ViewModel.CopySlotPortAsync(slotId);
        }
    }
}
