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

using Microsoft.UI.Xaml.Media;
using ProtonVPN.Client.Logic.Connection.Contracts;
using ProtonVPN.Client.Logic.Connection.Contracts.MultiTunnel;
using ProtonVPN.Client.Settings.Contracts;
using ProtonVPN.Client.UI.Main.Home.Details.Connection;
using ProtonVPN.Common.Legacy.PortForwarding;

namespace ProtonVPN.Client.UI.Main.Features.PortForwarding;

public sealed class SlotForwardedPortItem
{
    public required string SlotId { get; init; }
    public required string HeaderText { get; init; }
    public required string PortText { get; init; }
    public required int? ActivePort { get; init; }
    public bool HasActivePort => ActivePort is > 0;
    public bool HasWarning { get; init; }
    public required SolidColorBrush SlotColorBrush { get; init; }

    public static List<SlotForwardedPortItem> BuildList(
        IMultiTunnelManager multiTunnelManager,
        IPortForwardingManager portForwardingManager,
        ISettings settings)
    {
        if (!multiTunnelManager.IsEnabled)
        {
            return [];
        }

        List<SlotForwardedPortItem> items = [];
        foreach (MultiTunnelSlotConfig slot in multiTunnelManager.Slots)
        {
            bool effectivePf = slot.ResolveEffectivePortForwarding(settings.IsPortForwardingEnabled);
            if (!slot.IsConnected || !effectivePf)
            {
                continue;
            }

            SlotPortForwardingState? pfState = portForwardingManager.GetSlotState(slot.SlotId);
            int? activePort = pfState is not null ? pfState.ActivePort : slot.ActiveForwardedPort;
            bool isFetching = pfState?.IsFetchingPort ?? (slot.PortForwardingStatus is not PortMappingStatus.Stopped and not PortMappingStatus.Error and not PortMappingStatus.DestroyPortMappingCommunication);
            bool hasError = pfState?.HasError ?? slot.HasPortForwardingError;

            string portText;
            bool hasWarning = false;
            if (!slot.IsP2PServer)
            {
                portText = "Non-P2P";
                hasWarning = true;
            }
            else if (activePort is > 0)
            {
                portText = activePort.Value.ToString();
            }
            else if (hasError)
            {
                portText = "Error";
                hasWarning = true;
            }
            else if (isFetching)
            {
                portText = "Loading...";
            }
            else
            {
                portText = "-";
            }

            string serverInfo = string.IsNullOrWhiteSpace(slot.ServerName) ? slot.CountryCode : slot.ServerName;
            items.Add(new SlotForwardedPortItem
            {
                SlotId = slot.SlotId,
                HeaderText = $"{slot.SlotId} ({serverInfo})",
                PortText = portText,
                ActivePort = activePort,
                HasWarning = hasWarning,
                SlotColorBrush = SlotColorBrushHelper.ToBrush(MultiTunnelSlotConfig.GetSlotColorHex(slot.SlotId)),
            });
        }

        return items;
    }
}
