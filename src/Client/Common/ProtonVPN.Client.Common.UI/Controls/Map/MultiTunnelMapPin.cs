/*
 * Copyright (c) 2026 Proton AG
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

namespace ProtonVPN.Client.Common.UI.Controls.Map;

public sealed record MultiTunnelMapPin
{
    public MultiTunnelMapPin()
    {
    }

    public MultiTunnelMapPin(
        string countryCode,
        string slotLabel,
        string colorHex,
        bool isConnected,
        bool isConnecting)
    {
        CountryCode = countryCode;
        SlotLabel = slotLabel;
        ColorHex = colorHex;
        IsConnected = isConnected;
        IsConnecting = isConnecting;
    }

    public string CountryCode { get; set; } = string.Empty;
    public string SlotLabel { get; set; } = string.Empty;
    public string ColorHex { get; set; } = string.Empty;
    public bool IsConnected { get; set; }
    public bool IsConnecting { get; set; }
}
