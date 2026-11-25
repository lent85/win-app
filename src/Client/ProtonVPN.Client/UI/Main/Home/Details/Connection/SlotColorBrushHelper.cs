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

using Microsoft.UI;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace ProtonVPN.Client.UI.Main.Home.Details.Connection;

public static class SlotColorBrushHelper
{
    public static SolidColorBrush ToBrush(string? colorHex, byte alpha = 255)
    {
        Color color = ParseColor(colorHex);
        color.A = alpha;
        return new SolidColorBrush(color);
    }

    public static Color ParseColor(string? colorHex)
    {
        if (string.IsNullOrWhiteSpace(colorHex))
        {
            return Color.FromArgb(255, 0x1E, 0xA8, 0x85);
        }

        string hex = colorHex.Trim().TrimStart('#');
        if (hex.Length == 6 &&
            byte.TryParse(hex[..2], System.Globalization.NumberStyles.HexNumber, null, out byte r) &&
            byte.TryParse(hex[2..4], System.Globalization.NumberStyles.HexNumber, null, out byte g) &&
            byte.TryParse(hex[4..6], System.Globalization.NumberStyles.HexNumber, null, out byte b))
        {
            return Color.FromArgb(255, r, g, b);
        }

        return Colors.MediumSeaGreen;
    }
}
