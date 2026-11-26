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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using ProtonVPN.Common.Core.Networking;
using ProtonVPN.OperatingSystems.Network.Contracts;
using ProtonVPN.OperatingSystems.Network.Contracts.Routing;

namespace ProtonVPN.Service.MultiTunnel;

internal static class MultiTunnelNetworkHelper
{
    public static bool IsTunnelSubnetIpv4(IPAddress? address)
    {
        if (address is null || address.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.None))
        {
            return true;
        }

        byte[] bytes = address.GetAddressBytes();
        return bytes[0] == 10 && bytes[1] is >= 2 and <= 6;
    }

    public static bool IsVpnOrVirtualTunnelInterface(INetworkInterface? iface)
    {
        if (iface is null || iface.Index == 0 || iface.IsLoopback)
        {
            return true;
        }

        string name = iface.Name ?? string.Empty;
        string desc = iface.Description ?? string.Empty;

        if (name.StartsWith("ProtonVPN", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("Wintun", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("ProTun", StringComparison.OrdinalIgnoreCase) ||
            desc.Contains("ProtonVPN", StringComparison.OrdinalIgnoreCase) ||
            desc.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) ||
            desc.Contains("Wintun", StringComparison.OrdinalIgnoreCase) ||
            desc.Contains("TAP-Windows", StringComparison.OrdinalIgnoreCase) ||
            desc.Contains("ProTun", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        try
        {
            List<NetworkAddress> unicast = iface.GetUnicastAddresses();
            if (unicast.Any(a => !a.IsIpV6 && IsTunnelSubnetIpv4(a.Ip)))
            {
                return true;
            }
        }
        catch
        {
            // Ignore transient NIC enumeration errors
        }

        return false;
    }

    public static bool TryResolvePhysicalInterface(
        ISystemNetworkInterfaces? networkInterfaces,
        IRoutingTableHelper? routingTableHelper,
        out INetworkInterface? physicalInterface,
        out IPAddress? physicalIpv4,
        out IPAddress? physicalIpv6,
        out IPAddress? gatewayIpv4,
        out uint interfaceMetric)
    {
        physicalInterface = null;
        physicalIpv4 = null;
        physicalIpv6 = null;
        gatewayIpv4 = null;
        interfaceMetric = 0;

        if (networkInterfaces is null)
        {
            return false;
        }

        INetworkInterface[] allInterfaces;
        try
        {
            allInterfaces = networkInterfaces.GetInterfaces();
        }
        catch
        {
            return false;
        }

        if (allInterfaces is null || allInterfaces.Length == 0)
        {
            return false;
        }

        (INetworkInterface Iface, IPAddress LocalIpv4, IPAddress GatewayIpv4, uint Metric, bool Active)? best = null;

        foreach (INetworkInterface iface in allInterfaces)
        {
            if (IsVpnOrVirtualTunnelInterface(iface))
            {
                continue;
            }

            IPAddress gw = iface.DefaultGateway;
            if (gw is null ||
                gw.AddressFamily != AddressFamily.InterNetwork ||
                gw.Equals(IPAddress.Any) ||
                gw.Equals(IPAddress.None) ||
                IsTunnelSubnetIpv4(gw))
            {
                continue;
            }

            IPAddress? localIpv4 = null;
            try
            {
                localIpv4 = iface.GetUnicastAddresses()
                    .FirstOrDefault(a => !a.IsIpV6 && !IsTunnelSubnetIpv4(a.Ip))
                    .Ip;
            }
            catch
            {
                continue;
            }

            if (localIpv4 is null || localIpv4.Equals(IPAddress.Any) || localIpv4.Equals(IPAddress.None))
            {
                continue;
            }

            uint metric = routingTableHelper?.GetInterfaceMetric(iface.Index, false) ?? 1000u;
            bool active = iface.IsActive;

            if (best is null ||
                (active && !best.Value.Active) ||
                (active == best.Value.Active && metric < best.Value.Metric))
            {
                best = (iface, localIpv4, gw, metric, active);
            }
        }

        if (best is null)
        {
            return false;
        }

        physicalInterface = best.Value.Iface;
        physicalIpv4 = best.Value.LocalIpv4;
        gatewayIpv4 = best.Value.GatewayIpv4;
        interfaceMetric = best.Value.Metric;

        try
        {
            physicalIpv6 = !string.IsNullOrEmpty(physicalInterface.Id)
                ? physicalInterface.GetPreferredIpv6UnicastAddress()
                : null;
        }
        catch
        {
            physicalIpv6 = null;
        }

        return true;
    }
}
