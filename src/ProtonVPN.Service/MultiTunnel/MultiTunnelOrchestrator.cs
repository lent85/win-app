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

namespace ProtonVPN.Service.MultiTunnel;

/// <summary>
/// Coordinates up to 5 concurrent Proton VPN tunnel slots (T1..T5), reference-counted physical endpoint routes,
/// dynamic DNS domain IP bindings, and priority-ordered selective routing rules.
/// </summary>
public sealed class MultiTunnelOrchestrator
{
    private readonly Dictionary<string, TunnelSlotRuntimeState> _slots = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, HashSet<string>> _endpointRouteOwnersByIp = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<SelectiveRoutingRule> _priorityRules = [];
    private readonly MultiTunnelDnsRoutingTable _dnsRoutingTable = new();
    private readonly object _lock = new();

    public RuleTargetType DefaultTargetType { get; private set; } = RuleTargetType.Direct;
    public string DefaultTunnelId { get; private set; } = "T1";

    public MultiTunnelOrchestrator()
    {
        for (int i = 0; i < TunnelSlotAllocation.MaxTunnelSlots; i++)
        {
            TunnelSlotAllocation alloc = TunnelSlotAllocation.ForSlot(i);
            _slots[alloc.SlotId] = new TunnelSlotRuntimeState
            {
                SlotId = alloc.SlotId,
                SlotIndex = alloc.SlotIndex,
                IsConnected = false,
                ClientIpv4 = alloc.ClientIpv4,
                ServerGatewayIpv4 = alloc.ServerGatewayIpv4,
                ClientIpv6 = null,
            };
        }
    }

    public IReadOnlyDictionary<string, TunnelSlotRuntimeState> GetSlotStates()
    {
        lock (_lock)
        {
            return new Dictionary<string, TunnelSlotRuntimeState>(_slots, StringComparer.OrdinalIgnoreCase);
        }
    }

    public IReadOnlyList<SelectiveRoutingRule> GetPriorityRules()
    {
        lock (_lock)
        {
            return _priorityRules.OrderBy(r => r.PriorityOrder).ToList();
        }
    }

    /// <summary>
    /// Activates a tunnel slot and acquires reference-counted ownership of its physical server endpoint route.
    /// Returns true if a new physical host route (/32) must be created on the physical interface.
    /// </summary>
    public bool ActivateSlot(
        string slotId,
        string countryCode,
        string serverName,
        string entryIp,
        string exitIp,
        uint interfaceIndex,
        IReadOnlySet<byte>? reservedLanSecondOctets = null,
        IPAddress? clientIpv6 = null)
    {
        lock (_lock)
        {
            string normalizedId = slotId.ToUpperInvariant();
            if (!_slots.TryGetValue(normalizedId, out TunnelSlotRuntimeState? slot))
            {
                throw new ArgumentException($"Unknown tunnel slot '{slotId}'.", nameof(slotId));
            }

            // Release previous endpoint route if slot was already connected to another endpoint
            if (slot.IsConnected && !string.IsNullOrWhiteSpace(slot.EntryIp) &&
                !string.Equals(slot.EntryIp, entryIp, StringComparison.OrdinalIgnoreCase))
            {
                ReleaseEndpointRouteInternal(normalizedId, slot.EntryIp);
            }

            TunnelSlotAllocation alloc = TunnelSlotAllocation.ForSlot(slot.SlotIndex, reservedLanSecondOctets);
            slot.ClientIpv4 = alloc.ClientIpv4;
            slot.ServerGatewayIpv4 = alloc.ServerGatewayIpv4;
            slot.ClientIpv6 = clientIpv6;
            slot.CountryCode = countryCode;
            slot.ServerName = serverName;
            slot.EntryIp = entryIp;
            slot.ExitIp = exitIp;
            slot.InterfaceIndex = interfaceIndex;
            slot.IsConnected = true;

            return AcquireEndpointRouteInternal(normalizedId, entryIp);
        }
    }

    /// <summary>
    /// Deactivates a tunnel slot and decrements reference count on its physical endpoint route.
    /// Returns true if this was the last tunnel using that EntryIp and the physical /32 route should now be deleted.
    /// </summary>
    public bool DeactivateSlot(string slotId, out string releasedEntryIp)
    {
        lock (_lock)
        {
            releasedEntryIp = string.Empty;
            string normalizedId = slotId.ToUpperInvariant();
            if (!_slots.TryGetValue(normalizedId, out TunnelSlotRuntimeState? slot) || !slot.IsConnected)
            {
                return false;
            }

            releasedEntryIp = slot.EntryIp;
            slot.IsConnected = false;
            slot.InterfaceIndex = 0;
            slot.ClientIpv6 = null;

            return ReleaseEndpointRouteInternal(normalizedId, releasedEntryIp);
        }
    }

    public int GetEndpointRouteOwnerCount(string entryIp)
    {
        lock (_lock)
        {
            return _endpointRouteOwnersByIp.TryGetValue(entryIp, out HashSet<string>? owners) ? owners.Count : 0;
        }
    }

    public void SetPriorityRules(IEnumerable<SelectiveRoutingRule> rules, RuleTargetType defaultTargetType, string defaultTunnelId)
    {
        lock (_lock)
        {
            _priorityRules.Clear();
            _priorityRules.AddRange(rules.OrderBy(r => r.PriorityOrder));
            PriorityRuleEngine.NormalizePriorities(_priorityRules);
            DefaultTargetType = defaultTargetType;
            DefaultTunnelId = string.IsNullOrWhiteSpace(defaultTunnelId) ? "T1" : defaultTunnelId.ToUpperInvariant();
        }
    }

    public bool MoveRulePriority(Guid ruleId, int directionDelta)
    {
        lock (_lock)
        {
            int idx = _priorityRules.FindIndex(r => r.Id == ruleId);
            if (idx < 0)
            {
                return false;
            }

            int targetIdx = Math.Clamp(idx + directionDelta, 0, _priorityRules.Count - 1);
            if (targetIdx == idx)
            {
                return false;
            }

            SelectiveRoutingRule item = _priorityRules[idx];
            _priorityRules.RemoveAt(idx);
            _priorityRules.Insert(targetIdx, item);
            PriorityRuleEngine.NormalizePriorities(_priorityRules);
            return true;
        }
    }

    public RoutingDecision EvaluateTraffic(TrafficQuery query)
    {
        lock (_lock)
        {
            return PriorityRuleEngine.Evaluate(query, _priorityRules, _slots, DefaultTargetType, DefaultTunnelId);
        }
    }

    public List<RuleConflictWarning> GetRuleConflicts()
    {
        lock (_lock)
        {
            return PriorityRuleEngine.DetectConflicts(_priorityRules);
        }
    }

    public MultiTunnelDnsRoutingTable DnsRoutingTable => _dnsRoutingTable;

    private bool AcquireEndpointRouteInternal(string slotId, string entryIp)
    {
        if (string.IsNullOrWhiteSpace(entryIp))
        {
            return false;
        }

        if (!_endpointRouteOwnersByIp.TryGetValue(entryIp, out HashSet<string>? owners))
        {
            owners = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _endpointRouteOwnersByIp[entryIp] = owners;
        }

        bool isFirstOwner = owners.Count == 0;
        owners.Add(slotId);
        return isFirstOwner;
    }

    private bool ReleaseEndpointRouteInternal(string slotId, string entryIp)
    {
        if (string.IsNullOrWhiteSpace(entryIp) ||
            !_endpointRouteOwnersByIp.TryGetValue(entryIp, out HashSet<string>? owners))
        {
            return false;
        }

        owners.Remove(slotId);
        if (owners.Count == 0)
        {
            _endpointRouteOwnersByIp.Remove(entryIp);
            return true;
        }

        return false;
    }
}
