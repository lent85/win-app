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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace ProtonVPN.Service.MultiTunnel;

public sealed record DnsQuestionInfo(string QueryDomain, ushort QueryType, ushort TransactionId);

public sealed record DnsResolvedRecord(IPAddress Address, int TtlSeconds);

public sealed record DynamicDomainRouteEntry(
    string Domain,
    IPAddress Address,
    Guid? MatchedRuleId,
    int MatchedRulePriority,
    RuleTargetType TargetType,
    string? TargetTunnelId,
    DateTime ExpiresAtUtc);

/// <summary>
/// RFC 1035 DNS packet inspector and dynamic route/WFP cache for Proton VPN Multi-Tunnel domain routing.
/// </summary>
public sealed class MultiTunnelDnsRoutingTable
{
    private const int MinTtlSeconds = 30;
    private const int MaxTtlSeconds = 3600;
    private const int TtlGraceSeconds = 30;

    private readonly ConcurrentDictionary<IPAddress, DynamicDomainRouteEntry> _entriesByIp = new();

    public static bool TryParseQueryDomain(ReadOnlySpan<byte> dnsPayload, out DnsQuestionInfo question)
    {
        question = new DnsQuestionInfo(string.Empty, 0, 0);
        if (dnsPayload.Length < 12)
        {
            return false;
        }

        ushort txId = (ushort)((dnsPayload[0] << 8) | dnsPayload[1]);
        ushort qdCount = (ushort)((dnsPayload[4] << 8) | dnsPayload[5]);
        if (qdCount == 0)
        {
            return false;
        }

        int offset = 12;
        if (!TryReadDomainName(dnsPayload, ref offset, out string domain) || offset + 4 > dnsPayload.Length)
        {
            return false;
        }

        ushort qType = (ushort)((dnsPayload[offset] << 8) | dnsPayload[offset + 1]);
        question = new DnsQuestionInfo(domain.ToLowerInvariant(), qType, txId);
        return true;
    }

    public static List<DnsResolvedRecord> ExtractAnswerAddresses(ReadOnlySpan<byte> dnsResponse)
    {
        List<DnsResolvedRecord> records = [];
        if (dnsResponse.Length < 12)
        {
            return records;
        }

        ushort qdCount = (ushort)((dnsResponse[4] << 8) | dnsResponse[5]);
        ushort anCount = (ushort)((dnsResponse[6] << 8) | dnsResponse[7]);
        if (anCount == 0)
        {
            return records;
        }

        int offset = 12;
        for (int q = 0; q < qdCount; q++)
        {
            if (!TryReadDomainName(dnsResponse, ref offset, out _) || offset + 4 > dnsResponse.Length)
            {
                return records;
            }
            offset += 4;
        }

        for (int a = 0; a < anCount; a++)
        {
            if (!TryReadDomainName(dnsResponse, ref offset, out _) || offset + 10 > dnsResponse.Length)
            {
                break;
            }

            ushort rType = (ushort)((dnsResponse[offset] << 8) | dnsResponse[offset + 1]);
            int ttl = (dnsResponse[offset + 4] << 24) |
                      (dnsResponse[offset + 5] << 16) |
                      (dnsResponse[offset + 6] << 8) |
                      dnsResponse[offset + 7];
            ushort rdLength = (ushort)((dnsResponse[offset + 8] << 8) | dnsResponse[offset + 9]);
            offset += 10;

            if (offset + rdLength > dnsResponse.Length)
            {
                break;
            }

            if (rType == 1 && rdLength == 4) // A record
            {
                IPAddress ipv4 = new(dnsResponse.Slice(offset, 4));
                records.Add(new DnsResolvedRecord(ipv4, Math.Clamp(ttl, MinTtlSeconds, MaxTtlSeconds)));
            }
            else if (rType == 28 && rdLength == 16) // AAAA record
            {
                IPAddress ipv6 = new(dnsResponse.Slice(offset, 16));
                records.Add(new DnsResolvedRecord(ipv6, Math.Clamp(ttl, MinTtlSeconds, MaxTtlSeconds)));
            }

            offset += rdLength;
        }

        return records;
    }

    public void RegisterResolvedAddresses(
        string domain,
        RoutingDecision decision,
        IEnumerable<DnsResolvedRecord> records,
        DateTime? nowUtc = null)
    {
        DateTime now = nowUtc ?? DateTime.UtcNow;
        foreach (DnsResolvedRecord rec in records)
        {
            DateTime expiresAt = now.AddSeconds(rec.TtlSeconds + TtlGraceSeconds);
            DynamicDomainRouteEntry newEntry = new(
                Domain: domain,
                Address: rec.Address,
                MatchedRuleId: decision.MatchedRule?.Id,
                MatchedRulePriority: decision.MatchedRule?.PriorityOrder ?? int.MaxValue,
                TargetType: decision.EffectiveTargetType,
                TargetTunnelId: decision.EffectiveTunnelId,
                ExpiresAtUtc: expiresAt);

            _entriesByIp.AddOrUpdate(rec.Address, newEntry, (_, existing) =>
            {
                // If an existing non-expired entry belongs to a higher-priority rule, preserve its priority
                if (existing.ExpiresAtUtc > now && existing.MatchedRulePriority < newEntry.MatchedRulePriority)
                {
                    return existing;
                }
                return newEntry;
            });
        }
    }

    public IReadOnlyDictionary<Guid, IReadOnlyList<IPAddress>> GetActiveAddressesByRule(DateTime? nowUtc = null)
    {
        DateTime now = nowUtc ?? DateTime.UtcNow;
        PruneExpired(now);

        Dictionary<Guid, List<IPAddress>> map = new();
        foreach (DynamicDomainRouteEntry entry in _entriesByIp.Values)
        {
            if (entry.MatchedRuleId.HasValue)
            {
                if (!map.TryGetValue(entry.MatchedRuleId.Value, out List<IPAddress>? list))
                {
                    list = [];
                    map[entry.MatchedRuleId.Value] = list;
                }
                list.Add(entry.Address);
            }
        }

        Dictionary<Guid, IReadOnlyList<IPAddress>> result = new();
        foreach ((Guid ruleId, List<IPAddress> list) in map)
        {
            result[ruleId] = list;
        }
        return result;
    }

    public int PruneExpired(DateTime? nowUtc = null)
    {
        DateTime now = nowUtc ?? DateTime.UtcNow;
        int removed = 0;
        foreach ((IPAddress ip, DynamicDomainRouteEntry entry) in _entriesByIp)
        {
            if (entry.ExpiresAtUtc <= now &&
                _entriesByIp.TryRemove(new KeyValuePair<IPAddress, DynamicDomainRouteEntry>(ip, entry)))
            {
                removed++;
            }
        }
        return removed;
    }

    public void Clear()
    {
        _entriesByIp.Clear();
    }

    private static bool TryReadDomainName(ReadOnlySpan<byte> packet, ref int offset, out string domain)
    {
        StringBuilder sb = new();
        int currentOffset = offset;
        bool jumped = false;
        int jumpCount = 0;

        while (currentOffset < packet.Length)
        {
            byte len = packet[currentOffset];
            if (len == 0)
            {
                if (!jumped)
                {
                    offset = currentOffset + 1;
                }
                domain = sb.ToString();
                return true;
            }

            // RFC 1035 pointer compression (11xxxxxx)
            if ((len & 0xC0) == 0xC0)
            {
                if (currentOffset + 1 >= packet.Length || ++jumpCount > 16)
                {
                    domain = string.Empty;
                    return false;
                }

                if (!jumped)
                {
                    offset = currentOffset + 2;
                    jumped = true;
                }

                currentOffset = ((len & 0x3F) << 8) | packet[currentOffset + 1];
                continue;
            }

            currentOffset++;
            if (currentOffset + len > packet.Length)
            {
                domain = string.Empty;
                return false;
            }

            if (sb.Length > 0)
            {
                sb.Append('.');
            }

            sb.Append(Encoding.ASCII.GetString(packet.Slice(currentOffset, len)));
            currentOffset += len;
        }

        domain = string.Empty;
        return false;
    }
}
