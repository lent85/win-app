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

using ProtonVPN.ProcessCommunication.Contracts.Entities.MultiTunnel;

namespace ProtonVPN.Client.Logic.Connection.Contracts.MultiTunnel;

public enum RoutingPresetApplyMode
{
    Add = 0,
    Replace = 1,
    ReplaceTarget = 2,
}

public sealed record RoutingRulePreset(
    string Id,
    string Category,
    string Name,
    string Description,
    string? AppPattern = null,
    string? DomainPattern = null,
    string? IpCidrPattern = null,
    string? PortPattern = null,
    RuleProtocolIpcEntity Protocol = RuleProtocolIpcEntity.Any,
    RuleTargetTypeIpcEntity DefaultTargetType = RuleTargetTypeIpcEntity.Tunnel,
    string DefaultTargetTunnelId = "T1",
    TunnelFallbackBehaviorIpcEntity DefaultFallbackBehavior = TunnelFallbackBehaviorIpcEntity.KillSwitchBlock,
    string? DefaultFallbackTunnelId = null)
{
    public string RecommendedTargetLabel => DefaultTargetType switch
    {
        RuleTargetTypeIpcEntity.Direct => "Direct",
        RuleTargetTypeIpcEntity.Block => "Block",
        _ => $"Tunnel {(string.IsNullOrWhiteSpace(DefaultTargetTunnelId) ? "T1" : DefaultTargetTunnelId.ToUpperInvariant())}",
    };

    public string ConditionPreview
    {
        get
        {
            List<string> parts = [];
            if (!string.IsNullOrWhiteSpace(DomainPattern))
            {
                parts.Add($"Domain: {DomainPattern}");
            }
            if (!string.IsNullOrWhiteSpace(AppPattern))
            {
                parts.Add($"App: {AppPattern}");
            }
            if (!string.IsNullOrWhiteSpace(IpCidrPattern))
            {
                parts.Add($"IP: {IpCidrPattern}");
            }
            if (!string.IsNullOrWhiteSpace(PortPattern) || Protocol != RuleProtocolIpcEntity.Any)
            {
                string port = string.IsNullOrWhiteSpace(PortPattern) ? "*" : PortPattern;
                parts.Add($"Port: {port}/{Protocol}");
            }
            return string.Join("  •  ", parts);
        }
    }

    public bool MatchesSearch(string? query)
    {
        if (string.IsNullOrWhiteSpace(query))
        {
            return true;
        }

        string q = query.Trim();
        return Id.Contains(q, StringComparison.OrdinalIgnoreCase)
            || Name.Contains(q, StringComparison.OrdinalIgnoreCase)
            || Description.Contains(q, StringComparison.OrdinalIgnoreCase)
            || Category.Contains(q, StringComparison.OrdinalIgnoreCase)
            || (DomainPattern is not null && DomainPattern.Contains(q, StringComparison.OrdinalIgnoreCase))
            || (AppPattern is not null && AppPattern.Contains(q, StringComparison.OrdinalIgnoreCase))
            || (IpCidrPattern is not null && IpCidrPattern.Contains(q, StringComparison.OrdinalIgnoreCase))
            || (PortPattern is not null && PortPattern.Contains(q, StringComparison.OrdinalIgnoreCase));
    }

    public bool MatchesRule(MultiTunnelRuleConfig? rule)
    {
        if (rule is null)
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(rule.Name) &&
            string.Equals(rule.Name.Trim(), Name.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return rule.Protocol == Protocol &&
               string.Equals(NormalizePattern(rule.AppPattern), NormalizePattern(AppPattern), StringComparison.OrdinalIgnoreCase) &&
               string.Equals(NormalizePattern(rule.DomainPattern), NormalizePattern(DomainPattern), StringComparison.OrdinalIgnoreCase) &&
               string.Equals(NormalizePattern(rule.IpCidrPattern), NormalizePattern(IpCidrPattern), StringComparison.OrdinalIgnoreCase) &&
               string.Equals(NormalizePattern(rule.PortPattern), NormalizePattern(PortPattern), StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizePattern(string? pattern) =>
        string.IsNullOrWhiteSpace(pattern) ? string.Empty : pattern.Trim();

    public MultiTunnelRuleConfig ToRuleConfig(
        IReadOnlyCollection<string> availableSlotIds,
        RuleTargetTypeIpcEntity? targetTypeOverride = null,
        string? targetTunnelIdOverride = null,
        TunnelFallbackBehaviorIpcEntity? fallbackBehaviorOverride = null,
        string? fallbackTunnelIdOverride = null)
    {
        List<string> normalizedSlots = availableSlotIds
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Select(s => s.Trim().ToUpperInvariant())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (normalizedSlots.Count == 0)
        {
            normalizedSlots.Add("T1");
        }

        RuleTargetTypeIpcEntity targetType = targetTypeOverride ?? DefaultTargetType;
        string targetTunnelId = normalizedSlots[0];
        if (targetType == RuleTargetTypeIpcEntity.Tunnel)
        {
            string preferredSlot = !string.IsNullOrWhiteSpace(targetTunnelIdOverride)
                ? targetTunnelIdOverride.Trim().ToUpperInvariant()
                : (string.IsNullOrWhiteSpace(DefaultTargetTunnelId) ? normalizedSlots[0] : DefaultTargetTunnelId.Trim().ToUpperInvariant());

            targetTunnelId = normalizedSlots.Contains(preferredSlot, StringComparer.OrdinalIgnoreCase)
                ? preferredSlot
                : normalizedSlots[0];
        }

        TunnelFallbackBehaviorIpcEntity fallbackBehavior = TunnelFallbackBehaviorIpcEntity.KillSwitchBlock;
        string? fallbackTunnelId = null;

        if (targetType == RuleTargetTypeIpcEntity.Tunnel)
        {
            fallbackBehavior = fallbackBehaviorOverride ?? DefaultFallbackBehavior;
            if (fallbackBehavior == TunnelFallbackBehaviorIpcEntity.FallbackToTunnel)
            {
                string? preferredFb = !string.IsNullOrWhiteSpace(fallbackTunnelIdOverride)
                    ? fallbackTunnelIdOverride.Trim().ToUpperInvariant()
                    : DefaultFallbackTunnelId?.Trim().ToUpperInvariant();

                string? resolvedFb = !string.IsNullOrWhiteSpace(preferredFb) &&
                                     normalizedSlots.Contains(preferredFb, StringComparer.OrdinalIgnoreCase) &&
                                     !string.Equals(preferredFb, targetTunnelId, StringComparison.OrdinalIgnoreCase)
                    ? preferredFb
                    : normalizedSlots.FirstOrDefault(s => !string.Equals(s, targetTunnelId, StringComparison.OrdinalIgnoreCase));

                if (!string.IsNullOrWhiteSpace(resolvedFb))
                {
                    fallbackTunnelId = resolvedFb;
                }
                else
                {
                    fallbackBehavior = TunnelFallbackBehaviorIpcEntity.KillSwitchBlock;
                }
            }
        }

        return new MultiTunnelRuleConfig
        {
            Id = Guid.NewGuid(),
            PriorityOrder = 1,
            Name = Name,
            IsEnabled = true,
            AppPattern = AppPattern,
            DomainPattern = DomainPattern,
            IpCidrPattern = IpCidrPattern,
            PortPattern = PortPattern,
            Protocol = Protocol,
            TargetType = targetType,
            TargetTunnelId = targetTunnelId,
            FallbackBehavior = fallbackBehavior,
            FallbackTunnelId = fallbackTunnelId,
        };
    }
}

public static class MultiTunnelRoutingPresetCatalog
{
    public static IReadOnlyList<string> Categories { get; } =
    [
        "All",
        "BigTech",
        "Social",
        "AiDev",
        "MediaGaming",
        "Network",
    ];

    public static IReadOnlyList<RoutingRulePreset> All { get; } =
    [
        new(
            Id: "google-services",
            Category: "BigTech",
            Name: "Google Services",
            Description: "Search, Gmail, Drive, Docs, YouTube & Google APIs",
            DomainPattern: "*.google.com, *.googleapis.com, *.gstatic.com, *.googleusercontent.com, *.gmail.com, *.youtube.com, *.youtu.be, *.googlevideo.com, *.ytimg.com, *.ggpht.com, *.gvt1.com",
            DefaultTargetType: RuleTargetTypeIpcEntity.Tunnel,
            DefaultTargetTunnelId: "T1",
            DefaultFallbackBehavior: TunnelFallbackBehaviorIpcEntity.KillSwitchBlock),
        new(
            Id: "facebook-services",
            Category: "Social",
            Name: "Facebook / Meta Services",
            Description: "Facebook, Messenger, Instagram, WhatsApp & Threads",
            DomainPattern: "*.facebook.com, *.fbcdn.net, *.fb.com, *.fbsbx.com, *.messenger.com, *.instagram.com, *.cdninstagram.com, *.whatsapp.com, *.whatsapp.net, *.threads.net, *.meta.com",
            DefaultTargetType: RuleTargetTypeIpcEntity.Tunnel,
            DefaultTargetTunnelId: "T1",
            DefaultFallbackBehavior: TunnelFallbackBehaviorIpcEntity.KillSwitchBlock),
        new(
            Id: "youtube-media",
            Category: "MediaGaming",
            Name: "YouTube & Google Media",
            Description: "YouTube video streaming, thumbnails & CDN",
            DomainPattern: "*.youtube.com, *.youtu.be, *.googlevideo.com, *.ytimg.com, *.ggpht.com, *.youtube-nocookie.com",
            DefaultTargetType: RuleTargetTypeIpcEntity.Tunnel,
            DefaultTargetTunnelId: "T1",
            DefaultFallbackBehavior: TunnelFallbackBehaviorIpcEntity.FallbackToDirect),
        new(
            Id: "microsoft-365",
            Category: "BigTech",
            Name: "Microsoft 365 & Azure",
            Description: "Office 365, OneDrive, Teams, Outlook, Azure & Windows Update",
            DomainPattern: "*.microsoft.com, *.live.com, *.office.com, *.office365.com, *.microsoftonline.com, *.sharepoint.com, *.onedrive.com, *.teams.microsoft.com, *.azure.com, *.windowsupdate.com",
            DefaultTargetType: RuleTargetTypeIpcEntity.Direct),
        new(
            Id: "apple-icloud",
            Category: "BigTech",
            Name: "Apple & iCloud Services",
            Description: "iCloud, App Store, Apple Music & Apple CDN",
            DomainPattern: "*.apple.com, *.icloud.com, *.icloud-content.com, *.mzstatic.com, *.cdn-apple.com, *.me.com",
            DefaultTargetType: RuleTargetTypeIpcEntity.Direct),
        new(
            Id: "ai-assistants",
            Category: "AiDev",
            Name: "AI Assistants (OpenAI, Claude, Gemini)",
            Description: "ChatGPT, OpenAI API, Claude, Gemini, Perplexity & Cursor",
            DomainPattern: "*.openai.com, *.chatgpt.com, *.oaistatic.com, *.oaiusercontent.com, *.claude.ai, *.anthropic.com, *.gemini.google.com, *.perplexity.ai, *.cursor.sh",
            DefaultTargetType: RuleTargetTypeIpcEntity.Tunnel,
            DefaultTargetTunnelId: "T2",
            DefaultFallbackBehavior: TunnelFallbackBehaviorIpcEntity.KillSwitchBlock),
        new(
            Id: "developer-cloud",
            Category: "AiDev",
            Name: "Developer & Cloud Platforms",
            Description: "GitHub, GitLab, Docker Hub, npm, PyPI, NuGet, AWS & Cloudflare",
            DomainPattern: "*.github.com, *.githubusercontent.com, *.gitlab.com, *.docker.com, *.docker.io, *.npmjs.org, *.pypi.org, *.nuget.org, *.amazonaws.com, *.cloudflare.com",
            DefaultTargetType: RuleTargetTypeIpcEntity.Tunnel,
            DefaultTargetTunnelId: "T1",
            DefaultFallbackBehavior: TunnelFallbackBehaviorIpcEntity.FallbackToDirect),
        new(
            Id: "x-reddit-telegram",
            Category: "Social",
            Name: "X (Twitter), Reddit & Telegram",
            Description: "X/Twitter, Reddit & Telegram web/API endpoints",
            DomainPattern: "*.x.com, *.twitter.com, *.twimg.com, *.reddit.com, *.redd.it, *.redditstatic.com, *.telegram.org, *.t.me",
            DefaultTargetType: RuleTargetTypeIpcEntity.Tunnel,
            DefaultTargetTunnelId: "T1",
            DefaultFallbackBehavior: TunnelFallbackBehaviorIpcEntity.KillSwitchBlock),
        new(
            Id: "tiktok-bytedance",
            Category: "Social",
            Name: "TikTok & ByteDance",
            Description: "TikTok web, mobile CDN & ByteDance media domains",
            DomainPattern: "*.tiktok.com, *.tiktokv.com, *.tiktokcdn.com, *.musical.ly, *.byteoversea.com, *.ibytedtos.com",
            DefaultTargetType: RuleTargetTypeIpcEntity.Tunnel,
            DefaultTargetTunnelId: "T1",
            DefaultFallbackBehavior: TunnelFallbackBehaviorIpcEntity.KillSwitchBlock),
        new(
            Id: "streaming-services",
            Category: "MediaGaming",
            Name: "Streaming (Netflix, Spotify, Twitch, Disney+)",
            Description: "International video and music streaming platforms",
            DomainPattern: "*.netflix.com, *.nflxvideo.net, *.nflxso.net, *.spotify.com, *.scdn.co, *.twitch.tv, *.ttvnw.net, *.disneyplus.com, *.primevideo.com",
            DefaultTargetType: RuleTargetTypeIpcEntity.Tunnel,
            DefaultTargetTunnelId: "T2",
            DefaultFallbackBehavior: TunnelFallbackBehaviorIpcEntity.KillSwitchBlock),
        new(
            Id: "gaming-platforms",
            Category: "MediaGaming",
            Name: "Gaming Platforms (Steam, Discord, Riot, Epic)",
            Description: "Steam, Discord, Riot Games, Epic Games & Battle.net domains",
            DomainPattern: "*.steampowered.com, *.steamcommunity.com, *.steamcontent.com, *.discord.com, *.discord.gg, *.discordapp.com, *.riotgames.com, *.epicgames.com, *.battle.net",
            DefaultTargetType: RuleTargetTypeIpcEntity.Direct),
        new(
            Id: "voice-meetings-udp",
            Category: "MediaGaming",
            Name: "Voice & Video Meetings (Low-Latency UDP)",
            Description: "Real-time UDP media ports for Zoom, Discord, Teams & Slack",
            AppPattern: "zoom, discord, teams, slack",
            PortPattern: "3478-3481, 8801-8810",
            Protocol: RuleProtocolIpcEntity.Udp,
            DefaultTargetType: RuleTargetTypeIpcEntity.Direct),
        new(
            Id: "p2p-bittorrent",
            Category: "Network",
            Name: "P2P / BitTorrent (Strict Kill-Switch)",
            Description: "BitTorrent clients locked to VPN with strict Kill-Switch",
            AppPattern: "qbittorrent, transmission, transmission-gtk, deluge, utorrent",
            DefaultTargetType: RuleTargetTypeIpcEntity.Tunnel,
            DefaultTargetTunnelId: "T3",
            DefaultFallbackBehavior: TunnelFallbackBehaviorIpcEntity.KillSwitchBlock),
        new(
            Id: "private-lan",
            Category: "Network",
            Name: "Private LAN & Corporate Subnets",
            Description: "RFC1918 & IPv6 link-local/ULA subnets bypassed directly",
            IpCidrPattern: "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, fc00::/7, fe80::/10",
            DefaultTargetType: RuleTargetTypeIpcEntity.Direct),
        new(
            Id: "banking-vn-local",
            Category: "Network",
            Name: "Banking & Local Services (.VN)",
            Description: "Vietnamese banking, government & .vn domestic services",
            DomainPattern: "*.vn, *.com.vn, *.gov.vn, *.edu.vn, *.vietcombank.com.vn, *.techcombank.com.vn, *.vneid.gov.vn",
            DefaultTargetType: RuleTargetTypeIpcEntity.Direct),
        new(
            Id: "ads-trackers-block",
            Category: "Network",
            Name: "Ads & Trackers (Block)",
            Description: "Block major advertising & analytics tracker domains",
            DomainPattern: "*.doubleclick.net, *.googlesyndication.com, *.googleadservices.com, *.google-analytics.com, *.googletagmanager.com, *.ads-twitter.com, *.adnxs.com, *.taboola.com, *.outbrain.com",
            DefaultTargetType: RuleTargetTypeIpcEntity.Block),
    ];

    public static RoutingRulePreset? FindById(string? id)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            return null;
        }

        return All.FirstOrDefault(p => string.Equals(p.Id, id.Trim(), StringComparison.OrdinalIgnoreCase));
    }
}
