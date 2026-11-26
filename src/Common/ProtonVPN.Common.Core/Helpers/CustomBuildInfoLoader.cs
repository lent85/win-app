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

using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ProtonVPN.Common.Core.Helpers;

public sealed record BuildInfoDocument(
    string? Component,
    string? BaseVersion,
    int? BuildNumber,
    string? NumericVersion,
    string? Win32FileVersion,
    string? FullVersion,
    string? GitCommit,
    string? GitCommitFull,
    string? GitBranch,
    string? Platform,
    string? Configuration,
    string? BuiltAtUtc,
    string? UpstreamBaseCommit,
    string? OriginRemoteUrl,
    int? CustomCommitCount);

public sealed record CustomChangelogEntry(
    string Commit,
    string Date,
    string Author,
    string Subject,
    string Category);

public sealed record CustomChangelogDocument(
    string? BaseVersion,
    string? UpstreamBaseCommit,
    string? Branch,
    string? OriginRemoteUrl,
    string? FullVersion,
    string? BuiltAtUtc,
    List<CustomChangelogEntry>? Entries);

public sealed record CustomChangelogDateGroup(
    string DateLabel,
    IReadOnlyList<CustomChangelogEntry> Entries);

public sealed record InstalledBuildSnapshot(
    string UpstreamBaseVersion,
    string CustomFullVersion,
    string InstalledBuildVersion,
    string RunningBuildVersion,
    string? InstalledServiceVersion,
    bool HasServiceVersionMismatch,
    string GitBranch,
    string GitCommit,
    string UpstreamBaseCommit,
    string OriginRemoteUrl,
    DateTime? BuiltAtUtc,
    string InstallFolderName,
    int CustomCommitCount,
    IReadOnlyList<CustomChangelogEntry> Entries);

public static partial class CustomBuildInfoLoader
{
    private const string DEFAULT_INSTALL_ROOT = @"C:\Program Files\Proton\VPN";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private static readonly HashSet<string> KnownCategories = new(StringComparer.OrdinalIgnoreCase)
    {
        "feat",
        "fix",
        "chore",
        "refactor",
        "perf",
        "docs",
        "test",
        "build",
        "ci",
    };

    [GeneratedRegex(@"\+g([0-9a-fA-F]+)", RegexOptions.CultureInvariant)]
    private static partial Regex CommitSuffixRegex();

    [GeneratedRegex(@"^([a-zA-Z]+)(?:\([^)]+\))?:\s*", RegexOptions.CultureInvariant)]
    private static partial Regex ConventionalPrefixRegex();

    public static InstalledBuildSnapshot Load(
        string? baseDirectory = null,
        Assembly? assembly = null,
        string? installedRootDirectory = null)
    {
        string baseDir = string.IsNullOrWhiteSpace(baseDirectory)
            ? AppContext.BaseDirectory
            : baseDirectory;
        string installRoot = string.IsNullOrWhiteSpace(installedRootDirectory)
            ? DEFAULT_INSTALL_ROOT
            : installedRootDirectory;
        Assembly targetAssembly = assembly ?? Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();

        BuildInfoDocument? buildInfo = TryReadJson<BuildInfoDocument>(Path.Combine(baseDir, "BUILD_INFO.json"));
        CustomChangelogDocument? changelog =
            TryReadJson<CustomChangelogDocument>(Path.Combine(baseDir, "CUSTOM_CHANGELOG.json")) ??
            TryReadJson<CustomChangelogDocument>(Path.Combine(baseDir, "Assets", "CustomChangelog.json"));

        string assemblyThreePart = (targetAssembly.GetName().Version ?? new Version(0, 0, 0)).ToString(3);
        string? assemblyFileVersion = targetAssembly.GetCustomAttribute<AssemblyFileVersionAttribute>()?.Version;
        string? assemblyInfoVersion = targetAssembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;

        string upstreamBaseVersion = FirstNonEmpty(
            buildInfo?.BaseVersion,
            changelog?.BaseVersion,
            assemblyThreePart) ?? "0.0.0";

        string runningBuildVersion = FirstNonEmpty(
            buildInfo?.NumericVersion,
            buildInfo?.Win32FileVersion,
            assemblyFileVersion,
            upstreamBaseVersion) ?? upstreamBaseVersion;

        string? usableInfoVersion = !string.IsNullOrWhiteSpace(assemblyInfoVersion) &&
                                    !string.Equals(assemblyInfoVersion.Trim(), "$AssemblyVersion", StringComparison.OrdinalIgnoreCase)
            ? assemblyInfoVersion.Trim()
            : null;

        string customFullVersion = FirstNonEmpty(
            buildInfo?.FullVersion,
            usableInfoVersion,
            changelog?.FullVersion,
            runningBuildVersion) ?? runningBuildVersion;

        IReadOnlyList<CustomChangelogEntry> entries = changelog?.Entries?
            .Where(e => e is not null && !string.IsNullOrWhiteSpace(e.Subject))
            .Select(e => e with
            {
                Commit = e.Commit?.Trim() ?? string.Empty,
                Date = e.Date?.Trim() ?? string.Empty,
                Author = e.Author?.Trim() ?? string.Empty,
                Subject = e.Subject.Trim(),
                Category = string.IsNullOrWhiteSpace(e.Category) ? ParseCommitCategory(e.Subject) : e.Category.Trim(),
            })
            .ToList() ?? [];

        string gitCommit = FirstNonEmpty(
            buildInfo?.GitCommit,
            ExtractCommitFromFullVersion(customFullVersion),
            entries.FirstOrDefault()?.Commit) ?? string.Empty;

        string gitBranch = FirstNonEmpty(
            buildInfo?.GitBranch,
            changelog?.Branch,
            "master") ?? "master";

        string upstreamBaseCommit = FirstNonEmpty(
            buildInfo?.UpstreamBaseCommit,
            changelog?.UpstreamBaseCommit) ?? string.Empty;

        string originRemoteUrl = FirstNonEmpty(
            buildInfo?.OriginRemoteUrl,
            changelog?.OriginRemoteUrl) ?? string.Empty;

        DateTime? builtAtUtc = TryParseUtcDateTime(buildInfo?.BuiltAtUtc) ??
                               TryParseUtcDateTime(changelog?.BuiltAtUtc) ??
                               TryGetAssemblyLastWriteUtc(targetAssembly);

        string? installedServiceVersion = TryReadFileVersion(Path.Combine(baseDir, "ProtonVPNService.exe"));
        (string? newestInstalledFolderName, string? newestInstalledVersion, string? newestInstalledServiceVersion) =
            FindNewestInstalledVersion(installRoot);

        if (string.IsNullOrWhiteSpace(installedServiceVersion))
        {
            installedServiceVersion = newestInstalledServiceVersion;
        }

        string leafDirName = GetLeafDirectoryName(baseDir);
        bool isRunningFromVersionFolder = leafDirName.StartsWith("v", StringComparison.OrdinalIgnoreCase) &&
                                          Version.TryParse(leafDirName[1..], out _);

        string installedBuildVersion;
        string installFolderName;
        if (isRunningFromVersionFolder)
        {
            installFolderName = leafDirName;
            installedBuildVersion = runningBuildVersion != upstreamBaseVersion
                ? runningBuildVersion
                : leafDirName[1..];
        }
        else if (!string.IsNullOrWhiteSpace(newestInstalledVersion) && !string.IsNullOrWhiteSpace(newestInstalledFolderName))
        {
            installedBuildVersion = newestInstalledVersion;
            installFolderName = $"{newestInstalledFolderName} (Dev run)";
        }
        else
        {
            installedBuildVersion = runningBuildVersion;
            installFolderName = "Dev build";
        }

        bool hasServiceMismatch = !string.IsNullOrWhiteSpace(installedServiceVersion) &&
                                  !string.Equals(installedServiceVersion.Trim(), runningBuildVersion.Trim(), StringComparison.OrdinalIgnoreCase);

        int customCommitCount = buildInfo?.CustomCommitCount is > 0
            ? buildInfo.CustomCommitCount.Value
            : entries.Count;

        return new InstalledBuildSnapshot(
            UpstreamBaseVersion: upstreamBaseVersion,
            CustomFullVersion: customFullVersion,
            InstalledBuildVersion: installedBuildVersion,
            RunningBuildVersion: runningBuildVersion,
            InstalledServiceVersion: installedServiceVersion,
            HasServiceVersionMismatch: hasServiceMismatch,
            GitBranch: gitBranch,
            GitCommit: gitCommit,
            UpstreamBaseCommit: upstreamBaseCommit,
            OriginRemoteUrl: originRemoteUrl,
            BuiltAtUtc: builtAtUtc,
            InstallFolderName: installFolderName,
            CustomCommitCount: customCommitCount,
            Entries: entries);
    }

    public static string ParseCommitCategory(string? subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
        {
            return "change";
        }

        Match match = ConventionalPrefixRegex().Match(subject.Trim());
        if (match.Success)
        {
            string candidate = match.Groups[1].Value.ToLowerInvariant();
            if (KnownCategories.Contains(candidate))
            {
                return candidate;
            }
        }

        return "change";
    }

    public static IReadOnlyList<CustomChangelogDateGroup> GroupEntriesByDate(IReadOnlyList<CustomChangelogEntry> entries)
    {
        if (entries.Count == 0)
        {
            return [];
        }

        List<CustomChangelogDateGroup> groups = [];
        List<string> orderedDates = [];
        Dictionary<string, List<CustomChangelogEntry>> byDate = new(StringComparer.OrdinalIgnoreCase);

        foreach (CustomChangelogEntry entry in entries)
        {
            string dateKey = string.IsNullOrWhiteSpace(entry.Date) ? "Unreleased" : entry.Date.Trim();
            if (!byDate.TryGetValue(dateKey, out List<CustomChangelogEntry>? list))
            {
                list = [];
                byDate[dateKey] = list;
                orderedDates.Add(dateKey);
            }

            list.Add(entry);
        }

        foreach (string date in orderedDates)
        {
            groups.Add(new CustomChangelogDateGroup(date, byDate[date]));
        }

        return groups;
    }

    private static T? TryReadJson<T>(string path) where T : class
    {
        try
        {
            if (!File.Exists(path))
            {
                return null;
            }

            string json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<T>(json, JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    private static string? TryReadFileVersion(string executablePath)
    {
        try
        {
            if (!File.Exists(executablePath))
            {
                return null;
            }

            FileVersionInfo info = FileVersionInfo.GetVersionInfo(executablePath);
            return string.IsNullOrWhiteSpace(info.FileVersion) ? null : info.FileVersion.Trim();
        }
        catch
        {
            return null;
        }
    }

    private static (string? FolderName, string? VersionString, string? ServiceVersion) FindNewestInstalledVersion(string installRoot)
    {
        try
        {
            if (!Directory.Exists(installRoot))
            {
                return (null, null, null);
            }

            (string FolderName, string VersionString, Version Parsed, string DirPath)? best = null;
            foreach (string dir in Directory.EnumerateDirectories(installRoot, "v*"))
            {
                string name = Path.GetFileName(dir);
                if (name.Length <= 1)
                {
                    continue;
                }

                string rawVersion = name[1..];
                if (!Version.TryParse(rawVersion, out Version? parsed))
                {
                    continue;
                }

                if (best is null || parsed > best.Value.Parsed)
                {
                    best = (name, rawVersion, parsed, dir);
                }
            }

            if (best is null)
            {
                return (null, null, null);
            }

            string? serviceVersion = TryReadFileVersion(Path.Combine(best.Value.DirPath, "ProtonVPNService.exe"));
            return (best.Value.FolderName, best.Value.VersionString, serviceVersion);
        }
        catch
        {
            return (null, null, null);
        }
    }

    private static string GetLeafDirectoryName(string directoryPath)
    {
        try
        {
            string trimmed = directoryPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return Path.GetFileName(trimmed);
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string? ExtractCommitFromFullVersion(string fullVersion)
    {
        Match match = CommitSuffixRegex().Match(fullVersion);
        return match.Success ? match.Groups[1].Value : null;
    }

    private static DateTime? TryParseUtcDateTime(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        return DateTime.TryParse(
            raw,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal,
            out DateTime parsed)
            ? parsed
            : null;
    }

    private static DateTime? TryGetAssemblyLastWriteUtc(Assembly assembly)
    {
        try
        {
            string location = assembly.Location;
            return !string.IsNullOrWhiteSpace(location) && File.Exists(location)
                ? File.GetLastWriteTimeUtc(location)
                : null;
        }
        catch
        {
            return null;
        }
    }

    private static string? FirstNonEmpty(params string?[] values)
    {
        foreach (string? value in values)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value.Trim();
            }
        }

        return null;
    }
}
