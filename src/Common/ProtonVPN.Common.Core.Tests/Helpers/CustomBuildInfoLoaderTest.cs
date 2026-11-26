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

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using ProtonVPN.Common.Core.Helpers;

namespace ProtonVPN.Common.Core.Tests.Helpers;

[TestClass]
public class CustomBuildInfoLoaderTest
{
    [TestMethod]
    public void Load_ReadsBuildInfoAndCustomChangelogFromBaseDirectory()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), $"pvpn-buildinfo-{Guid.NewGuid():N}");
        string versionDir = Path.Combine(tempRoot, "v5.1.10.1959");
        Directory.CreateDirectory(versionDir);

        try
        {
            File.WriteAllText(Path.Combine(versionDir, "BUILD_INFO.json"), JsonSerializer.Serialize(new
            {
                component = "proton-win-app",
                baseVersion = "5.1.10",
                buildNumber = 1959,
                numericVersion = "5.1.10.1959",
                win32FileVersion = "5.1.10.1959",
                fullVersion = "5.1.10.1959+g1234abc",
                gitCommit = "1234abc",
                gitBranch = "master",
                builtAtUtc = "2026-11-26T11:30:00Z",
                upstreamBaseCommit = "52b9967",
                originRemoteUrl = "https://github.com/lent85/win-app.git",
                customCommitCount = 12,
            }));

            File.WriteAllText(Path.Combine(versionDir, "CUSTOM_CHANGELOG.json"), JsonSerializer.Serialize(new
            {
                baseVersion = "5.1.10",
                upstreamBaseCommit = "52b9967",
                branch = "master",
                entries = new[]
                {
                    new { commit = "1234abc", date = "2026-11-26", author = "Casper Ngo", subject = "fix(multi-tunnel): route fix", category = "fix" },
                    new { commit = "a68b0ce", date = "2026-11-26", author = "Casper Ngo", subject = "feat: multi-tunnel", category = "feat" },
                    new { commit = "510a3e3", date = "2026-11-25", author = "Casper Ngo", subject = "feat: installer", category = "feat" },
                },
            }));

            InstalledBuildSnapshot snapshot = CustomBuildInfoLoader.Load(
                baseDirectory: versionDir,
                assembly: typeof(CustomBuildInfoLoader).Assembly,
                installedRootDirectory: tempRoot,
                registeredServiceExecutablePath: string.Empty);

            snapshot.UpstreamBaseVersion.Should().Be("5.1.10");
            snapshot.CustomFullVersion.Should().Be("5.1.10.1959+g1234abc");
            snapshot.InstalledBuildVersion.Should().Be("5.1.10.1959");
            snapshot.RunningBuildVersion.Should().Be("5.1.10.1959");
            snapshot.GitBranch.Should().Be("master");
            snapshot.GitCommit.Should().Be("1234abc");
            snapshot.UpstreamBaseCommit.Should().Be("52b9967");
            snapshot.CustomCommitCount.Should().Be(12);
            snapshot.InstallFolderName.Should().Be("v5.1.10.1959");
            snapshot.Entries.Should().HaveCount(3);

            IReadOnlyList<CustomChangelogDateGroup> groups = CustomBuildInfoLoader.GroupEntriesByDate(snapshot.Entries);
            groups.Should().HaveCount(2);
            groups[0].DateLabel.Should().Be("2026-11-26");
            groups[0].Entries.Should().HaveCount(2);
            groups[1].DateLabel.Should().Be("2026-11-25");
            groups[1].Entries.Should().ContainSingle();
        }
        finally
        {
            try { Directory.Delete(tempRoot, recursive: true); } catch { }
        }
    }

    [TestMethod]
    public void Load_FallsBackToAssetsCustomChangelogAndDetectsInstalledVersionFolder()
    {
        string tempDevDir = Path.Combine(Path.GetTempPath(), $"pvpn-dev-{Guid.NewGuid():N}");
        string tempAssetsDir = Path.Combine(tempDevDir, "Assets");
        string tempInstallRoot = Path.Combine(Path.GetTempPath(), $"pvpn-inst-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempAssetsDir);
        Directory.CreateDirectory(Path.Combine(tempInstallRoot, "v5.1.10.1958"));
        Directory.CreateDirectory(Path.Combine(tempInstallRoot, "v5.1.10.1957"));

        try
        {
            File.WriteAllText(Path.Combine(tempAssetsDir, "CustomChangelog.json"), JsonSerializer.Serialize(new
            {
                baseVersion = "5.1.10",
                upstreamBaseCommit = "52b9967",
                branch = "master",
                fullVersion = "5.1.10-dev (origin/master)",
                entries = new[]
                {
                    new { commit = "a68b0ce", date = "2026-11-26", author = "Casper Ngo", subject = "feat: multi-tunnel", category = "" },
                },
            }));

            InstalledBuildSnapshot snapshot = CustomBuildInfoLoader.Load(
                baseDirectory: tempDevDir,
                assembly: typeof(CustomBuildInfoLoader).Assembly,
                installedRootDirectory: tempInstallRoot,
                registeredServiceExecutablePath: string.Empty);

            snapshot.UpstreamBaseVersion.Should().Be("5.1.10");
            snapshot.InstalledBuildVersion.Should().Be("5.1.10.1958");
            snapshot.InstallFolderName.Should().Be("v5.1.10.1958 (Dev run)");
            snapshot.Entries.Should().ContainSingle();
            snapshot.Entries[0].Category.Should().Be("feat");
            snapshot.CustomCommitCount.Should().Be(1);
        }
        finally
        {
            try { Directory.Delete(tempDevDir, recursive: true); } catch { }
            try { Directory.Delete(tempInstallRoot, recursive: true); } catch { }
        }
    }

    [TestMethod]
    public void ParseCommitCategory_ExtractsConventionalPrefixOrDefaultsToChange()
    {
        CustomBuildInfoLoader.ParseCommitCategory("feat: add multi-tunnel").Should().Be("feat");
        CustomBuildInfoLoader.ParseCommitCategory("fix(wfp): handle IPv6").Should().Be("fix");
        CustomBuildInfoLoader.ParseCommitCategory("chore: ignore artifacts").Should().Be("chore");
        CustomBuildInfoLoader.ParseCommitCategory("Update dependencies").Should().Be("change");
        CustomBuildInfoLoader.ParseCommitCategory(null).Should().Be("change");
    }

    [TestMethod]
    public void Load_ComparesRegisteredServiceExecutableAgainstWin32FileVersion()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), $"pvpn-svc-check-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempRoot);

        try
        {
            string probeBinaryPath = typeof(CustomBuildInfoLoader).Assembly.Location;
            string probeFileVersion = System.Diagnostics.FileVersionInfo.GetVersionInfo(probeBinaryPath).FileVersion!;

            File.WriteAllText(Path.Combine(tempRoot, "BUILD_INFO.json"), JsonSerializer.Serialize(new
            {
                baseVersion = "5.1.10",
                buildNumber = 70000,
                numericVersion = "5.1.10.70000",
                win32FileVersion = probeFileVersion,
                fullVersion = "5.1.10.70000+g1234abc",
            }));

            InstalledBuildSnapshot matchingSnapshot = CustomBuildInfoLoader.Load(
                baseDirectory: tempRoot,
                assembly: typeof(CustomBuildInfoLoader).Assembly,
                installedRootDirectory: tempRoot,
                registeredServiceExecutablePath: probeBinaryPath);

            matchingSnapshot.HasServiceVersionMismatch.Should().BeFalse();

            File.WriteAllText(Path.Combine(tempRoot, "BUILD_INFO.json"), JsonSerializer.Serialize(new
            {
                baseVersion = "5.1.10",
                buildNumber = 70000,
                numericVersion = "5.1.10.70000",
                win32FileVersion = "5.1.10.9999",
                fullVersion = "5.1.10.70000+g1234abc",
            }));

            InstalledBuildSnapshot mismatchSnapshot = CustomBuildInfoLoader.Load(
                baseDirectory: tempRoot,
                assembly: typeof(CustomBuildInfoLoader).Assembly,
                installedRootDirectory: tempRoot,
                registeredServiceExecutablePath: probeBinaryPath);

            mismatchSnapshot.HasServiceVersionMismatch.Should().BeTrue();
        }
        finally
        {
            try { Directory.Delete(tempRoot, recursive: true); } catch { }
        }
    }
}
