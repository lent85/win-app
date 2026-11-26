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

using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace ProtonVPN.Client.UI.Main.Settings.Pages.Connection;

public sealed record DiscoveredAppItem(
    string DisplayName,
    string ProcessName,
    string ExecutablePath,
    bool IsRunning,
    int ProcessCount)
{
    public string Subtitle => IsRunning
        ? $"Running ({ProcessCount}) • {ExecutablePath}"
        : $"Installed • {ExecutablePath}";

    public string BadgeText => IsRunning ? $"Running ({ProcessCount})" : "Installed";
}

public static class WindowsAppDiscoveryHelper
{
    private const uint ProcessQueryLimitedInformation = 0x1000;

    public static IReadOnlyList<DiscoveredAppItem> DiscoverApps()
    {
        Dictionary<string, (string DisplayName, string ProcessName, int Count)> runningByPath =
            new(StringComparer.OrdinalIgnoreCase);

        try
        {
            foreach (Process proc in Process.GetProcesses())
            {
                using (proc)
                {
                    string? path = TryGetProcessImagePath(proc);
                    if (string.IsNullOrWhiteSpace(path) || !File.Exists(path) || IsWindowsCoreBinary(path))
                    {
                        continue;
                    }

                    if (runningByPath.TryGetValue(path, out (string DisplayName, string ProcessName, int Count) existing))
                    {
                        runningByPath[path] = (existing.DisplayName, existing.ProcessName, existing.Count + 1);
                    }
                    else
                    {
                        string procName = proc.ProcessName;
                        string display = ResolveFriendlyName(path, procName);
                        runningByPath[path] = (display, procName, 1);
                    }
                }
            }
        }
        catch
        {
        }

        Dictionary<string, (string DisplayName, string ProcessName)> installedByPath =
            new(StringComparer.OrdinalIgnoreCase);

        if (OperatingSystem.IsWindows())
        {
            ScanRegistryAppPaths(Registry.CurrentUser, installedByPath);
            ScanRegistryAppPaths(Registry.LocalMachine, installedByPath);
        }

        ScanWellKnownInstalledApps(installedByPath);

        List<DiscoveredAppItem> result = [];
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

        foreach ((string path, (string display, string procName, int count)) in runningByPath
            .OrderBy(kvp => kvp.Value.DisplayName, StringComparer.OrdinalIgnoreCase))
        {
            if (seen.Add(path))
            {
                result.Add(new DiscoveredAppItem(display, procName, path, IsRunning: true, ProcessCount: count));
            }
        }

        foreach ((string path, (string display, string procName)) in installedByPath
            .OrderBy(kvp => kvp.Value.DisplayName, StringComparer.OrdinalIgnoreCase))
        {
            if (seen.Add(path))
            {
                result.Add(new DiscoveredAppItem(display, procName, path, IsRunning: false, ProcessCount: 0));
            }
        }

        return result;
    }

    private static bool IsWindowsCoreBinary(string path)
    {
        string normalized = path.Replace('/', '\\');
        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrWhiteSpace(winDir))
        {
            return false;
        }

        string sys32 = Path.Combine(winDir, "System32") + "\\";
        string sysWow = Path.Combine(winDir, "SysWOW64") + "\\";
        return normalized.StartsWith(sys32, StringComparison.OrdinalIgnoreCase) ||
               normalized.StartsWith(sysWow, StringComparison.OrdinalIgnoreCase);
    }

    private static string ResolveFriendlyName(string exePath, string fallbackProcessName)
    {
        try
        {
            FileVersionInfo info = FileVersionInfo.GetVersionInfo(exePath);
            if (!string.IsNullOrWhiteSpace(info.FileDescription))
            {
                return info.FileDescription.Trim();
            }
            if (!string.IsNullOrWhiteSpace(info.ProductName))
            {
                return info.ProductName.Trim();
            }
        }
        catch
        {
        }

        return fallbackProcessName;
    }

    private static void ScanRegistryAppPaths(
        RegistryKey root,
        Dictionary<string, (string DisplayName, string ProcessName)> dest)
    {
        try
        {
            using RegistryKey? key = root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\App Paths");
            if (key is null)
            {
                return;
            }

            foreach (string subName in key.GetSubKeyNames())
            {
                try
                {
                    using RegistryKey? sub = key.OpenSubKey(subName);
                    string? rawPath = sub?.GetValue(null) as string;
                    string? exePath = ExtractExePath(rawPath);
                    if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath) || IsWindowsCoreBinary(exePath))
                    {
                        continue;
                    }

                    string procName = Path.GetFileNameWithoutExtension(exePath);
                    if (!dest.ContainsKey(exePath))
                    {
                        dest[exePath] = (ResolveFriendlyName(exePath, procName), procName);
                    }
                }
                catch
                {
                }
            }
        }
        catch
        {
        }
    }

    private static void ScanWellKnownInstalledApps(
        Dictionary<string, (string DisplayName, string ProcessName)> dest)
    {
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        List<(string Label, string Candidate)> candidates =
        [
            ("Opera Browser", Path.Combine(localAppData, "Programs", "Opera", "opera.exe")),
            ("Opera GX", Path.Combine(localAppData, "Programs", "Opera GX", "opera.exe")),
            ("Opera Air", Path.Combine(localAppData, "Programs", "Opera Air", "opera.exe")),
            ("Opera Browser", Path.Combine(programFiles, "Opera", "opera.exe")),
            ("Google Chrome", Path.Combine(programFiles, "Google", "Chrome", "Application", "chrome.exe")),
            ("Google Chrome", Path.Combine(programFilesX86, "Google", "Chrome", "Application", "chrome.exe")),
            ("Google Chrome", Path.Combine(localAppData, "Google", "Chrome", "Application", "chrome.exe")),
            ("Microsoft Edge", Path.Combine(programFilesX86, "Microsoft", "Edge", "Application", "msedge.exe")),
            ("Microsoft Edge", Path.Combine(programFiles, "Microsoft", "Edge", "Application", "msedge.exe")),
            ("Brave Browser", Path.Combine(programFiles, "BraveSoftware", "Brave-Browser", "Application", "brave.exe")),
            ("Mozilla Firefox", Path.Combine(programFiles, "Mozilla Firefox", "firefox.exe")),
            ("Vivaldi", Path.Combine(localAppData, "Vivaldi", "Application", "vivaldi.exe")),
            ("Telegram Desktop", Path.Combine(appData, "Telegram Desktop", "Telegram.exe")),
            ("qBittorrent", Path.Combine(programFiles, "qBittorrent", "qbittorrent.exe")),
            ("Steam", Path.Combine(programFilesX86, "Steam", "steam.exe")),
            ("Zoom", Path.Combine(appData, "Zoom", "bin", "Zoom.exe")),
            ("Visual Studio Code", Path.Combine(localAppData, "Programs", "Microsoft VS Code", "Code.exe")),
        ];

        foreach ((string label, string candidate) in candidates)
        {
            if (!string.IsNullOrWhiteSpace(candidate) && File.Exists(candidate) && !dest.ContainsKey(candidate))
            {
                dest[candidate] = (label, Path.GetFileNameWithoutExtension(candidate));
            }
        }
    }

    private static string? ExtractExePath(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        string trimmed = raw.Trim().Trim('"');
        int exeIdx = trimmed.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeIdx >= 0)
        {
            return trimmed[..(exeIdx + 4)].Trim('"');
        }

        return trimmed;
    }

    private static string? TryGetProcessImagePath(Process proc)
    {
        if (OperatingSystem.IsWindows())
        {
            IntPtr hProcess = IntPtr.Zero;
            try
            {
                hProcess = OpenProcess(ProcessQueryLimitedInformation, false, proc.Id);
                if (hProcess != IntPtr.Zero)
                {
                    char[] buffer = new char[1024];
                    int size = buffer.Length;
                    if (QueryFullProcessImageName(hProcess, 0, buffer, ref size) && size > 0)
                    {
                        return new string(buffer, 0, size);
                    }
                }
            }
            catch
            {
            }
            finally
            {
                if (hProcess != IntPtr.Zero)
                {
                    CloseHandle(hProcess);
                }
            }
        }

        try
        {
            return proc.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(
        IntPtr hProcess,
        int dwFlags,
        [Out] char[] lpExeName,
        ref int lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
}
