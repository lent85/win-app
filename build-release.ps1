<#
.SYNOPSIS
    Builds and packages Proton VPN Multi-Tunnel Release binaries and Windows Installer (.exe / .zip)
    with a monotonically increasing Git-commit build number for seamless in-place upgrades.
.DESCRIPTION
    Run on Windows 10/11 (x64 or ARM64) with Visual Studio 2022 / .NET 10 SDK and optionally Inno Setup 6.
#>
[CmdletBinding()]
param(
    [ValidateSet("x64", "arm64")]
    [string]$Platform = "x64",

    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",

    [string]$BaseVersion = "",

    [switch]$SkipDependencies,
    [switch]$SkipTests,
    [switch]$SkipInstaller,
    [switch]$Bti
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoRoot

# 0. Resolve Git commit build number & base version from src/GlobalAssemblyInfo.cs
$GlobalAssemblyInfoPath = Join-Path $RepoRoot "src\GlobalAssemblyInfo.cs"
$OriginalGlobalAssemblyInfo = Get-Content -Raw -Encoding UTF8 $GlobalAssemblyInfoPath

if ([string]::IsNullOrWhiteSpace($BaseVersion)) {
    if ($OriginalGlobalAssemblyInfo -match 'AssemblyVersion\("(\d+\.\d+\.\d+)\.\d+"\)') {
        $BaseVersion = $Matches[1]
    } else {
        $BaseVersion = "5.1.10"
    }
}

$BuildNumber = 1
$GitHash = "nogit"
$GitFullHash = "unknown"
$GitBranch = "unknown"
$UpstreamBaseCommit = ""
$UpstreamBaseShort = ""
$OriginRemoteUrl = ""
try {
    $BuildNumberRaw = (& git -C $RepoRoot rev-list --count HEAD 2>$null)
    if ($LASTEXITCODE -eq 0 -and $BuildNumberRaw) {
        $BuildNumber = [int]$BuildNumberRaw.Trim()
    }
    $GitHashRaw = (& git -C $RepoRoot rev-parse --short=7 HEAD 2>$null)
    if ($LASTEXITCODE -eq 0 -and $GitHashRaw) { $GitHash = $GitHashRaw.Trim() }
    $GitFullRaw = (& git -C $RepoRoot rev-parse HEAD 2>$null)
    if ($LASTEXITCODE -eq 0 -and $GitFullRaw) { $GitFullHash = $GitFullRaw.Trim() }
    $GitBranchRaw = (& git -C $RepoRoot rev-parse --abbrev-ref HEAD 2>$null)
    if ($LASTEXITCODE -eq 0 -and $GitBranchRaw) { $GitBranch = $GitBranchRaw.Trim() }
    $UpstreamRaw = (& git -C $RepoRoot log --grep="^Promote release " --format="%H" -n 1 2>$null)
    if ($LASTEXITCODE -eq 0 -and $UpstreamRaw) {
        $UpstreamBaseCommit = $UpstreamRaw.Trim()
        if ($UpstreamBaseCommit.Length -ge 7) {
            $UpstreamBaseShort = $UpstreamBaseCommit.Substring(0, 7)
        }
    }
    $RemoteRaw = (& git -C $RepoRoot remote get-url origin 2>$null)
    if ($LASTEXITCODE -eq 0 -and $RemoteRaw) {
        $OriginRemoteUrl = ($RemoteRaw.Trim() -replace '^(https?://)[^/@]+@', '$1')
    }
} catch {
    $BuildNumber = [int](Get-Date).ToUniversalTime().ToString("yyMMddHH")
}

$BuildMod = $BuildNumber % 65535
$NumericVersion = "$BaseVersion.$BuildNumber"
$Win32FileVersion = "$BaseVersion.$BuildMod"
$FullVersion = "$BaseVersion.$BuildNumber+g$GitHash"
$FileVersionTag = "$BaseVersion.$BuildNumber-g$GitHash"
$BuiltAtUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$Rid = "win-$Platform"
if ($Bti) {
    $PublishRelPath = "src/bin/$Rid/BTI/publish"
} else {
    $PublishRelPath = "src/bin/$Rid/publish"
}

$PublishDir = Join-Path $RepoRoot ($PublishRelPath -replace '/', '\')
$ResourcesDir = Join-Path $PublishDir "Resources"
$DistDir = Join-Path $RepoRoot "dist"

Write-Host "==> [proton-win-app] Building $Configuration ($Rid)" -ForegroundColor Cyan
Write-Host "    Version: $FullVersion (FileVersion=$Win32FileVersion, BuildNumber=$BuildNumber, Commit=$GitHash)" -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $PublishDir, $ResourcesDir, $DistDir | Out-Null

try {
    # Stamp GlobalAssemblyInfo.cs transiently during build, then restore in finally block so git diff remains clean.
    $StampedAssemblyInfo = $OriginalGlobalAssemblyInfo `
        -replace 'AssemblyFileVersion\("[^"]*"\)', "AssemblyFileVersion(`"$Win32FileVersion`")" `
        -replace 'AssemblyInformationalVersion\("[^"]*"\)', "AssemblyInformationalVersion(`"$FullVersion`")"
    [System.IO.File]::WriteAllText($GlobalAssemblyInfoPath, $StampedAssemblyInfo, [System.Text.UTF8Encoding]::new($false))

    # 1. Stage local native binaries and optional remote dependency cache
    if (-not $SkipDependencies) {
        $NativeDir = Join-Path $RepoRoot "Setup\Native\$Platform"
        if (Test-Path $NativeDir) {
            Write-Host "==> Staging native drivers and libraries from $NativeDir..."
            Copy-Item -Path "$NativeDir\wireguard.dll","$NativeDir\tunnel.dll","$NativeDir\wireguard-tunnel-tcp.dll","$NativeDir\wintun.dll" -Destination $PublishDir -Force -ErrorAction SilentlyContinue
            Copy-Item -Path "$NativeDir\ProtonVPN.CalloutDriver.sys","$NativeDir\openvpn.exe","$NativeDir\libcrypto-*.dll","$NativeDir\libssl-*.dll","$NativeDir\libpkcs11-helper-1.dll","$NativeDir\vcruntime140.dll" -Destination $ResourcesDir -Force -ErrorAction SilentlyContinue
        }

        $ProTunDll = Join-Path $RepoRoot "src\ProTun\ProtonVPN.ProTun.Generated\$Platform\protun.dll"
        if (Test-Path $ProTunDll) {
            $ProTunArchOut = Join-Path $PublishDir $Platform
            New-Item -ItemType Directory -Force -Path $ProTunArchOut | Out-Null
            Copy-Item -Path $ProTunDll -Destination $ProTunArchOut -Force
        }

        if ($env:DEPENDENCY_CACHE_URL) {
            $env:PLATFORM = $Platform
            $arg = if ($Bti) { "publish-BTI" } else { "publish" }
            & cmd.exe /c "`"$RepoRoot\BuildDependencies.bat`" $arg"
            if ($LASTEXITCODE -ne 0) { throw "BuildDependencies.bat failed with exit code $LASTEXITCODE" }
        } else {
            Write-Warning "DEPENDENCY_CACHE_URL is not set; checking local Proton VPN installation for prebuilt C++/Rust binaries."
            $InstalledDir = Get-ChildItem "C:\Program Files\Proton\VPN" -Directory -Filter "v*" -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $parsedVer = $null
                    if ([version]::TryParse($_.Name.Substring(1), [ref]$parsedVer)) {
                        [pscustomobject]@{ Version = $parsedVer; FullName = $_.FullName }
                    }
                } |
                Sort-Object Version -Descending |
                Select-Object -First 1 -ExpandProperty FullName
            if ($InstalledDir) {
                Write-Host "==> Staging prebuilt C++/Rust binaries from $InstalledDir..."
                Copy-Item "$InstalledDir\ProtonVPN.InstallActions.dll" "$ResourcesDir\ProtonVPN.InstallActions.dll" -Force -ErrorAction SilentlyContinue
                Copy-Item "$InstalledDir\Resources\ProtonVPN.InstallActions.x86.dll","$InstalledDir\Resources\ProtonVPN.IPFilter.dll","$InstalledDir\Resources\ProtonVPN.NetworkUtil.dll","$InstalledDir\Resources\LocalAgent.dll" -Destination $ResourcesDir -Force -ErrorAction SilentlyContinue
                Copy-Item "$InstalledDir\proton_vpn_ipv6chaos.dll","$InstalledDir\proton_srp_cffi.dll","$InstalledDir\proton_vpn_binary_status.dll" -Destination $PublishDir -Force -ErrorAction SilentlyContinue
                $PrefixTreeSrc = Join-Path $InstalledDir "ServiceData\IPv6\PrefixTree.bin"
                $DataDir = Join-Path $RepoRoot "data"
                $PrefixTreeDst = Join-Path $DataDir "ipv6_chaos_prefixtree.bin"
                if ((Test-Path $PrefixTreeSrc) -and -not (Test-Path $PrefixTreeDst)) {
                    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
                    Copy-Item $PrefixTreeSrc $PrefixTreeDst -Force
                }
            } else {
                Write-Warning "No local Proton VPN installation found; skipped external C++/Rust binaries (IPFilter, LocalAgent, SRP)."
            }
        }
    }

    # 2. Publish all Windows executables in Release configuration
    $ProjectsToPublish = @(
        "src\ProtonVPN.Launcher\ProtonVPN.Launcher.csproj",
        "src\ProtonVPN.Service\ProtonVPN.Service.csproj",
        "src\ProtonVPN.WireGuardService\ProtonVPN.WireGuardService.csproj",
        "src\ProtonVPN.RestoreInternet\ProtonVPN.RestoreInternet.csproj",
        "src\ProtonVPN.NrptWatchdog\ProtonVPN.NrptWatchdog.csproj",
        "src\ProtonVPN.TlsVerify\ProtonVPN.TlsVerify.csproj",
        "src\Client\ProtonVPN.Client\ProtonVPN.Client.csproj"
    )

    foreach ($Proj in $ProjectsToPublish) {
        $ProjPath = Join-Path $RepoRoot $Proj
        if (Test-Path $ProjPath) {
            Write-Host "==> Publishing $Proj ($Configuration | $Rid | v$NumericVersion)..."
            dotnet publish $ProjPath `
                -c $Configuration `
                -r $Rid `
                -p:Platform=$Platform `
                -p:AppendRuntimeIdentifierToOutputPath=true `
                --self-contained true `
                -o $PublishDir
            if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed for $Proj" }
        }
    }

    # Collect custom origin commits since upstream base and write BUILD_INFO.json, CUSTOM_CHANGELOG.json, VERSION.txt
    $CustomEntries = [System.Collections.Generic.List[object]]::new()
    try {
        $LogArgs = if ($UpstreamBaseCommit) {
            @("-C", $RepoRoot, "log", "$UpstreamBaseCommit..HEAD", "--max-count=100", "--format=%h%x1f%ad%x1f%an%x1f%s", "--date=short")
        } else {
            @("-C", $RepoRoot, "log", "-n", "30", "--format=%h%x1f%ad%x1f%an%x1f%s", "--date=short")
        }
        $RawLogLines = @(& git @LogArgs 2>$null)
        if ($LASTEXITCODE -eq 0 -and $RawLogLines) {
            $Sep = [char]0x1f
            foreach ($Line in $RawLogLines) {
                if ([string]::IsNullOrWhiteSpace($Line)) { continue }
                $Parts = $Line -split $Sep, 4
                if ($Parts.Count -lt 4) { continue }
                $Subject = $Parts[3].Trim()
                $Category = "change"
                if ($Subject -match '^(feat|fix|chore|refactor|perf|docs|test|build|ci)(?:\([^)]+\))?:\s*') {
                    $Category = $Matches[1].ToLowerInvariant()
                }
                $CustomEntries.Add([ordered]@{
                    commit = $Parts[0].Trim()
                    date = $Parts[1].Trim()
                    author = $Parts[2].Trim()
                    subject = $Subject
                    category = $Category
                })
            }
        }
    } catch {
        Write-Warning "Failed to collect custom git changelog: $($_.Exception.Message)"
    }

    $BuildInfoObj = [ordered]@{
        component = "proton-win-app"
        baseVersion = $BaseVersion
        buildNumber = $BuildNumber
        numericVersion = $NumericVersion
        win32FileVersion = $Win32FileVersion
        fullVersion = $FullVersion
        gitCommit = $GitHash
        gitCommitFull = $GitFullHash
        gitBranch = $GitBranch
        platform = $Platform
        configuration = $Configuration
        builtAtUtc = $BuiltAtUtc
        upstreamBaseCommit = $UpstreamBaseShort
        originRemoteUrl = $OriginRemoteUrl
        customCommitCount = $CustomEntries.Count
    }
    $BuildInfoJson = $BuildInfoObj | ConvertTo-Json -Depth 4

    $CustomChangelogObj = [ordered]@{
        baseVersion = $BaseVersion
        upstreamBaseCommit = $UpstreamBaseShort
        branch = $GitBranch
        originRemoteUrl = $OriginRemoteUrl
        fullVersion = $FullVersion
        builtAtUtc = $BuiltAtUtc
        entries = $CustomEntries.ToArray()
    }
    $CustomChangelogJson = $CustomChangelogObj | ConvertTo-Json -Depth 5

    [System.IO.File]::WriteAllText((Join-Path $PublishDir "BUILD_INFO.json"), $BuildInfoJson, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText((Join-Path $DistDir "BUILD_INFO.json"), $BuildInfoJson, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText((Join-Path $PublishDir "CUSTOM_CHANGELOG.json"), $CustomChangelogJson, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText((Join-Path $DistDir "CUSTOM_CHANGELOG.json"), $CustomChangelogJson, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText((Join-Path $PublishDir "VERSION.txt"), "$FullVersion`n", [System.Text.UTF8Encoding]::new($false))

    # 3. Run unit tests
    if (-not $SkipTests) {
        $TestProjects = @(
            "src\Common\ProtonVPN.Common.Core.Tests\ProtonVPN.Common.Core.Tests.csproj",
            "src\Tests\ProtonVPN.Service.Tests\ProtonVPN.Service.Tests.csproj",
            "src\Client\Logic\Auth\ProtonVPN.Client.Logic.Auth.Tests\ProtonVPN.Client.Logic.Auth.Tests.csproj",
            "src\Client\Logic\Connection\ProtonVPN.Client.Logic.Connection.Tests\ProtonVPN.Client.Logic.Connection.Tests.csproj"
        )
        foreach ($Tp in $TestProjects) {
            $TpPath = Join-Path $RepoRoot $Tp
            if (Test-Path $TpPath) {
                $TestName = [System.IO.Path]::GetFileNameWithoutExtension($Tp)
                $TestOutDir = Join-Path $RepoRoot "src\bin\tests\$TestName"
                if (Test-Path $TestOutDir) { Remove-Item -Recurse -Force $TestOutDir }
                Write-Host "==> Testing $Tp..."
                dotnet test $TpPath -c $Configuration -o $TestOutDir
                if ($LASTEXITCODE -ne 0) { throw "dotnet test failed for $Tp" }
            }
        }
    }

    # 4. Create Portable ZIP archive + SHA256
    $PortableZip = Join-Path $DistDir "ProtonVPN-MultiTunnel-$Rid-$Configuration-v$FileVersionTag-portable.zip"
    if (Test-Path $PortableZip) { Remove-Item $PortableZip -Force }
    Compress-Archive -Path "$PublishDir\*" -DestinationPath $PortableZip -CompressionLevel Optimal
    $ZipHash = (Get-FileHash -Algorithm SHA256 $PortableZip).Hash.ToLowerInvariant()
    "$ZipHash  $(Split-Path -Leaf $PortableZip)" | Out-File -Encoding ascii "$PortableZip.sha256"
    Write-Host "==> Created portable archive: $PortableZip" -ForegroundColor Green

    # 5. Build Inno Setup Installer (.exe) if ISCC.exe is installed
    # Passes /DMyAppVersion="$BaseVersion.$BuildNumber" and /DHash="g$GitHash" so VersionInfoVersion and {app}\v... auto-increment on every commit.
    if (-not $SkipInstaller) {
        $IsccCandidates = @(
            "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
            "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
            "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
            (Get-Command ISCC.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue)
        ) | Where-Object { $_ -and (Test-Path $_) }

        $Iscc = $IsccCandidates | Select-Object -First 1
        if ($Iscc) {
            $env:BUILD_PATH = $PublishRelPath
            $IssFile = Join-Path $RepoRoot "Setup\Setup.$Platform.iss"
            Write-Host "==> Running Inno Setup: $Iscc /DMyAppVersion=$NumericVersion /DHash=g$GitHash $IssFile" -ForegroundColor Cyan
            & $Iscc "/DMyAppVersion=$NumericVersion" "/DHash=g$GitHash" $IssFile
            if ($LASTEXITCODE -ne 0) { throw "ISCC.exe failed with exit code $LASTEXITCODE" }

            $InstallerOutDir = Join-Path $RepoRoot "Setup\Installers"
            Get-ChildItem -Path $InstallerOutDir -Filter "*.exe" | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | ForEach-Object {
                $DestExe = Join-Path $DistDir $_.Name
                Copy-Item $_.FullName $DestExe -Force
                $ExeHash = (Get-FileHash -Algorithm SHA256 $DestExe).Hash.ToLowerInvariant()
                "$ExeHash  $($_.Name)" | Out-File -Encoding ascii "$DestExe.sha256"
                Write-Host "==> Created Windows Installer: $DestExe" -ForegroundColor Green
            }
        } else {
            Write-Warning "Inno Setup 6 (ISCC.exe) not found. Portable ZIP created; install Inno Setup 6 to build Setup.$Platform.iss."
        }
    }
} finally {
    # Always restore original GlobalAssemblyInfo.cs
    [System.IO.File]::WriteAllText($GlobalAssemblyInfoPath, $OriginalGlobalAssemblyInfo, [System.Text.UTF8Encoding]::new($false))
}
