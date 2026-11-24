#!/usr/bin/env bash
set -euo pipefail

export DOTNET_ROOT="${DOTNET_ROOT:-$HOME/.dotnet}"
export PATH="$DOTNET_ROOT:$DOTNET_ROOT/tools:$PATH"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PLATFORM="x64"
CONFIGURATION="Release"
BASE_VERSION="${BASE_VERSION:-}"
CUSTOM_VERSION=""

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Cross-builds Windows Multi-Tunnel core assemblies (NetworkFilter, ProcessCommunication.Contracts,
ProtonVPN.Service, ProtonVPN.WireGuardService) in Release configuration from Linux and stages
native Windows drivers/DLLs (CalloutDriver, Wintun, WireGuard, ProTun) into proton-win-app/dist/,
automatically embedding the Git commit build number so every commit produces an upgrade-ready version.

Note: Full WinUI 3 Desktop (ProtonVPN.Client.csproj) & Inno Setup (.exe installer) require
Windows with Visual Studio / Windows App SDK via build-release.ps1.

Options:
  --arch <x64|arm64>     Target Windows architecture (default: x64)
  --base-version <x.y.z> Override base version (default: extracted from src/GlobalAssemblyInfo.cs)
  --version <ver>        Override full version string directly
  -h, --help             Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch) PLATFORM="${2:-}"; shift 2 ;;
        --base-version) BASE_VERSION="${2:-}"; shift 2 ;;
        --version) CUSTOM_VERSION="${2:-}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

GLOBAL_ASSEMBLY_INFO="$SCRIPT_DIR/src/GlobalAssemblyInfo.cs"
if [[ -z "$BASE_VERSION" ]]; then
    BASE_VERSION="$(grep -oE 'AssemblyVersion\("[0-9]+\.[0-9]+\.[0-9]+' "$GLOBAL_ASSEMBLY_INFO" | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "5.1.10")"
fi

if git -C "$SCRIPT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    BUILD_NUMBER="$(git -C "$SCRIPT_DIR" rev-list --count HEAD 2>/dev/null || echo 1)"
    GIT_HASH="$(git -C "$SCRIPT_DIR" rev-parse --short=7 HEAD 2>/dev/null || echo "nogit")"
    GIT_FULL_HASH="$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null || echo "unknown")"
    GIT_BRANCH="$(git -C "$SCRIPT_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")"
else
    BUILD_NUMBER="$(date -u +%y%m%d%H)"
    GIT_HASH="nogit"
    GIT_FULL_HASH="unknown"
    GIT_BRANCH="unknown"
fi

if [[ -n "$CUSTOM_VERSION" ]]; then
    FULL_VERSION="$CUSTOM_VERSION"
    FILE_VERSION="${CUSTOM_VERSION//+/_}"
    NUMERIC_VERSION="${CUSTOM_VERSION%%[-+]*}"
    WIN32_FILE_VERSION="$NUMERIC_VERSION"
else
    BUILD_MOD=$((BUILD_NUMBER % 65535))
    NUMERIC_VERSION="${BASE_VERSION}.${BUILD_NUMBER}"
    WIN32_FILE_VERSION="${BASE_VERSION}.${BUILD_MOD}"
    FULL_VERSION="${BASE_VERSION}.${BUILD_NUMBER}+g${GIT_HASH}"
    FILE_VERSION="${BASE_VERSION}.${BUILD_NUMBER}-g${GIT_HASH}"
fi

BUILT_AT_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

DIST_DIR="$SCRIPT_DIR/dist"
STAGE_DIR="$DIST_DIR/win-${PLATFORM}-release-stage"
RES_DIR="$STAGE_DIR/Resources"
mkdir -p "$DIST_DIR"
rm -f "$DIST_DIR"/*.tar.gz "$DIST_DIR"/*.zip "$DIST_DIR/SHA256SUMS.txt" "$DIST_DIR/BUILD_INFO.json"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR" "$RES_DIR" "$STAGE_DIR/$PLATFORM"

echo "==> [proton-win-app] Building Windows Multi-Tunnel Core ($CONFIGURATION | win-$PLATFORM)"
echo "    Version: $FULL_VERSION (Win32FileVersion=$WIN32_FILE_VERSION, BuildNumber=$BUILD_NUMBER, Commit=$GIT_HASH)"

# Temporarily stamp GlobalAssemblyInfo.cs for this build and always restore cleanly afterwards
ORIG_ASSEMBLY_INFO="$(mktemp)"
cp "$GLOBAL_ASSEMBLY_INFO" "$ORIG_ASSEMBLY_INFO"
restore_assembly_info() {
    if [[ -f "$ORIG_ASSEMBLY_INFO" ]]; then
        cp "$ORIG_ASSEMBLY_INFO" "$GLOBAL_ASSEMBLY_INFO"
        rm -f "$ORIG_ASSEMBLY_INFO"
    fi
}
trap restore_assembly_info EXIT

sed -i -E \
    -e "s/AssemblyFileVersion\(\"[^\"]*\"\)/AssemblyFileVersion(\"${WIN32_FILE_VERSION}\")/" \
    -e "s/AssemblyInformationalVersion\(\"[^\"]*\"\)/AssemblyInformationalVersion(\"${FULL_VERSION}\")/" \
    "$GLOBAL_ASSEMBLY_INFO"

dotnet build "$SCRIPT_DIR/src/ProtonVPN.NetworkFilter/ProtonVPN.NetworkFilter.csproj" \
    -c "$CONFIGURATION" -p:EnableWindowsTargeting=true -o "$STAGE_DIR"

dotnet build "$SCRIPT_DIR/src/ProcessCommunication/ProtonVPN.ProcessCommunication.Contracts/ProtonVPN.ProcessCommunication.Contracts.csproj" \
    -c "$CONFIGURATION" -p:EnableWindowsTargeting=true -o "$STAGE_DIR"

dotnet build "$SCRIPT_DIR/src/ProtonVPN.Service/ProtonVPN.Service.csproj" \
    -c "$CONFIGURATION" -p:EnableWindowsTargeting=true -o "$STAGE_DIR"

dotnet build "$SCRIPT_DIR/src/ProtonVPN.WireGuardService/ProtonVPN.WireGuardService.csproj" \
    -c "$CONFIGURATION" -p:EnableWindowsTargeting=true -o "$STAGE_DIR"

# Stage prebuilt Windows kernel drivers and native DLLs included in Setup/Native & ProTun
if [[ -d "$SCRIPT_DIR/Setup/Native/$PLATFORM" ]]; then
    cp -f "$SCRIPT_DIR/Setup/Native/$PLATFORM"/{wireguard.dll,tunnel.dll,wireguard-tunnel-tcp.dll,wintun.dll} "$STAGE_DIR/" 2>/dev/null || true
    cp -f "$SCRIPT_DIR/Setup/Native/$PLATFORM"/{ProtonVPN.CalloutDriver.sys,openvpn.exe,vcruntime140.dll} "$RES_DIR/" 2>/dev/null || true
    cp -f "$SCRIPT_DIR/Setup/Native/$PLATFORM"/lib*.dll "$RES_DIR/" 2>/dev/null || true
fi

if [[ -f "$SCRIPT_DIR/src/ProTun/ProtonVPN.ProTun.Generated/$PLATFORM/protun.dll" ]]; then
    cp -f "$SCRIPT_DIR/src/ProTun/ProtonVPN.ProTun.Generated/$PLATFORM/protun.dll" "$STAGE_DIR/$PLATFORM/"
fi

cat > "$STAGE_DIR/BUILD_INFO.json" <<EOF
{
  "component": "proton-win-app",
  "baseVersion": "$BASE_VERSION",
  "buildNumber": $BUILD_NUMBER,
  "numericVersion": "$NUMERIC_VERSION",
  "win32FileVersion": "$WIN32_FILE_VERSION",
  "fullVersion": "$FULL_VERSION",
  "gitCommit": "$GIT_HASH",
  "gitCommitFull": "$GIT_FULL_HASH",
  "gitBranch": "$GIT_BRANCH",
  "platform": "$PLATFORM",
  "configuration": "$CONFIGURATION",
  "builtAtUtc": "$BUILT_AT_UTC"
}
EOF
cp -f "$STAGE_DIR/BUILD_INFO.json" "$DIST_DIR/BUILD_INFO.json"
printf "%s\n" "$FULL_VERSION" > "$STAGE_DIR/VERSION.txt"

cat > "$STAGE_DIR/README_WINDOWS_RELEASE.txt" <<EOF
Proton VPN Multi-Tunnel Windows Core Release Stage (win-$PLATFORM, v$FULL_VERSION)
Build Number: $BUILD_NUMBER (git commit: $GIT_FULL_HASH, branch: $GIT_BRANCH)
================================================================================
Included in this cross-built stage:
- ProtonVPNService.exe / .dll (with MultiTunnelOrchestrator, PriorityRuleEngine, MultiTunnelWfpManager, MultiTunnelDnsRoutingTable)
- ProtonVPN.NetworkFilter.dll (with CreateRemoteNetworkCalloutFilter / CreateRemoteIPv4CalloutFilter)
- ProtonVPN.ProcessCommunication.Contracts.dll (with MultiTunnel IPC contracts)
- ProtonVPN.WireGuardService.exe
- Native kernel callout driver: Resources/ProtonVPN.CalloutDriver.sys
- ProTun native engine: $PLATFORM/protun.dll

To build the complete WinUI 3 Client + Inno Setup Installer (.exe) on Windows 10/11:
  pwsh -File build-release.ps1 -Platform $PLATFORM
EOF

TAR_OUT="$DIST_DIR/protonvpn-win-service-multitunnel-win-${PLATFORM}-v${FILE_VERSION}.tar.gz"
tar -C "$DIST_DIR" -czf "$TAR_OUT" "win-${PLATFORM}-release-stage"

if command -v zip >/dev/null 2>&1; then
    ZIP_OUT="$DIST_DIR/protonvpn-win-service-multitunnel-win-${PLATFORM}-v${FILE_VERSION}.zip"
    (cd "$DIST_DIR" && zip -rq "$ZIP_OUT" "win-${PLATFORM}-release-stage")
fi

(
    cd "$DIST_DIR"
    find . -maxdepth 1 -type f \( -name "*.tar.gz" -o -name "*.zip" -o -name "BUILD_INFO.json" \) -printf "%f\n" | sort | xargs -r sha256sum > SHA256SUMS.txt
)

echo "==> [proton-win-app] Windows Release artifacts written to $DIST_DIR"
ls -lh "$DIST_DIR"
