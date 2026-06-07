# Download OpenVPN binaries for embedding into JamVPN.
# Run this once before building with -WithOpenVPN flag.
# License: OpenVPN is GPL-2 — binaries cannot be committed to the repo.
#
# Usage:
#   .\scripts\download-openvpn.ps1

param(
    [string]$Version = "2.6.12",
    [string]$Build   = "I003"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$outDir = Join-Path $PSScriptRoot "..\internal\vpn\assets\openvpn"
New-Item -ItemType Directory -Force $outDir | Out-Null

$msiName = "OpenVPN-$Version-$Build-amd64.msi"
$msiUrl  = "https://swupdate.openvpn.org/community/releases/$msiName"
$msiPath = Join-Path $env:TEMP $msiName

Write-Host "Downloading $msiName ..."
Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing
Write-Host "  $([math]::Round((Get-Item $msiPath).Length/1MB,1)) MB"

$extractDir = Join-Path $env:TEMP "openvpn_extract_$Version"
New-Item -ItemType Directory -Force $extractDir | Out-Null

Write-Host "Extracting MSI (no install) ..."
$proc = Start-Process msiexec.exe -Wait -PassThru `
    -ArgumentList "/a `"$msiPath`" /qn TARGETDIR=`"$extractDir`""
if ($proc.ExitCode -ne 0) { throw "msiexec failed with exit code $($proc.ExitCode)" }

$needed = @("openvpn.exe", "libssl-3-x64.dll", "libcrypto-3-x64.dll", "liblzo2-2.dll")
$found  = 0
Get-ChildItem $extractDir -Recurse -Include $needed | ForEach-Object {
    $dst = Join-Path $outDir $_.Name
    Copy-Item $_.FullName $dst -Force
    Write-Host "  Copied: $($_.Name)  ($([math]::Round($_.Length/1KB,0)) KB)"
    $found++
}

if ($found -lt $needed.Count) {
    $missing = $needed | Where-Object { -not (Test-Path (Join-Path $outDir $_)) }
    Write-Warning "Missing files: $($missing -join ', ')"
    Write-Warning "Check the MSI extract path: $extractDir"
} else {
    Write-Host ""
    Write-Host "Done. Build with OpenVPN bundled:" -ForegroundColor Green
    Write-Host "  .\build.ps1 -WithOpenVPN"  -ForegroundColor Cyan
}

# Cleanup
Remove-Item $msiPath -Force -ErrorAction SilentlyContinue
