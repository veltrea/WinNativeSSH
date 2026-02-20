<#
.SYNOPSIS
    Downloads and installs the latest Nushell binary for use with WinNativeSSH.

.DESCRIPTION
    This script automates the process of fetching the latest Nushell release from GitHub,
    extracting it, and placing it in the WinNativeSSH project directory.
    It identifies the system architecture and ensures a clean installation.

.EXAMPLE
    .\Get-Nushell.ps1
#>

$ErrorActionPreference = "Stop"

# Configuration
$repo = "nushell/nushell"
$installDir = Join-Path $PSScriptRoot "..\bin"
$tempDir = Join-Path $env:TEMP "WNSSH_Nu_Install"

if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir | Out-Null
}

Write-Host "--- Nushell Installation Helper for WinNativeSSH ---" -ForegroundColor Cyan

# 1. Get latest release info
Write-Host "[1/4] Fetching latest release info from GitHub..."
$apiUrl = "https://api.github.com/repos/$repo/releases/latest"
$release = Invoke-RestMethod -Uri $apiUrl

$version = $release.tag_name
Write-Host "Found version: $version" -ForegroundColor Green

# 2. Identify the correct asset for Windows (x86_64)
# Note: Ryzen AI 9 is x64, so we target x86_64-pc-windows-msvc.zip
$assetNamePattern = "x86_64-pc-windows-msvc.zip"
$asset = $release.assets | Where-Object { $_.name -like "*$assetNamePattern*" }

if ($null -eq $asset) {
    throw "Could not find a matching Windows asset for Nushell version $version."
}

$downloadUrl = $asset.browser_download_url
$localZip = Join-Path $env:TEMP "$($asset.name)"

# 3. Download
Write-Host "[2/4] Downloading: $($asset.name)..."
Invoke-WebRequest -Uri $downloadUrl -OutFile $localZip

# 4. Extract and Deploy
Write-Host "[3/4] Extracting to $installDir..."
if (Test-Path $tempDir) { Remove-Item -Recurse -Force $tempDir }
New-Item -ItemType Directory -Path $tempDir | Out-Null

Expand-Archive -Path $localZip -DestinationPath $tempDir

# Nushell zip usually contains a folder, find nu.exe inside it
$nuExe = Get-ChildItem -Path $tempDir -Filter "nu.exe" -Recurse | Select-Object -First 1

if ($null -eq $nuExe) {
    throw "nu.exe not found in the downloaded archive."
}

$targetPath = Join-Path $installDir "nu.exe"
Copy-Item -Path $nuExe.FullName -Destination $targetPath -Force

# Also copy LICENSE if present
$license = Get-ChildItem -Path $tempDir -Filter "LICENSE" -Recurse | Select-Object -First 1
if ($license) {
    Copy-Item -Path $license.FullName -Destination (Join-Path $installDir "LICENSE_Nushell") -Force
}

# 5. Cleanup
Write-Host "[4/4] Cleaning up..."
Remove-Item -Path $localZip -Force
Remove-Item -Path $tempDir -Recurse -Force

Write-Host "`n[SUCCESS] Nushell $version installed successfully." -ForegroundColor Green
Write-Host "Location: $targetPath"
Write-Host "To use with WinNativeSSH, you can now point your session or worker config to this path."
