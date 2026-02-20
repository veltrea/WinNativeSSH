# Requires: Run as Administrator
# Purpose : Add Windows Defender exclusions for WinNativeSSH debug workflow.
#
# Usage examples:
#   powershell -ExecutionPolicy Bypass -File .\scripts\Setup-DefenderDebugExclusions.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\Setup-DefenderDebugExclusions.ps1 -EnableDefender
#   powershell -ExecutionPolicy Bypass -File .\scripts\Setup-DefenderDebugExclusions.ps1 -DeployRoot "C:\Users\<username>\ssh-server-deploy"

[CmdletBinding()]
param(
    [string]$DeployRoot = "",
    [string]$ExePath = "",
    [switch]$EnableDefender
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Error "Administrator privileges are required. Re-run PowerShell as Administrator."
}

Write-Host "=== WinNativeSSH Defender Debug Exclusions ===" -ForegroundColor Cyan
if ([string]::IsNullOrWhiteSpace($DeployRoot)) {
    $DeployRoot = Join-Path $env:USERPROFILE "ssh-server-deploy"
}
if ([string]::IsNullOrWhiteSpace($ExePath)) {
    $ExePath = Join-Path $DeployRoot "target\\release\\vlt-admin.exe"
}
Write-Host "DeployRoot : $DeployRoot"
Write-Host "ExePath    : $ExePath"

if (-not (Test-Path -LiteralPath $DeployRoot)) {
    Write-Warning "DeployRoot does not exist yet: $DeployRoot"
}
if (-not (Test-Path -LiteralPath $ExePath)) {
    Write-Warning "ExePath does not exist yet: $ExePath"
}

if ($EnableDefender) {
    Write-Host "Enabling Defender real-time protection..." -ForegroundColor Yellow
    Set-MpPreference -DisableRealtimeMonitoring $false
}

Write-Host "Applying exclusions..." -ForegroundColor Yellow
Add-MpPreference -ExclusionPath $DeployRoot
Add-MpPreference -ExclusionProcess $ExePath

$mp = Get-MpPreference
$pathExists = $mp.ExclusionPath -contains $DeployRoot
$procExists = $mp.ExclusionProcess -contains $ExePath

Write-Host "`n=== Result ===" -ForegroundColor Green
Write-Host "Path exclusion    : $pathExists"
Write-Host "Process exclusion : $procExists"

Write-Host "`nCurrent exclusion paths:" -ForegroundColor Cyan
$mp.ExclusionPath | Sort-Object | ForEach-Object { "  - $_" }

Write-Host "`nCurrent exclusion processes:" -ForegroundColor Cyan
$mp.ExclusionProcess | Sort-Object | ForEach-Object { "  - $_" }

Write-Host "`nDone." -ForegroundColor Green
