param(
    [string]$ServiceName = "WinNativeSSH",
    [string]$DeployDir = "$PSScriptRoot\..",
    [string]$BuildDir = "$PSScriptRoot\..\target\release",
    [switch]$SkipBackup
)

$ErrorActionPreference = "Stop"

if (-not $SkipBackup) {
    & "$PSScriptRoot\Backup-WinNativeSSH.ps1" -SourceDir $DeployDir
}

sc.exe stop $ServiceName | Out-Null
Start-Sleep -Seconds 2

$bins = @("vlt-sshd.exe", "vlt-worker.exe", "vlt_admin.exe", "vlt_admin_api.exe")
foreach ($b in $bins) {
    $src = Join-Path $BuildDir $b
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination (Join-Path $DeployDir $b) -Force
    }
}

sc.exe start $ServiceName | Out-Null
Write-Host "Upgrade completed. Service restarted: $ServiceName"
