# リモートPC上で実行するデプロイ・ビルド手順です。
# 1. Windows Defender の除外登録（必須・管理者で実行）
# 2. cargo build --release
#
# Usage (リモートPCで、プロジェクトのルートに cd した状態で):
#   powershell -ExecutionPolicy Bypass -File .\scripts\Deploy-And-Build-OnRemote.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\Deploy-And-Build-OnRemote.ps1 -DeployPath "C:\deploy\ssh-server-relink" -SkipDefender

[CmdletBinding()]
param(
    [string]$DeployPath = "",
    [switch]$SkipDefender
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($DeployPath)) {
    $DeployPath = (Get-Location).Path
}
$DeployPath = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DeployPath)

Write-Host "=== Deploy & Build (Remote PC) ===" -ForegroundColor Cyan
Write-Host "DeployPath: $DeployPath"

# Step 1: Windows Defender 除外（管理者の場合は実行）
if (-not $SkipDefender) {
    $scriptDir = Join-Path $PSScriptRoot ".."
    $addExclusion = Join-Path $PSScriptRoot "Add-WindowsDefenderDeployExclusion.ps1"
    if (Test-Path $addExclusion) {
        Write-Host "`n[Step 1] Windows Defender 除外を登録します（管理者で実行している場合）..." -ForegroundColor Yellow
        & $addExclusion -DeployPath $DeployPath
    } else {
        Write-Warning "Add-WindowsDefenderDeployExclusion.ps1 が見つかりません。手動で除外を登録してください。"
    }
} else {
    Write-Host "`n[Step 1] Skip Defender exclusion (-SkipDefender)." -ForegroundColor Gray
}

# Step 2: ビルド
Write-Host "`n[Step 2] cargo build --release ..." -ForegroundColor Yellow
Push-Location $DeployPath
try {
    cargo build --release
    if ($LASTEXITCODE -ne 0) {
        Write-Error "cargo build --release failed with exit code $LASTEXITCODE"
    }
    Write-Host "`nBuild succeeded." -ForegroundColor Green
    Get-ChildItem -Path (Join-Path $DeployPath "target\release") -Filter "*.exe" | ForEach-Object { Write-Host "  $($_.FullName)" }
} finally {
    Pop-Location
}
