# Requires: Run as Administrator
# Purpose : デプロイ用フォルダを Windows Defender の除外に登録する（ビルド・実行がウイルス誤検知されないようにする）。
# デプロイ・ビルドの「一番最初」にリモートPC上で実行してください。
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\scripts\Add-WindowsDefenderDeployExclusion.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\Add-WindowsDefenderDeployExclusion.ps1 -DeployPath "C:\deploy\ssh-server"
#
# 既存の詳細版（ExePath 指定など）は Setup-DefenderDebugExclusions.ps1 を使用してください。

[CmdletBinding()]
param(
    [string]$DeployPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Error "管理者権限が必要です。PowerShell を管理者として実行し直してください。"
}

if ([string]::IsNullOrWhiteSpace($DeployPath)) {
    $DeployPath = (Get-Location).Path
}
$DeployPath = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DeployPath)

Write-Host "=== Windows Defender: デプロイ用フォルダ除外登録 ===" -ForegroundColor Cyan
Write-Host "除外パス: $DeployPath"

if (-not (Test-Path -LiteralPath $DeployPath)) {
    Write-Warning "指定パスは存在しません（後で作成する場合は問題ありません）: $DeployPath"
}

Add-MpPreference -ExclusionPath $DeployPath

$mp = Get-MpPreference
$pathExists = $mp.ExclusionPath -contains $DeployPath
Write-Host "登録結果: $pathExists" -ForegroundColor $(if ($pathExists) { "Green" } else { "Red" })
Write-Host "Done." -ForegroundColor Green
