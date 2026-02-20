param(
    [Parameter(Mandatory=$true)][string]$ArchivePath,
    [string]$TargetDir = "$PSScriptRoot\..",
    [string]$ServiceName = "WinNativeSSH"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ArchivePath)) {
    throw "Archive not found: $ArchivePath"
}

sc.exe stop $ServiceName | Out-Null
Start-Sleep -Seconds 2
Expand-Archive -Path $ArchivePath -DestinationPath $TargetDir -Force
sc.exe start $ServiceName | Out-Null

Write-Host "Restore completed from: $ArchivePath"
