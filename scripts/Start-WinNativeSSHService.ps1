param(
    [string]$ServiceName = "WinNativeSSH"
)

$ErrorActionPreference = "Stop"

sc.exe start $ServiceName | Out-Null
Write-Host "Service started: $ServiceName"
