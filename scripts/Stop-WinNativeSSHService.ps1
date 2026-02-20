param(
    [string]$ServiceName = "WinNativeSSH"
)

$ErrorActionPreference = "Stop"

sc.exe stop $ServiceName | Out-Null
Write-Host "Service stop requested: $ServiceName"
