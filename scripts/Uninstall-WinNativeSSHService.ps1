param(
    [string]$ServiceName = "WinNativeSSH",
    [int]$Port = 2222
)

$ErrorActionPreference = "Stop"

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -eq $service) {
    Write-Host "Service not found: $ServiceName"
    exit 0
}

if ($service.Status -ne "Stopped") {
    sc.exe stop $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

sc.exe delete $ServiceName | Out-Null
netsh advfirewall firewall delete rule name="$ServiceName-$Port" | Out-Null
Write-Host "Service removed: $ServiceName"
