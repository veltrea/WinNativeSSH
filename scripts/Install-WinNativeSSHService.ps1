param(
    [string]$ServiceName = "WinNativeSSH",
    [string]$DisplayName = "WinNative SSH Server",
    [string]$Description = "WinNative-SSH service",
    [string]$BinaryPath = "$PSScriptRoot\..\target\release\vlt-sshd.exe",
    [int]$Port = 2222
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $BinaryPath)) {
    throw "Binary not found: $BinaryPath"
}

$resolvedBinary = (Resolve-Path $BinaryPath).Path
$binPathWithArg = "`"$resolvedBinary`""

function Test-ServiceExists([string]$Name) {
    $null -ne (Get-Service -Name $Name -ErrorAction SilentlyContinue)
}

if (Test-ServiceExists $ServiceName) {
    # Idempotent path: update existing service configuration.
    sc.exe config $ServiceName binPath= $binPathWithArg start= auto DisplayName= "$DisplayName" | Out-Null
    sc.exe description $ServiceName "$Description" | Out-Null
    sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    Write-Host "Service already exists; updated configuration: $ServiceName"
} else {
    sc.exe create $ServiceName binPath= $binPathWithArg start= auto DisplayName= "$DisplayName" | Out-Null
    sc.exe description $ServiceName "$Description" | Out-Null
    sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    Write-Host "Service installed: $ServiceName"
}

# Best-effort firewall rule (ignore error if it already exists).
try {
    netsh advfirewall firewall add rule name="$ServiceName-$Port" dir=in action=allow protocol=TCP localport=$Port | Out-Null
} catch {
    # no-op
}

Write-Host "Binary: $resolvedBinary"
Write-Host "Firewall rule: $ServiceName-$Port"
