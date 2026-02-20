# Requires: Run as Administrator
# Purpose : Enable WinRM + register a JEA endpoint that only exposes Restart-Computer.
#
# Usage (run on the Windows machine you want to reboot remotely):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\Enable-WinRM-RebootOnlyJEA.ps1 -AllowedClientIp 192.168.1.10
#
# Client example (PowerShell):
#   $cred = Get-Credential
#   Invoke-Command -ComputerName <HOST_IP> -UseSSL -Port 5986 -Credential $cred -ConfigurationName RebootOnlyJEA -ScriptBlock { Restart-Computer -Force }
#
# Notes:
# - This creates a self-signed certificate and HTTPS listener on 5986.
# - Auth is still required; you can use a local account. For non-domain clients you may need TrustedHosts on the client.

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$AllowedClientIp,

  [string]$EndpointName = "RebootOnlyJEA",

  [string]$JeaRoot = "$env:ProgramData\\JEA\\$EndpointName",

  [int]$HttpsPort = 5986
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
  throw "Administrator privileges are required."
}

Write-Host "== Enabling WinRM (HTTP) and preparing HTTPS listener on port $HttpsPort ==" -ForegroundColor Cyan
Enable-PSRemoting -Force

Write-Host "== Creating self-signed certificate for WinRM HTTPS ==" -ForegroundColor Cyan
$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation "Cert:\\LocalMachine\\My"
$thumb = $cert.Thumbprint

Write-Host "== Creating/ensuring WinRM HTTPS listener ==" -ForegroundColor Cyan
$listenerPath = "WSMan:\\Localhost\\Listener"
$existing = Get-ChildItem $listenerPath -ErrorAction SilentlyContinue | Where-Object { $_.Keys -match "Transport=HTTPS" }
if (-not $existing) {
  New-Item -Path $listenerPath -Transport HTTPS -Address * -CertificateThumbPrint $thumb -Port $HttpsPort | Out-Null
} else {
  # Keep existing; do not overwrite.
  Write-Host "HTTPS listener already exists; leaving as-is." -ForegroundColor Yellow
}

Write-Host "== Hardening WinRM service settings (no Basic, no unencrypted) ==" -ForegroundColor Cyan
Set-Item -Path WSMan:\\localhost\\Service\\AllowUnencrypted -Value $false
Set-Item -Path WSMan:\\localhost\\Service\\Auth\\Basic -Value $false
Set-Item -Path WSMan:\\localhost\\Service\\Auth\\Kerberos -Value $true
Set-Item -Path WSMan:\\localhost\\Service\\Auth\\Negotiate -Value $true

Write-Host "== Configuring firewall rule for WinRM HTTPS from $AllowedClientIp only ==" -ForegroundColor Cyan
$ruleName = "WinRM HTTPS ($EndpointName) from $AllowedClientIp"
if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
  Write-Host "Firewall rule already exists; leaving as-is." -ForegroundColor Yellow
} else {
  New-NetFirewallRule `
    -DisplayName $ruleName `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort $HttpsPort `
    -RemoteAddress $AllowedClientIp `
    -Profile Any | Out-Null
}

Write-Host "== Creating JEA role capability + session configuration ==" -ForegroundColor Cyan
New-Item -ItemType Directory -Path $JeaRoot -Force | Out-Null
New-Item -ItemType Directory -Path "$JeaRoot\\RoleCapabilities" -Force | Out-Null

$psrc = "$JeaRoot\\RoleCapabilities\\RebootOnly.psrc"
$pssc = "$JeaRoot\\$EndpointName.pssc"

@"
@{
  VisibleCmdlets = @(
    @{ Name = 'Restart-Computer'; Parameters = @(@{ Name='Force' }) }
  )
}
"@ | Set-Content -Path $psrc -Encoding UTF8

@"
@{
  SchemaVersion = '2.0.0.0'
  SessionType = 'RestrictedRemoteServer'
  RunAsVirtualAccount = \$true
  RunAsVirtualAccountGroups = @('Administrators')

  TranscriptDirectory = '$JeaRoot\\Transcripts'
  RoleDefinitions = @{
    'BUILTIN\\Remote Management Users' = @{ RoleCapabilities = @('RebootOnly') }
    'BUILTIN\\Administrators'          = @{ RoleCapabilities = @('RebootOnly') }
  }
}
"@ | Set-Content -Path $pssc -Encoding UTF8

New-Item -ItemType Directory -Path "$JeaRoot\\Transcripts" -Force | Out-Null

Write-Host "== Registering JEA endpoint: $EndpointName ==" -ForegroundColor Cyan
if (Get-PSSessionConfiguration -Name $EndpointName -ErrorAction SilentlyContinue) {
  Write-Host "Endpoint already registered; updating configuration file path." -ForegroundColor Yellow
  Unregister-PSSessionConfiguration -Name $EndpointName -Force
}
Register-PSSessionConfiguration -Name $EndpointName -Path $pssc -Force | Out-Null

Write-Host "`n== Done ==" -ForegroundColor Green
Write-Host "WinRM HTTPS port: $HttpsPort"
Write-Host "JEA endpoint     : $EndpointName"
Write-Host "Cert thumbprint  : $thumb"
Write-Host "Firewall rule    : $ruleName"
Write-Host ""
Write-Host "Next (client):" -ForegroundColor Cyan
Write-Host "  PowerShell: Invoke-Command -ComputerName <ip> -UseSSL -Port $HttpsPort -ConfigurationName $EndpointName -Credential (Get-Credential) -ScriptBlock { Restart-Computer -Force }"
