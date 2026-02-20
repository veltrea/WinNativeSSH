param(
    [Parameter(Mandatory=$true)]
    [string]$Target, # <USER>@<HOST>
    [int]$Port = 2222,
    [string]$OutputDir = "$PSScriptRoot\..\verification_results"
)

$ErrorActionPreference = "Continue" # Don't stop on single command failure

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logfile = Join-Path $OutputDir "interop_smoke_$timestamp.txt"

function Log-Output {
    param([string]$Message)
    $timestamp = Get-Date -Format "HH:mm:ss"
    $msg = "[$timestamp] $Message"
    Write-Host $msg
    $msg | Out-File -FilePath $logfile -Append
}

Log-Output "Starting Interop Smoke Test for $Target on port $Port"
Log-Output "--------------------------------------------------------"

$commands = @(
    "whoami",
    "whoami /user",
    "sysinfo",
    "fs stat C:\Windows",
    "svc list",
    "netinfo",
    "eventlog tail System limit 5",
    "echo INTEROP_SMOKE_VERIFICATION_STRING"
)

foreach ($cmd in $commands) {
    Log-Output "Executing: $cmd"
    try {
        $out = ssh.exe -o "StrictHostKeyChecking=no" -p $Port $Target $cmd 2>&1
        $out | Out-File -FilePath $logfile -Append
        Log-Output "Success."
    } catch {
        Log-Output "Error: $($_.Exception.Message)"
    }
    Log-Output "--------------------------------------------------------"
}

Log-Output "Smoke test complete. Results saved to: $logfile"
