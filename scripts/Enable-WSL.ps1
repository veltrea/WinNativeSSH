<#
.SYNOPSIS
    Checks and enables Windows Subsystem for Linux (WSL) and Virtual Machine Platform.

.DESCRIPTION
    This script automates the prerequisites for running WSL on Windows 10/11.
    It checks the current status of "Microsoft-Windows-Subsystem-Linux" and 
    "VirtualMachinePlatform", enables them if necessary, and prompts for a restart.

.EXAMPLE
    .\Enable-WSL.ps1
#>

$ErrorActionPreference = "Stop"

Write-Host "--- WSL Activation Helper for WinNativeSSH ---" -ForegroundColor Cyan

function Test-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Warning "This script requires Administrator privileges to enable Windows features."
    Write-Host "Please restart PowerShell as Administrator."
    exit 1
}

# 1. State check
Write-Host "[1/3] Checking Windows features status..."
$features = @(
    "Microsoft-Windows-Subsystem-Linux",
    "VirtualMachinePlatform"
)

$needsRestart = $false
$anyChange = $false

foreach ($feature in $features) {
    try {
        $status = Get-WindowsOptionalFeature -Online -FeatureName $feature
        if ($status.State -ne "Enabled") {
            Write-Host "Feature '$feature' is currently disabled." -ForegroundColor Yellow
            $anyChange = $true
            
            Write-Host "Enabling '$feature'..." -NoNewline
            Enable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart | Out-Null
            Write-Host " Done." -ForegroundColor Green
            $needsRestart = $true
        }
        else {
            Write-Host "Feature '$feature' is already enabled." -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to check or enable feature: $feature. Error: $($_.Exception.Message)"
    }
}

# 2. WSL version/update check (Best effort)
Write-Host "[2/3] Checking for WSL kernel updates..."
try {
    # Try to update WSL kernel to the latest version (Windows 10 2004+ / Windows 11)
    wsl.exe --update | Out-Null
    Write-Host "WSL kernel update check completed." -ForegroundColor Green
}
catch {
    Write-Warning "wsl.exe --update failed or not available. This is normal if WSL is not yet fully initialized."
}

# 3. Finalization
Write-Host "[3/3] Finalizing configuration..."
if (-not $anyChange) {
    Write-Host "`n[SUCCESS] WSL is already fully configured and ready to use." -ForegroundColor Green
}
else {
    Write-Host "`n[NOTICE] Windows features have been modified." -ForegroundColor Cyan
    if ($needsRestart) {
        Write-Host "IMPORTANT: A system restart is REQUIRED to complete the WSL activation." -ForegroundColor Red
        Write-Host "Please save your work and restart your computer."
    }
}

Write-Host "`nNext Step (after restart):"
Write-Host "  Run 'wsl --install -d <DistroName>' (e.g. Ubuntu-22.04)"
Write-Host "  Then verify with 'wsl --status'"
