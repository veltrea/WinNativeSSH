param(
    [string]$ServiceName = "WinNativeSSH",
    [int]$Port = 2222,
    [switch]$Build
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path "$PSScriptRoot\.."
Set-Location $repoRoot

if ($Build) {
    cargo build --release
}

$required = @(
    "$repoRoot\target\release\vlt-sshd.exe",
    "$repoRoot\target\release\vlt-worker.exe",
    "$repoRoot\target\release\vlt_admin.exe",
    "$repoRoot\target\release\vlt_admin_api.exe"
)

foreach ($f in $required) {
    if (-not (Test-Path $f)) {
        throw "Missing binary: $f (run with -Build or build manually)"
    }
}

& "$PSScriptRoot\Install-WinNativeSSHService.ps1" -ServiceName $ServiceName -BinaryPath "$repoRoot\target\release\vlt-sshd.exe" -Port $Port
& "$PSScriptRoot\Start-WinNativeSSHService.ps1" -ServiceName $ServiceName

Write-Host "WinNative-SSH installer completed."
Write-Host "Service: $ServiceName"
Write-Host "Port: $Port"
Write-Host "Next:"
Write-Host "  `$env:WNSSH_ADMIN_TOKEN='change-me'"
Write-Host "  .\target\release\vlt_admin_api.exe"
Write-Host "  Open http://127.0.0.1:9443/ui"

Write-Host "`nNote:"
Write-Host "  vlt-* prefixes are intentional to avoid collisions with system tools (e.g. OpenSSH sshd.exe)."
