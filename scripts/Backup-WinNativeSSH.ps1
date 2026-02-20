param(
    [string]$SourceDir = "$PSScriptRoot\..",
    [string]$OutputDir = "$PSScriptRoot\..\backups"
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$archive = Join-Path $OutputDir "winnative-backup-$stamp.zip"

$db = Join-Path $SourceDir "winnative.db"
$cfg = Join-Path $SourceDir "server.json"
$key = Join-Path $SourceDir "host_key.pem"
$items = @()
if (Test-Path $db) { $items += $db }
if (Test-Path $cfg) { $items += $cfg }
if (Test-Path $key) { $items += $key }

if ($items.Count -eq 0) {
    throw "No backup targets found under $SourceDir"
}

Compress-Archive -Path $items -DestinationPath $archive -Force
Write-Host "Backup created: $archive"
