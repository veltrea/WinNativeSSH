param(
    [string]$DbPath = "$PSScriptRoot\..\winnative.db",
    [string]$OutputPath = "$PSScriptRoot\..\audit-export.jsonl",
    [int]$Limit = 1000
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $DbPath)) {
    throw "DB not found: $DbPath"
}

$query = @"
SELECT event_id, session_id, sid, ts, category, code, detail_json
FROM audit_events
ORDER BY ts DESC
LIMIT $Limit
"@

$rows = sqlite3.exe $DbPath $query -json | ConvertFrom-Json
if ($null -eq $rows) {
    New-Item -ItemType File -Path $OutputPath -Force | Out-Null
    Write-Host "No rows exported."
    exit 0
}

$lines = foreach ($r in $rows) { $r | ConvertTo-Json -Compress }
$lines | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "Exported $($rows.Count) rows to $OutputPath"
