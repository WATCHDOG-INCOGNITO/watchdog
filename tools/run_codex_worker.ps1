param(
    [Parameter(Mandatory = $true)]
    [string]$ScanRunId,

    [int]$Iterations = 1,
    [string]$WorkerId = "",
    [string]$BackendContainer = "watchdog-backend-1"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $WorkerId) {
    $WorkerId = "codex-$env:USERNAME-$(Get-Random)"
}

function Invoke-WatchdogCli {
    param(
        [Parameter(Mandatory = $true)][string]$Tool,
        [Parameter(Mandatory = $true)][hashtable]$Payload
    )

    docker cp watchdog_cli.py "$BackendContainer`:/tmp/watchdog_cli.py" | Out-Null
    $json = $Payload | ConvertTo-Json -Depth 40 -Compress
    $json | docker exec -i `
        -e PYTHONPATH=/app `
        -e DJANGO_SETTINGS_MODULE=config.settings `
        $BackendContainer python /tmp/watchdog_cli.py $Tool
}

for ($i = 0; $i -lt $Iterations; $i++) {
    $leaseRaw = Invoke-WatchdogCli -Tool "lease_node" -Payload @{
        scan_run_id = $ScanRunId
        worker_kind = "codex"
        worker_id = $WorkerId
    }
    $lease = $leaseRaw | ConvertFrom-Json

    if ($lease.action -ne "LEASED") {
        Write-Host $leaseRaw
        break
    }

    $missionPath = Join-Path $env:TEMP "watchdog-codex-$($lease.leased_node).json"
    $lease.mission_packet | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $missionPath -Encoding UTF8

    $prompt = @"
You are a Watchdog Codex subscription worker for an authorized security scan.

Read the mission JSON at:
$missionPath

Use watchdog_cli.py through the documented docker exec pattern to gather context,
record trace entries, push discoveries before testing, store secrets immediately,
and finalize the leased node as explored, confirmed, or dead_end.

Prefer Codex strengths: source audit, critic/confirmer work, reproducibility checks,
queue scoring improvements, and report-quality evidence. Do not add yourself as a
git contributor or co-author.
"@

    codex exec $prompt
}
