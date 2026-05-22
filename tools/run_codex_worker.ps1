param(
    [Parameter(Mandatory = $true)]
    [string]$ScanRunId,

    [int]$Iterations = 1,
    [string]$WorkerId = "",
    [string]$WorkerKind = "codex",
    [string]$CodexModel = "gpt-5.5",
    [string]$CodexCommand = "codex",
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
    $payloadPath = Join-Path $env:TEMP "watchdog-$Tool-$([guid]::NewGuid().ToString('N')).json"
    [System.IO.File]::WriteAllText($payloadPath, $json, [System.Text.UTF8Encoding]::new($false))
    try {
        cmd /c "type ""$payloadPath"" | docker exec -i -e PYTHONPATH=/app -e DJANGO_SETTINGS_MODULE=config.settings $BackendContainer python /tmp/watchdog_cli.py $Tool"
    } finally {
        Remove-Item -LiteralPath $payloadPath -Force -ErrorAction SilentlyContinue
    }
}

for ($i = 0; $i -lt $Iterations; $i++) {
    $leaseRaw = Invoke-WatchdogCli -Tool "lease_work" -Payload @{
        scan_run_id = $ScanRunId
        worker_kind = $WorkerKind
        worker_id = $WorkerId
    }
    $lease = $leaseRaw | ConvertFrom-Json

    if ($lease.action -ne "LEASED") {
        Write-Host $leaseRaw
        break
    }

    $missionDir = Join-Path (Get-Location).Path ".watchdog-missions"
    New-Item -ItemType Directory -Force -Path $missionDir | Out-Null
    $missionPath = Join-Path $missionDir "watchdog-codex-$($lease.leased_work).json"
    $lease.mission_packet | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $missionPath -Encoding UTF8

    $prompt = @"
You are a Watchdog Codex subscription worker for an authorized security scan.

Read the mission JSON at:
$missionPath

Use watchdog_cli.py through the documented docker exec pattern to gather context,
record trace entries, push discoveries before testing, store secrets immediately,
and finalize the leased node as explored, confirmed, or dead_end.
Finish by calling complete_work or fail_work for the leased work item.
Use add_agent_exchange to record claims, evidence, counterarguments, consensus,
handoffs, or recheck requests for Claude/Codex collaboration.
When handing work to Claude, call add_agent_exchange with enqueue_recheck=true
and recheck_provider_hint="claude" so the scheduler creates Claude work.

Prefer Codex strengths: source audit, critic/confirmer work, reproducibility checks,
queue scoring improvements, and report-quality evidence. Do not add yourself as a
git contributor or co-author.
"@

    & $CodexCommand exec `
        -m $CodexModel `
        --sandbox danger-full-access `
        --dangerously-bypass-approvals-and-sandbox `
        -C (Get-Location).Path `
        $prompt
}
