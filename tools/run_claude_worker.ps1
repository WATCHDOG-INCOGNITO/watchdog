param(
    [Parameter(Mandatory = $true)]
    [string]$ScanRunId,

    [int]$Iterations = 1,
    [string]$WorkerId = "",
    [string]$ClaudeCommand = "claude",
    [string]$BackendContainer = "watchdog-backend-1"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $WorkerId) {
    $WorkerId = "claude-$env:USERNAME-$(Get-Random)"
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
    $leaseRaw = Invoke-WatchdogCli -Tool "lease_work" -Payload @{
        scan_run_id = $ScanRunId
        worker_kind = "claude"
        worker_id = $WorkerId
    }
    $lease = $leaseRaw | ConvertFrom-Json

    if ($lease.action -ne "LEASED") {
        Write-Host $leaseRaw
        break
    }

    $missionDir = Join-Path (Get-Location).Path ".watchdog-missions"
    New-Item -ItemType Directory -Force -Path $missionDir | Out-Null
    $missionPath = Join-Path $missionDir "watchdog-claude-$($lease.leased_work).json"
    $lease.mission_packet | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $missionPath -Encoding UTF8

    $prompt = @"
You are a Watchdog Claude subscription worker for an authorized security scan.

Read the mission JSON at:
$missionPath

Use watchdog_cli.py through the documented docker exec pattern to gather context,
record trace entries, push discoveries before testing, store secrets immediately,
and finalize the leased node as explored, confirmed, or dead_end.
Finish by calling complete_work or fail_work for the leased work item.
Use add_agent_exchange to record claims, evidence, counterarguments, consensus,
handoffs, or recheck requests for Claude/Codex collaboration.
When handing work to Codex, call add_agent_exchange with enqueue_recheck=true
and recheck_provider_hint="codex" so the scheduler creates Codex work.

Prefer Claude strengths: live target exploration, hypothesis generation,
multi-step chain reasoning, and concise handoff notes. Stay inside the target
scope described in the mission.
"@

    & $ClaudeCommand --permission-mode bypassPermissions --dangerously-skip-permissions --add-dir (Get-Location).Path -p $prompt
}
