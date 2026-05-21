# Subscription Workers

Watchdog supports two model execution modes:

- API mode: the backend calls providers directly through `ANTHROPIC_API_KEY`
  and `OPENAI_API_KEY`.
- Subscription worker mode: a local Claude Code or Codex CLI session leases
  one DiscoveryNode, uses Watchdog CLI/MCP tools, and writes results back to
  the same Discovery Tree and Living KB.

Subscription plans are not backend API credentials. Use this mode when Claude
Code or Codex is authenticated locally with a paid plan, but the Watchdog
backend should not call that provider API directly.

## Queue Contract

`lease_node` is the handoff point for external workers:

```powershell
docker cp watchdog_cli.py watchdog-backend-1:/tmp/watchdog_cli.py
echo '{"scan_run_id":"<RUN_ID>","worker_kind":"codex","worker_id":"codex-local"}' |
  docker exec -i -e PYTHONPATH=/app -e DJANGO_SETTINGS_MODULE=config.settings `
    watchdog-backend-1 python /tmp/watchdog_cli.py lease_node
```

The response contains a `mission_packet` with:

- target and node identity
- queue lane, priority score, provider hint, score breakdown, and lease data
- required init/work/finalize checklist
- slot hints when endpoint/vulnerability history exists
- a finalize contract requiring `record_trace` and a terminal node status

Workers must finalize leased nodes with `update_node_status` or
`mark_dead_end`. Leases expire through the same stale recovery window used by
the Discovery Queue, so interrupted workers can be reclaimed.

## Local Runners

Codex worker:

```powershell
.\tools\run_codex_worker.ps1 -ScanRunId <RUN_ID> -Iterations 1
```

Claude worker:

```powershell
.\tools\run_claude_worker.ps1 -ScanRunId <RUN_ID> -Iterations 1
```

Recommended role split:

- Claude: live target exploration, hypothesis generation, and chain reasoning.
- Codex: source audit, critic/confirmer work, reproducibility checks, queue
  scoring changes, and report-quality evidence review.

Both workers share state only through Watchdog: DiscoveryNode rows, traces,
findings, secrets, endpoint specs, dead ends, and scan notes.

## Safety

Run subscription workers only against authorized targets, local labs, or CTF
targets. The runner prompts intentionally remind workers to push discoveries
before testing, store secrets immediately, and keep all activity inside the
mission scope.
