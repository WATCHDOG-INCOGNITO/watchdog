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

`lease_work` is the preferred handoff point for external workers:

```powershell
docker cp watchdog_cli.py watchdog-backend-1:/tmp/watchdog_cli.py
echo '{"scan_run_id":"<RUN_ID>","worker_kind":"codex","worker_id":"codex-local"}' |
  docker exec -i -e PYTHONPATH=/app -e DJANGO_SETTINGS_MODULE=config.settings `
    watchdog-backend-1 python /tmp/watchdog_cli.py lease_work
```

The response contains a `mission_packet` with:

- WorkItem identity, work type, objective, preconditions, expected outputs,
  oracle hint, and provider hint
- target and node identity
- queue lane, priority score, provider hint, score breakdown, and lease data
- recent related `agent_exchanges` for the leased WorkItem, node, and linked
  recheck source plus a dialogue contract
- required init/work/finalize checklist
- slot hints when endpoint/vulnerability history exists
- a finalize contract requiring `record_trace`, `complete_work` or `fail_work`,
  and a terminal node status when the WorkItem closes a DiscoveryNode

Workers should finalize leased work with `complete_work` or `fail_work`.
When the work closes a DiscoveryNode, pass `node_status` to `complete_work` or
also call `update_node_status` / `mark_dead_end`. Leases expire through the
same stale recovery window used by the Discovery Queue, so interrupted workers
can be reclaimed.

If a work item is missing a prerequisite such as a credential, token, or
baseline response, use `block_work`. When the prerequisite is later stored,
use `unblock_work` so the scheduler can lease it again.

## Agent Exchanges

Claude and Codex do not need a shared chat room. They talk through structured
`AgentExchange` records attached to the WorkItem:

```powershell
echo '{
  "scan_run_id":"<RUN_ID>",
  "work_id":"<WORK_ID>",
  "provider":"claude",
  "agent_name":"claude-local",
  "message_type":"claim",
  "stance":"supports",
  "confidence":0.72,
  "content":"The endpoint likely has IDOR because the numeric id is accepted without an ownership check.",
  "evidence_refs":["trace:<TRACE_ID>"]
}' |
  docker exec -i -e PYTHONPATH=/app -e DJANGO_SETTINGS_MODULE=config.settings `
    watchdog-backend-1 python /tmp/watchdog_cli.py add_agent_exchange
```

Supported message types are `claim`, `question`, `counterargument`, `evidence`,
`decision`, `handoff`, `recheck_request`, and `consensus`. Use
`list_agent_exchanges` to inspect the thread and `resolve_agent_exchange` when
an objection or recheck request has been handled.

To force the other model to verify a claim, set `enqueue_recheck=true` on
`add_agent_exchange`. The CLI creates a `recheck` WorkItem with the opposite
provider hint when possible, so a Claude claim becomes Codex recheck work and
a Codex claim becomes Claude recheck work.

## Local Runners

Codex worker:

```powershell
.\tools\run_codex_worker.ps1 -ScanRunId <RUN_ID> -Iterations 1 -CodexModel gpt-5.5
```

Claude worker:

```powershell
.\tools\run_claude_worker.ps1 -ScanRunId <RUN_ID> -Iterations 1 -ClaudeModel opus
```

These high-performance defaults are intentionally expensive: Codex uses
`gpt-5.5`, and Claude uses the latest `opus` alias with maximum effort. Override the
model parameters only when a lower-cost or compatibility run is needed.

Recommended role split:

- Claude: live target exploration, hypothesis generation, and chain reasoning.
- Codex: source audit, critic/confirmer work, reproducibility checks, queue
  scoring changes, and report-quality evidence review.

Both workers share state only through Watchdog: DiscoveryNode rows, traces,
WorkItems, AgentExchanges, findings, secrets, endpoint specs, dead ends, and
scan notes.

## Safety

Run subscription workers only against authorized targets, local labs, or CTF
targets. The runner prompts intentionally remind workers to push discoveries
before testing, store secrets immediately, and keep all activity inside the
mission scope.
