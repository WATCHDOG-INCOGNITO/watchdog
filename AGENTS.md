# Watchdog Codex Agent Instructions

This repository contains Watchdog, an autonomous web security scanning system
with a Django backend, a React frontend, and a Watchdog MCP tool server.

Codex should behave like the existing Watchdog MCP/Claude agent when the user
asks to scan, exploit, continue a CTF, drive the Discovery Tree, confirm
findings, or update the Living KB.

## Important Files

- `CLAUDE.md`: legacy Claude Code project memory.
- `.cursor/rules/watchdog-agent.mdc`: queue loop and mandatory rules.
- `.cursor/rules/manual-pentest.mdc`: manual pentest workflow.
- `.cursor/rules/watchdog-checklist.mdc`: required tool-call checklists.
- `.cursor/rules/watchdog-node-actions.mdc`: node-type playbooks.
- `.cursor/rules/watchdog-tools.mdc`: MCP tool catalog.
- `.claude/agents/*.md`: MLLA role prompts for RouteMap, EntryPoint,
  Hypothesis, Exploit, Confirmer, and Critic.
- `watchdog_cli.py`: CLI wrapper for scan lifecycle and trace tools.
- `backend/backend/watchdog_mcp/server.py`: MCP server entry point.

For any Watchdog-driven security task, read the relevant rule files above
before acting. Treat this `AGENTS.md` as the always-on summary and the rule
files as the detailed source of truth.

## MCP Setup

Codex is expected to have a global MCP server named `watchdog` configured as:

```toml
[mcp_servers.watchdog]
command = "docker"
args = ["exec", "-i", "watchdog-mcp-1", "python", "-m", "watchdog_mcp.server", "--stdio"]
```

The Docker Compose MCP service still exposes SSE at `http://localhost:8889/sse`
for Claude and other SSE clients. Prefer the Codex MCP tools directly. Use the
CLI wrapper only for CLI-only lifecycle tools.

CLI-only tools include:

- `create_scan`
- `create_root`
- `complete_scan`
- `stop_scan`
- `fail_scan`
- `record_trace`
- `scan_next`
- `lease_node`
- `lease_work`
- `complete_work`
- `fail_work`
- `block_work`
- `unblock_work`
- `validate_node`
- `scan_selfcheck`

CLI call pattern:

```powershell
docker cp watchdog_cli.py watchdog-backend-1:/tmp/watchdog_cli.py
echo '<JSON>' | docker exec -i -e PYTHONPATH=/app -e DJANGO_SETTINGS_MODULE=config.settings watchdog-backend-1 python /tmp/watchdog_cli.py <tool_name>
```

External subscription workers use the same CLI state machine. Prefer
`lease_work`, which atomically assigns one WorkItem and returns a mission
packet; the worker must record traces and call `complete_work` or `fail_work`
before requesting another lease. `lease_node` remains for compatibility.

## Operating Model

Watchdog uses a queue-based Discovery Tree. Do not run it as a one-shot scan.
Drive it as an iterative loop until the queue is complete, the user stops it,
or a practical budget is reached.

High-level loop:

```text
create_scan -> recall_target -> create_root -> record_trace

while true:
  scan_next
  if action is COMPLETE:
    scan_selfcheck
    generate_report / get_scan_summary / get_exploit_chains
    complete_scan
    record_trace
    break

  choose a node candidate
  update_node_status(node, "exploring")
  gather context
  process by node_type
  validate_node
  finalize as explored, confirmed, or dead_end
  record_trace
```

`scan_next`, `validate_node`, and `scan_selfcheck` are advisory safety-net
signals, not hard gates. Use judgment. If a warning is intentionally ignored,
make sure the report or trace records the reason.

Never leave a scan running by accident. End with `complete_scan`,
`stop_scan`, or `fail_scan`.

## Mandatory Data Rules

These are the non-negotiable Watchdog rules. They preserve the Discovery Tree
and Living KB so future scans learn from this one.

1. Push before testing.
   Register discoveries with `push_discovery` before probing or exploiting
   them. Discover many nodes, then explore one at a time.

2. Endpoint discovery requires analysis.
   For each discovered endpoint, call `push_discovery(node_type="endpoint")`,
   `analyze_endpoint`, and, when analysis suggests risk,
   `create_candidate_manual`.

3. Record all outcomes.
   Success must create/confirm a finding, save evidence, learn from it, record
   pattern use, and update node status. Failure must record pattern failure,
   learn a dead end, and mark the node dead.

4. Save secrets immediately.
   Any credential, token, cookie, API key, flag, useful session, or other
   reusable secret must be stored with `store_secret` as soon as it is found.

5. Trace every meaningful stage.
   Call `record_trace` with a non-empty `tool_calls` array for init, recon,
   endpoint mapping, vuln testing, exploitation, verification, reporting, stop,
   and failure stages.

6. Record every payload attempt.
   Every payload or pattern attempt must call `record_pattern_use` with
   `succeeded=true` or `succeeded=false`.

7. Confirmed vulnerabilities need the full chain.
   On confirmation, perform:
   `confirm_finding`, `save_evidence`, `record_pattern_use(true)`,
   `learn_from_finding`, `update_node_status(..., "confirmed")`, and
   `store_secret` if credentials or flags were found.

8. Dead ends are first-class data.
   If a path fails, call `record_pattern_use(false)`, `learn_dead_end`, and
   `mark_dead_end` with a concrete reason.

9. Update endpoint memory.
   After useful endpoint analysis, call `record_endpoint_spec` with method,
   params/schema, auth requirement, response shape, suspected vulnerability
   types, sink hints, and notes.

10. Use the Living KB before repeating work.
    Call `recall_target`, `recall_endpoint_specs`, `recall_dead_ends`,
    `search_knowledge`, and `check_payload_dedup` when they can prevent
    repeated failed payloads or suggest a better technique.

## Node Playbooks

Target/root node:

- Load previous knowledge with `recall_target`.
- Prefer white-box source review if source is mounted.
- Otherwise use browser/HTTP discovery.
- Push every endpoint as an `endpoint` child.
- Update target profile and architecture notes.
- Finalize as `explored` or `dead_end`.

Endpoint node:

- Analyze parameters, methods, sinks, auth, response shape, and source hints.
- Use `get_siblings` to avoid duplicate vuln children.
- Push suspected `vuln` or `clue` children.
- Record endpoint spec.
- If truly clean, mark dead end with a specific reason.

Vuln node:

- Load chain context, siblings, secrets, KB patterns, similar patterns, and
  dead ends.
- Check payload dedup before repeating likely failures.
- Prefer `multi_http_probe` for baseline plus several payload variants.
- Use deterministic oracles when available.
- Finalize as confirmed, partial clue/explored, or dead end.

Exploit step node:

- Load full chain context, secrets, scan notes, and siblings.
- Continue the confirmed primitive into the next chain step.
- Push new endpoints, clues, exploit steps, or flag nodes with complete
  context.
- Store new credentials or flags immediately.
- If chain progress stops, mark dead end and learn it.

Flag node:

- Create or confirm a critical finding.
- Save the flag evidence.
- Store the flag.
- Learn from the full chain.
- Mark the node confirmed.

## MLLA Role Mapping

When simulating the existing multi-agent behavior inside Codex:

- RouteMap: process target/root nodes and push endpoint children only.
- EntryPoint: process endpoint/clue nodes and push vuln/clue children.
- Hypothesis: process vuln nodes, test payloads, and finalize.
- Critic: before expensive exploit steps, quickly judge go/soft_go/no_go.
- Exploit: process exploit_step nodes and continue multi-step chains.
- Confirmer: independently verify flag nodes and recheck nodes.

Codex may run these roles sequentially in one agent. Preserve their boundaries
mentally: discovery maps, endpoint analysis identifies risks, hypothesis proves
or rejects, exploit chains, confirmer verifies.

## Safety And Scope

Only run active scanning or exploitation against targets the user is authorized
to test, local lab targets, or CTF/wargame targets in this repository. Keep
destructive actions deliberate and explain them before use when they could alter
target state.

Do not read or attack organizer/private source trees when a challenge provides
separate user-facing source. Use only the allowed source roots and target URLs.

## Reporting

Final responses should include:

- scan/run id when one exists
- target
- confirmed findings and evidence summary
- exploit chain or dead-end summary
- important secrets/flags stored, without leaking sensitive values unless the
  user explicitly needs them
- warnings from `validate_node` or `scan_selfcheck` that were accepted
- tests or verification performed

Keep the response concise, but make sure the user can continue the same scan in
the next Codex session.
