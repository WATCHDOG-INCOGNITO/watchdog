# Strategy Brain

Watchdog's Strategy Brain is a read-only global queue composer. It does not
replace the Discovery Tree or mutate the WorkItem queue in this phase. Instead
it normalizes scan artifacts into an Evidence Graph, extracts exploit
primitives, composes chain candidates, and returns Top-3 queue-plan
suggestions with provider hints.

## Data Flow

```text
DiscoveryNode / Candidate / Finding / Trace / WorkItem / AgentExchange
        |
        v
EvidenceNode + EvidenceEdge
        |
        v
PrimitiveInstance
        |
        v
ChainCandidate
        |
        v
StrategySnapshot
```

## CLI

Run CLI tools through the backend container:

```powershell
docker cp watchdog_cli.py watchdog-backend-1:/tmp/watchdog_cli.py
echo '{"scan_run_id":"<uuid>"}' | docker exec -i -e PYTHONPATH=/app -e DJANGO_SETTINGS_MODULE=config.settings watchdog-backend-1 python /tmp/watchdog_cli.py build_evidence_graph
```

Available strategy commands:

- `build_evidence_graph`: rebuild graph, primitives, chains, and a snapshot.
- `compose_chains`: alias for a full rebuild and chain composition.
- `get_strategy_snapshot`: return latest snapshot, optionally `rebuild=true`.
- `list_evidence_graph`: summarize graph counts and representative nodes.

## Current Behavior

- Secrets are represented only by key/category metadata; secret values are not
  copied into EvidenceNode payloads.
- `provider_hint` is advisory:
  - `claude` for workflow, auth, browser, and live target reasoning.
  - `codex` for source/code-heavy, file/path, replay, and critic work.
- Queue plans are suggestions only. Actual queue rewriting belongs in the next
  phase after replay evaluation.

## Example Output Shape

```json
{
  "top_chains": [
    {
      "name": "Group access / IDOR chain",
      "total_score": 71.4,
      "provider_hint": "claude",
      "missing_evidence": ["deterministic verification"]
    }
  ],
  "queue_plan": [
    {
      "work_type": "primitive_verify",
      "provider_hint": "claude",
      "objective": "Advance Group access / IDOR chain..."
    }
  ]
}
```
