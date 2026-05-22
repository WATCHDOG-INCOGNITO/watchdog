#!/usr/bin/env python3
"""Watchdog MCP CLI — 에이전트의 모든 MCP 도구를 CLI에서 호출.

Usage:
  echo '{"vuln_type":"ssrf"}' | python watchdog_cli.py search_knowledge
  echo '{"scan_run_id":"...", "parent_node_id":"...", ...}' | python watchdog_cli.py push_discovery
  python watchdog_cli.py list_tools

환경 변수:
  DJANGO_SETTINGS_MODULE=config.settings
  PYTHONPATH=/app
"""
import json
import os
import sys

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django
django.setup()

# ──────────────────────────────────────────────────────
# Direct imports of the _sync_ helper functions
# ──────────────────────────────────────────────────────
from watchdog_mcp.tools_knowledge import (
    _search, _retrieve_similar, _mutate_payload, _retrieve_cve_variants, _record_use,
)
from watchdog_mcp.tools_learn import (
    _learn_from_finding, _learn_dead_end, _update_target_profile,
    _recall_target, _recall_dead_ends,
)
from watchdog_mcp.tools_source import _list_tree, _read_file, _grep
from watchdog_mcp.tools_discovery import build_exploit_chains, pick_next_node
from watchdog_mcp.tools_oracle import _safe_get, _response_diff_blocks
from watchdog_mcp.tools_oob import _register_token, _get_hits, _clear_hits
from watchdog_mcp.link_extractor import extract_links_and_hashes

from api.storage_service import (
    confirm_candidate as _confirm_candidate,
    dismiss_candidate as _dismiss_candidate,
    attach_evidence as _attach_evidence,
    get_finding_detail as _finding_detail,
    get_scan_findings_summary as _scan_summary,
)
from api.services import analyze_params, analyze_path, calculate_priority
from api.llm_trace_store import record_llm_trace as _record_llm_trace
from api.discovery_queue import build_queue_metadata, node_queue_summary
from api.work_scheduler import (
    block_work_item,
    build_work_mission_packet,
    complete_work_item,
    enqueue_work_item,
    ensure_work_item_for_node,
    fail_work_item,
    lease_next_work_item,
    unblock_work_item,
)
from api.agent_exchange import (
    add_agent_exchange,
    exchange_summary,
    summarize_work_exchanges,
)
from api.mcp_agent import (
    _gather_previous_knowledge,
    _seed_from_previous,
    _auto_push_discovered_links,
)

from api.models import (
    ScanRun, DiscoveryNode, Candidate, Finding, RequestCatalog, LLMTrace,
    PayloadPattern, VulnerabilityEntry, DeadEnd, TargetProfile, WorkItem,
    AgentExchange,
)

from django.db import transaction
from django.utils import timezone

import re
import statistics
import requests as req_lib
import time
from datetime import timedelta


def _json_out(obj):
    print(json.dumps(obj, ensure_ascii=False, default=str, indent=2))


# ═══════════════════════════════════════════════════════
# Knowledge Base tools
# ═══════════════════════════════════════════════════════

def cmd_search_knowledge(p):
    _json_out(_search(
        vuln_type=p.get("vuln_type"),
        keyword=p.get("keyword"),
        limit=int(p.get("limit", 10)),
    ))

def cmd_retrieve_similar(p):
    _json_out(_retrieve_similar(
        query=p["query"],
        k=int(p.get("k", 5)),
        vuln_type=p.get("vuln_type"),
    ))

def cmd_mutate_payload(p):
    _json_out(_mutate_payload(
        seed_pattern_id=p["seed_pattern_id"],
        mutation_type=p.get("mutation_type", "custom"),
        hint=p.get("hint", ""),
    ))

def cmd_retrieve_cve_variants(p):
    _json_out(_retrieve_cve_variants(
        framework=p.get("framework", ""),
        endpoint_pattern=p.get("endpoint_pattern", ""),
        k=int(p.get("k", 5)),
    ))

def cmd_record_pattern_use(p):
    _json_out(_record_use(
        pattern_id=p["pattern_id"],
        succeeded=bool(p.get("succeeded", False)),
        false_positive=bool(p.get("false_positive", False)),
    ))


# ═══════════════════════════════════════════════════════
# Living KB (learn) tools
# ═══════════════════════════════════════════════════════

def cmd_recall_target(p):
    _json_out(_recall_target(target_host=p["target_host"]))

def cmd_recall_dead_ends(p):
    _json_out(_recall_dead_ends(
        target_host=p["target_host"],
        vuln_type=p.get("vuln_type", ""),
        endpoint=p.get("endpoint", ""),
    ))

def cmd_learn_from_finding(p):
    _json_out(_learn_from_finding(
        finding_id=p["finding_id"],
        target_host=p["target_host"],
        payload_used=p.get("payload_used", ""),
        oracle_signature=p.get("oracle_signature", ""),
        pattern_id=p.get("pattern_id", ""),
        notes=p.get("notes", ""),
        is_novel=bool(p.get("is_novel", False)),
        novelty_reason=p.get("novelty_reason", ""),
    ))

def cmd_learn_dead_end(p):
    _json_out(_learn_dead_end(
        target_host=p["target_host"],
        endpoint=p["endpoint"],
        vuln_type=p["vuln_type"],
        pattern_id=p.get("pattern_id", ""),
        payload_used=p.get("payload_used", ""),
        reason=p.get("reason", ""),
    ))

def cmd_update_target_profile(p):
    _json_out(_update_target_profile(
        target_host=p["target_host"],
        framework=p.get("framework", ""),
        server=p.get("server", ""),
        waf=p.get("waf", ""),
        fingerprint_json=p.get("fingerprint_json", ""),
        notes=p.get("notes", ""),
    ))


# ═══════════════════════════════════════════════════════
# Source code tools
# ═══════════════════════════════════════════════════════

def cmd_list_source_tree(p):
    _json_out(_list_tree(
        root_path=p.get("root", ""),
        max_depth=int(p.get("max_depth", 4)),
        glob=p.get("glob", "**/*"),
    ))

def cmd_read_source(p):
    _json_out(_read_file(
        path=p["path"],
        start_line=int(p.get("start_line", 1)),
        end_line=int(p.get("end_line", 0)),
    ))

def cmd_grep_source(p):
    _json_out(_grep(
        pattern=p["pattern"],
        root_path=p.get("root", ""),
        glob=p.get("glob", "**/*"),
        flags=p.get("flags", ""),
    ))


# ═══════════════════════════════════════════════════════
# Discovery Queue tools
# ═══════════════════════════════════════════════════════

def cmd_push_discovery(p):
    """Create DiscoveryNode with MCP-equivalent semantics: normalize + dedup +
    merge_context + depth/node-count guards. CLI 와 MCP 도구 가 동일하게
    동작하도록 watchdog_mcp.tools_discovery 의 helper 를 재사용."""
    from watchdog_mcp.tools_discovery import (
        _normalize_ep,
        _merge_context,
        _canonicalize_vuln_type,
        DISCOVERY_MAX_DEPTH,
        DISCOVERY_MAX_NODES,
    )

    ctx = p.get("context", p.get("context_json", {}))
    if isinstance(ctx, str):
        try:
            ctx = json.loads(ctx)
        except Exception:
            ctx = {"raw": ctx}

    scan_run_id = p["scan_run_id"]
    ntype = p.get("node_type", "clue")
    raw_ep = p.get("endpoint", "")

    parent = None
    depth = 0
    parent_id = p.get("parent_node_id") or p.get("parent")
    if parent_id:
        try:
            parent = DiscoveryNode.objects.get(node_id=parent_id)
            depth = parent.depth + 1
        except DiscoveryNode.DoesNotExist:
            _json_out({"error": f"parent {parent_id} not found"})
            return

    # Stage 1 — taxonomy canonicalize + require vuln_type for vuln /
    # exploit_step. Mirrors MCP push_discovery so CLI wrapper can't
    # re-fragment the tree with synonym strings.
    vuln_type_raw = p.get("vuln_type", "") or ""
    vuln_type = _canonicalize_vuln_type(vuln_type_raw)
    if vuln_type and vuln_type != vuln_type_raw and isinstance(ctx, dict):
        ctx.setdefault("vuln_type_raw", vuln_type_raw)
    if ntype in ("vuln", "exploit_step") and not vuln_type:
        if ntype == "exploit_step" and parent and parent.vuln_type:
            vuln_type = _canonicalize_vuln_type(parent.vuln_type)
            if isinstance(ctx, dict):
                ctx.setdefault("vuln_type_inherited_from_parent", True)
        else:
            _json_out({
                "error": "vuln_type is required for vuln/exploit_step nodes",
                "hint": (
                    "Pick a canonical type (sqli, idor, xss, ssrf, "
                    "access_control, auth_bypass, information_disclosure, "
                    "path_traversal, rce, csrf, xxe, file_upload, "
                    "logic_flaw, jwt, ssti, open_redirect, nosqli, "
                    "deserialization). Synonyms (privilege_escalation, "
                    "user_enum, ...) are auto-canonicalized."
                ),
                "node_type": ntype,
                "summary_seen": (p.get("summary", "") or "")[:160],
            })
            return

    if depth > DISCOVERY_MAX_DEPTH:
        _json_out({
            "error": f"max depth {DISCOVERY_MAX_DEPTH} reached",
            "depth": depth,
        })
        return

    existing_count = DiscoveryNode.objects.filter(scan_run_id=scan_run_id).count()
    if existing_count >= DISCOVERY_MAX_NODES:
        _json_out({
            "error": f"max nodes {DISCOVERY_MAX_NODES} reached",
            "total_nodes": existing_count,
        })
        return

    target_url = ""
    try:
        sr = ScanRun.objects.get(run_id=scan_run_id)
        target_url = sr.target_url or ""
    except Exception:
        pass

    # Dedup: same (scan, normalized_endpoint variants, vuln_type, node_type)
    # Mirrors MCP push_discovery logic so CLI and MCP converge.
    if raw_ep and ntype in ("endpoint", "vuln", "exploit_step"):
        ep_norm = _normalize_ep(raw_ep, target_url)
        ep_variants = set()
        for v in (raw_ep, ep_norm, ep_norm.rstrip("/"), ep_norm + "/"):
            ep_variants.add(v)
            ep_variants.add(v.lower())
        if "?" not in ep_norm:
            path_only = ep_norm.split("?", 1)[0]
            ep_variants.add(path_only)
            ep_variants.add(path_only + "/")
            ep_variants.add(path_only.lower())
        ep_variants.discard("")

        existing = (
            DiscoveryNode.objects
            .filter(scan_run_id=scan_run_id, node_type=ntype)
            .filter(endpoint__in=ep_variants)
            .filter(vuln_type=vuln_type)
            .order_by("created_at")
            .first()
        )
        if existing:
            _merge_context(existing, ctx)
            work_info = {}
            try:
                work = ensure_work_item_for_node(existing)
                work_info = {"work_id": str(work.work_id), "work_type": work.work_type}
            except Exception as e:
                work_info = {"work_enqueue_error": str(e)}
            _json_out({
                "node_id": str(existing.node_id),
                "depth": existing.depth,
                "node_type": existing.node_type,
                **node_queue_summary(existing),
                **work_info,
                "deduped": True,
                "context_merged": bool(ctx),
                "deduped_reason": "same scan+endpoint+vuln_type+node_type already exists",
            })
            return

    store_ep = raw_ep or (parent.endpoint if parent else "")
    if store_ep:
        store_ep = _normalize_ep(store_ep, target_url)

    queue_meta = build_queue_metadata(
        node_type=ntype,
        vuln_type=vuln_type,
        context=ctx,
        depth=depth,
        parent_status=parent.status if parent else "",
    )

    node = DiscoveryNode.objects.create(
        scan_run_id=scan_run_id,
        parent=parent,
        depth=depth,
        node_type=ntype,
        endpoint=store_ep,
        vuln_type=vuln_type,
        summary=p.get("summary", ""),
        context=ctx,
        status=p.get("status", "pending"),
        **queue_meta,
    )

    result = {"node_id": str(node.node_id), "depth": depth, **node_queue_summary(node)}

    if ntype in ("vuln", "exploit_step", "clue"):
        cand = Candidate.objects.create(
            scan_run_id=scan_run_id,
            vuln_type=vuln_type or "signal_stub",
            hypothesis=p.get("summary", ""),
            priority_score=node.priority_score or 0.5,
            detection_stage="llm_deep",
            status="open",
            features={
                "discovery_node_id": str(node.node_id),
                "node_type": ntype,
                "endpoint": store_ep,
                "depth": depth,
                "queue_lane": node.queue_lane,
                "provider_hint": node.provider_hint,
            },
        )
        result["cand_id"] = str(cand.cand_id)

    try:
        work = ensure_work_item_for_node(node)
        result["work_id"] = str(work.work_id)
        result["work_type"] = work.work_type
    except Exception as e:
        result["work_enqueue_error"] = str(e)

    _json_out(result)


def cmd_get_chain_context(p):
    node_id = p.get("node_id")
    try:
        node = DiscoveryNode.objects.get(node_id=node_id)
    except DiscoveryNode.DoesNotExist:
        _json_out({"error": f"node {node_id} not found"})
        return

    IMPORTANT_TYPES = {"vuln", "exploit_step", "clue", "flag"}
    chain = []
    current = node
    while current is not None:
        hops = node.depth - current.depth
        include_context = hops <= 3 or current.node_type in IMPORTANT_TYPES
        chain.append({
            "node_id": str(current.node_id),
            "depth": current.depth,
            "node_type": current.node_type,
            "endpoint": current.endpoint or "",
            "vuln_type": current.vuln_type or "",
            "summary": current.summary,
            "context": current.context if include_context else {},
            "status": current.status,
        })
        current = current.parent
    chain.reverse()
    _json_out({"chain_length": len(chain), "chain": chain})


def cmd_mark_dead_end(p):
    node_id = p.get("node_id")
    reason = p.get("reason", "")
    try:
        node = DiscoveryNode.objects.get(node_id=node_id)
    except DiscoveryNode.DoesNotExist:
        _json_out({"error": f"node {node_id} not found"})
        return

    node.status = "dead_end"
    node.explored_at = timezone.now()
    node.lease_owner = None
    node.leased_until = None
    node.save(update_fields=["status", "explored_at", "lease_owner", "leased_until"])
    _json_out({"node_id": str(node.node_id), "status": "dead_end"})


VALID_STATUSES = {"pending", "exploring", "explored", "dead_end", "confirmed"}


def cmd_update_node_status(p):
    node_id = p.get("node_id")
    new_status = p.get("status", "")
    if new_status not in VALID_STATUSES:
        _json_out({"error": f"invalid status '{new_status}'. valid: {sorted(VALID_STATUSES)}"})
        return
    try:
        node = DiscoveryNode.objects.get(node_id=node_id)
    except DiscoveryNode.DoesNotExist:
        _json_out({"error": f"node {node_id} not found"})
        return

    old_status = node.status
    node.status = new_status
    fields = ["status"]
    if new_status == "exploring":
        node.explored_at = timezone.now()
        if p.get("worker_id"):
            node.worker_id = p.get("worker_id")
            fields.append("worker_id")
        node.lease_owner = p.get("worker_id") or node.worker_id
        lease_seconds = int(os.environ.get("WATCHDOG_DISCOVERY_STALE_S", "300"))
        node.leased_until = timezone.now() + timedelta(seconds=lease_seconds)
        fields.extend(["explored_at", "lease_owner", "leased_until"])
    elif new_status in {"explored", "dead_end", "confirmed"}:
        node.lease_owner = None
        node.leased_until = None
        fields.extend(["lease_owner", "leased_until"])
    node.save(update_fields=fields)

    _json_out({
        "node_id": str(node.node_id),
        "old_status": old_status,
        "new_status": new_status,
    })


def cmd_get_siblings(p):
    node_id = p.get("node_id")
    try:
        node = DiscoveryNode.objects.get(node_id=node_id)
    except DiscoveryNode.DoesNotExist:
        _json_out({"error": f"node {node_id} not found"})
        return

    siblings = DiscoveryNode.objects.filter(
        parent=node.parent, scan_run=node.scan_run,
    ).exclude(node_id=node.node_id).values(
        "node_id", "node_type", "endpoint", "vuln_type", "summary", "status",
    )[:20]

    _json_out({"count": len(siblings), "siblings": [
        {**s, "node_id": str(s["node_id"]), "summary": s["summary"][:200]}
        for s in siblings
    ]})


def cmd_get_exploit_chains(p):
    chains = build_exploit_chains(p["scan_run_id"])
    _json_out({"count": len(chains), "chains": chains})


def cmd_store_secret(p):
    with transaction.atomic():
        run = ScanRun.objects.select_for_update().get(run_id=p["scan_run_id"])
        config = run.config or {}
        secrets = config.get("_secrets", {})
        secrets[p["key"]] = {
            "value": p["value"],
            "category": p.get("category", "credential"),
            "stored_at": str(timezone.now()),
        }
        config["_secrets"] = secrets
        run.config = config
        run.save(update_fields=["config"])
    _json_out({"stored": p["key"], "total_secrets": len(secrets)})


def cmd_get_secrets(p):
    run = ScanRun.objects.get(run_id=p["scan_run_id"])
    secrets = (run.config or {}).get("_secrets", {})
    cat = p.get("category", "")
    if cat:
        secrets = {k: v for k, v in secrets.items() if v.get("category") == cat}
    _json_out({"count": len(secrets), "secrets": secrets})


def cmd_add_scan_note(p):
    with transaction.atomic():
        run = ScanRun.objects.select_for_update().get(run_id=p["scan_run_id"])
        config = run.config or {}
        notes = config.get("_notes", [])
        notes.append({
            "topic": p["topic"],
            "content": p["content"][:500],
            "ts": str(timezone.now()),
        })
        if len(notes) > 50:
            notes = notes[-50:]
        config["_notes"] = notes
        run.config = config
        run.save(update_fields=["config"])
    _json_out({"added": p["topic"], "total_notes": len(notes)})


def cmd_get_scan_notes(p):
    run = ScanRun.objects.get(run_id=p["scan_run_id"])
    notes = (run.config or {}).get("_notes", [])
    topic = p.get("topic", "")
    if topic:
        notes = [n for n in notes if n.get("topic") == topic]
    _json_out({"count": len(notes), "notes": notes})


# ═══════════════════════════════════════════════════════
# Scan management
# ═══════════════════════════════════════════════════════

def cmd_create_scan(p):
    cfg = p.get("config", {"mode": "manual"})
    run = ScanRun.objects.create(
        target_url=p["target_url"],
        mode=p.get("mode", "discovery"),
        status="running",
        request_budget_total=int(p.get("budget", 200)),
        config=cfg,
    )
    result = {"scan_id": str(run.run_id), "status": run.status}

    resume_from = cfg.get("resume_from", "auto")
    try:
        prev = _gather_previous_knowledge(
            run.target_url, str(run.run_id), resume_from,
        )
    except Exception:
        prev = None

    if prev:
        new_cfg = dict(run.config or {})
        new_cfg["_prev_run_id"] = prev.get("prev_run_id", "")
        run.config = new_cfg
        run.save(update_fields=["config"])
        result["resume_from"] = prev.get("prev_run_id", "")
        result["prev_nodes"] = len(prev.get("nodes") or [])
        result["prev_findings"] = len(prev.get("findings") or [])

    _json_out(result)


def cmd_create_root(p):
    run = ScanRun.objects.get(run_id=p["scan_run_id"])
    ctx = {"target_url": p["target_url"]}
    node = DiscoveryNode.objects.create(
        scan_run=run,
        parent=None,
        depth=0,
        node_type="target",
        endpoint=p["target_url"],
        summary=f"Root target: {p['target_url']}",
        context=ctx,
        status="pending",
        **build_queue_metadata(node_type="target", context=ctx, depth=0),
    )

    cfg = dict(run.config or {})
    cfg["_root_node_id"] = str(node.node_id)

    prev_run_id = cfg.pop("_prev_run_id", None)
    run.config = cfg
    run.save(update_fields=["config"])

    result = {"root_id": str(node.node_id)}
    try:
        work = ensure_work_item_for_node(node)
        result["work_id"] = str(work.work_id)
        result["work_type"] = work.work_type
    except Exception as e:
        result["work_enqueue_error"] = str(e)

    if prev_run_id:
        try:
            prev = _gather_previous_knowledge(
                run.target_url, str(run.run_id), prev_run_id,
            )
            if prev:
                seeded = _seed_from_previous(run, node, prev)
                result["seeded"] = seeded
        except Exception as e:
            result["seed_error"] = str(e)

    _json_out(result)


def cmd_create_finding(p):
    node = DiscoveryNode.objects.get(node_id=p["node_id"])
    node.status = "confirmed"
    node.save(update_fields=["status"])

    cand = Candidate.objects.filter(
        features__discovery_node_id=str(p["node_id"])
    ).first()
    if cand:
        cand.status = "confirmed"
        cand.save(update_fields=["status"])

    finding = Finding.objects.create(
        scan_run_id=p["scan_run_id"],
        candidate=cand,
        title=p["title"],
        vuln_type=p["vuln_type"],
        severity=p.get("severity", "medium"),
        confidence=float(p.get("confidence", 0.9)),
        summary=p.get("summary", p["title"]),
    )
    _json_out({"finding_id": str(finding.finding_id)})


def cmd_complete_scan(p):
    from django.utils import timezone
    sr = ScanRun.objects.get(run_id=p["scan_run_id"])
    sr.status = "finished"
    sr.finished_at = timezone.now()
    sr.save(update_fields=["status", "finished_at"])

    exported = _auto_export_learned()

    _json_out({"status": "finished", "finished_at": str(sr.finished_at), "auto_export": exported})


def cmd_stop_scan(p):
    """Mark a scan as stopped (user-initiated cancellation or interruption)."""
    from django.utils import timezone
    sr = ScanRun.objects.get(run_id=p["scan_run_id"])
    sr.status = "stopped"
    if not sr.finished_at:
        sr.finished_at = timezone.now()
    sr.error_log = p.get("reason", "User requested stop")
    sr.save(update_fields=["status", "finished_at", "error_log"])
    _json_out({"status": "stopped", "finished_at": str(sr.finished_at), "reason": sr.error_log})


def cmd_fail_scan(p):
    """Mark a scan as failed due to an error."""
    from django.utils import timezone
    sr = ScanRun.objects.get(run_id=p["scan_run_id"])
    sr.status = "failed"
    sr.finished_at = timezone.now()
    sr.error_log = p.get("error", "Unknown error")
    sr.save(update_fields=["status", "finished_at", "error_log"])
    _json_out({"status": "failed", "finished_at": str(sr.finished_at), "error": sr.error_log})


def _auto_export_learned():
    """Export new learned patterns as .md files + generate embeddings on scan completion."""
    from api.management.commands.export_learned import pattern_to_md, _clean_name, TECHNIQUES_DIR
    from datetime import date

    qs = PayloadPattern.objects.filter(
        source="learned", is_active=True, times_succeeded__gte=1,
    ).order_by("-times_succeeded")

    existing_names = set(
        PayloadPattern.objects.filter(source="technique").values_list("name", flat=True)
    )

    exported = []
    to_embed = []
    for pat in qs:
        if (pat.attack_metadata or {}).get("exported_to_md"):
            # Still ensure embedding exists even if already exported
            if pat.embedding is None:
                to_embed.append(pat)
            continue
        filename, vuln_type, md_content = pattern_to_md(pat)
        clean_name = _clean_name(pat.name, pat.vuln_type, str(pat.pattern_id))
        if clean_name in existing_names:
            continue
        existing_names.add(clean_name)

        target_dir = TECHNIQUES_DIR / vuln_type
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / filename).write_text(md_content, encoding="utf-8")

        meta = pat.attack_metadata or {}
        meta["exported_to_md"] = True
        meta["exported_date"] = str(date.today())
        pat.attack_metadata = meta
        pat.save(update_fields=["attack_metadata"])

        exported.append({"name": clean_name, "vuln_type": vuln_type,
                         "file": f"{vuln_type}/{filename}"})
        to_embed.append(pat)

    # Generate embeddings for learned patterns so retrieve_similar can find them
    embedded_count = _embed_patterns(to_embed)

    return exported


def _embed_patterns(patterns):
    """Generate embeddings for patterns that don't have one yet."""
    if not patterns:
        return 0
    try:
        from api.embedding_service import (
            EMBEDDING_MODEL, embed_documents, is_available as embeddings_available,
        )
        if not embeddings_available():
            return 0
    except ImportError:
        return 0

    need_embed = [p for p in patterns if p.embedding is None]
    if not need_embed:
        return 0

    texts = []
    for p in need_embed:
        meta = p.attack_metadata or {}
        parts = [
            f"name: {meta.get('name', p.name)}",
            f"vuln_type: {p.vuln_type}",
            f"applies_when: {meta.get('applies_when', meta.get('novelty_reason', ''))}",
            f"prerequisites: {' / '.join(meta.get('prerequisites') or [])}",
            f"steps: {meta.get('technique_steps_md', '')[:500]}",
            f"tags: {', '.join(meta.get('tags') or p.tags or [])}",
        ]
        texts.append("\n".join(parts))

    vectors = embed_documents(texts)
    if not vectors:
        return 0

    for p, vec in zip(need_embed, vectors):
        p.embedding = vec
        p.embedding_model = EMBEDDING_MODEL
        p.save(update_fields=["embedding", "embedding_model"])

    return len(vectors)


def cmd_list_nodes(p):
    nodes = DiscoveryNode.objects.filter(
        scan_run_id=p["scan_run_id"]
    ).order_by("-priority_score", "-depth", "created_at")
    items = []
    for n in nodes:
        items.append({
            "node_id": str(n.node_id)[:8],
            "depth": n.depth,
            "type": n.node_type,
            "status": n.status,
            "lane": n.queue_lane,
            "priority_score": n.priority_score,
            "provider_hint": n.provider_hint,
            "attempt_count": n.attempt_count,
            "parent": str(n.parent_id)[:8] if n.parent_id else "root",
            "summary": n.summary[:80],
        })
    _json_out({"total": len(items), "nodes": items})


# ═══════════════════════════════════════════════════════
# MCP parity helpers (auto-push, UA/auth injection)
# ═══════════════════════════════════════════════════════

def _cli_auto_push(scan_run_id, result_dict, tool_name, current_node_id=""):
    """Reuse mcp_agent._auto_push_discovered_links to auto-create child nodes."""
    try:
        scan_run = ScanRun.objects.get(run_id=scan_run_id)
        raw_text = json.dumps(result_dict, default=str)
        _auto_push_discovered_links(scan_run, raw_text, tool_name, current_node_id)
    except Exception:
        pass


def _maybe_inject_headers(p):
    """Inject Bug Bounty UA and auto-auth headers when scan_run_id is present."""
    scan_run_id = p.get("scan_run_id")
    if not scan_run_id:
        return
    try:
        run = ScanRun.objects.get(run_id=scan_run_id)
    except ScanRun.DoesNotExist:
        return

    headers = p.get("headers") or {}
    cfg = run.config or {}

    ua_id = cfg.get("bug_bounty_ua")
    if ua_id and "User-Agent" not in headers:
        headers["User-Agent"] = f"WatchdogMCP/1.0 (BugBounty: {ua_id})"

    if "Authorization" not in headers and "Cookie" not in headers:
        creds = cfg.get("credentials")
        if creds and isinstance(creds, list):
            for cred in creds:
                if cred.get("type") == "bearer" and cred.get("token"):
                    headers["Authorization"] = f"Bearer {cred['token']}"
                    break

    p["headers"] = headers


# ═══════════════════════════════════════════════════════
# HTTP tools (session-based)
# ═══════════════════════════════════════════════════════

_SESSIONS = {}

def cmd_http_request(p):
    _maybe_inject_headers(p)

    method = p.get("method", "GET").upper()
    url = p["url"]
    headers = p.get("headers", {})
    body = p.get("body", "")
    timeout = int(p.get("timeout", 15))
    follow = p.get("follow_redirects", True)

    session_id = p.get("session_id")
    if session_id:
        if session_id not in _SESSIONS:
            _SESSIONS[session_id] = req_lib.Session()
        sess = _SESSIONS[session_id]
    else:
        sess = req_lib.Session()

    kwargs = {"headers": headers, "allow_redirects": follow, "timeout": timeout}
    if body:
        kwargs["data"] = body
    form = p.get("form")
    if form:
        kwargs["data"] = form

    try:
        t0 = time.time()
        resp = sess.request(method, url, **kwargs)
        elapsed = round(time.time() - t0, 3)
    except Exception as e:
        _json_out({"error": str(e)})
        return

    full_body = resp.text
    ct = resp.headers.get("Content-Type", "")
    try:
        links, hashes = extract_links_and_hashes(
            full_body, ct, dict(resp.headers), url,
        )
    except Exception:
        links, hashes = [], []

    result = {
        "url": resp.url,
        "status_code": resp.status_code,
        "elapsed": elapsed,
        "content_length": len(full_body),
        "headers": dict(resp.headers),
        "cookies": {c.name: c.value for c in resp.cookies},
        "session_cookies": {c.name: c.value for c in sess.cookies} if session_id else {},
        "body": full_body[:5000],
        "discovered_links": links,
        "hash_routes": hashes,
    }

    scan_run_id = p.get("scan_run_id")
    if scan_run_id:
        _cli_auto_push(
            scan_run_id, result, "http_request",
            p.get("current_node_id", ""),
        )

    _json_out(result)


# ═══════════════════════════════════════════════════════
# Oracle tools
# ═══════════════════════════════════════════════════════

_LFI_SIGS = [
    (re.compile(r"(?:^|>|\n)\s*root:[^:\n]*:\d+:\d+:"), "/etc/passwd (unix)"),
    (re.compile(r"daemon:[^:]*:\d+:\d+:"), "/etc/passwd (daemon)"),
    (re.compile(r"\[boot loader\]", re.I), "boot.ini (windows)"),
    (re.compile(r"<\?php\b"), "php source"),
    (re.compile(r"DocumentRoot|ServerName", re.I), "apache config"),
    (re.compile(r"^[A-Za-z0-9+/=]{200,}\s*$", re.M), "base64 (php filter)"),
]
_SSRF_SIGS = [
    (re.compile(r"ami-id|instance-id|iam/security-credentials", re.I), "AWS metadata"),
    (re.compile(r"computeMetadata/v1", re.I), "GCP metadata"),
    (re.compile(r"metadata\.azure", re.I), "Azure metadata"),
    (re.compile(r"<title>.{0,200}localhost", re.I | re.S), "localhost banner"),
    (re.compile(r"127\.0\.0\.1[:\s]"), "loopback echo"),
    (re.compile(r"(?:^|>|\n)\s*root:[^:\n]*:\d+:\d+:"), "file:// /etc/passwd echoed"),
]


def cmd_oracle_response_diff(p):
    try:
        r_base = _safe_get(p["baseline_url"])
        r_pay = _safe_get(p["payload_url"])
        r_ctrl = _safe_get(p["control_url"]) if p.get("control_url") else None
    except Exception as e:
        _json_out({"error": str(e)}); return
    diff = _response_diff_blocks(r_base.text, r_pay.text, r_ctrl.text if r_ctrl else "")
    _json_out({
        "baseline_status": r_base.status_code, "payload_status": r_pay.status_code,
        "control_status": r_ctrl.status_code if r_ctrl else None,
        "len_baseline": len(r_base.text), "len_payload": len(r_pay.text), **diff,
    })


def cmd_oracle_sqli_boolean(p):
    try:
        r_true = _safe_get(p["url_true"])
        r_false = _safe_get(p["url_false"])
        r_base = _safe_get(p["url_baseline"]) if p.get("url_baseline") else r_true
    except Exception as e:
        _json_out({"error": str(e)}); return
    lt, lf, lb = len(r_true.text), len(r_false.text), len(r_base.text)
    diff_tf = abs(lt - lf) / max(lt, lf, 1)
    diff_tb = abs(lt - lb) / max(lt, lb, 1)
    diff_fb = abs(lf - lb) / max(lf, lb, 1)
    confirmed = diff_tf > 0.05 or r_true.status_code != r_false.status_code or max(diff_tb, diff_fb) > 0.10
    _json_out({
        "confirmed": confirmed,
        "diff_true_vs_false": round(diff_tf, 4),
        "status_true": r_true.status_code, "status_false": r_false.status_code,
        "len_true": lt, "len_false": lf, "len_baseline": lb,
        "snippet_true": r_true.text[:300], "snippet_false": r_false.text[:300],
    })


def cmd_oracle_sqli_time(p):
    delay = int(p.get("expected_delay_ms", 3000))
    samples = max(1, min(int(p.get("samples", 3)), 5))
    def _measure(u):
        t0 = time.time()
        try:
            r = _safe_get(u, timeout=delay // 1000 + 5)
            ok = r.status_code < 500
        except Exception:
            ok = False
        return (time.time() - t0) * 1000.0, ok
    b_ms = [_measure(p["url_baseline"]) for _ in range(samples)]
    p_ms = [_measure(p["url_payload"]) for _ in range(samples)]
    b_med = statistics.median(t for t, _ in b_ms)
    p_med = statistics.median(t for t, _ in p_ms)
    delta = p_med - b_med
    confirmed = delta >= max(delay - 1500, 1500)
    _json_out({
        "confirmed": confirmed, "baseline_median_ms": round(b_med, 1),
        "payload_median_ms": round(p_med, 1), "delta_ms": round(delta, 1),
        "expected_delay_ms": delay, "samples": samples,
    })


def cmd_oracle_lfi(p):
    try:
        r = _safe_get(p["url"])
    except Exception as e:
        _json_out({"error": str(e)}); return
    matched = [label for pat, label in _LFI_SIGS if pat.search(r.text)]
    _json_out({"confirmed": bool(matched), "matched_signatures": matched,
               "status_code": r.status_code, "snippet": r.text[:500]})


def cmd_oracle_ssrf(p):
    try:
        r = _safe_get(p["url"])
    except Exception as e:
        _json_out({"error": str(e)}); return
    matched = [label for pat, label in _SSRF_SIGS if pat.search(r.text)]
    _json_out({"confirmed": bool(matched), "matched_signatures": matched,
               "status_code": r.status_code, "snippet": r.text[:500]})


# ═══════════════════════════════════════════════════════
# Storage tools
# ═══════════════════════════════════════════════════════

def cmd_confirm_candidate(p):
    evidence = []
    if p.get("evidence_json"):
        try:
            evidence = json.loads(p["evidence_json"]) if isinstance(p["evidence_json"], str) else p["evidence_json"]
        except Exception:
            evidence = []
    try:
        result = _confirm_candidate(
            cand_id=p["cand_id"],
            severity=p.get("severity") or None,
            title=p.get("title") or None,
            summary=p.get("summary") or None,
            evidence_list=evidence or None,
        )
        _json_out(result)
    except Exception as e:
        _json_out({"error": str(e)})


def cmd_dismiss_candidate(p):
    try:
        result = _dismiss_candidate(cand_id=p["cand_id"], reason=p.get("reason", "false_positive"))
        _json_out(result)
    except Exception as e:
        _json_out({"error": str(e)})


def cmd_save_evidence(p):
    try:
        result = _attach_evidence(finding_id=p["finding_id"], evidence_data={
            "kind": p["kind"], "content": p["content"], "role": p.get("role", "supporting"),
        })
        _json_out(result)
    except Exception as e:
        _json_out({"error": str(e)})


def cmd_get_finding_detail(p):
    try:
        _json_out(_finding_detail(finding_id=p["finding_id"]))
    except Exception as e:
        _json_out({"error": str(e)})


def cmd_get_scan_summary(p):
    try:
        _json_out(_scan_summary(run_id=p["run_id"]))
    except Exception as e:
        _json_out({"error": str(e)})


# ═══════════════════════════════════════════════════════
# Analysis tools
# ═══════════════════════════════════════════════════════

def cmd_analyze_endpoint(p):
    try:
        params_dict = json.loads(p.get("params", "{}")) if isinstance(p.get("params"), str) else p.get("params", {})
    except json.JSONDecodeError:
        params_dict = {}
    param_hits = analyze_params(params_dict)
    path_hits = analyze_path(p["endpoint"])
    score = calculate_priority(param_hits, path_hits)
    _json_out({
        "endpoint": p["endpoint"], "method": p.get("method", "GET"),
        "vuln_types": list(set(h["vuln_type"] for h in param_hits + path_hits)),
        "priority_score": round(score, 3),
        "param_hits": param_hits, "path_hits": path_hits,
    })


def cmd_list_candidates(p):
    qs = Candidate.objects.filter(scan_run_id=p["run_id"]).select_related("request")
    if p.get("status"):
        qs = qs.filter(status=p["status"])
    if p.get("vuln_type"):
        qs = qs.filter(vuln_type=p["vuln_type"])
    results = []
    for c in qs.order_by("-priority_score")[:30]:
        results.append({
            "cand_id": str(c.cand_id), "vuln_type": c.vuln_type,
            "status": c.status, "priority_score": round(c.priority_score, 3),
            "hypothesis": c.hypothesis,
            "endpoint": c.request.endpoint if c.request else None,
            "method": c.request.method if c.request else None,
        })
    _json_out({"count": len(results), "candidates": results})


def cmd_create_candidate_manual(p):
    try:
        params_dict = json.loads(p.get("params", "{}")) if isinstance(p.get("params"), str) else p.get("params", {})
    except json.JSONDecodeError:
        params_dict = {}
    try:
        scan_run = ScanRun.objects.get(run_id=p["run_id"])
        req = RequestCatalog.objects.create(
            scan_run=scan_run, endpoint=p["endpoint"],
            method=p.get("method", "GET").upper(), params=params_dict, source="llm_manual",
        )
        param_hits = analyze_params(params_dict)
        path_hits = analyze_path(p["endpoint"])
        score = calculate_priority(param_hits, path_hits)
        cand = Candidate.objects.create(
            scan_run=scan_run, request=req, vuln_type=p["vuln_type"],
            hypothesis=p.get("hypothesis", f"Manual: {p['endpoint']} ({p['vuln_type']})"),
            priority_score=max(score, 0.8), detection_stage="llm_screen",
            status="open", features={"source": "llm_manual", "params": params_dict},
        )
        _json_out({"cand_id": str(cand.cand_id), "vuln_type": p["vuln_type"],
                    "endpoint": p["endpoint"], "status": "open"})
    except Exception as e:
        _json_out({"error": str(e)})


# ═══════════════════════════════════════════════════════
# OOB tools
# ═══════════════════════════════════════════════════════

def cmd_oob_register_token(p):
    _json_out(_register_token(p.get("scan_run_id", "")))


def cmd_oob_get_hits(p):
    try:
        _json_out(_get_hits(
            token=p["token"],
            since_iso=p.get("since_iso", ""),
            limit=int(p.get("limit", 50)),
        ))
    except Exception as e:
        _json_out({"error": str(e)})


def cmd_oob_clear_hits(p):
    try:
        _json_out(_clear_hits(token=p["token"]))
    except Exception as e:
        _json_out({"error": str(e)})


def cmd_oob_wait_for_hit(p):
    token = p["token"]
    timeout_s = max(1, min(int(p.get("timeout_s", 30)), 120))
    poll_s = max(1, int(p.get("poll_interval_s", 2)))
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        try:
            last = _get_hits(token=token, since_iso="", limit=10)
            if last.get("count", 0) > 0:
                _json_out({"timed_out": False, **last}); return
        except Exception:
            pass
        time.sleep(poll_s)
    _json_out({"timed_out": True, **(last or {"token": token, "count": 0, "hits": []})})


# ═══════════════════════════════════════════════════════
# LLM Trace
# ═══════════════════════════════════════════════════════

def cmd_record_trace(p):
    try:
        run = ScanRun.objects.get(run_id=p["scan_run_id"])
        # Use the same resolver the auto-trace path uses — checks
        # target_node_id / current_node_id / node_id / parent_node_id in order.
        target_node = _resolve_trace_node(run, p)
        _record_llm_trace(
            scan_run=run,
            call_index=int(p.get("call_index", 0)),
            stage=p.get("stage", "cursor_agent"),
            model=p.get("model", "cursor-claude"),
            prompt_preview=p.get("prompt_preview", "")[:6000],
            response_preview=p.get("response_preview", "")[:6000],
            tool_calls=p.get("tool_calls"),
            stop_reason=p.get("stop_reason", ""),
            input_tokens=int(p.get("input_tokens", 0)),
            output_tokens=int(p.get("output_tokens", 0)),
            metadata=p.get("metadata"),
            error=p.get("error", ""),
            target_node=target_node,
        )
        _json_out({"recorded": True, "stage": p.get("stage", "cursor_agent")})
    except Exception as e:
        _json_out({"error": str(e)})


# ═══════════════════════════════════════════════════════
# Export
# ═══════════════════════════════════════════════════════

def cmd_export_learned(p):
    from api.management.commands.export_learned import pattern_to_md, _clean_name, TECHNIQUES_DIR
    from datetime import date
    min_succ = int(p.get("min_succeeded", 1))
    write = bool(p.get("write", False))
    promote = bool(p.get("promote", False))
    qs = PayloadPattern.objects.filter(
        source="learned", is_active=True, times_succeeded__gte=min_succ,
    ).order_by("-times_succeeded")
    existing_names = set(
        PayloadPattern.objects.filter(source="technique").values_list("name", flat=True)
    )
    results = []
    for pat in qs:
        if (pat.attack_metadata or {}).get("exported_to_md") and not promote:
            continue
        filename, vuln_type, md_content = pattern_to_md(pat)
        clean_name = _clean_name(pat.name, pat.vuln_type, str(pat.pattern_id))
        if clean_name in existing_names:
            continue
        existing_names.add(clean_name)
        action = "preview"
        if write:
            from pathlib import Path
            target_dir = TECHNIQUES_DIR / vuln_type
            target_dir.mkdir(parents=True, exist_ok=True)
            (target_dir / filename).write_text(md_content, encoding="utf-8")
            meta = pat.attack_metadata or {}
            meta["exported_to_md"] = True
            meta["exported_date"] = str(date.today())
            pat.attack_metadata = meta
            pat.save(update_fields=["attack_metadata"])
            action = "written"
        if promote and write:
            vuln_map = {v.vuln_type: v for v in VulnerabilityEntry.objects.all()}
            pat.source = "technique"
            pat.name = clean_name
            pat.target_host = None
            pat.category = "exploitation"
            pat.vulnerability = vuln_map.get(pat.vuln_type)
            pat.mutation_type = "original"
            pat.save()
            action = "promoted"
        results.append({"name": clean_name, "vuln_type": vuln_type,
                        "file": f"{vuln_type}/{filename}", "action": action})
    _json_out({"count": len(results), "patterns": results})


# ═══════════════════════════════════════════════════════
# Orchestration — BFS Loop Driver + Validator
# ═══════════════════════════════════════════════════════

_REQUIRED_ACTIONS = {
    "target": {
        "init": ["update_node_status(exploring)"],
        "work": [
            "http_request (initial recon)",
            "update_target_profile",
            "add_scan_note(topic=architecture)",
            "EACH endpoint → push_discovery(node_type=endpoint) + analyze_endpoint + create_candidate_manual",
        ],
        "finalize": ["update_node_status(explored)", "record_trace"],
    },
    "endpoint": {
        "init": ["update_node_status(exploring)"],
        "work": [
            "analyze_endpoint(endpoint, method, params)",
            "EACH suspected vuln_type → push_discovery(node_type=vuln) + create_candidate_manual",
            "IF no suspects → mark_dead_end",
        ],
        "finalize": ["update_node_status(explored|dead_end)", "record_trace"],
    },
    "vuln": {
        "init": ["update_node_status(exploring)", "search_knowledge(vuln_type)", "recall_dead_ends"],
        "work": [
            "EACH payload → http_request + record_pattern_use(succeeded=T/F)",
            "IF confirmed → create_finding + save_evidence + confirm_finding + learn_from_finding + store_secret(if cred) + push_discovery(exploit_step)",
            "IF all failed → mark_dead_end + learn_dead_end",
        ],
        "finalize": ["update_node_status(confirmed|dead_end)", "record_trace"],
    },
    "exploit_step": {
        "init": ["update_node_status(exploring)", "get_chain_context", "get_secrets"],
        "work": [
            "Execute exploit using chain context",
            "EACH new discovery → push_discovery + analyze_endpoint(if endpoint) + create_candidate_manual",
            "store_secret (if new cred found)",
        ],
        "finalize": ["update_node_status(confirmed|explored)", "record_trace"],
    },
    "clue": {
        "init": ["update_node_status(exploring)"],
        "work": [
            "Investigate clue (http_request, source analysis)",
            "IF useful → push_discovery(child node)",
            "IF dead end → mark_dead_end",
        ],
        "finalize": ["update_node_status(explored|dead_end)", "record_trace"],
    },
    "flag": {
        "init": ["update_node_status(exploring)"],
        "work": [
            "create_finding(severity=critical, title=Flag Captured)",
            "save_evidence(finding_id, kind=response, content=FLAG)",
            "confirm_finding(cand_id)",
            "learn_from_finding(is_novel)",
            "store_secret(key=flag, value=FLAG)",
        ],
        "finalize": ["update_node_status(confirmed)", "record_trace"],
    },
}


def _mission_packet(sr, node, actions=None, slot_hints=None):
    actions = actions or _REQUIRED_ACTIONS.get(node.node_type, {})
    packet = {
        "scan_run_id": str(sr.run_id),
        "target_url": sr.target_url,
        "node_id": str(node.node_id),
        "node_type": node.node_type,
        "endpoint": node.endpoint or "",
        "vuln_type": node.vuln_type or "",
        "summary": node.summary,
        "queue": node_queue_summary(node),
        "required_init": actions.get("init", []),
        "required_work": actions.get("work", []),
        "required_finalize": actions.get("finalize", []),
    }
    if slot_hints:
        packet["slot_hints"] = slot_hints
    return packet


def _candidate_packet(sr, node, rank, vuln_slot_hints=None):
    parent_status = ""
    if node.parent_id:
        par = DiscoveryNode.objects.filter(node_id=node.parent_id).only("status").first()
        parent_status = par.status if par else ""
    reasons = [
        f"priority rank {rank}",
        f"score={node.priority_score:.4f}",
        f"{node.node_type} @ depth={node.depth}",
    ]
    if parent_status == "dead_end":
        reasons.append("parent is dead_end; lower value unless new angle exists")
    elif parent_status == "confirmed":
        reasons.append("parent confirmed; chain continuation is valuable")

    cand = {
        "rank": rank,
        "node_id": str(node.node_id),
        "node_type": node.node_type,
        "depth": node.depth,
        "summary": (node.summary or "")[:160],
        "endpoint": node.endpoint or "",
        "parent_id": str(node.parent_id)[:8] if node.parent_id else None,
        "parent_status": parent_status,
        "reason": " · ".join(reasons),
        **node_queue_summary(node),
    }
    if vuln_slot_hints and node.endpoint and node.node_type in ("endpoint", "vuln", "exploit_step"):
        try:
            cand["slot_hints"] = vuln_slot_hints(sr, node.endpoint)
        except Exception:
            pass
    return cand


def _parse_jsonish(value, default):
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return json.loads(value)
        except Exception:
            return default
    return default


def _parse_bool(value, default=True):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in {"0", "false", "no", "off"}
    return bool(value)


def cmd_scan_next(p):
    """Priority frontier driver: show the best pending nodes and required actions."""
    sr = ScanRun.objects.get(run_id=p["scan_run_id"])

    # Check if any node is currently "exploring" (in-progress)
    exploring = DiscoveryNode.objects.filter(scan_run=sr, status="exploring").first()
    if exploring:
        actions = _REQUIRED_ACTIONS.get(exploring.node_type, {})
        _json_out({
            "action": "RESUME",
            "message": f"Node {str(exploring.node_id)[:8]} is still 'exploring'. Finish it first.",
            "node_id": str(exploring.node_id),
            "node_type": exploring.node_type,
            "depth": exploring.depth,
            "summary": exploring.summary,
            **node_queue_summary(exploring),
            "mission_packet": _mission_packet(sr, exploring, actions),
            "required_work": actions.get("work", []),
            "required_finalize": actions.get("finalize", []),
        })
        return

    # 후보 여러 개를 보여주고 LLM이 직접 선택하게 한다 (자율성 우선).
    # BFS 정석은 0번 후보(recommend); 그러나 LLM이 다른 후보가 더 가치있다고
    # 판단하면 그쪽으로 가도 OK. 강제는 안전망에만.
    pending_qs = DiscoveryNode.objects.filter(
        scan_run=sr, status="pending"
    ).order_by("-priority_score", "-depth", "created_at")
    pending_list = list(pending_qs[:8])
    pending = pending_list[0] if pending_list else None

    if not pending:
        total = DiscoveryNode.objects.filter(scan_run=sr).count()
        by_status = {}
        for n in DiscoveryNode.objects.filter(scan_run=sr):
            by_status[n.status] = by_status.get(n.status, 0) + 1

        # If only root exists, initial recon hasn't been done yet
        if total <= 1:
            root = DiscoveryNode.objects.filter(scan_run=sr, depth=0).first()
            actions = _REQUIRED_ACTIONS.get("target", {})
            _json_out({
                "action": "INIT_RECON",
                "message": "Root exists but no endpoints pushed yet. Do initial recon on the target and push_discovery for all discovered endpoints.",
                "root_id": str(root.node_id) if root else None,
                "target_url": sr.target_url,
                "step_1_work": actions.get("work", []),
                "step_2_finalize": ["Push all endpoints as pending nodes, then call scan_next again."],
                "reminder": "R3: Push generously. R8: Each endpoint needs push_discovery + analyze_endpoint + create_candidate_manual.",
            })
            return

        findings = Finding.objects.filter(scan_run=sr).count()
        _json_out({
            "action": "COMPLETE",
            "message": "Queue empty. Run scan_selfcheck then complete_scan.",
            "total_nodes": total,
            "by_status": by_status,
            "findings": findings,
        })
        return

    # Pick this node — show what to do
    actions = _REQUIRED_ACTIONS.get(pending.node_type, {})
    siblings = DiscoveryNode.objects.filter(
        scan_run=sr, parent=pending.parent, status="pending"
    ).count()

    # 후보 N개 — 0번이 BFS 정석(recommend). LLM이 직접 보고 다른 걸 골라도 됨.
    # slot_hints: endpoint 가 있는 후보에 한해 "이미 시도된 vuln_type /
    # 아직 안 해본 vuln_type / 과거 scan 에서 dead_end 였던 vuln_type" 을
    # 첨부 → sub-agent 가 동일 endpoint 에 중복 hypothesis 만드는 것 방지.
    try:
        from watchdog_mcp.tools_discovery import _vuln_slot_hints
    except Exception:
        _vuln_slot_hints = None

    candidates = []
    for idx, n in enumerate(pending_list):
        parent_status = ""
        if n.parent_id:
            par = DiscoveryNode.objects.filter(node_id=n.parent_id).only("status").first()
            parent_status = par.status if par else ""
        reasons = [f"BFS rank {idx}", f"{n.node_type} @ depth={n.depth}"]
        if parent_status == "dead_end":
            reasons.append("(parent is dead_end — 가치 낮을 수 있음)")
        elif parent_status == "confirmed":
            reasons.append("(parent confirmed — chain 후속, 가치 높음)")
        cand = {
            "rank": idx,
            "node_id": str(n.node_id),
            "node_type": n.node_type,
            "depth": n.depth,
            "summary": (n.summary or "")[:160],
            "endpoint": n.endpoint or "",
            "parent_id": str(n.parent_id)[:8] if n.parent_id else None,
            "parent_status": parent_status,
            "reason": " · ".join(reasons),
        }
        if _vuln_slot_hints and n.endpoint and n.node_type in ("endpoint", "vuln", "exploit_step"):
            try:
                cand["slot_hints"] = _vuln_slot_hints(sr, n.endpoint)
            except Exception:
                pass
        candidates.append(cand)

    candidates = [
        _candidate_packet(sr, n, idx, _vuln_slot_hints)
        for idx, n in enumerate(pending_list)
    ]

    _json_out({
        "action": "EXPLORE",
        "scheduler_message": (
            f"{len(candidates)} candidates; rank 0 is the priority-frontier recommendation. "
            "Pick another only when chain context is clearly more valuable."
        ),
        "message": (
            f"{len(candidates)}개 후보 — 0번이 BFS 추천. 다른 후보가 더 가치 있다고 "
            f"판단하면 자유롭게 그것을 선택. 선택 후 update_node_status(exploring) 먼저."
        ),
        "candidates": candidates,
        "recommend": 0,
        # ── backward-compat: 0번 후보의 필드를 top-level에도 노출 ──
        "node_id": str(pending.node_id),
        "node_type": pending.node_type,
        "depth": pending.depth,
        "summary": pending.summary,
        "parent_id": str(pending.parent_id)[:8] if pending.parent_id else None,
        "scheduler": "priority_frontier",
        **node_queue_summary(pending),
        "mission_packet": _mission_packet(
            sr,
            pending,
            actions,
            candidates[0].get("slot_hints") if candidates else None,
        ),
        "pending_siblings": siblings - 1,
        "step_1_init": actions.get("init", []),
        "step_2_work": actions.get("work", []),
        "step_3_finalize": actions.get("finalize", []),
        "reminder": (
            "Call update_node_status(exploring) FIRST, then do the work, then finalize. "
            "If a candidate has slot_hints, prefer an untested_common_vuln_types value over "
            "anything in existing_vuln_types_here; avoid prior_dead_end_vuln_types unless "
            "you have a new payload angle."
        ),
    })


def cmd_lease_node(p):
    """Atomically lease one DiscoveryNode for a subscription/API worker."""
    sr = ScanRun.objects.get(run_id=p["scan_run_id"])
    worker_kind = (p.get("worker_kind") or p.get("provider") or "external").strip().lower()
    worker_id = p.get("worker_id") or f"{worker_kind}-{os.getpid()}"

    node = pick_next_node(str(sr.run_id), worker_id)
    if node is None:
        pending = DiscoveryNode.objects.filter(scan_run=sr, status="pending").count()
        exploring = DiscoveryNode.objects.filter(scan_run=sr, status="exploring").count()
        action = "WAIT" if pending or exploring else "COMPLETE"
        _json_out({
            "action": action,
            "scan_run_id": str(sr.run_id),
            "target_url": sr.target_url,
            "pending": pending,
            "exploring": exploring,
            "message": "No node leased. Wait for active leases or run scan_selfcheck/complete_scan.",
        })
        return

    actions = _REQUIRED_ACTIONS.get(node.node_type, {})
    slot_hints = None
    try:
        from watchdog_mcp.tools_discovery import _vuln_slot_hints
        if node.endpoint and node.node_type in ("endpoint", "vuln", "exploit_step"):
            slot_hints = _vuln_slot_hints(sr, node.endpoint)
    except Exception:
        slot_hints = None

    mission = _mission_packet(sr, node, actions, slot_hints)
    mission["worker_kind"] = worker_kind
    mission["worker_id"] = worker_id
    mission["finalize_contract"] = [
        "record_trace with a non-empty tool_calls array",
        "update_node_status to explored, confirmed, or dead_end",
        "store_secret immediately for reusable secrets",
    ]

    _json_out({
        "action": "LEASED",
        "worker_id": worker_id,
        "leased_node": str(node.node_id),
        "lease_owner": node.lease_owner,
        "leased_until": node.leased_until,
        **node_queue_summary(node),
        "mission_packet": mission,
    })


def _work_mission_with_actions(work):
    packet = build_work_mission_packet(work)
    node = work.node
    actions = _REQUIRED_ACTIONS.get(node.node_type if node else "", {})
    packet["required_init"] = actions.get("init", [])
    packet["required_work"] = actions.get("work", [])
    packet["required_finalize"] = actions.get("finalize", [])
    return packet


def cmd_enqueue_work(p):
    """Create a WorkItem for a node/candidate/artifact."""
    sr = ScanRun.objects.get(run_id=p["scan_run_id"])
    node = None
    candidate = None
    if p.get("node_id"):
        node = DiscoveryNode.objects.get(node_id=p["node_id"], scan_run=sr)
    if p.get("cand_id") or p.get("candidate_id"):
        candidate = Candidate.objects.get(cand_id=p.get("cand_id") or p.get("candidate_id"), scan_run=sr)

    context = _parse_jsonish(p.get("context", p.get("context_json")), {})
    work = enqueue_work_item(
        sr,
        work_type=p.get("work_type", "hypothesis_test"),
        node=node,
        candidate=candidate,
        objective=p.get("objective", ""),
        context=context,
        priority_score=p.get("priority_score") if p.get("priority_score") not in ("", None) else None,
        provider_hint=p.get("provider_hint", ""),
    )
    _json_out({
        "action": "ENQUEUED",
        **build_work_mission_packet(work),
    })


def cmd_lease_work(p):
    """Atomically lease one WorkItem for a subscription/API worker."""
    sr = ScanRun.objects.get(run_id=p["scan_run_id"])
    worker_kind = (p.get("worker_kind") or p.get("provider") or "external").strip().lower()
    worker_id = p.get("worker_id") or f"{worker_kind}-{os.getpid()}"
    work = lease_next_work_item(
        str(sr.run_id),
        worker_id,
        worker_kind=worker_kind,
        queue_lane=p.get("queue_lane", ""),
        work_type=p.get("work_type", ""),
    )
    if work is None:
        pending = WorkItem.objects.filter(scan_run=sr, status="pending").count()
        leased = WorkItem.objects.filter(scan_run=sr, status="leased").count()
        blocked = WorkItem.objects.filter(scan_run=sr, status="blocked").count()
        _json_out({
            "action": "WAIT" if pending or leased else "COMPLETE",
            "scan_run_id": str(sr.run_id),
            "target_url": sr.target_url,
            "pending": pending,
            "leased": leased,
            "blocked": blocked,
            "message": "No work item leased. Wait, unblock prerequisites, or run scan_selfcheck/complete_scan.",
        })
        return

    _json_out({
        "action": "LEASED",
        "worker_id": worker_id,
        "leased_work": str(work.work_id),
        "mission_packet": _work_mission_with_actions(work),
    })


def cmd_complete_work(p):
    result = _parse_jsonish(p.get("result", p.get("result_json")), {})
    work = complete_work_item(
        p["work_id"],
        result=result,
        node_status=p.get("node_status", ""),
    )
    _json_out({
        "action": "COMPLETED",
        "work_id": str(work.work_id),
        "node_id": str(work.node_id) if work.node_id else "",
        "status": work.status,
        "node_status": work.node.status if work.node else "",
    })


def cmd_fail_work(p):
    work = fail_work_item(
        p["work_id"],
        error=p.get("error", p.get("reason", "")),
        retry=_parse_bool(p.get("retry"), True),
    )
    node_status = p.get("node_status", "")
    if work.node and node_status in {"explored", "dead_end", "confirmed"}:
        work.node.status = node_status
        work.node.lease_owner = None
        work.node.leased_until = None
        work.node.explored_at = timezone.now()
        work.node.save(update_fields=["status", "lease_owner", "leased_until", "explored_at"])
    _json_out({
        "action": "RETRY" if work.status == "pending" else "FAILED",
        "work_id": str(work.work_id),
        "status": work.status,
        "node_status": work.node.status if work.node else "",
        "attempt_count": work.attempt_count,
        "max_attempts": work.max_attempts,
        "last_error": work.last_error,
        "warning": "" if node_status or work.status == "pending" else "node_status not changed; finalize the DiscoveryNode separately",
    })


def cmd_block_work(p):
    preconditions = _parse_jsonish(p.get("preconditions"), [])
    if isinstance(preconditions, str):
        preconditions = [preconditions]
    work = block_work_item(
        p["work_id"],
        preconditions=preconditions,
        error=p.get("error", p.get("reason", "")),
    )
    _json_out({
        "action": "BLOCKED",
        "work_id": str(work.work_id),
        "status": work.status,
        "preconditions": work.preconditions,
    })


def cmd_unblock_work(p):
    work = unblock_work_item(p["work_id"], note=p.get("note", "preconditions satisfied"))
    _json_out({
        "action": "UNBLOCKED",
        "work_id": str(work.work_id),
        "status": work.status,
        "preconditions": work.preconditions,
    })


def cmd_list_work(p):
    qs = WorkItem.objects.filter(scan_run_id=p["scan_run_id"])
    if p.get("status"):
        qs = qs.filter(status=p["status"])
    if p.get("work_type"):
        qs = qs.filter(work_type=p["work_type"])
    if p.get("queue_lane"):
        qs = qs.filter(queue_lane=p["queue_lane"])
    limit = int(p.get("limit", 30))
    items = []
    for work in qs.select_related("node").order_by("-priority_score", "created_at")[:limit]:
        items.append({
            "work_id": str(work.work_id),
            "work_type": work.work_type,
            "status": work.status,
            "queue_lane": work.queue_lane,
            "priority_score": work.priority_score,
            "provider_hint": work.provider_hint,
            "node_id": str(work.node_id)[:8] if work.node_id else "",
            "node_type": work.node.node_type if work.node else "",
            "endpoint": work.node.endpoint if work.node else "",
            "objective": work.objective[:180],
            "attempt_count": work.attempt_count,
            "preconditions": work.preconditions,
        })
    _json_out({"count": len(items), "work_items": items})


def _resolve_exchange_scope(p):
    sr = None
    work = None
    node = None

    if p.get("work_id"):
        work = WorkItem.objects.select_related("scan_run", "node").get(work_id=p["work_id"])
        sr = work.scan_run
        node = work.node

    if p.get("node_id") and node is None:
        node = DiscoveryNode.objects.select_related("scan_run").get(node_id=p["node_id"])
        sr = sr or node.scan_run

    if p.get("scan_run_id"):
        scan_run_id = p["scan_run_id"]
        if sr and str(sr.run_id) != str(scan_run_id):
            raise ValueError("scan_run_id does not match work_id/node_id")
        sr = ScanRun.objects.get(run_id=scan_run_id)

    if sr is None:
        raise ValueError("scan_run_id, work_id, or node_id is required")

    return sr, work, node


def _opposite_provider(provider):
    provider = (provider or "").strip().lower()
    if provider == "claude":
        return "codex"
    if provider == "codex":
        return "claude"
    return ""


def cmd_add_agent_exchange(p):
    """Append a structured claim/evidence/counterargument/handoff to a WorkItem."""
    try:
        sr, work, node = _resolve_exchange_scope(p)
    except Exception as e:
        _json_out({"error": str(e)})
        return

    parent_exchange = None
    if p.get("parent_exchange_id"):
        parent_exchange = AgentExchange.objects.get(exchange_id=p["parent_exchange_id"], scan_run=sr)

    evidence_refs = _parse_jsonish(p.get("evidence_refs"), [])
    metadata = _parse_jsonish(p.get("metadata", p.get("metadata_json")), {})
    exchange = add_agent_exchange(
        scan_run=sr,
        work=work,
        node=node,
        parent_exchange=parent_exchange,
        agent_name=p.get("agent_name") or p.get("worker_id", ""),
        provider=p.get("provider", "unknown"),
        message_type=p.get("message_type", "handoff"),
        stance=p.get("stance", "neutral"),
        content=p["content"],
        confidence=p.get("confidence", 0.0),
        evidence_refs=evidence_refs,
        requested_action=p.get("requested_action", ""),
        resolution_status=p.get("resolution_status", "open"),
        metadata=metadata,
    )

    result = {
        "action": "ADDED",
        "scan_run_id": str(sr.run_id),
        "work_id": str(work.work_id) if work else "",
        "node_id": str(node.node_id) if node else "",
        "exchange": exchange_summary(exchange),
    }

    if _parse_bool(p.get("enqueue_recheck"), False):
        context = {
            "source_exchange_id": str(exchange.exchange_id),
            "requested_by_provider": exchange.provider,
            "claim": exchange.content[:1200],
            "technique": f"exchange:{exchange.exchange_id}",
        }
        recheck = enqueue_work_item(
            sr,
            work_type="recheck",
            node=node,
            objective=p.get("recheck_objective") or f"Recheck {exchange.provider} exchange: {exchange.content[:180]}",
            context=context,
            provider_hint=p.get("recheck_provider_hint") or _opposite_provider(exchange.provider),
        )
        result["recheck_work_id"] = str(recheck.work_id)
        result["recheck_provider_hint"] = recheck.provider_hint

    _json_out(result)


def cmd_list_agent_exchanges(p):
    try:
        sr, work, node = _resolve_exchange_scope(p)
    except Exception as e:
        _json_out({"error": str(e)})
        return

    if work:
        exchanges = summarize_work_exchanges(work, limit=int(p.get("limit", 30)))
    else:
        qs = AgentExchange.objects.filter(scan_run=sr)
        if node:
            qs = qs.filter(node=node)
        if p.get("provider"):
            qs = qs.filter(provider=p["provider"])
        if p.get("message_type"):
            qs = qs.filter(message_type=p["message_type"])
        if p.get("resolution_status"):
            qs = qs.filter(resolution_status=p["resolution_status"])
        limit = int(p.get("limit", 30))
        recent = qs.select_related("work", "node", "parent_exchange").order_by("-created_at")[:limit]
        exchanges = [exchange_summary(exchange) for exchange in reversed(list(recent))]

    _json_out({
        "scan_run_id": str(sr.run_id),
        "work_id": str(work.work_id) if work else "",
        "node_id": str(node.node_id) if node else "",
        "count": len(exchanges),
        "exchanges": exchanges,
    })


def cmd_resolve_agent_exchange(p):
    exchange = AgentExchange.objects.get(exchange_id=p["exchange_id"])
    status = p.get("resolution_status", "resolved")
    if status not in {"open", "resolved", "superseded"}:
        _json_out({"error": "resolution_status must be open, resolved, or superseded"})
        return
    metadata = dict(exchange.metadata or {})
    if p.get("note"):
        metadata.setdefault("resolution_notes", []).append({
            "note": p["note"],
            "ts": str(timezone.now()),
        })
    exchange.resolution_status = status
    exchange.metadata = metadata
    exchange.save(update_fields=["resolution_status", "metadata"])
    _json_out({"action": "RESOLVED", "exchange": exchange_summary(exchange)})


def cmd_validate_node(p):
    """Validate a node has all required tool calls before finalize."""
    node = DiscoveryNode.objects.get(node_id=p["node_id"])
    sr = node.scan_run
    ntype = node.node_type
    errors = []
    warnings = []

    # 1. Node must not be 'pending' — should be at least 'exploring'
    if node.status == "pending":
        errors.append("Node is still 'pending'. Call update_node_status(exploring) first.")

    # 2. Check children exist (target/endpoint should have pushed children)
    children = DiscoveryNode.objects.filter(scan_run=sr, parent=node).count()

    if ntype == "target" and children == 0:
        errors.append("R8: target node has 0 children. Must push_discovery for discovered endpoints.")

    if ntype == "endpoint":
        vuln_children = DiscoveryNode.objects.filter(
            scan_run=sr, parent=node, node_type="vuln"
        ).count()
        if vuln_children == 0 and node.status != "dead_end":
            warnings.append("Endpoint has 0 vuln children. If no suspects, use mark_dead_end.")

    # 3. Check candidates exist for endpoint nodes (R8)
    if ntype == "endpoint":
        endpoint_str = node.endpoint or (node.context or {}).get("endpoint", "")
        if not endpoint_str:
            import re as _re
            m = _re.search(r'((?:GET|POST|PUT|DELETE|PATCH)\s+)?(/\S+)', node.summary)
            endpoint_str = m.group(2) if m else node.summary[:60]
        cands = Candidate.objects.filter(scan_run=sr, features__endpoint__icontains=endpoint_str[:30]).count()
        analyzed = RequestCatalog.objects.filter(scan_run=sr, endpoint__icontains=endpoint_str[:30]).count()
        if analyzed == 0:
            errors.append("R8: No analyze_endpoint found for this endpoint.")
        if cands == 0 and node.status != "dead_end":
            warnings.append("R8: No create_candidate_manual for this endpoint.")

    # 4. Check findings for confirmed vuln nodes (R9)
    if ntype == "vuln" and node.status == "confirmed":
        findings = Finding.objects.filter(scan_run=sr).count()
        if findings == 0:
            errors.append("R9: Node is confirmed but no findings exist.")

    # 5. Check dead_end has learn_dead_end (R4)
    if node.status == "dead_end":
        target_host = sr.target_url.split("//")[-1].rstrip("/") if sr.target_url else ""
        dead_ends = DeadEnd.objects.filter(target_host__icontains=target_host[:20]).count()
        if dead_ends == 0:
            warnings.append("R4: No learn_dead_end recorded for this target.")

    # 6. Check record_trace exists (R7)
    traces = LLMTrace.objects.filter(scan_run=sr).count()
    if traces == 0:
        errors.append("R7: No record_trace found for this scan.")

    # 7. Check secrets stored (R6) — only warn
    secrets_count = len((sr.config or {}).get("_secrets", {}))

    passed = len(errors) == 0
    _json_out({
        "node_id": str(node.node_id)[:8],
        "node_type": ntype,
        "status": node.status,
        "children": children,
        "passed": passed,
        "errors": errors,
        "warnings": warnings,
        "stats": {
            "children": children,
            "traces": traces,
            "secrets": secrets_count,
        },
        "verdict": "✅ OK to finalize" if passed else "❌ FIX ERRORS before finalize",
    })


def cmd_scan_selfcheck(p):
    """Pre-complete_scan validation. Checks all rules are satisfied."""
    sr = ScanRun.objects.get(run_id=p["scan_run_id"])
    errors = []
    warnings = []

    all_nodes = list(DiscoveryNode.objects.filter(scan_run=sr))
    target_url = sr.target_url or ""
    target_host = target_url.split("//")[-1].rstrip("/") if target_url else ""

    # 1. No pending nodes
    pending = [n for n in all_nodes if n.status == "pending"]
    if pending:
        errors.append(f"PENDING nodes remain: {len(pending)} nodes. Explore or mark_dead_end them all.")
        for n in pending[:5]:
            errors.append(f"  - {str(n.node_id)[:8]} d{n.depth} {n.node_type} | {n.summary[:60]}")

    # 2. No exploring nodes (stuck)
    exploring = [n for n in all_nodes if n.status == "exploring"]
    if exploring:
        errors.append(f"EXPLORING nodes stuck: {len(exploring)} nodes. Finalize them.")
        for n in exploring[:5]:
            errors.append(f"  - {str(n.node_id)[:8]} d{n.depth} {n.node_type} | {n.summary[:60]}")

    # 3. Endpoint count check
    endpoints = [n for n in all_nodes if n.node_type == "endpoint"]
    if len(endpoints) < 3:
        warnings.append(f"Only {len(endpoints)} endpoint nodes. Did you push all discovered endpoints? (R3: push generously)")

    # 4. Dead-end count check (should have some if testing was thorough)
    dead_ends = [n for n in all_nodes if n.status == "dead_end"]
    if len(dead_ends) == 0:
        warnings.append("0 dead_end nodes. Were all attack attempts successful? If not, mark failures as dead_end. (R4)")

    # 5. Findings check
    findings = Finding.objects.filter(scan_run=sr)
    confirmed_nodes = [n for n in all_nodes if n.status == "confirmed"]
    if confirmed_nodes and findings.count() == 0:
        errors.append("Confirmed nodes exist but 0 findings. Call create_finding for each. (R9)")

    # 6. R8: analyze_endpoint coverage
    analyzed = set(RequestCatalog.objects.filter(scan_run=sr).values_list("endpoint", flat=True))
    ep_summaries = [n.summary for n in endpoints]
    if endpoints and len(analyzed) == 0:
        errors.append("R8: 0 analyze_endpoint calls found. Must analyze each endpoint.")

    # 7. R10: record_pattern_use check
    # Can't easily check without pattern-level tracking, so just check if any patterns were recorded
    patterns_used = PayloadPattern.objects.filter(
        target_host__icontains=target_host[:20],
    ).count() if target_host else 0

    # 8. R7: record_trace check
    traces = LLMTrace.objects.filter(scan_run=sr).count()
    if traces == 0:
        errors.append("R7: 0 record_trace calls. Must record at least one per stage.")

    # 9. Secrets check
    secrets = (sr.config or {}).get("_secrets", {})

    # 10. Candidates check
    cands = Candidate.objects.filter(scan_run=sr)
    open_cands = cands.filter(status="open").count()
    if open_cands > 0:
        warnings.append(f"{open_cands} candidates still 'open'. Confirm or dismiss them all.")

    work_items = WorkItem.objects.filter(scan_run=sr)
    pending_work = work_items.filter(status="pending").count()
    leased_work = work_items.filter(status="leased").count()
    blocked_work = work_items.filter(status="blocked").count()
    if pending_work > 0:
        warnings.append(f"{pending_work} WorkItems still pending. Lease or cancel them before complete_scan.")
    if leased_work > 0:
        warnings.append(f"{leased_work} WorkItems still leased. Complete/fail them or wait for stale recovery.")
    if blocked_work > 0:
        warnings.append(f"{blocked_work} WorkItems blocked on prerequisites.")

    # 11. learn_dead_end check
    learned_de = DeadEnd.objects.filter(target_host__icontains=target_host[:20]).count() if target_host else 0
    if dead_ends and learned_de == 0:
        errors.append("R4: dead_end nodes exist but no learn_dead_end recorded.")

    # 12. Notes check
    notes = (sr.config or {}).get("_notes", [])

    passed = len(errors) == 0

    by_status = {}
    by_type = {}
    for n in all_nodes:
        by_status[n.status] = by_status.get(n.status, 0) + 1
        by_type[n.node_type] = by_type.get(n.node_type, 0) + 1

    _json_out({
        "passed": passed,
        "verdict": "✅ Ready for complete_scan" if passed else "❌ FIX ERRORS before complete_scan",
        "errors": errors,
        "warnings": warnings,
        "stats": {
            "total_nodes": len(all_nodes),
            "by_status": by_status,
            "by_type": by_type,
            "findings": findings.count(),
            "candidates": cands.count(),
            "open_candidates": open_cands,
            "work_items": work_items.count(),
            "work_pending": pending_work,
            "work_leased": leased_work,
            "work_blocked": blocked_work,
            "traces": traces,
            "secrets": len(secrets),
            "notes": len(notes),
            "dead_ends_learned": learned_de,
            "endpoints_analyzed": len(analyzed),
        },
    })


# ═══════════════════════════════════════════════════════
# Tool registry
# ═══════════════════════════════════════════════════════

TOOLS = {
    # KB
    "search_knowledge":       cmd_search_knowledge,
    "retrieve_similar":       cmd_retrieve_similar,
    "mutate_payload":         cmd_mutate_payload,
    "retrieve_cve_variants":  cmd_retrieve_cve_variants,
    "record_pattern_use":     cmd_record_pattern_use,
    # Living KB
    "recall_target":          cmd_recall_target,
    "recall_dead_ends":       cmd_recall_dead_ends,
    "learn_from_finding":     cmd_learn_from_finding,
    "learn_dead_end":         cmd_learn_dead_end,
    "update_target_profile":  cmd_update_target_profile,
    # Source
    "list_source_tree":       cmd_list_source_tree,
    "read_source":            cmd_read_source,
    "grep_source":            cmd_grep_source,
    # Discovery
    "push_discovery":         cmd_push_discovery,
    "update_node_status":     cmd_update_node_status,
    "get_chain_context":      cmd_get_chain_context,
    "mark_dead_end":          cmd_mark_dead_end,
    "get_siblings":           cmd_get_siblings,
    "get_exploit_chains":     cmd_get_exploit_chains,
    "store_secret":           cmd_store_secret,
    "get_secrets":            cmd_get_secrets,
    "add_scan_note":          cmd_add_scan_note,
    "get_scan_notes":         cmd_get_scan_notes,
    # Scan management
    "create_scan":            cmd_create_scan,
    "create_root":            cmd_create_root,
    "create_finding":         cmd_create_finding,
    "complete_scan":          cmd_complete_scan,
    "stop_scan":              cmd_stop_scan,
    "fail_scan":              cmd_fail_scan,
    "list_nodes":             cmd_list_nodes,
    # HTTP
    "http_request":           cmd_http_request,
    # Oracle
    "oracle_response_diff":   cmd_oracle_response_diff,
    "oracle_sqli_boolean":    cmd_oracle_sqli_boolean,
    "oracle_sqli_time":       cmd_oracle_sqli_time,
    "oracle_lfi":             cmd_oracle_lfi,
    "oracle_ssrf":            cmd_oracle_ssrf,
    # Storage
    "confirm_finding":        cmd_confirm_candidate,
    "dismiss_candidate":      cmd_dismiss_candidate,
    "save_evidence":          cmd_save_evidence,
    "get_finding":            cmd_get_finding_detail,
    "get_scan_summary":       cmd_get_scan_summary,
    # Analysis
    "analyze_endpoint":       cmd_analyze_endpoint,
    "list_candidates":        cmd_list_candidates,
    "create_candidate_manual": cmd_create_candidate_manual,
    # OOB
    "oob_register_token":     cmd_oob_register_token,
    "oob_get_hits":           cmd_oob_get_hits,
    "oob_clear_hits":         cmd_oob_clear_hits,
    "oob_wait_for_hit":       cmd_oob_wait_for_hit,
    # LLM Trace
    "record_trace":           cmd_record_trace,
    # Export
    "export_learned":         cmd_export_learned,
    # Orchestration
    "scan_next":              cmd_scan_next,
    "lease_node":             cmd_lease_node,
    "enqueue_work":           cmd_enqueue_work,
    "lease_work":             cmd_lease_work,
    "complete_work":          cmd_complete_work,
    "fail_work":              cmd_fail_work,
    "block_work":             cmd_block_work,
    "unblock_work":           cmd_unblock_work,
    "list_work":              cmd_list_work,
    "add_agent_exchange":     cmd_add_agent_exchange,
    "list_agent_exchanges":   cmd_list_agent_exchanges,
    "resolve_agent_exchange": cmd_resolve_agent_exchange,
    "validate_node":          cmd_validate_node,
    "scan_selfcheck":         cmd_scan_selfcheck,
}


def cmd_list_tools(_):
    _json_out({
        "tools": sorted(TOOLS.keys()),
        "usage": "echo '{...}' | python watchdog_cli.py <tool_name>",
    })


_TRACE_SKIP_TOOLS = frozenset({
    "record_trace", "scan_next", "lease_node", "lease_work", "list_work",
    "list_agent_exchanges", "scan_selfcheck", "list_tools", "export_learned",
    "validate_node",
})


def _resolve_trace_node(scan_run, params):
    """Pick the most relevant DiscoveryNode from a tool's params for trace FK."""
    if not isinstance(params, dict):
        return None
    # Priority order: explicit target_node_id > current_node_id > node_id > parent_node_id.
    # parent_node_id is last because tools that push a child node usually care
    # about their own current node, not the parent they were rooted under.
    for key in ("target_node_id", "current_node_id", "node_id", "parent_node_id"):
        raw = params.get(key)
        if not raw:
            continue
        try:
            return DiscoveryNode.objects.filter(scan_run=scan_run, node_id=raw).first()
        except Exception:
            continue
    return None


def _auto_record_trace(scan_run_id, tool_name, params):
    """Silently record an LLM trace entry for the tool call."""
    try:
        run = ScanRun.objects.get(run_id=scan_run_id)
        latest_idx = LLMTrace.objects.filter(scan_run=run).count()
        target_node = _resolve_trace_node(run, params)
        _record_llm_trace(
            scan_run=run,
            call_index=latest_idx + 1,
            stage="cli_auto",
            model="cursor-cli",
            prompt_preview=json.dumps(params, default=str)[:3000],
            response_preview="",
            tool_calls=[{"tool": tool_name, "params": params}],
            stop_reason="tool_use",
            input_tokens=0,
            output_tokens=0,
            target_node=target_node,
        )
    except Exception:
        pass


def main():
    if len(sys.argv) < 2:
        print("Usage: echo '{...}' | python watchdog_cli.py <tool_name>")
        print("       python watchdog_cli.py list_tools")
        sys.exit(1)

    tool_name = sys.argv[1]

    if tool_name == "list_tools":
        cmd_list_tools({})
        return

    if tool_name not in TOOLS:
        print(f"Unknown tool: {tool_name}")
        print(f"Available: {', '.join(sorted(TOOLS.keys()))}")
        sys.exit(1)

    stdin_data = sys.stdin.read().strip()
    if stdin_data:
        try:
            params = json.loads(stdin_data)
        except json.JSONDecodeError as e:
            print(f"Invalid JSON: {e}")
            sys.exit(1)
    else:
        params = {}

    TOOLS[tool_name](params)

    scan_run_id = params.get("scan_run_id")
    if scan_run_id and tool_name not in _TRACE_SKIP_TOOLS:
        _auto_record_trace(scan_run_id, tool_name, params)


if __name__ == "__main__":
    main()
