"""Discovery Queue MCP tools — push/pick/chain/dead_end/siblings.

Multi-agent safe: DB-level row locking via select_for_update(skip_locked).
"""

from __future__ import annotations

import json
import logging

from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

import os
from datetime import timedelta

DISCOVERY_MAX_DEPTH = 15
DISCOVERY_MAX_NODES = 200
DISCOVERY_STALE_S = int(os.environ.get("WATCHDOG_DISCOVERY_STALE_S", "300"))


def register(mcp):
    from api.models import DiscoveryNode, DeadEnd, TargetProfile

    @mcp.tool()
    def push_discovery(
        scan_run_id: str,
        parent_node_id: str = "",
        node_type: str = "clue",
        summary: str = "",
        context_json: str = "{}",
        endpoint: str = "",
        vuln_type: str = "",
    ) -> str:
        """Create a child DiscoveryNode and enqueue it for exploration.

        Args:
            scan_run_id: current scan run UUID
            parent_node_id: UUID of the parent node (empty for root)
            node_type: target | endpoint | vuln | clue | exploit_step | flag | dead_end
            summary: human-readable description of the discovery
            context_json: JSON dict with detailed context (tokens, URLs, response snippets)
            endpoint: the API endpoint this relates to (optional)
            vuln_type: canonical vuln_type if applicable (optional)

        Returns:
            JSON with the created node_id, depth, and queue position.
        """
        from api.models import ScanRun

        try:
            ctx = json.loads(context_json) if context_json else {}
        except (json.JSONDecodeError, TypeError):
            ctx = {"raw": context_json}

        parent = None
        depth = 0
        if parent_node_id:
            try:
                parent = DiscoveryNode.objects.get(node_id=parent_node_id)
                depth = parent.depth + 1
            except DiscoveryNode.DoesNotExist:
                return json.dumps({"error": f"parent node {parent_node_id} not found"})

        if depth > DISCOVERY_MAX_DEPTH:
            return json.dumps({
                "error": f"max depth {DISCOVERY_MAX_DEPTH} reached",
                "depth": depth,
            })

        existing_count = DiscoveryNode.objects.filter(scan_run_id=scan_run_id).count()
        if existing_count >= DISCOVERY_MAX_NODES:
            return json.dumps({
                "error": f"max nodes {DISCOVERY_MAX_NODES} reached",
                "total_nodes": existing_count,
            })

        # 안전망 — 같은 scan 에 (endpoint, vuln_type, node_type) 조합이 이미 있으면
        # 새로 만들지 않고 기존 노드 반환. worker race 또는 LLM 의 중복 push 방지.
        # endpoint 없는 clue/flag 등은 dedup 안 함 (의미가 다를 수 있음).
        # trailing-slash 변형 허용.
        if endpoint and node_type in ("endpoint", "vuln", "exploit_step"):
            ep_norm = endpoint.split("?", 1)[0].rstrip("/") or "/"
            ep_variants = [endpoint, ep_norm, ep_norm + "/"]
            existing = (
                DiscoveryNode.objects
                .filter(scan_run_id=scan_run_id, node_type=node_type)
                .filter(endpoint__in=ep_variants)
                .filter(vuln_type=vuln_type or "")
                .order_by("created_at")
                .first()
            )
            if existing:
                return json.dumps({
                    "node_id": str(existing.node_id),
                    "depth": existing.depth,
                    "node_type": existing.node_type,
                    "deduped": True,
                    "deduped_reason": "same scan+endpoint+vuln_type+node_type already exists",
                    "queue_pending": DiscoveryNode.objects.filter(
                        scan_run_id=scan_run_id, status="pending",
                    ).count(),
                })

        node = DiscoveryNode.objects.create(
            scan_run_id=scan_run_id,
            parent=parent,
            depth=depth,
            node_type=node_type,
            endpoint=endpoint or (parent.endpoint if parent else ""),
            vuln_type=vuln_type,
            summary=summary,
            context=ctx,
            status="pending",
        )

        cand_id = None
        if node_type in ("vuln", "exploit_step", "clue"):
            cand_id = _auto_create_candidate(node)

        pending_count = DiscoveryNode.objects.filter(
            scan_run_id=scan_run_id, status="pending",
        ).count()

        result = {
            "node_id": str(node.node_id),
            "depth": node.depth,
            "node_type": node.node_type,
            "queue_pending": pending_count,
        }
        if cand_id:
            result["cand_id"] = str(cand_id)
        return json.dumps(result)

    @mcp.tool()
    def get_chain_context(node_id: str) -> str:
        """Trace the full chain from a node back to root.

        Returns an ordered list (root first) of ancestor summaries and context,
        so the worker knows the full attack path that led here.
        """
        try:
            node = DiscoveryNode.objects.get(node_id=node_id)
        except DiscoveryNode.DoesNotExist:
            return json.dumps({"error": f"node {node_id} not found"})

        IMPORTANT_TYPES = {"vuln", "exploit_step", "clue", "flag"}
        chain = []
        current = node
        while current is not None:
            hops = node.depth - current.depth
            include_context = (
                hops <= 3
                or current.node_type in IMPORTANT_TYPES
            )
            entry = {
                "node_id": str(current.node_id),
                "depth": current.depth,
                "node_type": current.node_type,
                "endpoint": current.endpoint or "",
                "vuln_type": current.vuln_type or "",
                "summary": current.summary,
                "context": current.context if include_context else {},
                "status": current.status,
            }
            chain.append(entry)
            current = current.parent
        chain.reverse()

        return json.dumps({
            "chain_length": len(chain),
            "chain": chain,
        })

    @mcp.tool()
    def mark_dead_end(node_id: str, reason: str = "") -> str:
        """Mark a node as dead_end and optionally record in Living KB."""
        try:
            node = DiscoveryNode.objects.get(node_id=node_id)
        except DiscoveryNode.DoesNotExist:
            return json.dumps({"error": f"node {node_id} not found"})

        node.status = "dead_end"
        node.explored_at = timezone.now()
        node.save(update_fields=["status", "explored_at"])

        if node.endpoint and node.vuln_type:
            from urllib.parse import urlparse
            scan_run = node.scan_run
            host = urlparse(scan_run.target_url).hostname or scan_run.target_url
            DeadEnd.objects.update_or_create(
                target_host=host,
                endpoint=node.endpoint,
                vuln_type=node.vuln_type,
                pattern_id=None,
                defaults={"reason": reason or node.summary},
            )
            from django.db.models import F
            TargetProfile.objects.filter(host=host).update(
                dead_ends_count=F("dead_ends_count") + 1,
            )

        return json.dumps({"node_id": str(node.node_id), "status": "dead_end"})

    @mcp.tool()
    def get_siblings(node_id: str) -> str:
        """Get sibling nodes (same parent) to avoid duplicate exploration."""
        try:
            node = DiscoveryNode.objects.get(node_id=node_id)
        except DiscoveryNode.DoesNotExist:
            return json.dumps({"error": f"node {node_id} not found"})

        siblings = DiscoveryNode.objects.filter(
            parent=node.parent, scan_run=node.scan_run,
        ).exclude(node_id=node.node_id).values(
            "node_id", "node_type", "endpoint", "vuln_type", "summary", "status",
        )[:20]

        items = []
        for s in siblings:
            items.append({
                "node_id": str(s["node_id"]),
                "node_type": s["node_type"],
                "endpoint": s["endpoint"] or "",
                "vuln_type": s["vuln_type"] or "",
                "summary": s["summary"][:200],
                "status": s["status"],
            })

        return json.dumps({"count": len(items), "siblings": items})

    @mcp.tool()
    def get_exploit_chains(scan_run_id: str) -> str:
        """Reconstruct exploit chains by tracing parent links from terminal nodes."""
        chains = build_exploit_chains(scan_run_id)
        return json.dumps({"count": len(chains), "chains": chains})

    # ── Scan-level secrets store (cross-worker credential/token sharing) ──

    @mcp.tool()
    def store_secret(
        scan_run_id: str,
        key: str,
        value: str,
        category: str = "credential",
        obtained_via: str = "",
        source_vuln_node_id: str = "",
        auth_label: str = "",
        chain_summary: str = "",
        expires_hint: str = "",
        refresh_spec: str = "",
    ) -> str:
        """Store a discovered secret (credential, token, API key, session value,
        CSRF token, OTP, uploaded file path, etc.) for cross-worker sharing.
        Other workers exploring different nodes can retrieve these via
        get_secrets. Expirable artifacts should include `refresh_spec` so any
        worker hitting expiry can re-acquire them automatically.

        Args:
            scan_run_id: current scan run UUID
            key: descriptive key (e.g. "admin_password", "jwt_token",
                 "api_session", "csrf_token", "uploaded_shell_path")
            value: the secret value
            category: credential | token | api_key | session | csrf | otp |
                      file_path | config | other
            obtained_via: 획득 방법 short tag — "form_login" | "attack" |
                          "source_leak" | "user_provided" | "refetch_html" |
                          "oauth_refresh" | "otp_request" | "reupload" |
                          "api_key_reissue" | "" (unknown). 만료 시 빠른 분기용.
            source_vuln_node_id: obtained_via=attack 일 때, 이 secret 을 얻어낸
                                 vuln 노드 UUID. 만료 시 그 노드 replay.
            auth_label: obtained_via=form_login 일 때, 사용한 persona label
                        (auth_<label>_login_url/username/password 와 매칭).
            chain_summary: 획득 chain 한 줄 요약 (replay/디버그용).
            expires_hint: 만료 추정 (예: "1h", "30m", "per_request",
                          "until_logout"). null 가능.
            refresh_spec: **JSON string** describing how to re-acquire this
                          secret on expiry. 형식: {"kind":"<recipe>", ...params}.
                          Sub-agent 가 만료 감지 시 이 spec 을 읽어 판단 후
                          자율 재획득. 표준 recipe 예시:
                            form_login:     {"kind":"form_login","auth_label":"admin"}
                            attack_replay:  {"kind":"attack_replay",
                                             "source_vuln_node_id":"<uuid>"}
                            refetch_html:   {"kind":"refetch_html",
                                             "url":"/dashboard",
                                             "regex":"csrf_token\\s*=\\s*\"([^\"]+)"}
                            oauth_refresh:  {"kind":"oauth_refresh",
                                             "token_endpoint":"/oauth/token",
                                             "refresh_token_key":"<secret_key>"}
                            otp_request:    {"kind":"otp_request",
                                             "request_endpoint":"/auth/otp",
                                             "inbox_key":"<inbox_secret>"}
                            magic_link:     {"kind":"magic_link",
                                             "request_endpoint":"/auth/magic",
                                             "mailbox_key":"<inbox_secret>"}
                            api_key_reissue:{"kind":"api_key_reissue",
                                             "portal_url":"/settings/api",
                                             "method":"POST"}
                            reupload:       {"kind":"reupload",
                                             "upload_node_id":"<uuid>"}
                          custom recipe 도 OK — 다른 worker 가 읽고 판단.
                          Non-JSON 이면 raw string 으로 보존 (경고만).

        Returns:
            JSON with confirmation and total secrets count.
        """
        from api.models import ScanRun
        with transaction.atomic():
            run = ScanRun.objects.select_for_update().get(run_id=scan_run_id)
            config = run.config or {}
            secrets = config.get("_secrets", {})
            entry = {
                "value": value,
                "category": category,
                "stored_at": str(timezone.now()),
            }
            # 재획득용 metadata (session 만료 대응)
            if obtained_via:
                entry["obtained_via"] = obtained_via
            if source_vuln_node_id:
                entry["source_vuln_node_id"] = source_vuln_node_id
            if auth_label:
                entry["auth_label"] = auth_label
            if chain_summary:
                entry["chain_summary"] = chain_summary[:500]
            if expires_hint:
                entry["expires_hint"] = expires_hint
            if refresh_spec:
                try:
                    entry["refresh_spec"] = json.loads(refresh_spec)
                except (json.JSONDecodeError, TypeError):
                    entry["refresh_spec"] = {"kind": "raw",
                                             "raw": refresh_spec[:500]}
            secrets[key] = entry
            config["_secrets"] = secrets
            run.config = config
            run.save(update_fields=["config"])
        return json.dumps({"stored": key, "total_secrets": len(secrets),
                           "obtained_via": obtained_via or None})

    @mcp.tool()
    def get_secrets(scan_run_id: str, category: str = "") -> str:
        """Retrieve all stored secrets for the current scan. Use this to access
        credentials, tokens, or other values discovered by other workers.

        Args:
            scan_run_id: current scan run UUID
            category: optional filter by category (credential/token/api_key/session/config)

        Returns:
            JSON dict of all stored secrets.
        """
        from api.models import ScanRun
        try:
            run = ScanRun.objects.get(run_id=scan_run_id)
        except ScanRun.DoesNotExist:
            return json.dumps({"error": "scan run not found"})
        secrets = (run.config or {}).get("_secrets", {})
        if category:
            secrets = {k: v for k, v in secrets.items() if v.get("category") == category}
        return json.dumps({"count": len(secrets), "secrets": secrets})

    # ── Scan-level notes (cross-worker memos/observations) ──

    @mcp.tool()
    def add_scan_note(
        scan_run_id: str,
        topic: str,
        content: str,
        worker_id: str = "",
    ) -> str:
        """Add a note to the scan-level shared notepad. Use this for observations,
        hypotheses, architecture notes, or anything that other workers should know.
        Unlike push_discovery (which creates tree nodes), notes are flat and
        scan-global — ideal for "FYI" observations.

        Args:
            scan_run_id: current scan run UUID
            topic: short topic label (e.g. "architecture", "waf_detected", "auth_flow")
            content: the note content (keep concise, <500 chars)
            worker_id: optional worker identifier

        Returns:
            JSON with confirmation.
        """
        from api.models import ScanRun
        with transaction.atomic():
            run = ScanRun.objects.select_for_update().get(run_id=scan_run_id)
            config = run.config or {}
            notes = config.get("_notes", [])
            notes.append({
                "topic": topic,
                "content": content[:500],
                "worker_id": worker_id,
                "ts": str(timezone.now()),
            })
            if len(notes) > 50:
                notes = notes[-50:]
            config["_notes"] = notes
            run.config = config
            run.save(update_fields=["config"])
        return json.dumps({"added": topic, "total_notes": len(notes)})

    @mcp.tool()
    def get_scan_notes(scan_run_id: str, topic: str = "") -> str:
        """Retrieve scan-level notes left by all workers.

        Args:
            scan_run_id: current scan run UUID
            topic: optional topic filter

        Returns:
            JSON list of notes.
        """
        from api.models import ScanRun
        try:
            run = ScanRun.objects.get(run_id=scan_run_id)
        except ScanRun.DoesNotExist:
            return json.dumps({"error": "scan run not found"})
        notes = (run.config or {}).get("_notes", [])
        if topic:
            notes = [n for n in notes if n.get("topic") == topic]
        return json.dumps({"count": len(notes), "notes": notes})


# Module-level helper for orchestrator import
def pick_next_node(scan_run_id: str, worker_id: str):
    """Atomically pick the next pending node, or reclaim a stale exploring node."""
    from api.models import DiscoveryNode
    from django.db.models import Q

    stale_cutoff = timezone.now() - timedelta(seconds=DISCOVERY_STALE_S)

    now = timezone.now()

    with transaction.atomic():
        node = (
            DiscoveryNode.objects
            .select_for_update(skip_locked=True)
            .filter(
                Q(status="pending")
                | Q(status="exploring", explored_at__lt=stale_cutoff),
                scan_run_id=scan_run_id,
            )
            .order_by("-depth", "created_at")
            .first()
        )
        if node is None:
            return None
        node.status = "exploring"
        node.worker_id = worker_id
        node.explored_at = now  # pick 시점 기록 → stale 판정 기준
        node.save(update_fields=["status", "worker_id", "explored_at"])
        return node


def _auto_create_candidate(node):
    """Auto-create a Candidate record when a vuln/exploit_step/clue node is pushed."""
    from api.models import Candidate
    try:
        score_map = {"vuln": 0.7, "exploit_step": 0.85, "clue": 0.5}
        stage_map = {"vuln": "llm_deep", "exploit_step": "llm_deep", "clue": "llm_screen"}
        cand = Candidate.objects.create(
            scan_run=node.scan_run,
            vuln_type=node.vuln_type or "signal_stub",
            hypothesis=node.summary,
            priority_score=score_map.get(node.node_type, 0.5),
            detection_stage=stage_map.get(node.node_type, "llm_screen"),
            status="open",
            features={
                "discovery_node_id": str(node.node_id),
                "node_type": node.node_type,
                "endpoint": node.endpoint or "",
                "depth": node.depth,
            },
        )
        return cand.cand_id
    except Exception as e:
        logger.warning(f"auto_create_candidate failed for node {node.node_id}: {e}")
        return None


def auto_promote_finding(node):
    """Auto-create a Finding when a discovery node is confirmed/flag."""
    from api.models import Candidate, Finding
    try:
        cand = Candidate.objects.filter(
            features__discovery_node_id=str(node.node_id),
        ).first()
        if cand:
            cand.status = "confirmed"
            cand.save(update_fields=["status"])

        severity_map = {"flag": "critical", "exploit_step": "high", "vuln": "medium"}
        finding = Finding.objects.create(
            scan_run=node.scan_run,
            candidate=cand,
            title=node.summary[:256],
            vuln_type=node.vuln_type or "unknown",
            severity=severity_map.get(node.node_type, "medium"),
            confidence=0.8 if node.node_type == "flag" else 0.6,
            summary=node.summary,
        )
        return str(finding.finding_id)
    except Exception as e:
        logger.warning(f"auto_promote_finding failed for node {node.node_id}: {e}")
        return None


def build_exploit_chains(scan_run_id: str) -> list[list[dict]]:
    """Reconstruct exploit chains from confirmed/flag nodes."""
    from api.models import DiscoveryNode

    terminal_nodes = DiscoveryNode.objects.filter(
        scan_run_id=scan_run_id,
        status__in=["confirmed", "explored"],
        node_type__in=["flag", "exploit_step", "vuln"],
    ).order_by("-depth")

    chains = []
    seen_roots = set()
    for node in terminal_nodes:
        chain = []
        current = node
        while current is not None:
            chain.append({
                "depth": current.depth,
                "node_type": current.node_type,
                "endpoint": current.endpoint or "",
                "vuln_type": current.vuln_type or "",
                "summary": current.summary,
            })
            current = current.parent

        chain.reverse()
        root_key = chain[0].get("endpoint", "")
        if root_key not in seen_roots and len(chain) > 1:
            chains.append(chain)
            seen_roots.add(root_key)

    return chains
