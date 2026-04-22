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

DISCOVERY_MAX_DEPTH = int(os.environ.get("WATCHDOG_DISCOVERY_MAX_DEPTH", "50"))
DISCOVERY_MAX_NODES = int(os.environ.get("WATCHDOG_DISCOVERY_MAX_NODES", "1000"))
DISCOVERY_STALE_S = int(os.environ.get("WATCHDOG_DISCOVERY_STALE_S", "300"))


# ══════════════════════════════════════════════════════════════════════
# vuln_type taxonomy — sub-agent taxonomy drift 방지
# ══════════════════════════════════════════════════════════════════════
# Different sub-agents (hypothesis/exploit/routemap) classify the same
# attack vector with different strings (e.g. "privilege_escalation" vs
# "access_control", "user_enum" vs "information_disclosure"). This
# fragments dedup and inflates the tree with semantic duplicates.
# Canonicalize at push_discovery time so dedup works on one stable name.
#
# Keys: lowercase snake_case synonyms (after strip/lower/dash-to-underscore).
# Values: canonical vuln_type name used in KB (PayloadPattern, DeadEnd,
# EndpointSpec.suspected_vuln_types). Unknown values pass through — novel
# taxonomy still works, only well-known synonyms collapse.
VULN_TYPE_CANONICAL: dict[str, str] = {
    # access control family
    "acl": "access_control", "acl_bypass": "access_control",
    "authz": "access_control", "authorization": "access_control",
    "authorization_bypass": "access_control", "authz_bypass": "access_control",
    "method_bypass": "access_control", "http_method_bypass": "access_control",
    "options_bypass": "access_control",
    "privilege_escalation": "access_control", "privesc": "access_control",
    "forced_browsing": "access_control", "broken_access_control": "access_control",
    # authentication family
    "authentication_bypass": "auth_bypass", "authn_bypass": "auth_bypass",
    "brute_force": "auth_bypass", "credential_stuffing": "auth_bypass",
    "weak_password": "auth_bypass", "default_credentials": "auth_bypass",
    "no_rate_limit": "auth_bypass",
    # information disclosure family
    "user_enum": "information_disclosure", "user_enumeration": "information_disclosure",
    "username_enumeration": "information_disclosure",
    "email_enumeration": "information_disclosure",
    "info_disclosure": "information_disclosure", "info_leak": "information_disclosure",
    "data_leak": "information_disclosure", "pii_leak": "information_disclosure",
    "stack_trace": "information_disclosure", "error_leak": "information_disclosure",
    "verbose_error": "information_disclosure",
    "sensitive_data_exposure": "information_disclosure",
    # injection family
    "sql_injection": "sqli", "sql": "sqli", "blind_sqli": "sqli",
    "time_based_sqli": "sqli", "union_sqli": "sqli", "error_based_sqli": "sqli",
    "nosql_injection": "nosqli", "mongo_injection": "nosqli",
    "cmd_injection": "rce", "command_injection": "rce",
    "os_command_injection": "rce", "code_injection": "rce",
    "remote_code_execution": "rce",
    "xss_reflected": "xss", "xss_stored": "xss",
    "reflected_xss": "xss", "stored_xss": "xss", "dom_xss": "xss",
    "cross_site_scripting": "xss",
    "template_injection": "ssti", "ssti_injection": "ssti",
    # idor / direct object reference
    "direct_object_reference": "idor",
    "insecure_direct_object_reference": "idor",
    "broken_object_level_authorization": "idor", "bola": "idor",
    # logic flaw
    "business_logic": "logic_flaw", "logic_bug": "logic_flaw",
    "race_condition": "logic_flaw", "toctou": "logic_flaw",
    "rate_limit_bypass": "logic_flaw", "otp_bypass": "logic_flaw",
    "otp_brute_force": "logic_flaw",
    # csrf / ssrf
    "cross_site_request_forgery": "csrf",
    "server_side_request_forgery": "ssrf",
    # path / file
    "directory_traversal": "path_traversal",
    "lfi": "path_traversal", "local_file_inclusion": "path_traversal",
    "rfi": "path_traversal", "remote_file_inclusion": "path_traversal",
    # xxe / deserialize
    "xml_external_entity": "xxe", "xxe_injection": "xxe",
    "insecure_deserialization": "deserialization",
    "unsafe_deserialization": "deserialization",
    # file upload
    "unrestricted_file_upload": "file_upload",
    "arbitrary_file_upload": "file_upload",
    "file_upload_bypass": "file_upload",
    # open redirect
    "open_redirect_vuln": "open_redirect",
    # jwt
    "jwt_none": "jwt", "jwt_weak_secret": "jwt", "jwt_tampering": "jwt",
    "jwt_alg_confusion": "jwt",
}


def _canonicalize_vuln_type(vt: str) -> str:
    """Map synonym vuln_type strings to canonical form.

    Lowercases, converts dashes/spaces to underscores, then looks up
    VULN_TYPE_CANONICAL. Unknown values pass through normalized (not the
    alias map output), so novel taxonomy is preserved.
    """
    if not vt:
        return ""
    key = str(vt).strip().lower().replace("-", "_").replace(" ", "_")
    return VULN_TYPE_CANONICAL.get(key, key)


# Common vuln_types worth attempting against any web endpoint.
# Used by _vuln_slot_hints to suggest untested attack vectors to
# sub-agents so they don't re-try vectors already hypothesized.
COMMON_VULN_TYPES: frozenset[str] = frozenset({
    "sqli", "idor", "xss", "ssrf", "access_control", "auth_bypass",
    "path_traversal", "rce", "csrf", "open_redirect", "xxe",
    "information_disclosure", "file_upload", "deserialization",
    "nosqli", "logic_flaw", "jwt", "ssti",
})


def _vuln_slot_hints(scan_run, endpoint: str, target_host: str = "") -> dict:
    """Return "already tried vs untested" vuln_type slots for an endpoint.

    Combines three knowledge sources:
      - same-scan DiscoveryNode history (vuln/exploit_step children of
        this endpoint) → existing_vuln_types_here
      - cross-scan DeadEnd KB → prior_dead_end_vuln_types
      - EndpointSpec.suspected_vuln_types (from prior entrypoint
        analysis or confirm_finding auto-push) → kb_suspected_vuln_types

    untested_common_vuln_types = COMMON_VULN_TYPES − existing, excluding
    known dead ends. Empty dict if endpoint is blank.
    """
    from api.models import DiscoveryNode, DeadEnd, EndpointSpec
    result: dict = {
        "existing_vuln_types_here": [],
        "untested_common_vuln_types": [],
        "prior_dead_end_vuln_types": [],
        "kb_suspected_vuln_types": [],
    }
    if not endpoint:
        return result

    try:
        ep_norm = _normalize_ep(endpoint, scan_run.target_url or "")
    except Exception:
        ep_norm = endpoint
    # Match push_discovery dedup policy: path-only fallback ONLY when the
    # normalized endpoint carries no query string. Otherwise /search?q=
    # and /search are treated as distinct attack surfaces in storage, and
    # slot_hints must mirror that — else /search?q= would inherit the
    # vuln_type set from bare /search and hide untested vectors.
    ep_variants = {ep_norm, ep_norm.rstrip("/"), ep_norm + "/"}
    if "?" not in ep_norm:
        path_only = ep_norm.split("?", 1)[0]
        ep_variants.add(path_only)
        ep_variants.add(path_only + "/")
    ep_variants.discard("")

    try:
        existing_raw = (
            DiscoveryNode.objects
            .filter(
                scan_run=scan_run,
                node_type__in=("vuln", "exploit_step"),
                endpoint__in=ep_variants,
            )
            .exclude(vuln_type="")
            .values_list("vuln_type", flat=True)
        )
        existing = {_canonicalize_vuln_type(v) for v in existing_raw if v}
    except Exception:
        existing = set()
    result["existing_vuln_types_here"] = sorted(existing)

    if not target_host:
        try:
            from urllib.parse import urlparse as _up
            target_host = (_up(scan_run.target_url or "").netloc or "").lower()
        except Exception:
            target_host = ""

    dead_canon: set = set()
    if target_host:
        try:
            dead_raw = (
                DeadEnd.objects
                .filter(target_host=target_host, endpoint__in=ep_variants)
                .values_list("vuln_type", flat=True)
            )
            dead_canon = {_canonicalize_vuln_type(v) for v in dead_raw if v}
        except Exception:
            pass
        try:
            spec = (
                EndpointSpec.objects
                .filter(target_host=target_host, endpoint__in=ep_variants)
                .order_by("-last_seen_at")
                .first()
            )
            if spec and spec.suspected_vuln_types:
                svt = spec.suspected_vuln_types
                if isinstance(svt, str):
                    try:
                        svt = json.loads(svt)
                    except Exception:
                        svt = []
                if isinstance(svt, list):
                    result["kb_suspected_vuln_types"] = sorted(
                        {_canonicalize_vuln_type(v) for v in svt if v}
                    )
        except Exception:
            pass
    result["prior_dead_end_vuln_types"] = sorted(dead_canon)
    result["untested_common_vuln_types"] = sorted(
        COMMON_VULN_TYPES - existing - dead_canon
    )
    return result


def _normalize_ep(ep: str, target_url: str = "") -> str:
    """Normalize endpoint for storage and dedup.

    - Same-origin full URLs → path + sorted query param names.
    - Cross-origin full URLs → scheme://host:port/path + sorted query param names.
      Scheme is preserved because http vs https can expose different attack surfaces.
    - Trailing slash stripped, path lowercased.
    - target_url 의 path prefix (e.g. /lms) 가 endpoint path 앞에 붙어있으면
      제거 → /lms/register 와 /register 가 같은 dedup key. False merge 위험
      낮고 (prefix 가 일치할 때만), 같은 핸들러의 full-path/rel-path 변형
      (router 기준 rel vs server mounted full) 을 하나로 모음.
    """
    from urllib.parse import urlparse as _urlparse, parse_qs as _parse_qs
    if not ep:
        return "/"
    path_part = ep
    host_prefix = ""
    query = ""
    target_base_prefix = ""
    if target_url:
        try:
            _tp = _urlparse(target_url)
            target_base_prefix = (_tp.path or "").rstrip("/").lower()
        except Exception:
            pass
    if ep.startswith(("http://", "https://")):
        try:
            parsed = _urlparse(ep)
            target_host = ""
            target_scheme = ""
            if target_url:
                try:
                    tp = _urlparse(target_url)
                    target_host = tp.netloc.lower()
                    target_scheme = tp.scheme.lower()
                except Exception:
                    pass
            ep_host = parsed.netloc.lower()
            ep_scheme = parsed.scheme.lower()
            if target_host and ep_host != target_host:
                host_prefix = f"{ep_scheme}://{ep_host}"
            elif target_host and ep_host == target_host and ep_scheme != target_scheme:
                host_prefix = f"{ep_scheme}://{ep_host}"
            path_part = parsed.path
            query = parsed.query
        except Exception:
            pass
    elif "?" in ep:
        path_part, query = ep.split("?", 1)

    path_part = path_part.rstrip("/") or "/"

    # target base prefix strip — /lms/register → /register. host_prefix 쓰는
    # cross-origin 경우에는 적용 안 함 (다른 호스트의 path 를 target base 로
    # 잘라낼 근거 없음).
    if not host_prefix and target_base_prefix:
        pp_lower = path_part.lower()
        if pp_lower == target_base_prefix:
            path_part = "/"
        elif pp_lower.startswith(target_base_prefix + "/"):
            path_part = path_part[len(target_base_prefix):]

    param_suffix = ""
    if query:
        try:
            param_names = sorted(set(_parse_qs(query, keep_blank_values=True).keys()))
            if param_names:
                param_suffix = "?" + "&".join(f"{n}=" for n in param_names)
        except Exception:
            pass
    result = path_part.lower() + param_suffix
    if host_prefix:
        result = host_prefix + result
    return result


def _merge_context(existing_node, new_ctx: dict) -> None:
    """Merge new discovery context into an existing node.

    Accumulates methods, discovered_from sources, and other metadata
    so that a deduped endpoint doesn't lose information about how it was found.
    """
    if not new_ctx:
        return
    old_ctx = dict(existing_node.context or {})
    changed = False

    # Accumulate methods
    old_methods = set(old_ctx.get("methods") or [])
    new_methods = set(new_ctx.get("methods") or [])
    if new_methods - old_methods:
        old_ctx["methods"] = sorted(old_methods | new_methods)
        changed = True

    # Accumulate discovered_from sources
    old_sources = old_ctx.get("discovered_from_list") or []
    if isinstance(old_sources, str):
        old_sources = [old_sources]
    if old_ctx.get("discovered_from") and old_ctx["discovered_from"] not in old_sources:
        old_sources.append(old_ctx["discovered_from"])
    new_from = new_ctx.get("discovered_from", "")
    if new_from and new_from not in old_sources:
        old_sources.append(new_from)
        old_ctx["discovered_from_list"] = old_sources[-10:]
        changed = True

    # Accumulate params from context (type-safe: handle dict, list, or mixed)
    old_params = old_ctx.get("params")
    new_params = new_ctx.get("params")
    if new_params:
        if isinstance(old_params, list) and isinstance(new_params, list):
            merged = list(dict.fromkeys(old_params + new_params))
            if merged != old_params:
                old_ctx["params"] = merged
                changed = True
        elif isinstance(old_params, dict) and isinstance(new_params, dict):
            merged_params = {**old_params, **new_params}
            if merged_params != old_params:
                old_ctx["params"] = merged_params
                changed = True
        elif old_params is None:
            old_ctx["params"] = new_params
            changed = True
        else:
            def _params_to_dict(p):
                if isinstance(p, dict):
                    return p
                if isinstance(p, list):
                    return {str(v): "" for v in p}
                return {}
            merged_params = {**_params_to_dict(old_params), **_params_to_dict(new_params)}
            old_ctx["params"] = merged_params
            changed = True

    # Preserve any extra keys from new context that don't exist yet
    for k, v in new_ctx.items():
        if k not in old_ctx and k not in ("methods", "discovered_from", "params", "discovered_from_list"):
            old_ctx[k] = v
            changed = True

    if changed:
        existing_node.context = old_ctx
        existing_node.save(update_fields=["context"])


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

        # Canonicalize vuln_type so taxonomy drift between sub-agents
        # (privilege_escalation ↔ access_control, user_enum ↔
        # information_disclosure, ...) collapses to one dedup key.
        # Preserve the original string in context for traceability.
        vuln_type_raw = vuln_type or ""
        vuln_type = _canonicalize_vuln_type(vuln_type_raw)
        if vuln_type and vuln_type != vuln_type_raw:
            ctx.setdefault("vuln_type_raw", vuln_type_raw)

        # Require vuln_type for vuln/exploit_step so sub-agents can't push
        # under-classified nodes that bypass dedup. For exploit_step the
        # parent is usually a vuln node — inherit if missing.
        if node_type in ("vuln", "exploit_step") and not vuln_type:
            if node_type == "exploit_step" and parent and parent.vuln_type:
                vuln_type = _canonicalize_vuln_type(parent.vuln_type)
                ctx.setdefault("vuln_type_inherited_from_parent", True)
            else:
                return json.dumps({
                    "error": "vuln_type is required for vuln/exploit_step nodes",
                    "hint": (
                        "Pick a canonical type (sqli, idor, xss, ssrf, "
                        "access_control, auth_bypass, information_disclosure, "
                        "path_traversal, rce, csrf, xxe, file_upload, "
                        "logic_flaw, jwt, ssti, open_redirect, nosqli, "
                        "deserialization). Synonyms (privilege_escalation, "
                        "user_enum, ...) are auto-canonicalized."
                    ),
                    "node_type": node_type,
                    "summary_seen": (summary or "")[:160],
                })

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

        # Dedup: same scan + (normalized endpoint, vuln_type, node_type) → return existing.
        # Normalization preserves cross-origin host and query param names.
        if endpoint and node_type in ("endpoint", "vuln", "exploit_step"):
            from urllib.parse import urlparse as _urlparse, parse_qs as _parse_qs

            # Resolve target_url for same/cross-origin detection
            target_url = ""
            try:
                sr = ScanRun.objects.get(run_id=scan_run_id)
                target_url = sr.target_url or ""
            except Exception:
                pass

            ep_norm = _normalize_ep(endpoint, target_url)
            ep_variants = set()
            for raw in (endpoint, ep_norm, ep_norm.rstrip("/"), ep_norm + "/"):
                ep_variants.add(raw)
                ep_variants.add(raw.lower())
            # Only add path-only fallback when the normalized endpoint has NO query params.
            # Otherwise /search?q= would collapse into existing /search, losing the
            # distinct attack surface that query params represent.
            if "?" not in ep_norm:
                path_only = ep_norm.split("?", 1)[0]
                ep_variants.add(path_only)
                ep_variants.add(path_only + "/")
                ep_variants.add(path_only.lower())
            ep_variants.discard("")

            existing = (
                DiscoveryNode.objects
                .filter(scan_run_id=scan_run_id, node_type=node_type)
                .filter(endpoint__in=ep_variants)
                .filter(vuln_type=vuln_type or "")
                .order_by("created_at")
                .first()
            )
            if existing:
                # Merge new context into existing node (accumulate methods, sources)
                _merge_context(existing, ctx)
                return json.dumps({
                    "node_id": str(existing.node_id),
                    "depth": existing.depth,
                    "node_type": existing.node_type,
                    "deduped": True,
                    "context_merged": bool(ctx),
                    "deduped_reason": "same scan+endpoint+vuln_type+node_type already exists",
                    "queue_pending": DiscoveryNode.objects.filter(
                        scan_run_id=scan_run_id, status="pending",
                    ).count(),
                })

        # Normalize stored endpoint
        store_ep = endpoint or (parent.endpoint if parent else "")
        if store_ep:
            target_url = ""
            try:
                sr = ScanRun.objects.get(run_id=scan_run_id)
                target_url = sr.target_url or ""
            except Exception:
                pass
            store_ep = _normalize_ep(store_ep, target_url)

        node = DiscoveryNode.objects.create(
            scan_run_id=scan_run_id,
            parent=parent,
            depth=depth,
            node_type=node_type,
            endpoint=store_ep,
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
        """Get sibling nodes (same parent) + untested vuln_type slots.

        Siblings answer "what already exists at this branch" so the
        sub-agent can avoid duplicate work. slot_hints answers "what
        vuln_types are still untested on this endpoint across scans" so
        the sub-agent can deliberately pick a different angle instead of
        re-pushing an already-hypothesized type.
        """
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

        slot_hints = _vuln_slot_hints(node.scan_run, node.endpoint or "")

        return json.dumps({
            "count": len(items),
            "siblings": items,
            "endpoint": node.endpoint or "",
            "slot_hints": slot_hints,
        })

    @mcp.tool()
    def get_vuln_slot_hints(scan_run_id: str, endpoint: str) -> str:
        """Return already-tried vs untested vuln_type slots for an endpoint.

        Call before pushing a vuln node or picking an exploit angle so
        you don't duplicate an already-hypothesized vector or re-try a
        known dead_end from a previous scan.

        Returns JSON with:
          - existing_vuln_types_here: already on this endpoint this scan
          - untested_common_vuln_types: COMMON set − existing − dead ends
          - prior_dead_end_vuln_types: from DeadEnd KB (cross-scan)
          - kb_suspected_vuln_types: from EndpointSpec.suspected_vuln_types
        """
        from api.models import ScanRun
        try:
            run = ScanRun.objects.get(run_id=scan_run_id)
        except ScanRun.DoesNotExist:
            return json.dumps({"error": "scan run not found"})
        hints = _vuln_slot_hints(run, endpoint or "")
        return json.dumps({"endpoint": endpoint or "", **hints})

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
