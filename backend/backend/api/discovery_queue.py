"""Priority metadata for DiscoveryNode scheduling.

The Discovery Tree is still the source of truth. This module only adds a
small, deterministic frontier score so multiple workers can pick better
next nodes without rewriting the tree model.
"""

from __future__ import annotations

from typing import Any


QUEUE_LANES_BY_TYPE = {
    "target": "recon",
    "endpoint": "endpoint",
    "vuln": "hypothesis",
    "clue": "hypothesis",
    "exploit_step": "chain",
    "flag": "proof",
    "dead_end": "report",
}

PROVIDER_HINTS_BY_LANE = {
    "recon": "claude",
    "endpoint": "claude",
    "hypothesis": "claude",
    "chain": "claude",
    "proof": "codex",
    "recheck": "codex",
    "report": "codex",
}

BASE_SCORE_BY_TYPE = {
    "target": 0.35,
    "endpoint": 0.45,
    "clue": 0.55,
    "vuln": 0.72,
    "exploit_step": 0.88,
    "flag": 1.0,
    "dead_end": 0.05,
}

IMPACT_BY_VULN_TYPE = {
    "rce": 1.0,
    "ssti": 0.92,
    "sqli": 0.9,
    "ssrf": 0.86,
    "xxe": 0.82,
    "deserialization": 0.82,
    "file_upload": 0.78,
    "path_traversal": 0.72,
    "idor": 0.7,
    "access_control": 0.7,
    "auth_bypass": 0.68,
    "logic_flaw": 0.66,
    "nosqli": 0.64,
    "jwt": 0.62,
    "csrf": 0.45,
    "xss": 0.42,
    "open_redirect": 0.28,
    "information_disclosure": 0.35,
}


def _float_from_context(context: dict[str, Any], key: str, default: float) -> float:
    try:
        value = float(context.get(key, default))
    except (TypeError, ValueError):
        return default
    return max(0.0, min(value, 2.0))


def default_queue_lane(node_type: str, context: dict[str, Any] | None = None) -> str:
    context = context or {}
    lane = str(context.get("queue_lane") or context.get("lane") or "").strip().lower()
    return lane or QUEUE_LANES_BY_TYPE.get(node_type, "hypothesis")


def default_provider_hint(queue_lane: str, node_type: str, context: dict[str, Any] | None = None) -> str:
    context = context or {}
    explicit = str(context.get("provider_hint") or context.get("preferred_provider") or "").strip().lower()
    if explicit:
        return explicit
    if node_type in {"flag"}:
        return "codex"
    return PROVIDER_HINTS_BY_LANE.get(queue_lane, "")


def build_queue_metadata(
    *,
    node_type: str,
    vuln_type: str = "",
    context: dict[str, Any] | None = None,
    depth: int = 0,
    parent_status: str = "",
) -> dict[str, Any]:
    context = context or {}
    queue_lane = default_queue_lane(node_type, context)

    base = BASE_SCORE_BY_TYPE.get(node_type, 0.45)
    impact = _float_from_context(context, "impact", IMPACT_BY_VULN_TYPE.get(vuln_type, 0.5))
    confidence = _float_from_context(context, "confidence", 0.75)
    novelty = _float_from_context(context, "novelty", 1.0)
    estimated_cost = max(_float_from_context(context, "estimated_cost", 1.0), 0.1)
    depth_bonus = min(max(depth, 0) * 0.025, 0.2)

    parent_bonus = 0.0
    if parent_status == "confirmed":
        parent_bonus = 0.16
    elif parent_status == "dead_end":
        parent_bonus = -0.35

    blocked_by = context.get("blocked_by") or context.get("missing_prereqs") or []
    if isinstance(blocked_by, str):
        blocked_by = [blocked_by] if blocked_by else []
    prereq_ready = 0.45 if blocked_by else 1.0

    raw_score = ((base + depth_bonus + parent_bonus) * (0.6 + impact * 0.4))
    raw_score = raw_score * confidence * novelty * prereq_ready / estimated_cost
    priority_score = round(max(raw_score, 0.01), 4)

    score_breakdown = {
        "base": base,
        "impact": impact,
        "confidence": confidence,
        "novelty": novelty,
        "estimated_cost": estimated_cost,
        "depth_bonus": round(depth_bonus, 4),
        "parent_bonus": parent_bonus,
        "prereq_ready": prereq_ready,
    }

    return {
        "queue_lane": queue_lane,
        "priority_score": priority_score,
        "score_breakdown": score_breakdown,
        "blocked_by": blocked_by,
        "provider_hint": default_provider_hint(queue_lane, node_type, context),
        "mission": build_mission(node_type=node_type, queue_lane=queue_lane, context=context),
    }


def build_mission(*, node_type: str, queue_lane: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or {}
    objective_by_type = {
        "target": "Map the authorized target and enqueue discovered endpoints.",
        "endpoint": "Analyze this endpoint and enqueue diverse, non-duplicate hypotheses.",
        "vuln": "Test this hypothesis with KB/dead-end awareness and deterministic verification.",
        "clue": "Resolve the clue into endpoint/vuln children or mark it dead with evidence.",
        "exploit_step": "Continue the confirmed chain only within the authorized scope.",
        "flag": "Independently verify the terminal evidence and store the flag/secret.",
        "dead_end": "Preserve the failed path as reusable negative knowledge.",
    }
    return {
        "lane": queue_lane,
        "objective": context.get("objective") or objective_by_type.get(node_type, "Explore this discovery node."),
        "success_criteria": context.get("success_criteria") or [
            "record_trace includes meaningful tool_calls",
            "new discoveries are pushed before testing",
            "final status is explored, confirmed, or dead_end",
        ],
    }


def node_queue_summary(node: Any) -> dict[str, Any]:
    leased_until = getattr(node, "leased_until", None)
    if hasattr(leased_until, "isoformat"):
        leased_until = leased_until.isoformat()
    return {
        "queue_lane": getattr(node, "queue_lane", "") or "",
        "priority_score": getattr(node, "priority_score", 0.0) or 0.0,
        "score_breakdown": getattr(node, "score_breakdown", None) or {},
        "provider_hint": getattr(node, "provider_hint", "") or "",
        "blocked_by": getattr(node, "blocked_by", None) or [],
        "attempt_count": getattr(node, "attempt_count", 0) or 0,
        "lease_owner": getattr(node, "lease_owner", "") or "",
        "leased_until": leased_until,
        "mission": getattr(node, "mission", None) or {},
    }
