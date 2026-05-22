"""Pure strategy helpers for Watchdog's global queue composer.

This module intentionally avoids Django imports so the scoring and grouping
rules stay easy to unit test. The ORM-backed builder lives in ``strategy.py``.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any


PRIMITIVE_BY_VULN_TYPE = {
    "information_disclosure": "read",
    "idor": "object_reference",
    "access_control": "role_change",
    "auth_bypass": "auth",
    "jwt": "auth",
    "logic_flaw": "workflow_bypass",
    "xss": "browser_exec",
    "ssrf": "server_side_fetch",
    "path_traversal": "file",
    "lfi": "file",
    "file_upload": "file",
    "sqli": "read",
    "nosqli": "read",
    "ssti": "server_exec",
    "rce": "server_exec",
    "cmdi": "server_exec",
    "open_redirect": "redirect",
    "csrf": "workflow_bypass",
}

IMPACT_BY_PRIMITIVE = {
    "server_exec": 1.0,
    "server_side_fetch": 0.86,
    "auth": 0.78,
    "role_change": 0.76,
    "object_reference": 0.72,
    "file": 0.68,
    "workflow_bypass": 0.66,
    "read": 0.58,
    "browser_exec": 0.52,
    "redirect": 0.28,
}

PROVIDER_BY_CHAIN_FAMILY = {
    "password_reset_takeover": "claude",
    "group_access_chain": "claude",
    "admin_access_chain": "claude",
    "stored_xss_chain": "claude",
    "file_path_chain": "codex",
    "auth_surface_chain": "claude",
    "secret_to_auth_pivot": "codex",
}


@dataclass(frozen=True)
class PrimitiveFact:
    category: str
    vuln_type: str = ""
    endpoint: str = ""
    confidence: float = 0.0
    status: str = "proposed"
    supporting_evidence_ids: list[str] = field(default_factory=list)
    contradicting_evidence_ids: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ChainScore:
    confidence_score: float
    impact_score: float
    execution_score: float
    total_score: float
    novelty_score: float
    cost_score: float
    missing_evidence: list[str]
    prerequisite_gaps: list[str]
    provider_hint: str
    status: str


def normalize_endpoint(endpoint: str) -> str:
    text = (endpoint or "").strip().lower()
    text = re.sub(r"https?://[^/]+", "", text)
    text = re.sub(r"/+", "/", text)
    text = re.sub(r"/[0-9a-f-]{6,}(?=/|$)", "/{id}", text)
    text = re.sub(r"/\d+(?=/|$)", "/{id}", text)
    return text or "/"


def primitive_category_for(vuln_type: str = "", endpoint: str = "", text: str = "") -> str:
    vt = (vuln_type or "").strip().lower()
    if vt in PRIMITIVE_BY_VULN_TYPE:
        return PRIMITIVE_BY_VULN_TYPE[vt]

    haystack = f"{endpoint or ''} {text or ''}".lower()
    if any(term in haystack for term in ("password", "otp", "verify-code", "send-code")):
        return "workflow_bypass"
    if any(term in haystack for term in ("admin", "role", "approval", "refusal")):
        return "role_change"
    if any(term in haystack for term in ("image", "upload", "file", "assignment")):
        return "file"
    if any(term in haystack for term in ("token", "jwt", "login", "session")):
        return "auth"
    if any(term in haystack for term in ("announcement", "html", "script")):
        return "browser_exec"
    return "read"


def infer_chain_family(primitive: PrimitiveFact) -> str:
    endpoint = normalize_endpoint(primitive.endpoint)
    text = f"{endpoint} {primitive.vuln_type} {primitive.category}".lower()
    if any(term in text for term in ("password", "otp", "send-code", "verify-code")):
        return "password_reset_takeover"
    if "/admin" in text or "admin" in text:
        return "admin_access_chain"
    if "/group" in text or "group" in text:
        return "group_access_chain"
    if any(term in text for term in ("announcement", "xss", "browser_exec")):
        return "stored_xss_chain"
    if any(term in text for term in ("image", "upload", "file", "assignment", "path_traversal")):
        return "file_path_chain"
    if any(term in text for term in ("auth", "login", "jwt", "session")):
        return "auth_surface_chain"
    if "secret" in text:
        return "secret_to_auth_pivot"
    return f"{primitive.category}_chain"


def sigmoid(value: float) -> float:
    return 1.0 / (1.0 + math.exp(-max(min(value, 30.0), -30.0)))


def score_chain_family(family: str, primitives: list[PrimitiveFact]) -> ChainScore:
    if not primitives:
        return ChainScore(0, 0, 0, 0, 0, 1, ["no primitives"], ["no evidence"], "", "rejected")

    categories = {p.category for p in primitives}
    confidence_values = [max(min(p.confidence, 1.0), 0.0) for p in primitives]
    contradiction_count = sum(len(p.contradicting_evidence_ids or []) for p in primitives)
    verified_count = sum(1 for p in primitives if p.status == "verified")

    evidence_strength = sum(confidence_values) / len(confidence_values)
    if verified_count:
        evidence_strength = min(1.0, evidence_strength + 0.12 * verified_count)
    evidence_strength = max(0.0, evidence_strength - 0.08 * contradiction_count)

    impact_score = max(IMPACT_BY_PRIMITIVE.get(category, 0.45) for category in categories)
    primitive_compatibility = min(1.0, 0.35 + 0.18 * len(categories) + 0.06 * len(primitives))
    missing_evidence = []
    prerequisite_gaps = []

    if verified_count == 0:
        missing_evidence.append("deterministic verification")
    if any(category in categories for category in {"auth", "role_change", "object_reference"}):
        prerequisite_gaps.append("fresh authenticated persona/state")
    if contradiction_count:
        missing_evidence.append("contradiction arbitration")

    missing_penalty = 0.12 * len(missing_evidence) + 0.08 * len(prerequisite_gaps)
    execution_score = max(0.0, min(1.0, primitive_compatibility - missing_penalty))
    novelty_score = 0.55 if contradiction_count else 0.72
    cost_score = min(1.0, 0.18 + 0.08 * len(primitives) + 0.05 * len(missing_evidence))

    raw = (
        1.2 * evidence_strength
        + 1.0 * execution_score
        + 0.9 * impact_score
        + 0.35 * novelty_score
        - 0.45 * cost_score
    )
    total_score = round(100 * sigmoid(raw - 1.35), 2)
    status = "needs_recheck" if total_score >= 65 else "needs_evidence"
    if verified_count and total_score >= 80 and not contradiction_count:
        status = "verified"

    provider_hint = PROVIDER_BY_CHAIN_FAMILY.get(family)
    if not provider_hint:
        provider_hint = "codex" if any(category in categories for category in {"file", "read"}) else "claude"
    if contradiction_count:
        provider_hint = "codex"

    return ChainScore(
        confidence_score=round(evidence_strength, 4),
        impact_score=round(impact_score, 4),
        execution_score=round(execution_score, 4),
        total_score=total_score,
        novelty_score=round(novelty_score, 4),
        cost_score=round(cost_score, 4),
        missing_evidence=missing_evidence,
        prerequisite_gaps=prerequisite_gaps,
        provider_hint=provider_hint,
        status=status,
    )


def chain_display_name(family: str) -> str:
    labels = {
        "password_reset_takeover": "Password reset takeover chain",
        "group_access_chain": "Group access / IDOR chain",
        "admin_access_chain": "Admin workflow access chain",
        "stored_xss_chain": "Stored XSS to privileged action chain",
        "file_path_chain": "File upload / image path chain",
        "auth_surface_chain": "Authentication surface chain",
        "secret_to_auth_pivot": "Secret to auth pivot chain",
    }
    return labels.get(family, family.replace("_", " ").title())
