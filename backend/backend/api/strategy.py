"""Evidence graph and chain snapshot builder for Watchdog strategy brain."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

from django.db import transaction
from django.utils import timezone

from .models import (
    AgentExchange,
    Candidate,
    ChainCandidate,
    DeadEnd,
    DiscoveryNode,
    EndpointSpec,
    EvidenceEdge,
    EvidenceNode,
    Finding,
    LLMTrace,
    PrimitiveInstance,
    ScanRun,
    StrategySnapshot,
    WorkItem,
)
from .strategy_core import (
    PrimitiveFact,
    chain_display_name,
    infer_chain_family,
    normalize_endpoint,
    primitive_category_for,
    score_chain_family,
)


def _hash(*parts: Any) -> str:
    data = "|".join(str(part or "") for part in parts)
    return hashlib.sha256(data.encode("utf-8", "ignore")).hexdigest()


def _target_host(run: ScanRun) -> str:
    parsed = urlparse(run.target_url if "://" in run.target_url else f"https://{run.target_url}")
    return parsed.netloc or parsed.path.split("/")[0]


def _confidence_from_status(status: str) -> float:
    return {
        "confirmed": 0.95,
        "done": 0.82,
        "explored": 0.68,
        "verified": 0.92,
        "dead_end": 0.75,
        "failed": 0.42,
        "open": 0.45,
        "pending": 0.35,
        "leased": 0.28,
    }.get((status or "").lower(), 0.5)


def _evidence_status(kind: str, status: str) -> str:
    status = (status or "").lower()
    if kind == "dead_end" or status == "dead_end":
        return EvidenceNode.Status.DEAD_END
    if status in {"confirmed", "done", "verified"}:
        return EvidenceNode.Status.VERIFIED
    if status in {"false_positive", "dismissed", "failed", "cancelled"}:
        return EvidenceNode.Status.CONTRADICTED
    if kind in {"claim", "exchange"}:
        return EvidenceNode.Status.CLAIMED
    return EvidenceNode.Status.OBSERVED


def _redact_text(value: str, redactions: list[tuple[str, str]] | None = None) -> str:
    text = value or ""
    for key, secret in redactions or []:
        if secret and len(secret) >= 4:
            text = text.replace(secret, f"[redacted:{key}]")
    return text


def _safe_value(value: Any, max_len: int = 900, redactions: list[tuple[str, str]] | None = None) -> Any:
    """Keep strategy nodes small and avoid storing secret values."""
    if isinstance(value, str):
        return _redact_text(value, redactions)[:max_len]
    if isinstance(value, dict):
        return {str(k): _safe_value(v, max_len=max_len, redactions=redactions) for k, v in value.items()}
    if isinstance(value, list):
        return [_safe_value(v, max_len=max_len, redactions=redactions) for v in value[:50]]
    return value


class StrategyBuilder:
    def __init__(self, run: ScanRun):
        self.run = run
        self.host = _target_host(run)
        self.nodes_by_key: dict[str, EvidenceNode] = {}
        self.redactions: list[tuple[str, str]] = []
        for key, entry in ((run.config or {}).get("_secrets") or {}).items():
            value = str((entry or {}).get("value") or "")
            if value:
                self.redactions.append((str(key), value))

    def reset(self) -> None:
        StrategySnapshot.objects.filter(scan_run=self.run).delete()
        ChainCandidate.objects.filter(scan_run=self.run).delete()
        PrimitiveInstance.objects.filter(scan_run=self.run).delete()
        EvidenceEdge.objects.filter(scan_run=self.run).delete()
        EvidenceNode.objects.filter(scan_run=self.run).delete()
        self.nodes_by_key.clear()

    def node(
        self,
        *,
        kind: str,
        semantic_key: str,
        subtype: str = "",
        title: str = "",
        summary: str = "",
        value_json: dict | None = None,
        scope_json: dict | None = None,
        auth_scope: str = "",
        confidence: float = 0.5,
        status: str = EvidenceNode.Status.OBSERVED,
        source_worker: str = "",
        provider: str = "",
    ) -> EvidenceNode:
        semantic_hash = _hash(kind, subtype, semantic_key)
        defaults = {
            "kind": kind,
            "subtype": subtype or "",
            "title": _redact_text(title or "", self.redactions)[:512],
            "summary": _redact_text(summary or "", self.redactions),
            "value_json": _safe_value(value_json or {}, redactions=self.redactions),
            "scope_json": _safe_value(scope_json or {}, redactions=self.redactions),
            "auth_scope": auth_scope or "",
            "confidence": max(0.0, min(float(confidence or 0.0), 1.0)),
            "freshness": 1.0,
            "status": status,
            "source_worker": source_worker or "",
            "provider": provider or "",
            "semantic_hash": semantic_hash,
        }
        obj, _ = EvidenceNode.objects.update_or_create(
            scan_run=self.run,
            semantic_key=semantic_key,
            defaults=defaults,
        )
        self.nodes_by_key[semantic_key] = obj
        return obj

    def edge(self, src: EvidenceNode | None, dst: EvidenceNode | None, edge_type: str, *, weight: float = 1.0, rationale: str = "") -> None:
        if not src or not dst or src.evidence_id == dst.evidence_id:
            return
        EvidenceEdge.objects.update_or_create(
            scan_run=self.run,
            src=src,
            dst=dst,
            edge_type=edge_type,
            defaults={
                "weight": weight,
                "rationale": rationale[:1000],
                "created_by": "strategy",
                "active": True,
            },
        )

    def build_artifact_nodes(self) -> None:
        discovery_nodes = list(DiscoveryNode.objects.filter(scan_run=self.run).select_related("parent"))
        for node in discovery_nodes:
            self.node(
                kind="discovery_node",
                subtype=node.node_type,
                semantic_key=f"discovery:{node.node_id}",
                title=node.summary[:180],
                summary=node.summary,
                value_json={
                    "node_id": str(node.node_id),
                    "node_type": node.node_type,
                    "status": node.status,
                    "endpoint": node.endpoint or "",
                    "vuln_type": node.vuln_type or "",
                    "queue_lane": node.queue_lane,
                    "provider_hint": node.provider_hint,
                },
                scope_json={"endpoint": node.endpoint or "", "vuln_type": node.vuln_type or "", "depth": node.depth},
                confidence=_confidence_from_status(node.status),
                status=_evidence_status("discovery_node", node.status),
                source_worker=node.worker_id or "",
                provider=node.provider_hint or "",
            )
        for node in discovery_nodes:
            if node.parent_id:
                self.edge(
                    self.nodes_by_key.get(f"discovery:{node.parent_id}"),
                    self.nodes_by_key.get(f"discovery:{node.node_id}"),
                    "parent_of",
                    rationale="Discovery Tree parent",
                )

        for cand in Candidate.objects.filter(scan_run=self.run).select_related("request"):
            features = cand.features or {}
            endpoint = features.get("endpoint") or (cand.request.endpoint if cand.request_id and cand.request else "")
            ev = self.node(
                kind="claim",
                subtype=cand.vuln_type or "",
                semantic_key=f"candidate:{cand.cand_id}",
                title=(cand.hypothesis or cand.vuln_type or "candidate")[:180],
                summary=cand.hypothesis or "",
                value_json={
                    "candidate_id": str(cand.cand_id),
                    "vuln_type": cand.vuln_type,
                    "status": cand.status,
                    "endpoint": endpoint,
                    "priority_score": cand.priority_score,
                    "features": features,
                },
                scope_json={"endpoint": endpoint, "vuln_type": cand.vuln_type},
                confidence=max(_confidence_from_status(cand.status), min(cand.priority_score or 0.0, 1.0)),
                status=_evidence_status("claim", cand.status),
                provider=str(features.get("provider_hint") or ""),
            )
            node_id = features.get("discovery_node_id")
            if node_id:
                self.edge(self.nodes_by_key.get(f"discovery:{node_id}"), ev, "supports", rationale="Candidate created from DiscoveryNode")

        for finding in Finding.objects.filter(scan_run=self.run).select_related("candidate"):
            ev = self.node(
                kind="finding",
                subtype=finding.vuln_type or finding.severity,
                semantic_key=f"finding:{finding.finding_id}",
                title=finding.title,
                summary=finding.summary or "",
                value_json={
                    "finding_id": str(finding.finding_id),
                    "vuln_type": finding.vuln_type or "",
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "candidate_id": str(finding.candidate_id) if finding.candidate_id else "",
                },
                scope_json={"vuln_type": finding.vuln_type or "", "severity": finding.severity},
                confidence=max(finding.confidence or 0.0, 0.78),
                status=EvidenceNode.Status.VERIFIED,
            )
            if finding.candidate_id:
                self.edge(self.nodes_by_key.get(f"candidate:{finding.candidate_id}"), ev, "verified_by", rationale="Finding confirms candidate")

        for trace in LLMTrace.objects.filter(scan_run=self.run).select_related("target_node")[:500]:
            ev = self.node(
                kind="trace",
                subtype=trace.stage or "analysis",
                semantic_key=f"trace:{trace.trace_id}",
                title=f"{trace.stage or 'trace'} {trace.model or ''}".strip(),
                summary=trace.response_preview or trace.prompt_preview,
                value_json={
                    "trace_id": str(trace.trace_id),
                    "stage": trace.stage,
                    "model": trace.model,
                    "tool_calls": trace.tool_calls or [],
                    "error": trace.error or "",
                },
                scope_json={"target_node_id": str(trace.target_node_id) if trace.target_node_id else ""},
                confidence=0.54 if not trace.error else 0.25,
                status=EvidenceNode.Status.OBSERVED if not trace.error else EvidenceNode.Status.CONTRADICTED,
                provider=trace.model or "",
            )
            if trace.target_node_id:
                self.edge(self.nodes_by_key.get(f"discovery:{trace.target_node_id}"), ev, "observed_from", rationale="Trace target node")

        for work in WorkItem.objects.filter(scan_run=self.run).select_related("node", "candidate"):
            ev = self.node(
                kind="work_item",
                subtype=work.work_type,
                semantic_key=f"work:{work.work_id}",
                title=work.objective[:180] or work.work_type,
                summary=work.last_error or json.dumps(work.result or {}, default=str)[:1000],
                value_json={
                    "work_id": str(work.work_id),
                    "work_type": work.work_type,
                    "status": work.status,
                    "queue_lane": work.queue_lane,
                    "provider_hint": work.provider_hint,
                    "priority_score": work.priority_score,
                    "attempt_count": work.attempt_count,
                },
                scope_json={"node_id": str(work.node_id) if work.node_id else "", "candidate_id": str(work.candidate_id) if work.candidate_id else ""},
                confidence=_confidence_from_status(work.status),
                status=_evidence_status("work_item", work.status),
                source_worker=work.lease_owner or "",
                provider=work.provider_hint,
            )
            if work.node_id:
                self.edge(self.nodes_by_key.get(f"discovery:{work.node_id}"), ev, "scheduled_as", rationale="WorkItem leased/scheduled for node")
            if work.candidate_id:
                self.edge(self.nodes_by_key.get(f"candidate:{work.candidate_id}"), ev, "scheduled_as", rationale="WorkItem leased/scheduled for candidate")

        for exchange in AgentExchange.objects.filter(scan_run=self.run).select_related("work", "node", "parent_exchange"):
            ev = self.node(
                kind="exchange",
                subtype=exchange.message_type,
                semantic_key=f"exchange:{exchange.exchange_id}",
                title=f"{exchange.provider}:{exchange.message_type}",
                summary=exchange.content,
                value_json={
                    "exchange_id": str(exchange.exchange_id),
                    "provider": exchange.provider,
                    "message_type": exchange.message_type,
                    "stance": exchange.stance,
                    "resolution_status": exchange.resolution_status,
                    "evidence_refs": exchange.evidence_refs,
                    "requested_action": exchange.requested_action,
                },
                scope_json={"work_id": str(exchange.work_id) if exchange.work_id else "", "node_id": str(exchange.node_id) if exchange.node_id else ""},
                confidence=exchange.confidence or 0.45,
                status=_evidence_status("exchange", exchange.resolution_status),
                source_worker=exchange.agent_name,
                provider=exchange.provider,
            )
            if exchange.work_id:
                self.edge(self.nodes_by_key.get(f"work:{exchange.work_id}"), ev, "discussed_by", rationale="AgentExchange attached to WorkItem")
            if exchange.node_id:
                self.edge(self.nodes_by_key.get(f"discovery:{exchange.node_id}"), ev, "discussed_by", rationale="AgentExchange attached to DiscoveryNode")
            if exchange.parent_exchange_id:
                self.edge(self.nodes_by_key.get(f"exchange:{exchange.parent_exchange_id}"), ev, "replied_by", rationale="AgentExchange reply")

        for spec in EndpointSpec.objects.filter(target_host=self.host).order_by("-last_seen_at")[:250]:
            self.node(
                kind="endpoint_spec",
                subtype=spec.method,
                semantic_key=f"endpoint_spec:{spec.spec_id}",
                title=f"{spec.method} {spec.endpoint}",
                summary=spec.notes or "",
                value_json={
                    "spec_id": str(spec.spec_id),
                    "method": spec.method,
                    "endpoint": spec.endpoint,
                    "auth_required": spec.auth_required,
                    "suspected_vuln_types": spec.suspected_vuln_types or [],
                    "sink_hints": spec.sink_hints or [],
                    "times_seen": spec.times_seen,
                },
                scope_json={"endpoint": spec.endpoint, "auth_required": spec.auth_required},
                confidence=min(0.78, 0.42 + 0.05 * (spec.times_seen or 1)),
                status=EvidenceNode.Status.OBSERVED,
            )

        for dead_end in DeadEnd.objects.filter(target_host=self.host).order_by("-last_seen_at")[:250]:
            self.node(
                kind="dead_end",
                subtype=dead_end.vuln_type,
                semantic_key=f"dead_end:{dead_end.dead_end_id}",
                title=f"{dead_end.vuln_type} dead end @ {dead_end.endpoint}",
                summary=dead_end.reason or "",
                value_json={
                    "dead_end_id": str(dead_end.dead_end_id),
                    "endpoint": dead_end.endpoint,
                    "vuln_type": dead_end.vuln_type,
                    "pattern_id": str(dead_end.pattern_id) if dead_end.pattern_id else "",
                    "payload_used": dead_end.payload_used or "",
                    "times_seen": dead_end.times_seen,
                },
                scope_json={"endpoint": dead_end.endpoint, "vuln_type": dead_end.vuln_type},
                confidence=0.82,
                status=EvidenceNode.Status.DEAD_END,
            )

        config = self.run.config or {}
        for key, entry in (config.get("_secrets") or {}).items():
            self.node(
                kind="secret_candidate",
                subtype=str(entry.get("category") or "secret"),
                semantic_key=f"secret:{key}",
                title=f"stored secret: {key}",
                summary=f"Secret key '{key}' stored; value intentionally redacted.",
                value_json={"key": key, "category": entry.get("category", "credential"), "stored_at": entry.get("stored_at", "")},
                scope_json={"secret_key": key},
                confidence=0.86,
                status=EvidenceNode.Status.VERIFIED,
            )

        for idx, note in enumerate(config.get("_notes") or []):
            self.node(
                kind="scan_note",
                subtype=str(note.get("topic") or "note"),
                semantic_key=f"note:{idx}:{_hash(note.get('topic'), note.get('content'))[:12]}",
                title=str(note.get("topic") or "note"),
                summary=str(note.get("content") or ""),
                value_json={"topic": note.get("topic", ""), "ts": note.get("ts", "")},
                confidence=0.5,
                status=EvidenceNode.Status.OBSERVED,
            )

    def extract_primitives(self) -> list[PrimitiveInstance]:
        primitive_inputs: dict[str, dict[str, Any]] = {}

        def add_input(category: str, vuln_type: str, endpoint: str, evidence: EvidenceNode, confidence: float, auth_required: bool = False) -> None:
            endpoint_norm = normalize_endpoint(endpoint or "")
            key = f"primitive:{category}:{vuln_type or '-'}:{endpoint_norm}"
            item = primitive_inputs.setdefault(key, {
                "category": category,
                "vuln_type": vuln_type or "",
                "endpoint": endpoint_norm,
                "supporting": [],
                "contradicting": [],
                "confidence": 0.0,
                "auth_required": auth_required,
            })
            bucket = "contradicting" if evidence.status in {EvidenceNode.Status.DEAD_END, EvidenceNode.Status.CONTRADICTED} else "supporting"
            item[bucket].append(str(evidence.evidence_id))
            item["confidence"] = max(item["confidence"], confidence)
            item["auth_required"] = item["auth_required"] or auth_required

        for evidence in EvidenceNode.objects.filter(scan_run=self.run, kind__in=["claim", "finding", "endpoint_spec", "dead_end"]):
            value = evidence.value_json or {}
            scope = evidence.scope_json or {}
            endpoint = value.get("endpoint") or scope.get("endpoint") or ""
            auth_required = bool(value.get("auth_required") or scope.get("auth_required"))
            vuln_types = value.get("suspected_vuln_types") or [value.get("vuln_type") or evidence.subtype]
            if isinstance(vuln_types, str):
                vuln_types = [vuln_types]
            for vuln_type in [v for v in vuln_types if v]:
                category = primitive_category_for(vuln_type, endpoint, evidence.summary or evidence.title)
                add_input(category, str(vuln_type), endpoint, evidence, evidence.confidence, auth_required)

        primitives: list[PrimitiveInstance] = []
        for semantic_key, data in primitive_inputs.items():
            confidence = max(0.05, min(data["confidence"], 1.0))
            if data["contradicting"]:
                confidence = max(0.05, confidence - 0.12 * len(data["contradicting"]))
            status = PrimitiveInstance.Status.PROPOSED
            if data["contradicting"] and not data["supporting"]:
                status = PrimitiveInstance.Status.CONTRADICTED
            elif any(EvidenceNode.objects.filter(evidence_id=eid, status=EvidenceNode.Status.VERIFIED).exists() for eid in data["supporting"][:6]):
                status = PrimitiveInstance.Status.VERIFIED
            preconditions = ["authenticated persona"] if data["auth_required"] else []
            effects = [f"{data['category']} capability", f"{data['vuln_type']} hypothesis"]
            primitive, _ = PrimitiveInstance.objects.update_or_create(
                scan_run=self.run,
                semantic_key=semantic_key,
                defaults={
                    "category": data["category"],
                    "name": f"{data['category']} via {data['vuln_type'] or 'endpoint'}",
                    "endpoint": data["endpoint"],
                    "vuln_type": data["vuln_type"],
                    "supporting_evidence_ids": data["supporting"][:40],
                    "contradicting_evidence_ids": data["contradicting"][:40],
                    "preconditions_json": preconditions,
                    "effects_json": effects,
                    "auth_scope": "authenticated" if data["auth_required"] else "anonymous_or_unknown",
                    "confidence": round(confidence, 4),
                    "status": status,
                    "state_fingerprint": _hash(data["endpoint"], data["vuln_type"], data["category"])[:32],
                },
            )
            primitives.append(primitive)
        return primitives

    def compose_chains(self) -> list[ChainCandidate]:
        primitives = list(PrimitiveInstance.objects.filter(scan_run=self.run).order_by("-confidence"))
        grouped: dict[str, list[PrimitiveInstance]] = defaultdict(list)
        for primitive in primitives:
            fact = PrimitiveFact(
                category=primitive.category,
                vuln_type=primitive.vuln_type,
                endpoint=primitive.endpoint,
                confidence=primitive.confidence,
                status=primitive.status,
                supporting_evidence_ids=primitive.supporting_evidence_ids or [],
                contradicting_evidence_ids=primitive.contradicting_evidence_ids or [],
            )
            grouped[infer_chain_family(fact)].append(primitive)

        chains: list[ChainCandidate] = []
        for family, family_primitives in grouped.items():
            facts = [
                PrimitiveFact(
                    category=p.category,
                    vuln_type=p.vuln_type,
                    endpoint=p.endpoint,
                    confidence=p.confidence,
                    status=p.status,
                    supporting_evidence_ids=p.supporting_evidence_ids or [],
                    contradicting_evidence_ids=p.contradicting_evidence_ids or [],
                )
                for p in family_primitives
            ]
            score = score_chain_family(family, facts)
            evidence_ids = []
            primitive_ids = []
            contradictions = []
            for primitive in family_primitives[:20]:
                primitive_ids.append(str(primitive.primitive_id))
                evidence_ids.extend(primitive.supporting_evidence_ids or [])
                contradictions.extend(primitive.contradicting_evidence_ids or [])
            evidence_ids = list(dict.fromkeys(evidence_ids))[:80]
            contradictions = list(dict.fromkeys(contradictions))[:40]
            semantic_key = f"chain:{family}:{_hash(*primitive_ids)[:16]}"
            chain, _ = ChainCandidate.objects.update_or_create(
                scan_run=self.run,
                semantic_key=semantic_key,
                defaults={
                    "name": chain_display_name(family),
                    "goal_type": family,
                    "chain_graph_json": {
                        "family": family,
                        "primitive_categories": sorted({p.category for p in family_primitives}),
                        "endpoints": sorted({p.endpoint for p in family_primitives if p.endpoint})[:30],
                    },
                    "linearization_json": [
                        {
                            "primitive_id": str(p.primitive_id),
                            "category": p.category,
                            "endpoint": p.endpoint,
                            "vuln_type": p.vuln_type,
                            "confidence": p.confidence,
                        }
                        for p in family_primitives[:20]
                    ],
                    "supporting_evidence_ids": evidence_ids,
                    "primitive_ids": primitive_ids,
                    "confidence_score": score.confidence_score,
                    "impact_score": score.impact_score,
                    "execution_score": score.execution_score,
                    "total_score": score.total_score,
                    "novelty_score": score.novelty_score,
                    "cost_score": score.cost_score,
                    "missing_evidence_json": score.missing_evidence,
                    "prerequisite_gap_json": score.prerequisite_gaps,
                    "contradiction_json": contradictions,
                    "provider_hint": score.provider_hint,
                    "status": score.status,
                    "rationale": _chain_rationale(family, family_primitives, score),
                    "last_promoted_at": timezone.now() if score.total_score >= 65 else None,
                },
            )
            chains.append(chain)
        return sorted(chains, key=lambda c: c.total_score, reverse=True)

    def snapshot(self, chains: list[ChainCandidate]) -> StrategySnapshot:
        top = chains[:3]
        queue_plan = []
        for chain in top:
            queue_plan.append({
                "chain_id": str(chain.chain_id),
                "work_type": "primitive_verify" if chain.missing_evidence_json else "chain_expand",
                "provider_hint": chain.provider_hint,
                "objective": f"Advance {chain.name}: {chain.rationale[:220]}",
                "missing_evidence": chain.missing_evidence_json,
                "prerequisite_gaps": chain.prerequisite_gap_json,
                "score": chain.total_score,
            })
        stats = {
            "evidence_nodes": EvidenceNode.objects.filter(scan_run=self.run).count(),
            "evidence_edges": EvidenceEdge.objects.filter(scan_run=self.run).count(),
            "primitive_instances": PrimitiveInstance.objects.filter(scan_run=self.run).count(),
            "chain_candidates": ChainCandidate.objects.filter(scan_run=self.run).count(),
        }
        rationale = "\n".join(
            f"- {chain.name}: score={chain.total_score}, provider={chain.provider_hint}, missing={', '.join(chain.missing_evidence_json or []) or 'none'}"
            for chain in top
        )
        return StrategySnapshot.objects.create(
            scan_run=self.run,
            top_chain_ids_json=[str(chain.chain_id) for chain in top],
            queue_plan_json=queue_plan,
            rationale_md=rationale,
            graph_stats_json=stats,
        )


def _chain_rationale(family: str, primitives: list[PrimitiveInstance], score) -> str:
    endpoints = sorted({p.endpoint for p in primitives if p.endpoint})[:5]
    categories = sorted({p.category for p in primitives})
    parts = [
        f"{chain_display_name(family)} combines {len(primitives)} primitive(s)",
        f"categories={','.join(categories) or 'unknown'}",
        f"endpoints={','.join(endpoints) or 'none'}",
        f"confidence={score.confidence_score}",
        f"execution={score.execution_score}",
    ]
    if score.missing_evidence:
        parts.append(f"missing={','.join(score.missing_evidence)}")
    return "; ".join(parts)


@transaction.atomic
def build_strategy_snapshot(scan_run_id: str, *, reset: bool = True) -> dict[str, Any]:
    run = ScanRun.objects.select_for_update().get(run_id=scan_run_id)
    builder = StrategyBuilder(run)
    if reset:
        builder.reset()
    builder.build_artifact_nodes()
    builder.extract_primitives()
    chains = builder.compose_chains()
    snapshot = builder.snapshot(chains)
    return serialize_strategy_snapshot(snapshot)


def serialize_chain(chain: ChainCandidate) -> dict[str, Any]:
    return {
        "chain_id": str(chain.chain_id),
        "name": chain.name,
        "goal_type": chain.goal_type,
        "status": chain.status,
        "total_score": chain.total_score,
        "confidence_score": chain.confidence_score,
        "impact_score": chain.impact_score,
        "execution_score": chain.execution_score,
        "provider_hint": chain.provider_hint,
        "missing_evidence": chain.missing_evidence_json,
        "prerequisite_gaps": chain.prerequisite_gap_json,
        "contradictions": len(chain.contradiction_json or []),
        "rationale": chain.rationale,
        "linearization": chain.linearization_json,
    }


def serialize_strategy_snapshot(snapshot: StrategySnapshot) -> dict[str, Any]:
    chains = ChainCandidate.objects.filter(
        scan_run=snapshot.scan_run,
        chain_id__in=snapshot.top_chain_ids_json,
    )
    by_id = {str(chain.chain_id): chain for chain in chains}
    ordered = [serialize_chain(by_id[cid]) for cid in snapshot.top_chain_ids_json if cid in by_id]
    return {
        "snapshot_id": str(snapshot.snapshot_id),
        "scan_run_id": str(snapshot.scan_run_id),
        "created_at": snapshot.created_at.isoformat() if snapshot.created_at else "",
        "graph_stats": snapshot.graph_stats_json,
        "top_chains": ordered,
        "queue_plan": snapshot.queue_plan_json,
        "rationale": snapshot.rationale_md,
    }


def latest_strategy_snapshot(scan_run_id: str) -> dict[str, Any] | None:
    snapshot = StrategySnapshot.objects.filter(scan_run_id=scan_run_id).first()
    return serialize_strategy_snapshot(snapshot) if snapshot else None


def list_evidence_graph(scan_run_id: str, *, limit: int = 20) -> dict[str, Any]:
    nodes = EvidenceNode.objects.filter(scan_run_id=scan_run_id).order_by("-confidence", "kind")[:limit]
    edges = EvidenceEdge.objects.filter(scan_run_id=scan_run_id).count()
    by_kind: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for row in EvidenceNode.objects.filter(scan_run_id=scan_run_id).values("kind", "status"):
        by_kind[row["kind"]] = by_kind.get(row["kind"], 0) + 1
        by_status[row["status"]] = by_status.get(row["status"], 0) + 1
    return {
        "scan_run_id": scan_run_id,
        "counts": {
            "nodes": EvidenceNode.objects.filter(scan_run_id=scan_run_id).count(),
            "edges": edges,
            "by_kind": by_kind,
            "by_status": by_status,
            "primitives": PrimitiveInstance.objects.filter(scan_run_id=scan_run_id).count(),
            "chains": ChainCandidate.objects.filter(scan_run_id=scan_run_id).count(),
        },
        "nodes": [
            {
                "evidence_id": str(node.evidence_id),
                "kind": node.kind,
                "subtype": node.subtype,
                "status": node.status,
                "confidence": node.confidence,
                "title": node.title,
                "scope": node.scope_json,
            }
            for node in nodes
        ],
    }
