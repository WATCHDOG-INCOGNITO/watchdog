"""Artifact-backed WorkItem scheduler.

This is the layer above DiscoveryNode. DiscoveryNode records what was found;
WorkItem records what should be done next, who leased it, and how it ended.
"""

from __future__ import annotations

import os
from datetime import timedelta
from typing import Any

from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from .discovery_queue import build_work_item_metadata, work_item_summary
from .models import Candidate, DiscoveryNode, ScanRun, WorkItem


TERMINAL_NODE_STATUSES = {"explored", "dead_end", "confirmed"}
TERMINAL_WORK_STATUSES = {"done", "failed", "cancelled", "expired"}


def _lease_seconds() -> int:
    return int(os.environ.get("WATCHDOG_WORK_LEASE_S") or os.environ.get("WATCHDOG_DISCOVERY_STALE_S", "300"))


def _candidate_for_node(node: DiscoveryNode) -> Candidate | None:
    return (
        Candidate.objects
        .filter(scan_run=node.scan_run, features__discovery_node_id=str(node.node_id))
        .order_by("-created_at")
        .first()
    )


def ensure_work_item_for_node(
    node: DiscoveryNode,
    *,
    work_type: str = "",
    extra_context: dict[str, Any] | None = None,
) -> WorkItem:
    """Create the canonical WorkItem for a DiscoveryNode if one does not exist."""
    ctx = dict(node.context or {})
    if extra_context:
        ctx.update(extra_context)

    parent_status = node.parent.status if node.parent_id and node.parent else ""
    meta = build_work_item_metadata(
        node_type=node.node_type,
        work_type=work_type,
        vuln_type=node.vuln_type or "",
        endpoint=node.endpoint or "",
        context=ctx,
        depth=node.depth,
        parent_status=parent_status,
    )

    existing = (
        WorkItem.objects
        .filter(
            scan_run=node.scan_run,
            node=node,
            work_type=meta["work_type"],
            diversity_key=meta["diversity_key"],
        )
        .exclude(status__in=["cancelled", "expired"])
        .order_by("-created_at")
        .first()
    )
    if existing:
        return existing

    status = WorkItem.Status.BLOCKED if meta["preconditions"] else WorkItem.Status.PENDING
    return WorkItem.objects.create(
        scan_run=node.scan_run,
        node=node,
        candidate=_candidate_for_node(node),
        work_type=meta["work_type"],
        status=status,
        queue_lane=meta["queue_lane"],
        objective=meta["objective"],
        context=ctx,
        preconditions=meta["preconditions"],
        expected_outputs=meta["expected_outputs"],
        oracle=meta["oracle"],
        provider_hint=meta["provider_hint"],
        diversity_key=meta["diversity_key"],
        priority_score=meta["priority_score"],
        score_breakdown=meta["score_breakdown"],
        max_attempts=int(ctx.get("max_attempts") or 3),
    )


def enqueue_work_item(
    scan_run: ScanRun,
    *,
    work_type: str,
    node: DiscoveryNode | None = None,
    candidate: Candidate | None = None,
    objective: str = "",
    context: dict[str, Any] | None = None,
    priority_score: float | None = None,
    provider_hint: str = "",
) -> WorkItem:
    """Manually enqueue a WorkItem for an artifact."""
    context = context or {}
    node_type = node.node_type if node else context.get("node_type", "clue")
    vuln_type = (node.vuln_type if node else context.get("vuln_type", "")) or ""
    endpoint = (node.endpoint if node else context.get("endpoint", "")) or ""
    meta = build_work_item_metadata(
        node_type=node_type,
        work_type=work_type,
        vuln_type=vuln_type,
        endpoint=endpoint,
        context=context,
        depth=node.depth if node else int(context.get("depth", 0) or 0),
        parent_status=node.parent.status if node and node.parent_id and node.parent else "",
    )
    if priority_score is not None:
        meta["priority_score"] = float(priority_score)
    if provider_hint:
        meta["provider_hint"] = provider_hint

    diversity_key = context.get("diversity_key") or meta["diversity_key"]
    existing = (
        WorkItem.objects
        .filter(scan_run=scan_run, work_type=meta["work_type"], diversity_key=diversity_key)
        .exclude(status__in=["cancelled", "expired"])
        .order_by("-created_at")
        .first()
    )
    if existing:
        return existing

    status = WorkItem.Status.BLOCKED if meta["preconditions"] else WorkItem.Status.PENDING
    return WorkItem.objects.create(
        scan_run=scan_run,
        node=node,
        candidate=candidate,
        work_type=meta["work_type"],
        status=status,
        queue_lane=meta["queue_lane"],
        objective=objective or meta["objective"],
        context=context,
        preconditions=meta["preconditions"],
        expected_outputs=meta["expected_outputs"],
        oracle=meta["oracle"],
        provider_hint=meta["provider_hint"],
        diversity_key=diversity_key,
        priority_score=meta["priority_score"],
        score_breakdown=meta["score_breakdown"],
        max_attempts=int(context.get("max_attempts") or 3),
    )


def lease_next_work_item(
    scan_run_id: str,
    worker_id: str,
    *,
    worker_kind: str = "",
    queue_lane: str = "",
    work_type: str = "",
) -> WorkItem | None:
    """Atomically lease the best pending WorkItem."""
    now = timezone.now()
    lease_until = now + timedelta(seconds=_lease_seconds())
    with transaction.atomic():
        qs = (
            WorkItem.objects
            .select_for_update(skip_locked=True)
            .filter(scan_run_id=scan_run_id)
            .filter(Q(status="pending") | Q(status="leased", leased_until__lt=now))
            .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
        )
        if queue_lane:
            qs = qs.filter(queue_lane=queue_lane)
        if work_type:
            qs = qs.filter(work_type=work_type)
        if worker_kind and worker_kind != "external":
            qs = qs.filter(Q(provider_hint="") | Q(provider_hint=worker_kind) | Q(provider_hint__isnull=True))

        work = qs.order_by("-priority_score", "created_at").first()
        if work is None:
            return None

        work.status = WorkItem.Status.LEASED
        work.lease_owner = worker_id
        work.leased_until = lease_until
        work.attempt_count = (work.attempt_count or 0) + 1
        work.save(update_fields=["status", "lease_owner", "leased_until", "attempt_count", "updated_at"])

        if work.node and work.node.status == DiscoveryNode.Status.PENDING:
            work.node.status = DiscoveryNode.Status.EXPLORING
            work.node.worker_id = worker_id
            work.node.lease_owner = worker_id
            work.node.leased_until = lease_until
            work.node.explored_at = now
            work.node.attempt_count = (work.node.attempt_count or 0) + 1
            work.node.save(update_fields=[
                "status",
                "worker_id",
                "lease_owner",
                "leased_until",
                "explored_at",
                "attempt_count",
            ])

        return work


def complete_work_item(work_id: str, *, result: dict[str, Any] | None = None, node_status: str = "") -> WorkItem:
    work = WorkItem.objects.select_related("node").get(work_id=work_id)
    now = timezone.now()
    work.status = WorkItem.Status.DONE
    work.result = result or {}
    work.lease_owner = None
    work.leased_until = None
    work.completed_at = now
    work.last_error = ""
    work.save(update_fields=[
        "status",
        "result",
        "lease_owner",
        "leased_until",
        "completed_at",
        "last_error",
        "updated_at",
    ])
    if work.node and node_status in TERMINAL_NODE_STATUSES:
        work.node.status = node_status
        work.node.lease_owner = None
        work.node.leased_until = None
        work.node.explored_at = now
        work.node.save(update_fields=["status", "lease_owner", "leased_until", "explored_at"])
    return work


def fail_work_item(work_id: str, *, error: str = "", retry: bool = True) -> WorkItem:
    work = WorkItem.objects.get(work_id=work_id)
    can_retry = retry and (work.attempt_count or 0) < (work.max_attempts or 1)
    work.status = WorkItem.Status.PENDING if can_retry else WorkItem.Status.FAILED
    work.lease_owner = None
    work.leased_until = None
    work.last_error = error[:4000]
    work.save(update_fields=["status", "lease_owner", "leased_until", "last_error", "updated_at"])
    return work


def block_work_item(work_id: str, *, preconditions: list[str], error: str = "") -> WorkItem:
    work = WorkItem.objects.get(work_id=work_id)
    work.status = WorkItem.Status.BLOCKED
    work.preconditions = preconditions
    work.lease_owner = None
    work.leased_until = None
    work.last_error = error[:4000]
    work.save(update_fields=[
        "status",
        "preconditions",
        "lease_owner",
        "leased_until",
        "last_error",
        "updated_at",
    ])
    return work


def unblock_work_item(work_id: str, *, note: str = "") -> WorkItem:
    work = WorkItem.objects.get(work_id=work_id)
    work.status = WorkItem.Status.PENDING
    work.preconditions = []
    work.last_error = note[:4000]
    work.lease_owner = None
    work.leased_until = None
    work.save(update_fields=[
        "status",
        "preconditions",
        "last_error",
        "lease_owner",
        "leased_until",
        "updated_at",
    ])
    return work


def build_work_mission_packet(work: WorkItem) -> dict[str, Any]:
    from .agent_exchange import summarize_related_exchanges

    node = work.node
    return {
        "scan_run_id": str(work.scan_run_id),
        "work": work_item_summary(work),
        "work_id": str(work.work_id),
        "work_type": work.work_type,
        "objective": work.objective,
        "context": work.context,
        "node_id": str(node.node_id) if node else "",
        "node_type": node.node_type if node else "",
        "endpoint": node.endpoint if node else "",
        "vuln_type": node.vuln_type if node else "",
        "summary": node.summary if node else "",
        "candidate_id": str(work.candidate_id) if work.candidate_id else "",
        "preconditions": work.preconditions,
        "expected_outputs": work.expected_outputs,
        "oracle": work.oracle,
        "provider_hint": work.provider_hint,
        "agent_exchanges": summarize_related_exchanges(work),
        "dialogue_contract": [
            "Read prior agent_exchanges before deciding the next action",
            "Use add_agent_exchange for claims, evidence, counterarguments, handoffs, and recheck requests",
            "If you dispute another worker, include evidence_refs and requested_action",
            "If both workers converge, write a consensus or decision exchange before completing work",
        ],
        "finalize_contract": [
            "record_trace with a non-empty tool_calls array",
            "push discoveries before testing them",
            "store reusable secrets immediately",
            "complete_work or fail_work this work item",
            "terminal node work should also set node_status",
        ],
    }
