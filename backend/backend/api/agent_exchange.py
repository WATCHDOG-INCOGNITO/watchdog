"""Structured exchange helpers for Claude/Codex subscription workers."""

from __future__ import annotations

from typing import Any

from django.db.models import Q

from .models import AgentExchange, DiscoveryNode, ScanRun, WorkItem


VALID_PROVIDERS = {choice.value for choice in AgentExchange.Provider}
VALID_MESSAGE_TYPES = {choice.value for choice in AgentExchange.MessageType}
VALID_STANCES = {choice.value for choice in AgentExchange.Stance}
VALID_RESOLUTION_STATUSES = {choice.value for choice in AgentExchange.ResolutionStatus}


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _normalize_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    return [value]


def add_agent_exchange(
    *,
    scan_run: ScanRun,
    work: WorkItem | None = None,
    node: DiscoveryNode | None = None,
    parent_exchange: AgentExchange | None = None,
    agent_name: str = "",
    provider: str = "unknown",
    message_type: str = "handoff",
    stance: str = "neutral",
    content: str,
    confidence: float = 0.0,
    evidence_refs: list[Any] | None = None,
    requested_action: str = "",
    resolution_status: str = "open",
    metadata: dict[str, Any] | None = None,
) -> AgentExchange:
    provider = provider.strip().lower() if provider else "unknown"
    message_type = message_type.strip().lower() if message_type else "handoff"
    stance = stance.strip().lower() if stance else "neutral"
    resolution_status = resolution_status.strip().lower() if resolution_status else "open"

    if provider not in VALID_PROVIDERS:
        provider = "unknown"
    if message_type not in VALID_MESSAGE_TYPES:
        message_type = "handoff"
    if stance not in VALID_STANCES:
        stance = "neutral"
    if resolution_status not in VALID_RESOLUTION_STATUSES:
        resolution_status = "open"

    if work and not node:
        node = work.node

    return AgentExchange.objects.create(
        scan_run=scan_run,
        work=work,
        node=node,
        parent_exchange=parent_exchange,
        agent_name=agent_name[:128],
        provider=provider,
        message_type=message_type,
        stance=stance,
        content=content,
        confidence=max(0.0, min(1.0, _coerce_float(confidence))),
        evidence_refs=_normalize_list(evidence_refs),
        requested_action=requested_action[:64],
        resolution_status=resolution_status,
        metadata=metadata or {},
    )


def exchange_summary(exchange: AgentExchange) -> dict[str, Any]:
    created_at = exchange.created_at.isoformat() if exchange.created_at else ""
    return {
        "exchange_id": str(exchange.exchange_id),
        "parent_exchange_id": str(exchange.parent_exchange_id) if exchange.parent_exchange_id else "",
        "agent_name": exchange.agent_name,
        "provider": exchange.provider,
        "message_type": exchange.message_type,
        "stance": exchange.stance,
        "content": exchange.content[:1200],
        "confidence": exchange.confidence,
        "evidence_refs": exchange.evidence_refs or [],
        "requested_action": exchange.requested_action,
        "resolution_status": exchange.resolution_status,
        "created_at": created_at,
    }


def summarize_work_exchanges(work: WorkItem, *, limit: int = 12) -> list[dict[str, Any]]:
    exchanges = (
        AgentExchange.objects
        .filter(scan_run=work.scan_run)
        .filter(work=work)
        .select_related("parent_exchange")
        .order_by("-created_at")[:limit]
    )
    return [exchange_summary(exchange) for exchange in reversed(list(exchanges))]


def summarize_related_exchanges(work: WorkItem, *, limit: int = 16) -> list[dict[str, Any]]:
    """Summarize exchange context a worker should read before acting.

    A recheck WorkItem is often new, so filtering by work alone loses the
    original handoff. Include exchanges on the same node plus explicit
    source_exchange_id links from the WorkItem context.
    """
    query = Q(work=work)
    if work.node_id:
        query |= Q(node_id=work.node_id)

    source_exchange_id = (work.context or {}).get("source_exchange_id")
    if source_exchange_id:
        query |= Q(exchange_id=source_exchange_id) | Q(parent_exchange_id=source_exchange_id)

    exchanges = (
        AgentExchange.objects
        .filter(scan_run=work.scan_run)
        .filter(query)
        .select_related("parent_exchange")
        .order_by("-created_at")[:limit]
    )
    return [exchange_summary(exchange) for exchange in reversed(list(exchanges))]


def summarize_scan_exchanges(scan_run: ScanRun, *, limit: int = 30) -> list[dict[str, Any]]:
    exchanges = (
        AgentExchange.objects
        .filter(scan_run=scan_run)
        .select_related("parent_exchange")
        .order_by("-created_at")[:limit]
    )
    return [exchange_summary(exchange) for exchange in reversed(list(exchanges))]
