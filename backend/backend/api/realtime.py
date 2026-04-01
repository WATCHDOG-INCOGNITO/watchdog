from __future__ import annotations

from django.utils import timezone

from .models import Candidate, RequestCatalog, ScanRun
from .storage_service import get_scan_findings_summary


def _serialize_scan(scan_run: ScanRun) -> dict:
    return {
        "run_id": str(scan_run.run_id),
        "target_url": scan_run.target_url,
        "mode": scan_run.mode,
        "status": scan_run.status,
        "created_at": scan_run.created_at.isoformat() if scan_run.created_at else None,
        "updated_at": scan_run.updated_at.isoformat() if scan_run.updated_at else None,
        "finished_at": scan_run.finished_at.isoformat() if scan_run.finished_at else None,
        "request_budget_total": scan_run.request_budget_total,
        "request_budget_used": scan_run.request_budget_used,
        "llm_calls_count": scan_run.llm_calls_count,
        "llm_tokens_used": scan_run.llm_tokens_used,
        "llm_cost_usd": str(scan_run.llm_cost_usd),
        "config": scan_run.config,
        "error_log": scan_run.error_log,
    }


def _serialize_candidate(candidate: Candidate) -> dict:
    request = candidate.request
    return {
        "cand_id": str(candidate.cand_id),
        "vuln_type": candidate.vuln_type,
        "status": candidate.status,
        "priority_score": candidate.priority_score,
        "detection_stage": candidate.detection_stage,
        "hypothesis": candidate.hypothesis,
        "endpoint": request.endpoint if request else None,
        "method": request.method if request else None,
        "params": request.params if request else {},
        "created_at": candidate.created_at.isoformat() if candidate.created_at else None,
    }


def build_scan_list_payload(limit: int = 50) -> dict:
    scans = ScanRun.objects.all().order_by("-created_at")[:limit]
    return {
        "type": "scan_list_snapshot",
        "emitted_at": timezone.now().isoformat(),
        "scans": [_serialize_scan(scan) for scan in scans],
    }


def build_scan_detail_payload(run_id: str) -> dict | None:
    try:
        scan_run = ScanRun.objects.get(run_id=run_id)
    except ScanRun.DoesNotExist:
        return None

    candidates = (
        Candidate.objects.filter(scan_run_id=run_id)
        .select_related("request")
        .order_by("-priority_score", "-created_at")[:100]
    )

    return {
        "type": "scan_run_snapshot",
        "emitted_at": timezone.now().isoformat(),
        "run_id": str(run_id),
        "scan": _serialize_scan(scan_run),
        "summary": get_scan_findings_summary(run_id=run_id),
        "request_catalog_count": RequestCatalog.objects.filter(scan_run_id=run_id).count(),
        "candidate_count": Candidate.objects.filter(scan_run_id=run_id).count(),
        "candidates": [_serialize_candidate(candidate) for candidate in candidates],
    }


def _send_group_message(group_name: str, event_type: str, payload: dict) -> None:
    from asgiref.sync import async_to_sync
    from channels.layers import get_channel_layer

    channel_layer = get_channel_layer()
    if channel_layer is None:
        return

    async_to_sync(channel_layer.group_send)(
        group_name,
        {
            "type": event_type,
            "payload": payload,
        },
    )


def broadcast_scan_list_update() -> None:
    _send_group_message(
        "scan_list",
        "scan_list_message",
        build_scan_list_payload(),
    )


def broadcast_scan_run_update(run_id: str) -> None:
    payload = build_scan_detail_payload(str(run_id))
    if payload is None:
        return

    _send_group_message(
        f"scan_run_{run_id}",
        "scan_run_message",
        payload,
    )


def broadcast_scan_update(run_id: str) -> None:
    broadcast_scan_list_update()
    broadcast_scan_run_update(run_id)
