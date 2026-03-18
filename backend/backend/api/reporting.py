# backend/backend/api/reporting.py
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List


@dataclass
class ReportResult:
    run_id: str
    md_text: str
    json_obj: Dict[str, Any]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_report(run_id: str) -> ReportResult:
    """
    P5 Report 산출물 생성:
    - report.json: 머신용(구조화)
    - report.md: 사람용(요약)
    """
    # Django import는 함수 내부로 (import-order 이슈 방지)
    from django.db.models import Count
    from .models import (
        ScanRun,
        Candidate,
        Finding,
        EvidenceBlob,
        FindingEvidenceLink,
    )

    scan_run = ScanRun.objects.get(run_id=run_id)

    # ----------------------------
    # Querysets
    # ----------------------------
    candidates_qs = Candidate.objects.filter(scan_run_id=run_id).select_related("request")
    findings_qs = Finding.objects.filter(scan_run_id=run_id)

    # Severity summary
    severity_counts_map = {k: 0 for k, _ in Finding.Severity.choices}
    for row in findings_qs.values("severity").annotate(c=Count("finding_id")):
        sev = str(row.get("severity") or "info")
        severity_counts_map[sev] = int(row.get("c") or 0)

    # Evidence (distinct blobs reachable from findings in this run)
    direct_blob_ids = EvidenceBlob.objects.filter(
        finding__scan_run_id=run_id
    ).values_list("blob_id", flat=True)
    linked_blob_ids = FindingEvidenceLink.objects.filter(
        finding__scan_run_id=run_id
    ).values_list("blob_id", flat=True)
    blob_ids = set(direct_blob_ids) | set(linked_blob_ids)
    evidences_qs = EvidenceBlob.objects.filter(blob_id__in=blob_ids)

    # ----------------------------
    # Items limits (payload 보호)
    # ----------------------------
    TOP_CANDIDATES = 5
    MAX_FINDINGS = 50
    MAX_EVIDENCES = 50

    def _ser_candidate(c: Candidate) -> Dict[str, Any]:
        req = getattr(c, "request", None)
        return {
            "cand_id": str(c.cand_id),
            "vuln_type": c.vuln_type,
            "priority_score": float(c.priority_score),
            "detection_stage": c.detection_stage,
            "status": c.status,
            "hypothesis": c.hypothesis,
            "endpoint": getattr(req, "endpoint", None),
            "method": getattr(req, "method", None),
            "created_at": c.created_at.isoformat() if c.created_at else None,
        }

    def _ser_evidence(e: EvidenceBlob) -> Dict[str, Any]:
        # report에는 raw content를 절대 넣지 않음
        return {
            "blob_id": str(e.blob_id),
            "finding_id": str(e.finding_id) if e.finding_id else None,
            "kind": e.kind,
            "storage_ref": e.storage_ref,
            "sha256": e.sha256,
            "byte_size": e.byte_size,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }

    # Finding -> evidence refs preload
    link_map: Dict[str, List[Dict[str, Any]]] = {}
    for l in FindingEvidenceLink.objects.filter(finding__scan_run_id=run_id).select_related("blob"):
        fid = str(l.finding_id)
        link_map.setdefault(fid, []).append(
            {
                "blob_id": str(l.blob_id),
                "role": l.role,
                "storage_ref": getattr(l.blob, "storage_ref", None),
                "sha256": getattr(l.blob, "sha256", None),
                "kind": getattr(l.blob, "kind", None),
            }
        )

    def _ser_finding(f: Finding) -> Dict[str, Any]:
        return {
            "finding_id": str(f.finding_id),
            "candidate_id": str(f.candidate_id) if f.candidate_id else None,
            "title": f.title,
            "vuln_type": f.vuln_type,
            "severity": f.severity,
            "confidence": float(f.confidence),
            "summary": f.summary,
            "reproduction_steps": f.reproduction_steps,
            "created_at": f.created_at.isoformat() if f.created_at else None,
            "evidence_refs": link_map.get(str(f.finding_id), []),
        }

    top_candidates = [_ser_candidate(c) for c in candidates_qs.order_by("-priority_score")[:TOP_CANDIDATES]]
    findings_items = [_ser_finding(f) for f in findings_qs.order_by("-created_at")[:MAX_FINDINGS]]
    evidences_items = [_ser_evidence(e) for e in evidences_qs.order_by("-created_at")[:MAX_EVIDENCES]]

    json_obj: Dict[str, Any] = {
        "run_id": str(scan_run.run_id),
        "target_url": scan_run.target_url,
        "status": scan_run.status,
        "generated_at": _now_iso(),
        "candidates": {
            "count": candidates_qs.count(),
            "top": top_candidates,
        },
        "findings": {
            "count": findings_qs.count(),
            "by_severity": severity_counts_map,
            "items": findings_items,
        },
        "evidence": {
            "count": int(evidences_qs.count()),
            "items": evidences_items,
        },
        "notes": "generated",
    }

    sev_lines = "\n".join([f"- {k}: {v}" for k, v in json_obj["findings"]["by_severity"].items()])
    cand_lines = "\n".join(
        [
            f"- ({c['priority_score']:.2f}) {c['vuln_type']} [{c['status']}] {c.get('method') or ''} {c.get('endpoint') or ''}".strip()
            for c in top_candidates
        ]
    ) or "- (none)"

    md_text = f"""# Watchdog Report

## Run
- run_id: `{json_obj['run_id']}`
- target_url: `{json_obj['target_url']}`
- status: `{json_obj['status']}`
- generated_at: `{json_obj['generated_at']}`

## Candidates
- count: {json_obj['candidates']['count']}
{cand_lines}

## Findings
- count: {json_obj['findings']['count']}

### By Severity
{sev_lines}

## Evidence
- count: {json_obj['evidence']['count']}
"""

    return ReportResult(run_id=run_id, md_text=md_text, json_obj=json_obj)


def serialize_report_json(report: ReportResult) -> str:
    return json.dumps(report.json_obj, ensure_ascii=False, indent=2)


def serialize_report_md(report: ReportResult) -> str:
    return report.md_text