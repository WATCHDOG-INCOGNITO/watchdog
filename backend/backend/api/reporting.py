# backend/backend/api/reporting.py
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse

UNKNOWN_ENDPOINT = "unknown-endpoint"
UNKNOWN_HOST = "unknown-host"
SEVERITY_RANK = {
    "Critical": 4,
    "High": 3,
    "Moderate": 2,
    "Low": 1,
    "Informational": 0,
    "Unknown": -1,
}


@dataclass
class ReportResult:
    run_id: str
    md_text: str
    json_obj: Dict[str, Any]


@dataclass
class FindingReportResult:
    finding_id: str
    md_text: str
    json_obj: Dict[str, Any]


@dataclass
class DeveloperReportResult:
    run_id: str
    md_text: str
    json_obj: Dict[str, Any]

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _severity_label(severity: str | None) -> str:
    sev = (severity or "").lower().strip()
    return {
        "info": "Informational",
        "low": "Low",
        "medium": "Moderate",
        "high": "High",
        "critical": "Critical",
    }.get(sev, "Unknown")


def _safe_join_lines(lines: List[str]) -> str:
    cleaned = [line.strip() for line in lines if str(line or "").strip()]
    return "\n".join(cleaned)


def _target_host(target_url: str | None) -> str:
    parsed = urlparse(target_url or "")
    host = (parsed.netloc or parsed.hostname or "").strip()
    if not host:
        raw_target = (target_url or "").strip()
        if raw_target and "://" not in raw_target:
            host = raw_target.split("/", 1)[0].strip()
    return host or UNKNOWN_HOST


def _format_impacted_surface(host: str | None, endpoint: str | None) -> str:
    host_value = (host or "").strip()
    endpoint_value = str(endpoint or "").strip()
    if endpoint_value and endpoint_value != UNKNOWN_ENDPOINT:
        parsed_endpoint = urlparse(endpoint_value)
        if (parsed_endpoint.scheme and parsed_endpoint.netloc) or endpoint_value.startswith("//"):
            return endpoint_value
        if host_value and host_value != UNKNOWN_HOST:
            separator = "" if endpoint_value.startswith(("/", "?", "#")) else "/"
            return f"{host_value}{separator}{endpoint_value}"
        return endpoint_value
    if host_value and host_value != UNKNOWN_HOST:
        return host_value
    return "unknown"


def _affected_assets(host: str | None, endpoint: str | None) -> List[str]:
    assets: List[str] = []
    host_value = (host or "").strip()
    endpoint_value = str(endpoint or "").strip()
    if host_value and host_value != UNKNOWN_HOST:
        assets.append(host_value)
    if endpoint_value and endpoint_value != UNKNOWN_ENDPOINT:
        assets.append(endpoint_value)
    return assets


def _highest_severity(items: List[Dict[str, Any]]) -> str:
    return max(
        (item.get("severity", "Unknown") for item in items),
        key=lambda severity: SEVERITY_RANK.get(str(severity), -1),
        default="Unknown",
    )


def _developer_finding_item(finding: Any) -> Dict[str, Any]:
    candidate = getattr(finding, "candidate", None)
    request = getattr(candidate, "request", None) if candidate else None
    endpoint = (
        getattr(request, "endpoint", None)
        or ((candidate.features or {}).get("endpoint") if candidate else None)
        or UNKNOWN_ENDPOINT
    )
    method = (getattr(request, "method", None) or "GET").upper()
    host = _target_host(finding.scan_run.target_url)
    affected_products = _affected_assets(host, endpoint)
    return {
        "title": finding.title,
        "summary": (finding.summary or "").strip(),
        "details": _safe_join_lines(
            [
                f"Endpoint: `{method} {endpoint}`",
                f"Vulnerability type: {(finding.vuln_type or 'unknown').lower()}",
                f"Confidence: {finding.confidence}",
            ]
        ),
        "poc": (finding.reproduction_steps or "").strip(),
        "impact": _safe_join_lines(
            [
                f"Type: {(finding.vuln_type or 'unknown').lower()}",
                f"Severity: {_severity_label(finding.severity)}",
                f"Potentially impacted surface: {_format_impacted_surface(host, endpoint)}",
            ]
        ),
        "affected_products": affected_products,
        "severity": _severity_label(finding.severity),
        "endpoint": endpoint,
        "method": method,
        "vuln_type": (finding.vuln_type or "unknown").lower(),
        "confidence": finding.confidence,
    }


def build_developer_report(run_id: str) -> DeveloperReportResult:
    from django.db.models import Count
    from .models import ScanRun, Finding

    scan_run = ScanRun.objects.get(run_id=run_id)
    findings_qs = Finding.objects.filter(scan_run_id=run_id).select_related("candidate__request")

    severity_counts_map = {k: 0 for k, _ in Finding.Severity.choices}
    for row in findings_qs.values("severity").annotate(c=Count("finding_id")):
        sev = str(row.get("severity") or "info")
        severity_counts_map[sev] = int(row.get("c") or 0)

    finding_items = [_developer_finding_item(f) for f in findings_qs.order_by("-created_at")]
    host = _target_host(scan_run.target_url)

    if finding_items:
        highest_severity = _highest_severity(finding_items)
        executive_summary = (
            f"This report summarizes {len(finding_items)} finding(s) observed on {host}. "
            f"The highest reported severity is {highest_severity}."
        )
    else:
        executive_summary = (
            f"No confirmed findings were stored for {host} in this run. "
            f"The report is provided for developer review and verification only."
        )

    json_obj: Dict[str, Any] = {
        "target_url": scan_run.target_url,
        "status": scan_run.status,
        "generated_at": _now_iso(),
        "executive_summary": executive_summary,
        "findings_count": len(finding_items),
        "findings_by_severity": severity_counts_map,
        "findings": finding_items,
    }

    findings_md = []
    for idx, item in enumerate(finding_items, start=1):
        findings_md.append(
            f"""## Finding {idx}: {item['title']}

### Summary
{item['summary'] or 'No summary provided.'}

### Details
{item['details']}

### PoC
{item['poc'] or 'No reproduction steps stored.'}

### Impact
{item['impact']}

### Affected products
{_safe_join_lines([f"- {value}" for value in item['affected_products']]) or '- unknown'}

### Severity
{item['severity']}
"""
        )

    findings_md_text = (
        "\n\n".join(block.strip() for block in findings_md)
        if findings_md
        else "## Findings\nNo confirmed findings were included in this report."
    )

    md_text = f"""# Developer Vulnerability Report

## Executive Summary
{executive_summary}

## Target
- {scan_run.target_url}

## Findings Overview
- Total findings: {len(finding_items)}
{_safe_join_lines([f"- {k}: {v}" for k, v in severity_counts_map.items()])}

{findings_md_text}
"""

    return DeveloperReportResult(run_id=str(scan_run.run_id), md_text=md_text, json_obj=json_obj)


def build_finding_report(finding_id: str) -> FindingReportResult:
    from .models import Finding, FindingEvidenceLink

    finding = (
        Finding.objects.select_related("scan_run", "candidate__request")
        .get(finding_id=finding_id)
    )
    candidate = finding.candidate
    request = getattr(candidate, "request", None)
    host = _target_host(finding.scan_run.target_url)
    endpoint = (
        getattr(request, "endpoint", None)
        or ((candidate.features or {}).get("endpoint") if candidate else None)
        or UNKNOWN_ENDPOINT
    )
    method = (getattr(request, "method", None) or "GET").upper()
    vuln_type = (finding.vuln_type or getattr(candidate, "vuln_type", None) or "unknown").lower()
    candidate_hypothesis = getattr(candidate, "hypothesis", None) if candidate else None
    severity_label = _severity_label(finding.severity)

    evidence_links = list(
        FindingEvidenceLink.objects.filter(finding=finding).select_related("blob").order_by("created_at")
    )
    evidence_items: List[Dict[str, Any]] = []
    evidence_lines: List[str] = []
    for link in evidence_links:
        blob = link.blob
        preview = (blob.content or "").strip()
        if len(preview) > 240:
            preview = preview[:240] + "..."
        evidence_items.append(
            {
                "blob_id": str(blob.blob_id),
                "kind": blob.kind,
                "role": link.role,
                "storage_ref": blob.storage_ref,
                "sha256": blob.sha256,
                "byte_size": blob.byte_size,
                "content_preview": preview,
                "metadata": blob.metadata,
            }
        )
        evidence_lines.append(
            f"- {blob.kind} / {link.role}: {preview or blob.storage_ref or 'stored evidence'}"
        )

    if finding.summary:
        summary_text = finding.summary.strip()
    else:
        summary_text = (
            f"A {vuln_type} issue may affect {endpoint} on {host}. "
            f"Severity is currently assessed as {severity_label}."
        )

    details_lines = [
        f"Target host: `{host}`",
        f"Endpoint: `{method} {endpoint}`",
        f"Run ID: `{finding.scan_run_id}`",
        f"Finding ID: `{finding.finding_id}`",
    ]
    if candidate_hypothesis:
        details_lines.append(f"Candidate hypothesis: {candidate_hypothesis}")
    if finding.summary:
        details_lines.append(f"Observed summary: {finding.summary.strip()}")
    if evidence_lines:
        details_lines.append("")
        details_lines.append("Supporting evidence:")
        details_lines.extend(evidence_lines[:8])
    else:
        details_lines.append("No linked evidence blobs are currently stored for this finding.")

    if finding.reproduction_steps:
        poc_text = finding.reproduction_steps.strip()
    else:
        poc_text = _safe_join_lines(
            [
                f"1. Send a `{method}` request to `{endpoint}` on `{host}`.",
                "2. Replay the observed request flow with the same authentication context used during the scan.",
                "3. Compare the returned status code, response body, and any linked evidence against the stored finding.",
                "4. Verify whether the suspicious behavior can be reproduced consistently.",
            ]
        )

    impact_lines = [
        f"Vulnerability type: {vuln_type}",
        f"Impacted surface: {_format_impacted_surface(host, endpoint)}",
        f"Current finding severity: {severity_label}",
    ]
    if finding.confidence is not None:
        impact_lines.append(f"Confidence score: {finding.confidence}")

    affected_products = _affected_assets(host, endpoint)

    json_obj: Dict[str, Any] = {
        "finding_id": str(finding.finding_id),
        "run_id": str(finding.scan_run_id),
        "generated_at": _now_iso(),
        "summary": summary_text,
        "details": _safe_join_lines(details_lines),
        "poc": poc_text,
        "impact": _safe_join_lines(impact_lines),
        "affected_products": affected_products,
        "affected_assets": affected_products,
        "severity": severity_label,
        "metadata": {
            "title": finding.title,
            "vuln_type": vuln_type,
            "confidence": finding.confidence,
            "host": host,
            "endpoint": endpoint,
            "method": method,
            "candidate_id": str(finding.candidate_id) if finding.candidate_id else None,
            "evidence_count": len(evidence_items),
            "evidence": evidence_items,
        },
    }

    md_text = f"""## Summary
{json_obj['summary']}

## Details
{json_obj['details']}

## PoC
{json_obj['poc']}

## Impact
{json_obj['impact']}

### Affected products
{_safe_join_lines([f"- {item}" for item in affected_products]) or '- unknown'}

### Severity (Low, Moderate, High, Critical)
{severity_label}
"""

    return FindingReportResult(
        finding_id=str(finding.finding_id),
        md_text=md_text,
        json_obj=json_obj,
    )

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

    # Querysets
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

    # Items limits (payload 보호)
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


def serialize_finding_report_json(report: FindingReportResult) -> str:
    return json.dumps(report.json_obj, ensure_ascii=False, indent=2)


def serialize_finding_report_md(report: FindingReportResult) -> str:
    return report.md_text


def serialize_developer_report_json(report: DeveloperReportResult) -> str:
    return json.dumps(report.json_obj, ensure_ascii=False, indent=2)


def serialize_developer_report_md(report: DeveloperReportResult) -> str:
    return report.md_text
