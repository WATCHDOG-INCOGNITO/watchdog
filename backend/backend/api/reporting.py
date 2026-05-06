# backend/backend/api/reporting.py
from __future__ import annotations

import json
import re
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


@dataclass
class AggregateReportResult:
    scope: str
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


def _mapping_for(vuln_type: str | None) -> Dict[str, Any]:
    normalized = (vuln_type or "unknown").lower().strip()
    mappings = {
        "sqli": {
            "mitre": {"tactic": "Initial Access / Execution", "technique": "Exploit Public-Facing Application"},
            "cwe": {"id": "CWE-89", "name": "SQL Injection"},
            "cvss": {"score": 8.1, "severity": "High"},
        },
        "idor": {
            "mitre": {"tactic": "Privilege Escalation / Access Control", "technique": "Abuse of Authorization Logic"},
            "cwe": {"id": "CWE-639", "name": "Authorization Bypass Through User-Controlled Key"},
            "cvss": {"score": 6.5, "severity": "Moderate"},
        },
        "information_disclosure": {
            "mitre": {"tactic": "Collection / Information Disclosure", "technique": "Data from Information Repositories"},
            "cwe": {"id": "CWE-200", "name": "Exposure of Sensitive Information"},
            "cvss": {"score": 5.3, "severity": "Moderate"},
        },
        "xss": {
            "mitre": {"tactic": "Execution", "technique": "Exploitation for Client Execution"},
            "cwe": {"id": "CWE-79", "name": "Improper Neutralization of Input During Web Page Generation"},
            "cvss": {"score": 6.1, "severity": "Moderate"},
        },
        "csrf": {
            "mitre": {"tactic": "Initial Access / Impact", "technique": "Exploitation of Trusted Relationship"},
            "cwe": {"id": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)"},
            "cvss": {"score": 4.8, "severity": "Moderate"},
        },
        "auth_bypass": {
            "mitre": {"tactic": "Defense Evasion / Privilege Escalation", "technique": "Abuse of Authentication Logic"},
            "cwe": {"id": "CWE-287", "name": "Improper Authentication"},
            "cvss": {"score": 8.8, "severity": "High"},
        },
    }
    return mappings.get(normalized, {
        "mitre": {"tactic": "Collection / Discovery", "technique": "Analyze Application Behavior"},
        "cwe": {"id": "CWE-693", "name": "Protection Mechanism Failure"},
        "cvss": {"score": 4.0, "severity": "Low"},
    })


def _confidence_prefix(confidence: Any) -> str:
    try:
        score = float(confidence)
    except Exception:
        score = 0.0
    return "Potential issue" if score < 0.7 else "Confirmed vulnerability"


def _is_low_confidence(confidence: Any) -> bool:
    return _confidence_prefix(confidence) == "Potential issue"


def _soften_low_confidence_text(text: str, confidence: Any) -> str:
    value = str(text or "").strip()
    if not value or not _is_low_confidence(confidence):
        return value
    replacements = {
        "confirmed vulnerability": "potential issue",
        "Confirmed vulnerability": "Potential issue",
        "vulnerability confirmed": "possible vulnerability observed",
        "Vulnerability confirmed": "Possible vulnerability observed",
        "IDOR vulnerability confirmed": "possible IDOR signal observed",
        "indicating improper access control": "suggesting possible access control inconsistency",
        "Improper access control": "Possible access control inconsistency",
        "improper access control": "possible access control inconsistency",
        "users can access notifications they shouldn't have access to": "this may indicate a potential access control issue. Additional validation is required to confirm unauthorized access.",
        "can access notifications they shouldn't have access to": "may indicate a potential access control issue. Additional validation is required to confirm unauthorized access.",
        "users may be able to access notifications from competitions they shouldn't have access to": "this may indicate a potential access control issue. Additional validation is required to confirm unauthorized access.",
        "may be able to access notifications from competitions they shouldn't have access to": "may indicate a potential access control issue. Additional validation is required to confirm unauthorized access.",
        "lack of proper access control": "possible access control inconsistency",
    }
    for old, new in replacements.items():
        value = value.replace(old, new)
    value = re.sub(r"\bcan access\b", "may be able to access", value, flags=re.IGNORECASE)
    value = re.sub(r"\bis vulnerable to\b", "may be vulnerable to", value, flags=re.IGNORECASE)
    value = re.sub(r"\bconfirms\b", "suggests", value, flags=re.IGNORECASE)
    value = re.sub(r"\.\.+", ".", value)
    value = re.sub(r"\.\s*\.", ".", value)
    return value


def _report_title(title: str, vuln_type: str, endpoint: str, confidence: Any) -> str:
    base = str(title or "Untitled Finding").strip()
    if not _is_low_confidence(confidence):
        return base
    endpoint_name = endpoint if endpoint and endpoint != UNKNOWN_ENDPOINT else "the target endpoint"
    normalized = vuln_type.lower().strip()
    if normalized == "idor":
        return f"Potential Access Control Issue in {endpoint_name}"
    if normalized == "sqli":
        return f"Potential SQL Injection Issue in {endpoint_name}"
    if normalized == "information_disclosure":
        return f"Potential Information Disclosure Issue in {endpoint_name}"
    if normalized == "xss":
        return f"Potential Cross-Site Scripting Issue in {endpoint_name}"
    return f"Potential {normalized.replace('_', ' ').title()} Issue in {endpoint_name}"


def _finalize_low_confidence_item(item: Dict[str, Any]) -> Dict[str, Any]:
    confidence = item.get("confidence")
    if not _is_low_confidence(confidence):
        return item
    finalized = dict(item)
    finalized["title"] = _report_title(item.get("title", ""), item.get("vuln_type", "unknown"), item.get("endpoint", UNKNOWN_ENDPOINT), confidence)
    finalized["summary"] = _soften_low_confidence_text(str(item.get("summary", "")), confidence)
    finalized["details"] = _soften_low_confidence_text(str(item.get("details", "")), confidence)
    finalized["impact"] = _soften_low_confidence_text(str(item.get("impact", "")), confidence)
    return finalized


def _estimate_cvss(vuln_type: str | None, severity_label: str, endpoint: str | None) -> Dict[str, Any]:
    base = _mapping_for(vuln_type)["cvss"]
    score = float(base["score"])
    severity = str(base["severity"])
    endpoint_value = str(endpoint or "").lower()
    if "admin" in endpoint_value or severity_label in ("High", "Critical"):
        score = min(9.1, score + 0.7)
    if severity_label == "Low":
        score = max(3.1, score - 0.8)
        severity = "Low"
    elif severity_label == "Moderate":
        severity = "Moderate" if score < 7.0 else "High"
    elif severity_label in ("High", "Critical"):
        severity = "High" if score < 9.0 else "Critical"
    return {"score": round(score, 1), "severity": severity}


def _extract_concrete_request(method: str, endpoint: str, evidence_lines: List[str]) -> str:
    patterns = [
        r"`((?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+[^\s`]+)`",
        r"((?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+/[^\s]+)",
        r"(/[\w\-./{}]+(?:\?[^`\s]+)?)",
    ]
    for line in evidence_lines:
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                candidate = match.group(1).strip()
                if candidate.startswith("/"):
                    return f"{method} {candidate}"
                return candidate
    return f"{method} {endpoint}"


def _generate_poc(method: str, endpoint: str, evidence_lines: List[str], stored_steps: str | None) -> str:
    if stored_steps and stored_steps.strip():
        return stored_steps.strip()
    concrete_request = _extract_concrete_request(method, endpoint, evidence_lines)
    evidence_summary = evidence_lines[0] if evidence_lines else "No stored evidence summary available."
    return _safe_join_lines([
        f"1. Send the observed request: `{concrete_request}`.",
        "2. Use the same authentication context and headers that were present during scanning.",
        "3. Compare the returned status code, body structure, and visible data against the baseline response.",
        f"4. Confirm the observed evidence from the stored result: {evidence_summary}",
    ])


def _summary_text(vuln_type: str, endpoint: str, host: str, confidence: Any, summary: str | None) -> str:
    prefix = _confidence_prefix(confidence)
    if summary and summary.strip():
        return _soften_low_confidence_text(summary.strip(), confidence)
    return f"{prefix} involving {vuln_type} was observed on {endpoint} at {host}."


def _highest_severity(items: List[Dict[str, Any]]) -> str:
    return max(
        (item.get("severity", "Unknown") for item in items),
        key=lambda severity: SEVERITY_RANK.get(str(severity), -1),
        default="Unknown",
    )


def _flow_tactic(item: Dict[str, Any]) -> str:
    tactic = str(((item.get("mitre") or {}).get("tactic")) or "Discovery").strip()
    if _is_low_confidence(item.get("confidence")):
        if "Privilege Escalation" in tactic or "Access Control" in tactic:
            return "Potential Privilege Escalation / Access Control"
        if "Defense Evasion" in tactic:
            return "Potential Defense Evasion"
        if "Initial Access" in tactic or "Execution" in tactic:
            return f"Potential {tactic}"
        if "Collection" in tactic:
            return "Potential Collection"
        return f"Potential {tactic}"
    return tactic


def _mitre_flow_summary(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    confirmed_path: List[str] = []
    potential_extension: List[str] = []
    basis_lines: List[str] = []

    def _append_unique(values: List[str], value: str) -> None:
        if value and value not in values:
            values.append(value)

    for item in items:
        tactic = _flow_tactic(item)
        title = str(item.get("title") or "Untitled finding").strip()
        endpoint = str(item.get("endpoint") or UNKNOWN_ENDPOINT).strip()
        low_conf = _is_low_confidence(item.get("confidence"))
        if low_conf:
            _append_unique(potential_extension, tactic)
            basis_lines.append(
                f"- {title} in `{endpoint}` may indicate {tactic} and requires additional validation."
            )
        else:
            _append_unique(confirmed_path, tactic)
            basis_lines.append(
                f"- {title} in `{endpoint}` supports {tactic}."
            )

    observed_flow = " → ".join(confirmed_path + potential_extension) if (confirmed_path or potential_extension) else "No ATT&CK flow derived from generated findings."
    return {
        "observed_flow": observed_flow,
        "confirmed_path": confirmed_path,
        "potential_extension": potential_extension,
        "basis": basis_lines,
    }


def _mitre_flow_md(flow: Dict[str, Any]) -> str:
    confirmed = " → ".join(flow.get("confirmed_path") or []) or "None"
    potential = " → ".join(flow.get("potential_extension") or []) or "None"
    basis = _safe_join_lines(flow.get("basis") or ["- No supporting findings were available."])
    return f"""## MITRE ATT&CK Flow Summary
Observed / potential attack flow based on generated findings:

- Observed flow: {flow.get('observed_flow') or 'No ATT&CK flow derived from generated findings.'}

Confirmed path:
{confirmed}

Potential extension:
{potential}

Basis:
{basis}
"""


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
    vuln_type = (finding.vuln_type or "unknown").lower()
    severity_label = _severity_label(finding.severity)
    candidate_hypothesis = getattr(candidate, "hypothesis", None) if candidate else None
    mapping = _mapping_for(vuln_type)
    cvss = _estimate_cvss(vuln_type, severity_label, endpoint)
    evidence_lines: List[str] = []
    try:
        evidence_links = list(finding.evidence_links.select_related("blob").all()[:4])
        for link in evidence_links:
            blob = link.blob
            preview = (blob.content or "").strip()
            if len(preview) > 180:
                preview = preview[:180] + "..."
            evidence_lines.append(_soften_low_confidence_text(preview or blob.storage_ref or "stored evidence", finding.confidence))
    except Exception:
        evidence_lines = []
    report_severity = cvss["severity"]
    item = {
        "title": _report_title(finding.title, vuln_type, endpoint, finding.confidence),
        "summary": _summary_text(vuln_type, endpoint, host, finding.confidence, finding.summary),
        "details": _safe_join_lines(
            [
                f"Endpoint: `{method} {endpoint}`",
                f"Vulnerability type: {vuln_type}",
                f"Confidence: {finding.confidence}",
                f"Hypothesis: {candidate_hypothesis}" if candidate_hypothesis else "",
                "Observed evidence:" if evidence_lines else "",
                *evidence_lines[:6],
            ]
        ),
        "mitre": mapping["mitre"],
        "cwe": mapping["cwe"],
        "cvss": cvss,
        "poc": _generate_poc(method, endpoint, evidence_lines, finding.reproduction_steps),
        "impact": _safe_join_lines(
            [
                (
                    "This potential issue may indicate a possible "
                    f"{vuln_type} condition. Additional validation is required to confirm exploitability."
                    if _is_low_confidence(finding.confidence)
                    else f"This confirmed vulnerability is categorized as {vuln_type}."
                ),
                f"Severity: {report_severity}",
                f"Potentially impacted surface: {_format_impacted_surface(host, endpoint)}",
            ]
        ),
        "affected_products": affected_products,
        "severity": report_severity,
        "endpoint": endpoint,
        "method": method,
        "vuln_type": vuln_type,
        "confidence": finding.confidence,
    }
    return _finalize_low_confidence_item(item)


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
    flow = _mitre_flow_summary(finding_items)

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
        "mitre_flow": flow,
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

### MITRE ATT&CK
- Tactic: {item['mitre']['tactic']}
- Technique: {item['mitre']['technique']}

### CWE
- {item['cwe']['id']}: {item['cwe']['name']}

### CVSS
- Score: {item['cvss']['score']}
- Severity: {item['cvss']['severity']}

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

{_mitre_flow_md(flow)}

{findings_md_text}
"""

    return DeveloperReportResult(run_id=str(scan_run.run_id), md_text=md_text, json_obj=json_obj)


def build_aggregate_developer_report(host: str | None = None) -> AggregateReportResult:
    from .models import Finding

    findings_qs = Finding.objects.select_related("scan_run", "candidate__request").order_by("scan_run__target_url", "-created_at")
    if host:
        findings_qs = [f for f in findings_qs if _target_host(f.scan_run.target_url) == host]
    else:
        findings_qs = list(findings_qs)

    findings_by_target: Dict[str, List[Dict[str, Any]]] = {}
    for finding in findings_qs:
        item = _developer_finding_item(finding)
        target_url = finding.scan_run.target_url
        findings_by_target.setdefault(target_url, []).append(item)

    all_items = [item for items in findings_by_target.values() for item in items]
    target_urls = list(findings_by_target.keys())
    highest_severity = _highest_severity(all_items) if all_items else "Unknown"
    scope = host or "all-runs"
    overall_flow = _mitre_flow_summary(all_items)

    if all_items:
        executive_summary = (
            f"This report consolidates {len(all_items)} finding(s) across {len(target_urls)} scanned URL(s). "
            f"The highest reported severity is {highest_severity}."
        )
    else:
        executive_summary = "No confirmed findings were stored across the selected URLs."

    json_obj: Dict[str, Any] = {
        "scope": scope,
        "generated_at": _now_iso(),
        "executive_summary": executive_summary,
        "targets_count": len(target_urls),
        "findings_count": len(all_items),
        "mitre_flow": overall_flow,
        "targets": [
            {
                "target_url": target_url,
                "findings_count": len(items),
                "mitre_flow": _mitre_flow_summary(items),
                "findings": items,
            }
            for target_url, items in findings_by_target.items()
        ],
    }

    target_blocks: List[str] = []
    for target_url, items in findings_by_target.items():
        target_flow = _mitre_flow_summary(items)
        finding_blocks = []
        for idx, item in enumerate(items, start=1):
            finding_blocks.append(
                f"""### Finding {idx}: {item['title']}

### Summary
{item['summary'] or 'No summary provided.'}

### Details
{item['details']}

### MITRE ATT&CK
- Tactic: {item['mitre']['tactic']}
- Technique: {item['mitre']['technique']}

### CWE
- {item['cwe']['id']}: {item['cwe']['name']}

### CVSS
- Score: {item['cvss']['score']}
- Severity: {item['cvss']['severity']}

### PoC
{item['poc'] or 'No reproduction steps stored.'}

### Impact
{item['impact']}

### Affected products
{_safe_join_lines([f"- {value}" for value in item['affected_products']]) or '- unknown'}

### Severity (Low, Moderate, High, Critical)
{item['severity']}
"""
            )

        target_blocks.append(
            f"""## Target URL
{target_url}

{chr(10).join(block.strip() for block in finding_blocks) if finding_blocks else 'No confirmed findings for this URL.'}
"""
        )

    md_text = f"""# Consolidated Vulnerability Report

## Executive Summary
{executive_summary}

{_mitre_flow_md(overall_flow)}

## Included URLs
{_safe_join_lines([f"- {target}" for target in target_urls]) or '- none'}

{chr(10).join(block.strip() for block in target_blocks) if target_blocks else 'No confirmed findings were included in this report.'}
"""

    return AggregateReportResult(scope=scope, md_text=md_text, json_obj=json_obj)


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
    mapping = _mapping_for(vuln_type)
    cvss = _estimate_cvss(vuln_type, severity_label, endpoint)

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

    summary_text = _summary_text(vuln_type, endpoint, host, finding.confidence, finding.summary)

    details_lines = [
        f"Target host: `{host}`",
        f"Endpoint: `{method} {endpoint}`",
        f"Vulnerability type: {vuln_type}",
        f"Confidence: {finding.confidence}",
    ]
    if candidate_hypothesis:
        details_lines.append(f"Candidate hypothesis: {candidate_hypothesis}")
    if finding.summary:
        details_lines.append(f"Observed summary: {_soften_low_confidence_text(finding.summary.strip(), finding.confidence)}")
    if evidence_lines:
        details_lines.append("")
        details_lines.append("Supporting evidence:")
        details_lines.extend(evidence_lines[:8])
    else:
        details_lines.append("No linked evidence blobs are currently stored for this finding.")

    poc_text = _generate_poc(method, endpoint, evidence_lines, finding.reproduction_steps)

    impact_lines = [
        (
            f"This potential issue may indicate a possible {vuln_type} condition. Additional validation is required to confirm exploitability."
            if _is_low_confidence(finding.confidence)
            else f"This confirmed vulnerability is categorized as {vuln_type}"
        ),
        f"Impacted surface: {_format_impacted_surface(host, endpoint)}",
        f"Current finding severity: {cvss['severity']}",
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
        "mitre": mapping["mitre"],
        "cwe": mapping["cwe"],
        "cvss": cvss,
        "poc": poc_text,
        "impact": _safe_join_lines(impact_lines),
        "affected_products": affected_products,
        "affected_assets": affected_products,
        "severity": cvss["severity"],
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

## MITRE ATT&CK
- Tactic: {json_obj['mitre']['tactic']}
- Technique: {json_obj['mitre']['technique']}

## CWE
- {json_obj['cwe']['id']}: {json_obj['cwe']['name']}

## CVSS
- Score: {json_obj['cvss']['score']}
- Severity: {json_obj['cvss']['severity']}

## PoC
{json_obj['poc']}

## Impact
{json_obj['impact']}

### Affected products
{_safe_join_lines([f"- {item}" for item in affected_products]) or '- unknown'}

### Severity (Low, Moderate, High, Critical)
{cvss['severity']}
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


def serialize_aggregate_report_json(report: AggregateReportResult) -> str:
    return json.dumps(report.json_obj, ensure_ascii=False, indent=2)


def serialize_aggregate_report_md(report: AggregateReportResult) -> str:
    return report.md_text
