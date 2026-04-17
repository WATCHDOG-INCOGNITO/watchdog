"""
P4 Storage 서비스
- candidate → finding 전환 (confirm)
- evidence 생성 + finding 자동 연결
- finding 상세 조회 (evidence 포함)
"""

import logging
from django.db import transaction

from .models import Candidate, Finding, EvidenceBlob, FindingEvidenceLink

logger = logging.getLogger(__name__)

class StorageError(Exception):
    pass

def confirm_candidate(cand_id, severity=None, title=None, summary=None,
                      reproduction_steps=None, confidence=None, evidence_list=None):
    """
    candidate를 확정 finding으로 전환한다.

    Args:
        cand_id: 확정할 candidate의 UUID
        severity: 심각도 (info/low/medium/high/critical). 없으면 vuln_type으로 추정
        title: finding 제목. 없으면 candidate hypothesis에서 자동 생성
        summary: 취약점 요약
        reproduction_steps: 재현 절차
        confidence: 신뢰도 (0.0~1.0). 없으면 candidate priority_score 사용
        evidence_list: 함께 저장할 evidence 목록
            [{"kind": "request", "content": "GET /...", "storage_ref": "..."}]

    Returns:
        dict: 생성된 finding + evidence 정보
    """
    try:
        candidate = Candidate.objects.select_related("scan_run", "request").get(cand_id=cand_id)
    except Candidate.DoesNotExist:
        raise StorageError(f"candidate {cand_id} not found")

    # 이미 confirmed면 중복 방지
    if candidate.status == "confirmed":
        existing = Finding.objects.filter(candidate=candidate).first()
        if existing:
            raise StorageError(f"candidate already confirmed as finding {existing.finding_id}")

    # 상태 전이 검증: open 또는 verifying만 confirm 가능
    if candidate.status not in ("open", "verifying"):
        raise StorageError(f"candidate status is '{candidate.status}', cannot confirm")

    # 기본값 세팅
    if not title:
        title = f"{candidate.vuln_type.upper()}: {candidate.hypothesis or candidate.request.endpoint if candidate.request else 'unknown'}"
        title = title[:256]

    if severity is None:
        severity = _estimate_severity(candidate.vuln_type, candidate.priority_score)

    if confidence is None:
        confidence = candidate.priority_score

    # 트랜잭션으로 한 번에 처리
    with transaction.atomic():
        # 1. Finding 생성
        finding = Finding.objects.create(
            scan_run=candidate.scan_run,
            candidate=candidate,
            title=title,
            vuln_type=candidate.vuln_type,
            severity=severity,
            confidence=confidence,
            summary=summary or candidate.hypothesis,
            reproduction_steps=reproduction_steps,
        )

        # 2. Candidate 상태 업데이트
        candidate.status = "confirmed"
        candidate.save(update_fields=["status"])

        # 2b. Discovery node 연동: 연결된 노드가 있으면 confirmed로 승격.
        # features.discovery_node_id 가 없으면 endpoint+vuln_type 매칭으로 fallback —
        # create_candidate_manual 이 link 안 했던 candidate 도 자동으로 노드 상태 회복.
        from api.models import DiscoveryNode, EndpointSpec
        from urllib.parse import urlparse as _urlparse
        disc_node_id = (candidate.features or {}).get("discovery_node_id")
        if disc_node_id:
            DiscoveryNode.objects.filter(node_id=disc_node_id).update(status="confirmed")
        else:
            ep = (candidate.request.endpoint if candidate.request else
                  (candidate.features or {}).get("endpoint", "")) or ""
            ep_norm = ep.split("?", 1)[0].rstrip("/") or "/"
            qs = (
                DiscoveryNode.objects
                .filter(scan_run=candidate.scan_run, node_type="vuln")
                .filter(endpoint__in=[ep, ep_norm, ep_norm + "/"])
                .exclude(status="confirmed")
            )
            picked = qs.filter(vuln_type=candidate.vuln_type).order_by("-created_at").first()
            picked = picked or qs.order_by("-created_at").first()
            if picked:
                DiscoveryNode.objects.filter(node_id=picked.node_id).update(status="confirmed")

        # 2c. EndpointSpec 안전망 — 확정된 vuln_type 을 그 endpoint 의 명세에
        # 자동 추가 (다음 scan 의 RouteMap/EntryPoint 가 즉시 활용).
        # host 표기는 netloc 사용 (port 포함) — tools_learn._host_of 와 일관.
        try:
            target_url = candidate.scan_run.target_url or ""
            parsed = _urlparse(target_url)
            host = (parsed.netloc or parsed.hostname or "").lower()
            ep = (candidate.request.endpoint if candidate.request else "") or ""
            method = (candidate.request.method if candidate.request else "GET") or "GET"
            if host and ep:
                spec, _ = EndpointSpec.objects.get_or_create(
                    target_host=host, method=method, endpoint=ep,
                    defaults={"suspected_vuln_types": [candidate.vuln_type]},
                )
                cur = list(spec.suspected_vuln_types or [])
                if candidate.vuln_type and candidate.vuln_type not in cur:
                    cur.append(candidate.vuln_type)
                    spec.suspected_vuln_types = sorted(cur)
                    spec.save(update_fields=["suspected_vuln_types"])
        except Exception as e:
            logger.warning(f"EndpointSpec auto-update failed: {e}")

        # 3. Evidence 생성 + 링크
        created_evidence = []
        if evidence_list:
            for ev in evidence_list:
                blob = EvidenceBlob.objects.create(
                    finding=finding,
                    kind=ev.get("kind", "log"),
                    content=ev.get("content"),
                    storage_ref=ev.get("storage_ref", "local://auto"),
                    sha256=ev.get("sha256"),
                    byte_size=ev.get("byte_size"),
                    metadata=ev.get("metadata"),
                )
                link = FindingEvidenceLink.objects.create(
                    finding=finding,
                    blob=blob,
                    role=ev.get("role", "supporting"),
                )
                created_evidence.append({
                    "blob_id": str(blob.blob_id),
                    "kind": blob.kind,
                    "role": link.role,
                })

    logger.info(f"Candidate {cand_id} → Finding {finding.finding_id} "
                f"(severity={severity}, evidence={len(created_evidence)})")

    return {
        "finding_id": str(finding.finding_id),
        "candidate_id": str(candidate.cand_id),
        "title": finding.title,
        "vuln_type": finding.vuln_type,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "summary": finding.summary,
        "evidence": created_evidence,
    }

def dismiss_candidate(cand_id, reason="false_positive"):
    """
    candidate를 오탐/폐기 처리한다.

    Args:
        cand_id: candidate UUID
        reason: "false_positive" 또는 "dismissed"
    """
    if reason not in ("false_positive", "dismissed"):
        raise StorageError(f"invalid reason: {reason}")

    try:
        candidate = Candidate.objects.get(cand_id=cand_id)
    except Candidate.DoesNotExist:
        raise StorageError(f"candidate {cand_id} not found")

    if candidate.status == "confirmed":
        raise StorageError("confirmed candidate cannot be dismissed")

    candidate.status = reason
    candidate.save(update_fields=["status"])

    # 안전망 — 연결된 vuln 노드를 dead_end 로 자동 전이 (LLM 의 mark_dead_end 누락 보완).
    # discovery_node_id 또는 endpoint+vuln_type fallback.
    from api.models import DiscoveryNode
    from django.utils import timezone
    disc_node_id = (candidate.features or {}).get("discovery_node_id")
    target_node = None
    if disc_node_id:
        target_node = DiscoveryNode.objects.filter(node_id=disc_node_id).first()
    if not target_node:
        ep = ((candidate.features or {}).get("endpoint") or "")
        ep_norm = ep.split("?", 1)[0].rstrip("/") or "/"
        if ep:
            qs = (
                DiscoveryNode.objects
                .filter(scan_run=candidate.scan_run, node_type="vuln")
                .filter(endpoint__in=[ep, ep_norm, ep_norm + "/"])
                .exclude(status__in=["confirmed", "dead_end"])
            )
            target_node = (qs.filter(vuln_type=candidate.vuln_type).order_by("-created_at").first()
                           or qs.order_by("-created_at").first())
    if target_node:
        DiscoveryNode.objects.filter(node_id=target_node.node_id).update(
            status="dead_end", explored_at=timezone.now(),
        )

    logger.info(f"Candidate {cand_id} dismissed ({reason})")
    return {"candidate_id": str(cand_id), "status": reason}

def attach_evidence(finding_id, evidence_data):
    """
    기존 finding에 evidence를 추가한다.

    Args:
        finding_id: finding UUID
        evidence_data: dict or list of dicts
            {"kind": "request", "content": "...", "role": "primary"}
    """
    try:
        finding = Finding.objects.get(finding_id=finding_id)
    except Finding.DoesNotExist:
        raise StorageError(f"finding {finding_id} not found")

    if isinstance(evidence_data, dict):
        evidence_data = [evidence_data]

    created = []
    with transaction.atomic():
        for ev in evidence_data:
            blob = EvidenceBlob.objects.create(
                finding=finding,
                kind=ev.get("kind", "log"),
                content=ev.get("content"),
                storage_ref=ev.get("storage_ref", "local://auto"),
                sha256=ev.get("sha256"),
                byte_size=ev.get("byte_size"),
                metadata=ev.get("metadata"),
            )
            link = FindingEvidenceLink.objects.create(
                finding=finding,
                blob=blob,
                role=ev.get("role", "supporting"),
            )
            created.append({
                "blob_id": str(blob.blob_id),
                "kind": blob.kind,
                "role": link.role,
            })

    logger.info(f"Finding {finding_id}: {len(created)} evidence 추가")
    return {"finding_id": str(finding_id), "evidence_added": created}

def get_finding_detail(finding_id):
    """finding + 전체 evidence를 한 번에 조회"""
    try:
        finding = Finding.objects.select_related("scan_run", "candidate").get(finding_id=finding_id)
    except Finding.DoesNotExist:
        raise StorageError(f"finding {finding_id} not found")

    links = FindingEvidenceLink.objects.filter(finding=finding).select_related("blob")

    evidence = []
    for link in links:
        evidence.append({
            "blob_id": str(link.blob.blob_id),
            "kind": link.blob.kind,
            "role": link.role,
            "content": link.blob.content,
            "storage_ref": link.blob.storage_ref,
            "sha256": link.blob.sha256,
            "byte_size": link.blob.byte_size,
            "metadata": link.blob.metadata,
            "created_at": link.blob.created_at.isoformat(),
        })

    return {
        "finding_id": str(finding.finding_id),
        "scan_run_id": str(finding.scan_run_id),
        "candidate_id": str(finding.candidate_id) if finding.candidate_id else None,
        "title": finding.title,
        "vuln_type": finding.vuln_type,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "summary": finding.summary,
        "reproduction_steps": finding.reproduction_steps,
        "llm_analysis": finding.llm_analysis,
        "created_at": finding.created_at.isoformat(),
        "evidence": evidence,
    }

def get_scan_findings_summary(run_id):
    """스캔 전체 결과 요약 (P5 리포트용)"""
    findings = Finding.objects.filter(scan_run_id=run_id).select_related("candidate")

    summary = {
        "run_id": str(run_id),
        "total_findings": findings.count(),
        "by_severity": {},
        "by_vuln_type": {},
        "findings": [],
    }

    for f in findings:
        # severity별 카운트
        sev = f.severity
        summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1

        # vuln_type별 카운트
        vt = f.vuln_type or "unknown"
        summary["by_vuln_type"][vt] = summary["by_vuln_type"].get(vt, 0) + 1

        evidence_count = FindingEvidenceLink.objects.filter(finding=f).count()

        summary["findings"].append({
            "finding_id": str(f.finding_id),
            "title": f.title,
            "severity": f.severity,
            "confidence": f.confidence,
            "vuln_type": f.vuln_type,
            "evidence_count": evidence_count,
        })

    return summary

# 내부 유틸

def _estimate_severity(vuln_type, priority_score):
    """vuln_type + priority_score로 severity 추정"""
    high_severity_types = {"sqli", "ssrf", "file_upload", "rce", "deserialization"}
    medium_severity_types = {"xss", "idor", "csrf"}

    if vuln_type in high_severity_types:
        if priority_score >= 0.7:
            return "critical"
        return "high"
    elif vuln_type in medium_severity_types:
        if priority_score >= 0.7:
            return "high"
        return "medium"
    else:
        if priority_score >= 0.5:
            return "medium"
        return "low"



# ── GCS 증거 업로드 ──

def upload_evidence_to_gcs(blob: "EvidenceBlob", content_bytes: bytes) -> str:
    """EvidenceBlob의 content를 GCS에 업로드하고 storage_ref를 반환한다."""
    from django.conf import settings
    bucket_name = getattr(settings, "GCS_BUCKET_NAME", "")
    if not bucket_name:
        return "local://auto"

    try:
        from google.cloud import storage as gcs_storage
        client = gcs_storage.Client()
        bucket = client.bucket(bucket_name)
        gcs_path = f"evidence/{blob.finding_id}/{blob.blob_id}/{blob.kind}"
        gcs_blob = bucket.blob(gcs_path)
        gcs_blob.upload_from_string(content_bytes, content_type="application/json")
        ref = f"gs://{bucket_name}/{gcs_path}"
        blob.storage_ref = ref
        blob.save(update_fields=["storage_ref"])
        return ref
    except ImportError:
        return "local://auto"
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"GCS upload failed: {e}")
        return "local://auto"
