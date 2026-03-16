import threading


from django.http import JsonResponse, HttpResponse
from .reporting import build_report, serialize_report_json, serialize_report_md

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status, viewsets
from django.db import connection

from .models import (
    ScanRun, RequestCatalog, Candidate, Finding, EvidenceBlob,
    FindingEvidenceLink, AgentTask, VerificationLoop, Hypothesis,
    VisualAnalysis, IDORTestSession, WAFBypassAttempt,
    VulnerabilityEntry, PayloadPattern, ReportArchive, RunReport,
)
from .serializers import (
    ScanRunSerializer, RequestCatalogSerializer, CandidateSerializer,
    FindingSerializer, EvidenceBlobSerializer, FindingEvidenceLinkSerializer,
    AgentTaskSerializer, VerificationLoopSerializer, HypothesisSerializer,
    VisualAnalysisSerializer, IDORTestSessionSerializer, WAFBypassAttemptSerializer,
    VulnerabilityEntrySerializer, PayloadPatternSerializer, ReportArchiveSerializer,
)


ALLOWED_EVIDENCE_ROLES = {
    "primary_proof", "supporting", "poc", "screenshot", "log", "evidence",
}


# ==========================================================
# Health Check
# ==========================================================
@api_view(["GET"])
def health(request):
    db_alive = False
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            db_alive = cursor.fetchone()[0] == 1
    except Exception:
        pass
    return Response({"ok": True, "db_alive": db_alive})


# ==========================================================
# Scan Run
# ==========================================================
@api_view(["POST"])
def create_scan_run(request):
    data = {
        "target_url": request.data.get("target_url", "http://example.com"),
        "mode": request.data.get("mode", "hybrid-lite"),
        "request_budget_total": request.data.get("request_budget_total", 10),
        "config": request.data.get("config"),
    }
    serializer = ScanRunSerializer(data=data)
    serializer.is_valid(raise_exception=True)
    scan_run = serializer.save()

    return Response({
        "run_id": str(scan_run.run_id),
        "target_url": scan_run.target_url,
        "status": scan_run.status,
        "message": "scan created",
    }, status=status.HTTP_201_CREATED)


@api_view(["POST"])
def start_scan(request, run_id: str):
    """스캔 실행 (크롤링 + 규칙 기반 필터링)"""
    try:
        scan_run = ScanRun.objects.get(run_id=run_id)
    except ScanRun.DoesNotExist:
        return Response({"error": "run_id not found"}, status=status.HTTP_404_NOT_FOUND)

    if scan_run.status != "queued":
        return Response({"error": f"scan is already {scan_run.status}"}, status=status.HTTP_400_BAD_REQUEST)

    from .services import run_scan
    thread = threading.Thread(target=run_scan, args=(scan_run,), daemon=True)
    thread.start()

    return Response({
        "run_id": str(scan_run.run_id),
        "status": "running",
        "message": "scan started",
    })


@api_view(["GET"])
def get_scan_run(request, run_id: str):
    try:
        scan_run = ScanRun.objects.get(run_id=run_id)
    except ScanRun.DoesNotExist:
        return Response({"error": "run_id not found"}, status=status.HTTP_404_NOT_FOUND)
    return Response(ScanRunSerializer(scan_run).data)


# ==========================================================
# Findings
# ==========================================================
@api_view(["GET"])
def list_findings(request):
    run_id = request.query_params.get("run_id")
    if not run_id:
        return Response({"error": "run_id query param is required"}, status=status.HTTP_400_BAD_REQUEST)
    findings = Finding.objects.filter(scan_run_id=run_id)
    return Response({
        "run_id": run_id,
        "findings": FindingSerializer(findings, many=True).data,
    })

@api_view(["GET"])
def get_finding(request, finding_id: str):
    try:
        finding = Finding.objects.get(finding_id=finding_id)
    except Finding.DoesNotExist:
        return Response({"error": "finding_id not found"}, status=status.HTTP_404_NOT_FOUND)
    return Response(FindingSerializer(finding).data)


@api_view(["POST"])
def create_finding(request):
    """Finding 직접 생성"""
    run_id = request.data.get("run_id")
    if not run_id:
        return Response({"error": "run_id is required"}, status=status.HTTP_400_BAD_REQUEST)
    try:
        run = ScanRun.objects.get(run_id=run_id)
    except ScanRun.DoesNotExist:
        return Response({"error": "run_id not found"}, status=status.HTTP_404_NOT_FOUND)

    finding = Finding.objects.create(
        scan_run=run,
        title=request.data.get("title", "finding"),
        severity=request.data.get("severity_raw", "info"),
        confidence=float(request.data.get("confidence", 0.0) or 0.0),
    )
    return Response(FindingSerializer(finding).data, status=status.HTTP_201_CREATED)


@api_view(["POST"])
def promote_candidate_to_finding(request, cand_id: str):
    """Candidate를 Finding으로 승격"""
    try:
        cand = Candidate.objects.get(cand_id=cand_id)
    except Candidate.DoesNotExist:
        return Response({"error": "candidate not found"}, status=status.HTTP_404_NOT_FOUND)

    title = request.data.get("title", cand.vuln_type)
    severity = request.data.get("severity_raw", "info")
    confidence = float(request.data.get("confidence", cand.priority_score) or 0.0)

    finding = Finding.objects.create(
        scan_run=cand.scan_run,
        candidate=cand,
        title=title,
        severity=severity,
        confidence=confidence,
    )
    cand.status = "confirmed"
    cand.save(update_fields=["status"])

    return Response({
        "candidate_id": str(cand.cand_id),
        "finding": FindingSerializer(finding).data,
    }, status=status.HTTP_201_CREATED)


# ==========================================================
# Evidence Blobs
# ==========================================================
@api_view(["POST"])
def create_evidence_blob(request):
    serializer = EvidenceBlobSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    blob = serializer.save()
    return Response({
        "blob_id": str(blob.blob_id),
        "kind": blob.kind,
        "storage_ref": blob.storage_ref,
        "sha256": blob.sha256,
        "byte_size": blob.byte_size,
    }, status=status.HTTP_201_CREATED)


# ==========================================================
# Request Catalog
# ==========================================================
@api_view(["POST"])
def create_request_catalog_item(request):
    run_id = request.data.get("run_id")
    if not run_id:
        return Response({"error": "run_id is required"}, status=status.HTTP_400_BAD_REQUEST)
    if not ScanRun.objects.filter(run_id=run_id).exists():
        return Response({"error": "run_id not found"}, status=status.HTTP_404_NOT_FOUND)
    data = request.data.copy()
    data["scan_run"] = run_id
    serializer = RequestCatalogSerializer(data=data)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response(serializer.data, status=status.HTTP_201_CREATED)


@api_view(["GET"])
def list_request_catalog(request):
    run_id = request.query_params.get("run_id")
    if not run_id:
        return Response({"error": "run_id query param is required"}, status=status.HTTP_400_BAD_REQUEST)
    items = RequestCatalog.objects.filter(scan_run_id=run_id)
    return Response({
        "run_id": run_id,
        "requests": RequestCatalogSerializer(items, many=True).data,
    })


# ==========================================================
# Candidates
# ==========================================================
@api_view(["POST"])
def create_candidate(request):
    run_id = request.data.get("run_id")
    if not run_id:
        return Response({"error": "run_id is required"}, status=status.HTTP_400_BAD_REQUEST)
    if not ScanRun.objects.filter(run_id=run_id).exists():
        return Response({"error": "run_id not found"}, status=status.HTTP_404_NOT_FOUND)
    data = request.data.copy()
    data["scan_run"] = run_id
    serializer = CandidateSerializer(data=data)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response(serializer.data, status=status.HTTP_201_CREATED)


@api_view(["GET"])
def list_candidates(request):
    run_id = request.query_params.get("run_id")
    if not run_id:
        return Response({"error": "run_id query param is required"}, status=status.HTTP_400_BAD_REQUEST)
    items = Candidate.objects.filter(scan_run_id=run_id)
    return Response({
        "run_id": run_id,
        "candidates": CandidateSerializer(items, many=True).data,
    })


# ==========================================================
# Finding-Evidence Links
# ==========================================================
@api_view(["POST"])
def create_finding_evidence_link(request):
    finding_id = request.data.get("finding_id")
    blob_id = request.data.get("blob_id")
    role = request.data.get("role", "supporting")
    if not finding_id or not blob_id:
        return Response({"error": "finding_id and blob_id are required"}, status=status.HTTP_400_BAD_REQUEST)
    if not EvidenceBlob.objects.filter(blob_id=blob_id).exists():
        return Response({"error": "blob_id not found"}, status=status.HTTP_404_NOT_FOUND)
    if role not in ALLOWED_EVIDENCE_ROLES:
        return Response(
            {"error": f"invalid role: {role}", "allowed": sorted(ALLOWED_EVIDENCE_ROLES)},
            status=status.HTTP_400_BAD_REQUEST,
        )
    link = FindingEvidenceLink.objects.create(
        finding_id=finding_id, blob_id=blob_id, role=role,
    )
    return Response({
        "id": str(link.link_id),
        "finding_id": str(link.finding_id),
        "blob_id": str(link.blob_id),
        "role": link.role,
    }, status=status.HTTP_201_CREATED)


@api_view(["GET"])
def list_finding_evidence_links(request):
    finding_id = request.query_params.get("finding_id")
    if not finding_id:
        return Response({"error": "finding_id query param is required"}, status=status.HTTP_400_BAD_REQUEST)
    links = FindingEvidenceLink.objects.filter(finding_id=finding_id)
    return Response({
        "finding_id": finding_id,
        "links": FindingEvidenceLinkSerializer(links, many=True).data,
    })


# ==========================================================
# ViewSets (신규: /api/v1/)
# ==========================================================

class AgentTaskViewSet(viewsets.ModelViewSet):
    queryset = AgentTask.objects.all()
    serializer_class = AgentTaskSerializer
    lookup_field = "task_id"


class VerificationLoopViewSet(viewsets.ModelViewSet):
    queryset = VerificationLoop.objects.all()
    serializer_class = VerificationLoopSerializer
    lookup_field = "loop_id"


class HypothesisViewSet(viewsets.ModelViewSet):
    queryset = Hypothesis.objects.all()
    serializer_class = HypothesisSerializer
    lookup_field = "hypothesis_id"


class VulnerabilityEntryViewSet(viewsets.ModelViewSet):
    queryset = VulnerabilityEntry.objects.all()
    serializer_class = VulnerabilityEntrySerializer
    lookup_field = "vuln_id"


class PayloadPatternViewSet(viewsets.ModelViewSet):
    queryset = PayloadPattern.objects.filter(is_active=True)
    serializer_class = PayloadPatternSerializer
    lookup_field = "pattern_id"


class ReportArchiveViewSet(viewsets.ModelViewSet):
    queryset = ReportArchive.objects.all()
    serializer_class = ReportArchiveSerializer
    lookup_field = "report_id"


# ==========================================================
# P4 Storage API (candidate→finding 전환, evidence 관리)
# ==========================================================

@api_view(["POST"])
def confirm_candidate(request, cand_id: str):
    """candidate를 확정 finding으로 전환"""
    from .storage_service import confirm_candidate as do_confirm, StorageError
    try:
        result = do_confirm(
            cand_id=cand_id,
            severity=request.data.get("severity"),
            title=request.data.get("title"),
            summary=request.data.get("summary"),
            reproduction_steps=request.data.get("reproduction_steps"),
            confidence=request.data.get("confidence"),
            evidence_list=request.data.get("evidence"),
        )
        return Response(result, status=status.HTTP_201_CREATED)
    except StorageError as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
def dismiss_candidate(request, cand_id: str):
    """candidate를 오탐/폐기 처리"""
    from .storage_service import dismiss_candidate as do_dismiss, StorageError
    try:
        reason = request.data.get("reason", "false_positive")
        result = do_dismiss(cand_id=cand_id, reason=reason)
        return Response(result)
    except StorageError as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
def attach_evidence(request, finding_id: str):
    """기존 finding에 evidence 추가"""
    from .storage_service import attach_evidence as do_attach, StorageError
    try:
        result = do_attach(
            finding_id=finding_id,
            evidence_data=request.data.get("evidence", request.data),
        )
        return Response(result, status=status.HTTP_201_CREATED)
    except StorageError as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(["GET"])
def finding_detail(request, finding_id: str):
    """finding + 전체 evidence 한 번에 조회"""
    from .storage_service import get_finding_detail, StorageError
    try:
        result = get_finding_detail(finding_id=finding_id)
        return Response(result)
    except StorageError as e:
        return Response({"error": str(e)}, status=status.HTTP_404_NOT_FOUND)


@api_view(["GET"])
def scan_findings_summary(request, run_id: str):
    """스캔 전체 결과 요약"""
    from .storage_service import get_scan_findings_summary
    result = get_scan_findings_summary(run_id=run_id)
    return Response(result)


# ==========================================================
# LLM 분석 API
# ==========================================================

@api_view(["POST"])
def llm_analyze_candidates(request, run_id: str):
    """특정 스캔의 candidate를 Claude로 분석"""
    try:
        scan_run = ScanRun.objects.get(run_id=run_id)
    except ScanRun.DoesNotExist:
        return Response({"error": "run_id not found"}, status=status.HTTP_404_NOT_FOUND)

    max_candidates = request.data.get("max_candidates", 10)

    from .services import run_llm_screen
    import os
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return Response({"error": "ANTHROPIC_API_KEY not set"}, status=status.HTTP_400_BAD_REQUEST)

    thread = threading.Thread(target=run_llm_screen, args=(scan_run, max_candidates), daemon=True)
    thread.start()

    return Response({
        "run_id": str(run_id),
        "message": "LLM analysis started",
        "max_candidates": max_candidates,
    })


@api_view(["POST"])
def llm_analyze_single(request):
    """단일 candidate를 Claude로 분석 (즉시 응답)"""
    import os
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return Response({"error": "ANTHROPIC_API_KEY not set"}, status=status.HTTP_400_BAD_REQUEST)

    from .llm_router import analyze_candidate
    result = analyze_candidate(request.data)
    return Response(result)

@api_view(["GET", "POST"])
def scan_run_report(request, run_id):
    """
    POST /api/scan-runs/{run_id}/report/  -> generate & store
    GET  /api/scan-runs/{run_id}/report/?format=json|md -> fetch stored
    """
    run_id = str(run_id)

    if request.method == "POST":
        report = build_report(run_id)
        json_text = serialize_report_json(report)
        md_text = serialize_report_md(report)

        scan_run = ScanRun.objects.get(run_id=run_id)
        rr, _ = RunReport.objects.update_or_create(
            scan_run=scan_run,
            defaults={"json": json_text, "markdown": md_text},
        )

        return Response(
            {
                "run_id": run_id,
                "report_id": str(rr.report_id),
                "created_at": rr.created_at.isoformat() if rr.created_at else None,
                "updated_at": rr.updated_at.isoformat() if rr.updated_at else None,
                "message": "report generated",
            },
            status=status.HTTP_201_CREATED,
        )

    # GET
    rr = RunReport.objects.filter(scan_run__run_id=run_id).order_by("-updated_at").first()
    if not rr:
        return Response(
            {"detail": "report not generated yet. POST this endpoint first."},
            status=status.HTTP_404_NOT_FOUND,
        )

    fmt = (request.query_params.get("export") or request.query_params.get("out") or "json").lower().strip()

    if fmt in ("md", "markdown"):
        return HttpResponse(rr.markdown, content_type="text/markdown; charset=utf-8")
    return HttpResponse(rr.json, content_type="application/json; charset=utf-8")


# ==========================================================
# Verification API (검증 루프)
# ==========================================================

@api_view(["POST"])
def start_verification(request, run_id: str):
    """스캔의 candidate들을 검증 (실제 페이로드 전송)"""
    try:
        scan_run = ScanRun.objects.get(run_id=run_id)
    except ScanRun.DoesNotExist:
        return Response({"error": "run_id not found"}, status=status.HTTP_404_NOT_FOUND)

    max_candidates = request.data.get("max_candidates", 5)
    min_confidence = request.data.get("min_confidence", 0.3)

    from .verifier import run_verification_for_scan
    thread = threading.Thread(
        target=run_verification_for_scan,
        args=(scan_run,),
        kwargs={"max_candidates": max_candidates, "min_confidence": min_confidence},
        daemon=True,
    )
    thread.start()

    return Response({
        "run_id": str(run_id),
        "message": "verification started",
        "max_candidates": max_candidates,
    })


@api_view(["POST"])
def verify_single_candidate(request, cand_id: str):
    """단일 candidate를 즉시 검증 (동기)"""
    try:
        candidate = Candidate.objects.select_related("scan_run", "request").get(cand_id=cand_id)
    except Candidate.DoesNotExist:
        return Response({"error": "candidate not found"}, status=status.HTTP_404_NOT_FOUND)

    if candidate.status not in ("open", "verifying"):
        return Response({"error": f"candidate status is '{candidate.status}'"}, status=status.HTTP_400_BAD_REQUEST)

    from .verifier import run_verification_loop
    result = run_verification_loop(candidate, candidate.scan_run)
    return Response(result)


@api_view(["GET"])
def list_verification_loops(request, cand_id: str):
    """candidate의 검증 루프 이력 조회"""
    loops = VerificationLoop.objects.filter(candidate_id=cand_id).order_by("attempt_number")
    return Response({
        "cand_id": cand_id,
        "loops": VerificationLoopSerializer(loops, many=True).data,
    })
