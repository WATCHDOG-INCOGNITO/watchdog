import threading

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status, viewsets
from django.db import connection

from .models import (
    ScanRun, RequestCatalog, Candidate, Finding, EvidenceBlob,
    FindingEvidenceLink, AgentTask, VerificationLoop, Hypothesis,
    VisualAnalysis, IDORTestSession, WAFBypassAttempt,
    VulnerabilityEntry, PayloadPattern, ReportArchive,
)
from .serializers import (
    ScanRunSerializer, RequestCatalogSerializer, CandidateSerializer,
    FindingSerializer, EvidenceBlobSerializer, FindingEvidenceLinkSerializer,
    AgentTaskSerializer, VerificationLoopSerializer, HypothesisSerializer,
    VisualAnalysisSerializer, IDORTestSessionSerializer, WAFBypassAttemptSerializer,
    VulnerabilityEntrySerializer, PayloadPatternSerializer, ReportArchiveSerializer,
)


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
