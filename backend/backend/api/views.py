import threading
import json as json_mod

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status, viewsets
from rest_framework.pagination import PageNumberPagination
from django.db import connection

from .models import (
    ScanRun, LLMTrace, RequestCatalog, Candidate, Finding, EvidenceBlob,
    FindingEvidenceLink, AgentTask, VerificationLoop, Hypothesis,
    VisualAnalysis, IDORTestSession, WAFBypassAttempt,
    VulnerabilityEntry, PayloadPattern, ReportArchive, RunReport,
)
from .serializers import (
    ScanRunSerializer, LLMTraceSerializer, RequestCatalogSerializer, CandidateSerializer,
    FindingSerializer, EvidenceBlobSerializer, FindingEvidenceLinkSerializer,
    AgentTaskSerializer, VerificationLoopSerializer, HypothesisSerializer,
    VisualAnalysisSerializer, IDORTestSessionSerializer, WAFBypassAttemptSerializer,
    VulnerabilityEntrySerializer, PayloadPatternSerializer, ReportArchiveSerializer,
)
from .reporting import build_report, serialize_report_json, serialize_report_md
from .scan_control import request_scan_stop

class StandardPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100

def _paginate(request, queryset, serializer_class):
    paginator = StandardPagination()
    page = paginator.paginate_queryset(queryset, request)
    if page is not None:
        return paginator.get_paginated_response(serializer_class(page, many=True).data)
    return Response(serializer_class(queryset, many=True).data)

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

@api_view(["GET", "POST"])
def scan_runs(request):
    if request.method == "GET":
        return _paginate(request, ScanRun.objects.all().order_by("-created_at"), ScanRunSerializer)

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
def start_scan(request, run_id):
    try:
        scan_run = ScanRun.objects.get(run_id=run_id)
    except ScanRun.DoesNotExist:
        return Response({"error": "run_id not found"}, status=status.HTTP_404_NOT_FOUND)
    if scan_run.status != "queued":
        return Response({"error": f"scan is already {scan_run.status}"}, status=status.HTTP_400_BAD_REQUEST)

    from .services import run_scan
    threading.Thread(target=run_scan, args=(scan_run,), daemon=True).start()
    return Response({"run_id": str(scan_run.run_id), "status": "running", "message": "scan started"})

@api_view(["POST"])
def stop_scan(request, run_id):
    try:
        scan_run = ScanRun.objects.get(run_id=run_id)
    except ScanRun.DoesNotExist:
        return Response({"error": "run_id not found"}, status=status.HTTP_404_NOT_FOUND)

    if scan_run.status not in ("queued", "running"):
        return Response({"error": f"scan is already {scan_run.status}"}, status=status.HTTP_400_BAD_REQUEST)

    request_scan_stop(scan_run)
    return Response({
        "run_id": str(scan_run.run_id),
        "status": "stopped",
        "message": "stop requested",
    })


@api_view(["POST"])
def start_mcp_scan(request, run_id):
    """MCP 에이전트 루프를 사용하는 스캔 시작 엔드포인트."""
    try:
        scan_run = ScanRun.objects.get(run_id=run_id)
    except ScanRun.DoesNotExist:
        return Response({"error": "run_id not found"}, status=status.HTTP_404_NOT_FOUND)
    if scan_run.status != "queued":
        return Response({"error": f"scan is already {scan_run.status}"}, status=status.HTTP_400_BAD_REQUEST)

    from .mcp_agent import run_mcp_scan
    threading.Thread(target=run_mcp_scan, args=(scan_run,), daemon=True).start()
    return Response({"run_id": str(scan_run.run_id), "status": "running", "message": "MCP agent scan started"})

@api_view(["GET", "PATCH"])
def get_scan_run(request, run_id):
    try:
        scan_run = ScanRun.objects.get(run_id=run_id)
    except ScanRun.DoesNotExist:
        return Response({"error": "run_id not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == "PATCH":
        allowed = {"status", "request_budget_used", "llm_calls_count", "llm_tokens_used", "llm_cost_usd", "finished_at"}
        update_fields = []
        for field in allowed:
            if field in request.data:
                setattr(scan_run, field, request.data[field])
                update_fields.append(field)
        if update_fields:
            update_fields.append("updated_at")
            scan_run.save(update_fields=update_fields)

    return Response(ScanRunSerializer(scan_run).data)


@api_view(["GET"])
def scan_run_llm_traces(request, run_id):
    if not ScanRun.objects.filter(run_id=run_id).exists():
        return Response({"error": "run_id not found"}, status=status.HTTP_404_NOT_FOUND)

    queryset = LLMTrace.objects.filter(scan_run_id=run_id).order_by("-call_index", "-created_at")
    return _paginate(request, queryset, LLMTraceSerializer)

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
    return _paginate(request, RequestCatalog.objects.filter(scan_run_id=run_id), RequestCatalogSerializer)

@api_view(["POST"])
def create_candidate(request):
    run_id = request.data.get("run_id")
    if not run_id:
        return Response({"error": "run_id is required"}, status=status.HTTP_400_BAD_REQUEST)
    if not ScanRun.objects.filter(run_id=run_id).exists():
        return Response({"error": "run_id not found"}, status=status.HTTP_404_NOT_FOUND)

    endpoint = request.data.get("endpoint", "")
    method = request.data.get("method", "GET")
    params = request.data.get("params", {})

    req_catalog = None
    if endpoint:
        req_catalog = RequestCatalog.objects.create(
            scan_run_id=run_id,
            endpoint=endpoint,
            method=method.upper(),
            params=params if isinstance(params, dict) else {},
            source="api_manual",
        )

    data = request.data.copy()
    data["scan_run"] = run_id
    if req_catalog:
        data["request"] = str(req_catalog.req_id)
    serializer = CandidateSerializer(data=data)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response(serializer.data, status=status.HTTP_201_CREATED)

@api_view(["GET"])
def list_candidates(request):
    run_id = request.query_params.get("run_id")
    if not run_id:
        return Response({"error": "run_id query param is required"}, status=status.HTTP_400_BAD_REQUEST)
    return _paginate(request, Candidate.objects.filter(scan_run_id=run_id), CandidateSerializer)

@api_view(["GET"])
def get_candidate(request, cand_id):
    try:
        cand = Candidate.objects.select_related("request").get(cand_id=cand_id)
    except Candidate.DoesNotExist:
        return Response({"error": "candidate not found"}, status=status.HTTP_404_NOT_FOUND)
    return Response(CandidateSerializer(cand).data)

@api_view(["GET"])
def list_findings(request):
    run_id = request.query_params.get("run_id")
    if not run_id:
        return Response({"error": "run_id query param is required"}, status=status.HTTP_400_BAD_REQUEST)
    return _paginate(request, Finding.objects.filter(scan_run_id=run_id), FindingSerializer)

@api_view(["GET"])
def get_finding(request, finding_id):
    try:
        finding = Finding.objects.get(finding_id=finding_id)
    except Finding.DoesNotExist:
        return Response({"error": "finding_id not found"}, status=status.HTTP_404_NOT_FOUND)
    return Response(FindingSerializer(finding).data)

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

@api_view(["POST"])
def create_finding_evidence_link(request):
    finding_id = request.data.get("finding_id")
    blob_id = request.data.get("blob_id")
    role = request.data.get("role", "supporting")
    if not finding_id or not blob_id:
        return Response({"error": "finding_id and blob_id are required"}, status=status.HTTP_400_BAD_REQUEST)
    if not EvidenceBlob.objects.filter(blob_id=blob_id).exists():
        return Response({"error": "blob_id not found"}, status=status.HTTP_404_NOT_FOUND)
    link = FindingEvidenceLink.objects.create(finding_id=finding_id, blob_id=blob_id, role=role)
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
    return Response(FindingEvidenceLinkSerializer(
        FindingEvidenceLink.objects.filter(finding_id=finding_id), many=True
    ).data)

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

@api_view(["POST"])
def confirm_candidate(request, cand_id):
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
def dismiss_candidate(request, cand_id):
    from .storage_service import dismiss_candidate as do_dismiss, StorageError
    try:
        result = do_dismiss(cand_id=cand_id, reason=request.data.get("reason", "false_positive"))
        return Response(result)
    except StorageError as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
def attach_evidence(request, finding_id):
    from .storage_service import attach_evidence as do_attach, StorageError
    try:
        result = do_attach(finding_id=finding_id, evidence_data=request.data.get("evidence", request.data))
        return Response(result, status=status.HTTP_201_CREATED)
    except StorageError as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

@api_view(["GET"])
def finding_detail(request, finding_id):
    from .storage_service import get_finding_detail, StorageError
    try:
        return Response(get_finding_detail(finding_id=finding_id))
    except StorageError as e:
        return Response({"error": str(e)}, status=status.HTTP_404_NOT_FOUND)

@api_view(["GET"])
def scan_findings_summary(request, run_id):
    from .storage_service import get_scan_findings_summary
    return Response(get_scan_findings_summary(run_id=run_id))

@api_view(["POST"])
def llm_analyze_candidates(request, run_id):
    try:
        scan_run = ScanRun.objects.get(run_id=run_id)
    except ScanRun.DoesNotExist:
        return Response({"error": "run_id not found"}, status=status.HTTP_404_NOT_FOUND)

    import os
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return Response({"error": "ANTHROPIC_API_KEY not set"}, status=status.HTTP_400_BAD_REQUEST)

    max_candidates = request.data.get("max_candidates", 10)
    from .services import run_llm_screen
    threading.Thread(target=run_llm_screen, args=(scan_run, max_candidates), daemon=True).start()
    return Response({"run_id": str(run_id), "message": "LLM analysis started", "max_candidates": max_candidates})

@api_view(["POST"])
def llm_analyze_single(request):
    import os
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return Response({"error": "ANTHROPIC_API_KEY not set"}, status=status.HTTP_400_BAD_REQUEST)
    from .llm_router import analyze_candidate
    return Response(analyze_candidate(request.data))

@api_view(["POST"])
def start_verification(request, run_id):
    try:
        scan_run = ScanRun.objects.get(run_id=run_id)
    except ScanRun.DoesNotExist:
        return Response({"error": "run_id not found"}, status=status.HTTP_404_NOT_FOUND)

    max_candidates = request.data.get("max_candidates", 5)
    min_confidence = request.data.get("min_confidence", 0.3)

    from .verifier import run_verification_for_scan
    threading.Thread(
        target=run_verification_for_scan, args=(scan_run,),
        kwargs={"max_candidates": max_candidates, "min_confidence": min_confidence},
        daemon=True,
    ).start()
    return Response({"run_id": str(run_id), "message": "verification started", "max_candidates": max_candidates})

@api_view(["POST"])
def verify_single_candidate(request, cand_id):
    try:
        candidate = Candidate.objects.select_related("scan_run", "request").get(cand_id=cand_id)
    except Candidate.DoesNotExist:
        return Response({"error": "candidate not found"}, status=status.HTTP_404_NOT_FOUND)
    if candidate.status not in ("open", "verifying"):
        return Response({"error": f"candidate status is '{candidate.status}'"}, status=status.HTTP_400_BAD_REQUEST)

    from .verifier import run_verification_loop
    return Response(run_verification_loop(candidate, candidate.scan_run))

@api_view(["GET"])
def list_verification_loops(request, cand_id):
    loops = VerificationLoop.objects.filter(candidate_id=cand_id).order_by("attempt_number")
    return Response({"cand_id": cand_id, "loops": VerificationLoopSerializer(loops, many=True).data})

@api_view(["GET", "POST"])
def scan_run_report(request, run_id):
    run_id = str(run_id)

    if request.method == "POST":
        report = build_report(run_id)
        scan_run = ScanRun.objects.get(run_id=run_id)
        rr, _ = RunReport.objects.update_or_create(
            scan_run=scan_run,
            defaults={"json": serialize_report_json(report), "markdown": serialize_report_md(report)},
        )
        return Response({
            "run_id": run_id,
            "report_id": str(rr.report_id),
            "created_at": rr.created_at.isoformat() if rr.created_at else None,
            "updated_at": rr.updated_at.isoformat() if rr.updated_at else None,
            "message": "report generated",
        }, status=status.HTTP_201_CREATED)

    rr = RunReport.objects.filter(scan_run__run_id=run_id).order_by("-updated_at").first()
    if not rr:
        return Response({"detail": "report not generated yet. POST this endpoint first."}, status=status.HTTP_404_NOT_FOUND)

    fmt = (request.query_params.get("format") or request.query_params.get("export") or "json").lower().strip()
    if fmt in ("md", "markdown"):
        return Response({"run_id": run_id, "format": "md", "content": rr.markdown})
    return Response({"run_id": run_id, "format": "json", "content": json_mod.loads(rr.json)})
