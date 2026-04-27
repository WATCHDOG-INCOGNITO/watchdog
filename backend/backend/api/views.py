import threading
import json as json_mod
import time
import hashlib
from datetime import timedelta

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status, viewsets
from rest_framework.pagination import PageNumberPagination
from django.db import connection
from django.http import StreamingHttpResponse
from django.utils import timezone

from .models import (
    ScanRun, LLMTrace, RequestCatalog, Candidate, Finding, EvidenceBlob,
    FindingEvidenceLink, AgentTask, VerificationLoop, Hypothesis,
    VisualAnalysis, IDORTestSession, WAFBypassAttempt,
    VulnerabilityEntry, PayloadPattern, ReportArchive, RunReport,
    OOBHit,
)
from .serializers import (
    ScanRunSerializer, LLMTraceSerializer, RequestCatalogSerializer, CandidateSerializer,
    FindingSerializer, EvidenceBlobSerializer, FindingEvidenceLinkSerializer,
    AgentTaskSerializer, VerificationLoopSerializer, HypothesisSerializer,
    VisualAnalysisSerializer, IDORTestSessionSerializer, WAFBypassAttemptSerializer,
    VulnerabilityEntrySerializer, PayloadPatternSerializer, ReportArchiveSerializer,
)
from .reporting import (
    build_report,
    build_developer_report,
    build_finding_report,
    serialize_report_json,
    serialize_report_md,
)
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


# ── OOB callback receiver ────────────────────────────────────
# 공격 페이로드(XSS bot, SSRF, RCE 등)가 외부로 cookie/data를 보낼 때 사용할 endpoint.
# admin bot이 우리 backend를 hit하면 method/headers/query/body 전부 OOBHit으로 저장.
# tools_oob.oob_get_hits 가 token으로 폴링.

@api_view(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def oob_receiver(request, token):
    body = ""
    try:
        body = request.body.decode("utf-8", errors="replace")[:8000]
    except Exception:
        pass
    OOBHit.objects.create(
        token=token,
        method=request.method,
        path=request.path,
        query_string=request.META.get("QUERY_STRING", "")[:4000],
        headers={k: v for k, v in request.META.items()
                 if k.startswith("HTTP_") or k in ("CONTENT_TYPE", "CONTENT_LENGTH")},
        body=body,
        remote_addr=request.META.get("REMOTE_ADDR", ""),
    )
    return Response({"received": True, "token": token})

@api_view(["GET", "POST"])
def scan_runs(request):
    if request.method == "GET":
        return _paginate(request, ScanRun.objects.all().order_by("-created_at"), ScanRunSerializer)

    data = {
        "target_url": request.data.get("target_url", "http://example.com"),
        # default discovery — MLLA / critic / multi_http_probe / SimHash dedup 흐름.
        # frontend 트리 버튼 + worker swarm 활용. hybrid-lite 명시 시에만 그쪽 흐름.
        "mode": request.data.get("mode", "discovery"),
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
    qs = Finding.objects.filter(scan_run_id=run_id).prefetch_related("evidence_links")
    return _paginate(request, qs, FindingSerializer)

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
    kind = (request.query_params.get("kind") or request.data.get("kind") or "summary").lower().strip()

    if request.method == "POST":
        if kind == "developer":
            report = build_developer_report(run_id)
            fmt = (request.query_params.get("format") or request.data.get("format") or "md").lower().strip()
            if fmt in ("json",):
                return Response({"run_id": run_id, "kind": "developer", "format": "json", "content": report.json_obj}, status=status.HTTP_201_CREATED)
            return Response({"run_id": run_id, "kind": "developer", "format": "md", "content": report.md_text}, status=status.HTTP_201_CREATED)

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

    if kind == "developer":
        report = build_developer_report(run_id)
        fmt = (request.query_params.get("format") or request.query_params.get("export") or "md").lower().strip()
        if fmt in ("json",):
            return Response({"run_id": run_id, "kind": "developer", "format": "json", "content": report.json_obj})
        return Response({"run_id": run_id, "kind": "developer", "format": "md", "content": report.md_text})

    rr = RunReport.objects.filter(scan_run__run_id=run_id).order_by("-updated_at").first()
    if not rr:
        return Response({"detail": "report not generated yet. POST this endpoint first."}, status=status.HTTP_404_NOT_FOUND)

    fmt = (request.query_params.get("format") or request.query_params.get("export") or "json").lower().strip()
    if fmt in ("md", "markdown"):
        return Response({"run_id": run_id, "format": "md", "content": rr.markdown})
    return Response({"run_id": run_id, "format": "json", "content": json_mod.loads(rr.json)})


@api_view(["GET", "POST"])
def finding_report(request, finding_id):
    finding_id = str(finding_id)
    try:
        report = build_finding_report(finding_id)
    except Finding.DoesNotExist:
        return Response({"detail": "finding not found"}, status=status.HTTP_404_NOT_FOUND)
    fmt = (request.query_params.get("format") or request.data.get("format") or "md").lower().strip()
    if fmt in ("json",):
        return Response({"finding_id": finding_id, "format": "json", "content": report.json_obj})
    return Response({"finding_id": finding_id, "format": "md", "content": report.md_text})


@api_view(["GET"])
def discovery_tree(request, run_id):
    from django.db.models import Count
    from .models import DiscoveryNode
    from .serializers import DiscoveryNodeSerializer

    nodes = (
        DiscoveryNode.objects
        .filter(scan_run_id=run_id)
        .annotate(_children_count=Count("children"))
        .order_by("depth", "created_at")
    )
    return Response(DiscoveryNodeSerializer(nodes, many=True).data)


# ── Agent Working Route (real-time activity) ─────────────────────────────
# LLMTrace.target_node FK 덕분에 "지금 뭘 하고 있나"를 빠르게 조회할 수 있다.
# snapshot: 첫 paint / SSE reconnect 복구 용.
# activity_stream: text/event-stream SSE — 2초 폴링 + dedup push.

_ACTIVE_WINDOW_SEC = 30
_TIMELINE_LIMIT = 50


def _extract_tool_detail(tool_calls):
    """tool_calls JSON payload 에서 사람 읽기 쉬운 한 줄 요약 뽑기."""
    if not isinstance(tool_calls, list) or not tool_calls:
        return "", ""
    first = tool_calls[0] if isinstance(tool_calls[0], dict) else {}
    tool_name = first.get("tool") or first.get("name") or ""
    params = first.get("params") or first.get("input") or {}
    if isinstance(params, dict):
        method = params.get("method") or ""
        url = params.get("url") or params.get("endpoint") or params.get("target_url") or ""
        if method and url:
            detail = f"{method} {url}"
        elif url:
            detail = url
        else:
            # fallback: first couple of string values
            bits = []
            for k, v in list(params.items())[:3]:
                if isinstance(v, (str, int, float, bool)):
                    bits.append(f"{k}={v}")
            detail = ", ".join(bits)
    else:
        detail = str(params)[:200]
    return tool_name, detail[:500]


def _compute_activity_snapshot(run_id):
    """최근 traces 기반으로 activity snapshot 생성.

    Returns None if scan_run 자체가 없음.
    """
    from .models import ScanRun, LLMTrace, DiscoveryNode

    try:
        scan_run = ScanRun.objects.get(run_id=run_id)
    except ScanRun.DoesNotExist:
        return None

    traces = list(
        LLMTrace.objects
        .filter(scan_run_id=run_id)
        .select_related("target_node")
        .order_by("-created_at")[:_TIMELINE_LIMIT]
    )

    active_node = None
    active_path = []
    current_tool = ""
    current_tool_detail = ""
    last_activity_at = None

    # 가장 최근에 target_node 가 채워진 trace 하나를 찾는다.
    for tr in traces:
        if tr.target_node_id and active_node is None:
            active_node = tr.target_node
            t_name, t_detail = _extract_tool_detail(tr.tool_calls)
            current_tool = t_name
            current_tool_detail = t_detail
            last_activity_at = tr.created_at
            break

    if last_activity_at is None and traces:
        # target_node 없어도 최근 tool 이름은 보여준다 (banner 에 idle-like 로)
        top = traces[0]
        t_name, t_detail = _extract_tool_detail(top.tool_calls)
        current_tool = t_name
        current_tool_detail = t_detail
        last_activity_at = top.created_at

    if active_node is not None:
        path_ids = []
        cursor = active_node
        safety = 0
        while cursor is not None and safety < 64:
            path_ids.append(str(cursor.node_id))
            cursor = cursor.parent
            safety += 1
        active_path = list(reversed(path_ids))

    # 최근 N초간 trace 의 node_id set
    cutoff = timezone.now() - timedelta(seconds=_ACTIVE_WINDOW_SEC)
    recent_node_ids = {
        str(tr.target_node_id) for tr in traces
        if tr.target_node_id and tr.created_at >= cutoff
    }

    tool_history = []
    for tr in traces:
        t_name, t_detail = _extract_tool_detail(tr.tool_calls)
        tool_history.append({
            "ts": tr.created_at.isoformat() if tr.created_at else None,
            "tool": t_name,
            "stage": tr.stage or "",
            "node_id": str(tr.target_node_id) if tr.target_node_id else None,
            "detail": t_detail,
        })

    return {
        "scan_status": scan_run.status,
        "active_node_id": str(active_node.node_id) if active_node else None,
        "active_node_label": (
            f"{active_node.node_type}:{active_node.endpoint or active_node.summary[:60]}"
            if active_node else ""
        ),
        "active_path": active_path,
        "current_tool": current_tool,
        "current_tool_detail": current_tool_detail,
        "last_activity_at": last_activity_at.isoformat() if last_activity_at else None,
        "recent_node_ids": sorted(recent_node_ids),
        "tool_history": tool_history,
    }


@api_view(["GET"])
def activity_snapshot(request, run_id):
    snap = _compute_activity_snapshot(run_id)
    if snap is None:
        return Response({"error": "scan run not found"}, status=status.HTTP_404_NOT_FOUND)
    return Response(snap)


_SSE_POLL_INTERVAL_SEC = 2
_SSE_MAX_DURATION_SEC = 60 * 30  # 30분 안전 상한 — 아주 긴 세션은 클라이언트가 재연결.


async def activity_stream(request, run_id):
    """Server-Sent Events: 2초마다 snapshot 계산 → hash 바뀔 때만 push.

    scan 이 finished/failed/stopped 로 바뀌면 `event: done` 후 종료.
    async view — Daphne ASGI 에서 proper flush. DB 액세스는 sync_to_async 로 래핑.
    """
    import asyncio
    from asgiref.sync import sync_to_async
    compute = sync_to_async(_compute_activity_snapshot, thread_sensitive=True)

    async def gen():
        last_hash = None
        started = time.time()
        yield "retry: 3000\n\n"
        while True:
            if time.time() - started > _SSE_MAX_DURATION_SEC:
                yield "event: timeout\ndata: {}\n\n"
                return
            snap = await compute(run_id)
            if snap is None:
                yield "event: error\ndata: {\"error\": \"run not found\"}\n\n"
                return
            payload = json_mod.dumps(snap, default=str)
            h = hashlib.md5(payload.encode("utf-8")).hexdigest()
            if h != last_hash:
                yield f"data: {payload}\n\n"
                last_hash = h
            if snap["scan_status"] in ("finished", "failed", "stopped", "completed"):
                yield "event: done\ndata: {}\n\n"
                return
            await asyncio.sleep(_SSE_POLL_INTERVAL_SEC)

    resp = StreamingHttpResponse(gen(), content_type="text/event-stream")
    resp["Cache-Control"] = "no-cache"
    resp["X-Accel-Buffering"] = "no"
    resp["Connection"] = "keep-alive"
    return resp


@api_view(["GET"])
def scan_run_endpoint_specs(request, run_id):
    """이 scan 의 target_host 에 누적된 EndpointSpec 목록.
    frontend NodeDetailPanel 이 endpoint 노드에 명세 표시할 때 사용.
    """
    from urllib.parse import urlparse
    from .models import EndpointSpec

    try:
        scan_run = ScanRun.objects.get(run_id=run_id)
    except ScanRun.DoesNotExist:
        return Response({"error": "scan run not found"}, status=status.HTTP_404_NOT_FOUND)

    # host 표기 — tools_learn._host_of 와 일관. netloc(port 포함) 우선,
    # 없으면 hostname(port 없음) fallback. 매칭은 두 변형 모두 시도.
    parsed = urlparse(scan_run.target_url or "")
    netloc = (parsed.netloc or "").lower()
    hostname = (parsed.hostname or "").lower()
    host = netloc or hostname
    if not host:
        return Response({"host": "", "specs": []})

    # netloc 와 hostname 이 다르면 둘 다 매칭 (legacy data 호환).
    host_variants = list({netloc, hostname} - {""})
    specs = EndpointSpec.objects.filter(target_host__in=host_variants).order_by("-last_seen_at")[:200]
    return Response({
        "host": host,
        "count": len(specs),
        "specs": [
            {
                "spec_id": str(s.spec_id),
                "method": s.method,
                "endpoint": s.endpoint,
                "params_schema": s.params_schema,
                "headers_required": s.headers_required,
                "auth_required": s.auth_required,
                "response_shape": s.response_shape,
                "suspected_vuln_types": s.suspected_vuln_types or [],
                "sink_hints": s.sink_hints or [],
                "times_seen": s.times_seen,
                "notes": s.notes,
                "last_seen_at": s.last_seen_at.isoformat() if s.last_seen_at else None,
            }
            for s in specs
        ],
    })


# ═══════════════════════════════════════════════════════════════════════
# Browser profile bridge — SSO storage_state 파일 관리 + scan 첨부.
# `docker/browser/browser_agent.py` 가 headful chromium 로그인 완료 시
# POST /api/profiles/import/ 로 결과를 밀어넣고, frontend 는 /api/profiles/
# 와 /attach/ 로 scan 에 연결한다.
# ═══════════════════════════════════════════════════════════════════════

import os as _os_pb
import json as _json_pb
from pathlib import Path as _Path_pb

_PROFILE_DIR = _Path_pb(_os_pb.environ.get("PROFILES_DIR", "/app/profiles"))
_BROWSER_AGENT_URL = _os_pb.environ.get("BROWSER_AGENT_URL", "http://browser:8891")


def _profile_file_path(name: str) -> _Path_pb:
    safe = "".join(c for c in (name or "") if c.isalnum() or c in ("-", "_"))[:64]
    if not safe:
        raise ValueError("invalid profile name")
    return _PROFILE_DIR / f"{safe}.json"


def _profile_summary(path: _Path_pb) -> dict:
    try:
        data = _json_pb.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return {"name": path.stem, "error": f"parse_failed: {e}"}
    meta = data.get("_meta") or {}
    cookies = data.get("cookies") or []
    hosts = sorted({(c.get("domain") or "").lstrip(".") for c in cookies if c.get("domain")})
    return {
        "name": path.stem,
        "target": meta.get("target"),
        "saved_at": meta.get("saved_at") or meta.get("refreshed_at"),
        "detected_via": meta.get("detected_via"),
        "cookie_count": len(cookies),
        "cookie_hosts": hosts,
        "origin_count": len(data.get("origins") or []),
    }


@api_view(["GET"])
def profiles_collection(request):
    """List saved SSO profiles (storage_state files under /app/profiles)."""
    _PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    for p in sorted(_PROFILE_DIR.glob("*.json")):
        if p.name.startswith("."):
            continue
        rows.append(_profile_summary(p))
    return Response({"profiles": rows, "dir": str(_PROFILE_DIR)})


@api_view(["POST"])
def profiles_import(request):
    """Accept a storage_state blob (from browser_agent or manual upload) and
    persist it to disk. Payload:
      { "profile_name": "...", "state": {cookies, origins}, "target": "...", "detected_via": "..." }
    """
    body = request.data or {}
    name = (body.get("profile_name") or "").strip()
    state = body.get("state") or {}
    target = body.get("target") or ""
    detected_via = body.get("detected_via") or "manual"
    if not name:
        return Response({"error": "profile_name required"}, status=status.HTTP_400_BAD_REQUEST)
    if not isinstance(state, dict) or "cookies" not in state:
        return Response({"error": "state.cookies missing — not a Playwright storage_state"},
                        status=status.HTTP_400_BAD_REQUEST)
    try:
        path = _profile_file_path(name)
    except ValueError as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    path.parent.mkdir(parents=True, exist_ok=True)
    wrapper = {
        "_meta": {
            "target": target,
            "profile": path.stem,
            "saved_at": timezone.now().isoformat(),
            "detected_via": detected_via,
        },
        **state,
    }
    path.write_text(_json_pb.dumps(wrapper, ensure_ascii=False, indent=2), encoding="utf-8")
    return Response({
        "saved": str(path),
        "summary": _profile_summary(path),
    }, status=status.HTTP_201_CREATED)


@api_view(["GET", "DELETE"])
def profile_detail(request, name):
    try:
        path = _profile_file_path(name)
    except ValueError as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    if not path.exists():
        return Response({"error": "profile not found"}, status=status.HTTP_404_NOT_FOUND)
    if request.method == "DELETE":
        path.unlink()
        return Response({"deleted": str(path)})
    # GET
    summary = _profile_summary(path)
    if request.query_params.get("include_state") == "1":
        try:
            data = _json_pb.loads(path.read_text(encoding="utf-8"))
            state = {k: v for k, v in data.items() if k != "_meta"}
            summary["state"] = state
        except Exception as e:
            summary["state_error"] = str(e)
    return Response(summary)


@api_view(["POST"])
def profile_attach_to_scan(request, name):
    """Bind a saved profile to a ScanRun — reads the JSON file, writes it
    into ScanRun.config for the discovery/manual agent to consume, and syncs
    cookies as per-host _secrets entries so stateless HTTP tools auto-inject
    Cookie headers (see mcp_agent._select_browser_cookie_for_host).
    """
    run_id = (request.data or {}).get("scan_run_id") or request.query_params.get("scan_run_id")
    if not run_id:
        return Response({"error": "scan_run_id required"}, status=status.HTTP_400_BAD_REQUEST)
    try:
        sr = ScanRun.objects.get(run_id=run_id)
    except ScanRun.DoesNotExist:
        return Response({"error": "scan_run not found"}, status=status.HTTP_404_NOT_FOUND)
    try:
        path = _profile_file_path(name)
    except ValueError as e:
        return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    if not path.exists():
        return Response({"error": "profile not found"}, status=status.HTTP_404_NOT_FOUND)
    try:
        data = _json_pb.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return Response({"error": f"profile parse failed: {e}"}, status=500)

    cookies = data.get("cookies") or []
    # build per-host cookie strings
    by_host: dict[str, list[str]] = {}
    for c in cookies:
        h = (c.get("domain") or "").lstrip(".").lower()
        if not h:
            continue
        n = c.get("name") or ""
        v = c.get("value") or ""
        if n:
            by_host.setdefault(h, []).append(f"{n}={v}")

    cfg = dict(sr.config or {})
    secrets = dict(cfg.get("_secrets") or {})
    now = timezone.now().isoformat()
    for h, parts in by_host.items():
        secrets[f"cookie_{h}"] = {
            "value": "; ".join(parts),
            "category": "cookie",
            "stored_at": now,
            "source": f"profile:{name}",
            "host": h,
            "cookie_count": len(parts),
        }
    cfg["_secrets"] = secrets
    cfg["browser_profile"] = name
    cfg["browser_profile_attached_at"] = now
    sr.config = cfg
    sr.save(update_fields=["config"])
    return Response({
        "attached": name,
        "scan_run_id": run_id,
        "hosts": list(by_host.keys()),
        "total_secrets": len(secrets),
    })


@api_view(["POST"])
def browser_login_proxy(request):
    """Relay a login request to the browser agent (so the frontend doesn't
    need to speak to http://localhost:8891 directly — same-origin via
    nginx). Body: {target_url, profile_name}."""
    import requests as _rq
    body = request.data or {}
    try:
        r = _rq.post(f"{_BROWSER_AGENT_URL}/login", json=body, timeout=10)
        return Response(r.json(), status=r.status_code)
    except Exception as e:
        return Response({"error": f"browser agent unreachable: {e}"}, status=502)


@api_view(["GET"])
def browser_login_status(request, task_id):
    import requests as _rq
    try:
        r = _rq.get(f"{_BROWSER_AGENT_URL}/status/{task_id}", timeout=5)
        return Response(r.json(), status=r.status_code)
    except Exception as e:
        return Response({"error": f"browser agent unreachable: {e}"}, status=502)
