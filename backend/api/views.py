import uuid
from urllib.parse import urlparse

from django.db import transaction
from django.db.models import F
from django.utils.dateparse import parse_datetime
from rest_framework.decorators import api_view
from rest_framework import status

from .response import ok, fail
from .models import (
    ScanRun,
    ScopePolicy,
    RequestCatalogItem,
    Candidate,
    EvidenceBlob,
    Finding,
    FindingEvidenceLink,
)
from .tasks import execute_scan_run


# =========================================================
# 공통: error_log 기록 규칙 (키 고정)
# =========================================================
ALLOWED_ERROR_TYPES = {
    "auth_fail",
    "rate_limit",
    "waf",
    "timeout",
    "parse_error",
    "tool_error",
}


def _extract_host(target_url: str) -> str | None:
    try:
        parsed = urlparse(target_url)
        return parsed.hostname
    except Exception:
        return None


def _get_policy(scope_policy_id: str | None) -> ScopePolicy | None:
    if not scope_policy_id:
        return None
    try:
        return ScopePolicy.objects.get(scope_policy_id=scope_policy_id)
    except ScopePolicy.DoesNotExist:
        return None


def _guardrails_or_none(target_url: str, policy: ScopePolicy | None):
    """
    가드레일:
      - out-of-scope: 403
      - rate_limit/budget: 429
    현재는 "정책 기반 차단"만 최소 구현.
    """
    if not policy:
        return None  # 정책 미지정이면 통과(현 단계용)

    host = _extract_host(target_url)
    if not host:
        return ("parse_error", "Invalid target_url (cannot parse host)", "bad_target_url", status.HTTP_400_BAD_REQUEST)

    allowed_hosts = policy.allowed_hosts or []
    if allowed_hosts and host not in allowed_hosts:
        # out-of-scope 차단 → HTTP 403
        return ("tool_error", f"Out of scope host: {host}", "out_of_scope", status.HTTP_403_FORBIDDEN)

    max_runs = policy.max_runs
    if isinstance(max_runs, int) and max_runs >= 0:
        if int(policy.created_runs or 0) >= max_runs:
            return ("rate_limit", "rate_limit/budget exceeded (policy max_runs)", "rate_limit", status.HTTP_429_TOO_MANY_REQUESTS)

    return None


def _safe_parse_datetime(value):
    """
    sent_at 같은 datetime 입력 처리:
    - None/빈값이면 None
    - ISO8601 문자열이면 parse_datetime
    - 파싱 실패면 None (지금 단계는 엄격히 실패시키지 않고 유연하게)
    """
    if not value:
        return None
    if isinstance(value, str):
        dt = parse_datetime(value)
        return dt
    return None


# =========================================================
# Health Check
# =========================================================
@api_view(["GET"])
def health(request):
    return ok({"ok": True})


# =========================================================
# Scope Policies (✅ ORM)
# =========================================================
@api_view(["GET", "POST"])
def scope_policies(request):
    if request.method == "GET":
        qs = ScopePolicy.objects.all().order_by("-created_at")
        items = [p.to_dict() for p in qs]
        return ok(items, meta={"count": len(items)})

    payload = request.data or {}
    allowed_hosts = payload.get("allowed_hosts", [])
    if allowed_hosts is None:
        allowed_hosts = []
    if not isinstance(allowed_hosts, list):
        return fail("parse_error", "allowed_hosts must be a list", http_status=400)

    max_runs = payload.get("max_runs")
    if max_runs is not None and not isinstance(max_runs, int):
        return fail("parse_error", "max_runs must be an int or null", http_status=400)

    policy = ScopePolicy.objects.create(
        name=payload.get("name", "default-policy"),
        allowed_hosts=allowed_hosts,
        max_runs=max_runs,
        created_runs=0,
    )
    return ok(policy.to_dict(), http_status=201)


@api_view(["GET"])
def get_scope_policy(request, scope_policy_id: str):
    policy = _get_policy(scope_policy_id)
    if not policy:
        return fail("tool_error", "scope_policy not found", http_status=404)
    return ok(policy.to_dict())


# =========================================================
# Scan Runs (✅ ORM)
# =========================================================
@api_view(["GET", "POST"])
def scan_runs(request):
    if request.method == "GET":
        qs = ScanRun.objects.all().order_by("-created_at")
        items = [r.to_dict() for r in qs]
        return ok(items, meta={"count": len(items)})

    payload = request.data or {}
    target_url = payload.get("target_url")
    if not target_url:
        return fail("parse_error", "target_url is required", http_status=400)

    scope_policy_id = payload.get("scope_policy_id")
    policy = _get_policy(scope_policy_id)

    gr = _guardrails_or_none(target_url, policy)
    if gr:
        error_type, msg, subtype, http_status_code = gr

        failed_run = ScanRun.objects.create(
            target_url=target_url,
            scope_policy=policy,
            status=ScanRun.Status.FAILED,
            progress=0,
            error_log=[
                {
                    "error_type": error_type if error_type in ALLOWED_ERROR_TYPES else "tool_error",
                    "subtype": subtype,
                    "message": msg,
                }
            ],
        )

        return fail(
            code=subtype if subtype else error_type,
            message=msg,
            meta={"run_id": str(failed_run.run_id), "status": "failed"},
            http_status=http_status_code,
        )

    # 정상 run 생성 + 정책 카운트 업데이트는 동시에(레이스 방지)
    with transaction.atomic():
        run = ScanRun.objects.create(
            target_url=target_url,
            scope_policy=policy,
            status=ScanRun.Status.RUNNING,
            progress=30,
            error_log=[],
        )

        if policy:
            ScopePolicy.objects.filter(scope_policy_id=policy.scope_policy_id).update(created_runs=F("created_runs") + 1)
            policy.refresh_from_db()

        # ✅ 커밋 이후 Celery enqueue
        transaction.on_commit(lambda: execute_scan_run.delay(str(run.run_id)))

    # ✅ 시연용 최소 산출물: 이제 DB에 저장
    RequestCatalogItem.objects.create(
        run=run,
        method="GET",
        url="/",
        headers={},
        sent_at=None,
    )

    Candidate.objects.create(
        run=run,
        title="stub-candidate",
        severity_raw="info",
        confidence=0.1,
    )

    # findings는 0개도 허용 (지금 단계는 생성 안 함)

    return ok(run.to_dict(), meta={"created": True}, http_status=201)


@api_view(["GET"])
def get_scan_run(request, run_id: str):
    try:
        run = ScanRun.objects.get(run_id=run_id)
    except ScanRun.DoesNotExist:
        return fail("tool_error", "scan_run not found", http_status=404)
    return ok(run.to_dict())


# =========================================================
# Run-scoped lists (권장 형태: /scan-runs/{run_id}/...)
# ✅ 이제 DB 기반
# =========================================================
@api_view(["GET"])
def list_request_catalog_by_run(request, run_id: str):
    qs = RequestCatalogItem.objects.filter(run_id=run_id).order_by("-created_at")
    items = [x.to_dict() for x in qs]
    return ok(items, meta={"run_id": run_id, "count": len(items)})


@api_view(["GET"])
def list_candidates_by_run(request, run_id: str):
    qs = Candidate.objects.filter(run_id=run_id).order_by("-created_at")
    items = [x.to_dict() for x in qs]
    return ok(items, meta={"run_id": run_id, "count": len(items)})


@api_view(["GET"])
def list_findings_by_run(request, run_id: str):
    qs = Finding.objects.filter(run_id=run_id).order_by("-created_at")
    items = [x.to_dict() for x in qs]
    return ok(items, meta={"run_id": run_id, "count": len(items)})


# =========================================================
# 기존 endpoints 유지 (명세서/기존 호출 깨지지 않게)
# ✅ DB 기반으로 변경
# =========================================================
@api_view(["GET"])
def list_findings(request):
    qs = Finding.objects.all().order_by("-created_at")
    # 기존과 동일하게 run_id 포함해서 내려줌
    items = []
    for f in qs:
        d = f.to_dict()
        d["run_id"] = str(f.run_id) if getattr(f, "run_id", None) else None
        items.append(d)
    return ok(items, meta={"count": len(items)})


@api_view(["POST"])
def create_evidence_blob(request):
    payload = request.data or {}
    blob = EvidenceBlob.objects.create(
        content_type=payload.get("content_type", "text/plain"),
        storage_ref=payload.get("storage_ref", "stub://storage"),
    )
    return ok(blob.to_dict(), http_status=201)


@api_view(["POST"])
def create_request_catalog_item(request):
    payload = request.data or {}
    run_id = payload.get("run_id")
    if not run_id:
        return fail("parse_error", "run_id is required", http_status=400)

    try:
        run = ScanRun.objects.get(run_id=run_id)
    except ScanRun.DoesNotExist:
        return fail("tool_error", "scan_run not found", http_status=404)

    item = RequestCatalogItem.objects.create(
        run=run,
        method=payload.get("method", "GET"),
        url=payload.get("url", "/"),
        headers=payload.get("headers", {}) or {},
        sent_at=_safe_parse_datetime(payload.get("sent_at")),
    )
    return ok(item.to_dict(), http_status=201)


@api_view(["GET"])
def list_request_catalog(request):
    run_id = request.query_params.get("run_id")
    if not run_id:
        return fail("parse_error", "run_id query param is required", http_status=400)

    qs = RequestCatalogItem.objects.filter(run_id=run_id).order_by("-created_at")
    items = [x.to_dict() for x in qs]
    return ok(items, meta={"run_id": run_id, "count": len(items)})


@api_view(["POST"])
def create_candidate(request):
    payload = request.data or {}
    run_id = payload.get("run_id")
    if not run_id:
        return fail("parse_error", "run_id is required", http_status=400)

    try:
        run = ScanRun.objects.get(run_id=run_id)
    except ScanRun.DoesNotExist:
        return fail("tool_error", "scan_run not found", http_status=404)

    item = Candidate.objects.create(
        run=run,
        title=payload.get("title", "candidate"),
        severity_raw=payload.get("severity_raw", "info"),
        confidence=float(payload.get("confidence", 0.0) or 0.0),
    )
    return ok(item.to_dict(), http_status=201)


@api_view(["GET"])
def list_candidates(request):
    run_id = request.query_params.get("run_id")
    if not run_id:
        return fail("parse_error", "run_id query param is required", http_status=400)

    qs = Candidate.objects.filter(run_id=run_id).order_by("-created_at")
    items = [x.to_dict() for x in qs]
    return ok(items, meta={"run_id": run_id, "count": len(items)})


@api_view(["POST"])
def create_finding_evidence_link(request):
    payload = request.data or {}
    finding_id = payload.get("finding_id")
    blob_id = payload.get("blob_id")
    if not finding_id or not blob_id:
        return fail("parse_error", "finding_id and blob_id are required", http_status=400)

    try:
        finding = Finding.objects.get(finding_id=finding_id)
    except Finding.DoesNotExist:
        return fail("tool_error", "finding not found", http_status=404)

    try:
        blob = EvidenceBlob.objects.get(blob_id=blob_id)
    except EvidenceBlob.DoesNotExist:
        return fail("tool_error", "blob not found", http_status=404)

    link = FindingEvidenceLink.objects.create(
        finding=finding,
        blob=blob,
        role=payload.get("role", "evidence"),
    )
    return ok(link.to_dict(), http_status=201)


@api_view(["GET"])
def list_finding_evidence_links(request):
    finding_id = request.query_params.get("finding_id")
    if not finding_id:
        return fail("parse_error", "finding_id query param is required", http_status=400)

    qs = FindingEvidenceLink.objects.filter(finding_id=finding_id).order_by("-created_at")
    items = [x.to_dict() for x in qs]
    return ok(items, meta={"finding_id": finding_id, "count": len(items)})
