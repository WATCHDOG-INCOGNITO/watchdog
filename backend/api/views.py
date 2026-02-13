import uuid
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

# =========================================================
# ✅ 임시 메모리 저장소 (서버 재시작 시 초기화됨)
# =========================================================
SCAN_RUNS = {}                # run_id -> scan_run dict
FINDINGS = {}                 # run_id -> list[finding]
BLOBS = {}                    # blob_id -> blob dict

# ✅ 선택 B 확장: 스키마 전 단계 Stub
REQUEST_CATALOG = {}          # run_id -> list[request_item]
CANDIDATES = {}               # run_id -> list[candidate]
FINDING_EVIDENCE_LINKS = {}   # finding_id -> list[link]


# =========================================================
# Health Check
# =========================================================
@api_view(["GET"])
def health(request):
    return Response({"ok": True})


# =========================================================
# 1. Scan Run 생성 (POST /api/scan-runs/)
# =========================================================
@api_view(["POST"])
def create_scan_run(request):
    run_id = str(uuid.uuid4())
    target_url = request.data.get("target_url", "http://example.com")

    SCAN_RUNS[run_id] = {
        "run_id": run_id,
        "target_url": target_url,
        "status": "queued",
        "message": "stub response: scan started"
    }

    # 🔹 데모용 더미 finding 1개 생성
    FINDINGS[run_id] = [
        {
            "finding_id": f"F-{run_id[:8]}",
            "title": "Dummy SQL Injection",
            "severity": "high",
            "confidence": 0.3,
            "evidence_ids": []
        }
    ]

    # 선택 B: run 생성 시 '요청 카탈로그' 더미 1개도 기본으로 넣어둠(발표 시 흐름이 자연스러움)
    REQUEST_CATALOG.setdefault(run_id, []).append({
        "req_id": str(uuid.uuid4()),
        "run_id": run_id,
        "endpoint": "/admin",
        "method": "GET",
        "params": {},
        "auth_required": False,
        "sample_request": {"headers": {}, "body": None},
        "source": "stub",
        "discovered_at": "stub"
    })

    # 선택 B: run 생성 시 'candidate' 더미 1개도 기본으로 넣어둠
    CANDIDATES.setdefault(run_id, []).append({
        "cand_id": str(uuid.uuid4()),
        "run_id": run_id,
        "req_id": None,
        "type": "signal_stub",
        "hypothesis": "Possible SQLi based on stub rule",
        "priority_score": 0.5,
        "required_auth_context": None,
        "features": {
            "signal_rules_hit": ["stub_rule_1"],
            "llm_score": 0.12,
            "reason_refs": []
        },
        "created_at": "stub"
    })

    return Response(SCAN_RUNS[run_id], status=status.HTTP_201_CREATED)


# =========================================================
# 2. Scan Run 상태 조회 (GET /api/scan-runs/{run_id}/)
# =========================================================
@api_view(["GET"])
def get_scan_run(request, run_id: str):
    data = SCAN_RUNS.get(run_id)
    if not data:
        return Response({"error": "run_id not found"}, status=status.HTTP_404_NOT_FOUND)

    # 상태가 바뀌는 척 (stub)
    return Response({
        "run_id": run_id,
        "status": "running",
        "progress": 30
    })


# =========================================================
# 3. Findings 조회 (GET /api/findings/?run_id=...)
# =========================================================
@api_view(["GET"])
def list_findings(request):
    run_id = request.query_params.get("run_id")
    if not run_id:
        return Response({"error": "run_id query param is required"}, status=status.HTTP_400_BAD_REQUEST)

    return Response({
        "run_id": run_id,
        "findings": FINDINGS.get(run_id, [])
    })


# =========================================================
# 4. Evidence Blob 생성 (POST /api/evidence-blobs/)
# =========================================================
@api_view(["POST"])
def create_evidence_blob(request):
    blob_id = str(uuid.uuid4())

    BLOBS[blob_id] = {
        "blob_id": blob_id,
        "kind": request.data.get("kind", "log"),
        "storage_ref": request.data.get("storage_ref", "local://dummy"),
        "sha256": None,
        "byte_size": None,
    }

    return Response(BLOBS[blob_id], status=status.HTTP_201_CREATED)


# =========================================================
# 5. Request Catalog 생성/조회 (스키마 전 단계 Stub)
#    - POST /api/request-catalog/
#    - GET  /api/request-catalog/?run_id=...
# =========================================================
@api_view(["POST"])
def create_request_catalog_item(request):
    run_id = request.data.get("run_id")
    if not run_id:
        return Response({"error": "run_id is required"}, status=status.HTTP_400_BAD_REQUEST)
    if run_id not in SCAN_RUNS:
        return Response({"error": "run_id not found"}, status=status.HTTP_404_NOT_FOUND)

    req_id = str(uuid.uuid4())
    item = {
        "req_id": req_id,
        "run_id": run_id,
        "endpoint": request.data.get("endpoint", "/admin"),
        "method": request.data.get("method", "GET"),
        "params": request.data.get("params", {}),
        "auth_required": bool(request.data.get("auth_required", False)),
        "sample_request": request.data.get("sample_request", {"headers": {}, "body": None}),
        "source": request.data.get("source", "stub"),
        "discovered_at": "stub"
    }

    REQUEST_CATALOG.setdefault(run_id, []).append(item)
    return Response(item, status=status.HTTP_201_CREATED)


@api_view(["GET"])
def list_request_catalog(request):
    run_id = request.query_params.get("run_id")
    if not run_id:
        return Response({"error": "run_id query param is required"}, status=status.HTTP_400_BAD_REQUEST)

    return Response({
        "run_id": run_id,
        "requests": REQUEST_CATALOG.get(run_id, [])
    })


# =========================================================
# 6. Candidates 생성/조회 (스키마 전 단계 Stub)
#    - POST /api/candidates/
#    - GET  /api/candidates/?run_id=...
# =========================================================
@api_view(["POST"])
def create_candidate(request):
    run_id = request.data.get("run_id")
    if not run_id:
        return Response({"error": "run_id is required"}, status=status.HTTP_400_BAD_REQUEST)
    if run_id not in SCAN_RUNS:
        return Response({"error": "run_id not found"}, status=status.HTTP_404_NOT_FOUND)

    cand_id = str(uuid.uuid4())
    cand = {
        "cand_id": cand_id,
        "run_id": run_id,
        "req_id": request.data.get("req_id"),  # request_catalog과 연결 가능(없어도 됨)
        "type": request.data.get("type", "signal_stub"),
        "hypothesis": request.data.get("hypothesis", "Possible SQLi based on stub rule"),
        "priority_score": float(request.data.get("priority_score", 0.5)),
        "required_auth_context": request.data.get("required_auth_context"),
        "features": request.data.get("features", {
            "signal_rules_hit": ["stub_rule_1"],
            "llm_score": 0.12,
            "reason_refs": []
        }),
        "created_at": "stub"
    }

    CANDIDATES.setdefault(run_id, []).append(cand)
    return Response(cand, status=status.HTTP_201_CREATED)


@api_view(["GET"])
def list_candidates(request):
    run_id = request.query_params.get("run_id")
    if not run_id:
        return Response({"error": "run_id query param is required"}, status=status.HTTP_400_BAD_REQUEST)

    return Response({
        "run_id": run_id,
        "candidates": CANDIDATES.get(run_id, [])
    })


# =========================================================
# 7. Finding ↔ Evidence Link 생성/조회 (스키마 전 단계 Stub)
#    - POST /api/finding-evidence-links/
#    - GET  /api/finding-evidence-links/?finding_id=...
# =========================================================
@api_view(["POST"])
def create_finding_evidence_link(request):
    finding_id = request.data.get("finding_id")
    blob_id = request.data.get("blob_id")
    role = request.data.get("role", "supporting")

    if not finding_id or not blob_id:
        return Response({"error": "finding_id and blob_id are required"}, status=status.HTTP_400_BAD_REQUEST)

    if blob_id not in BLOBS:
        return Response({"error": "blob_id not found"}, status=status.HTTP_404_NOT_FOUND)

    link_id = str(uuid.uuid4())
    link = {
        "id": link_id,
        "finding_id": finding_id,
        "blob_id": blob_id,
        "role": role
    }

    FINDING_EVIDENCE_LINKS.setdefault(finding_id, []).append(link)

    # (선택) finding의 evidence_ids에도 blob_id 반영하면 더 자연스러움
    # finding이 어느 run에 속하는지 모르므로, 모든 run의 finding에서 찾아 갱신
    for run_id, flist in FINDINGS.items():
        for f in flist:
            if f.get("finding_id") == finding_id:
                if blob_id not in f.get("evidence_ids", []):
                    f.setdefault("evidence_ids", []).append(blob_id)

    return Response(link, status=status.HTTP_201_CREATED)


@api_view(["GET"])
def list_finding_evidence_links(request):
    finding_id = request.query_params.get("finding_id")
    if not finding_id:
        return Response({"error": "finding_id query param is required"}, status=status.HTTP_400_BAD_REQUEST)

    return Response({
        "finding_id": finding_id,
        "links": FINDING_EVIDENCE_LINKS.get(finding_id, [])
    })
