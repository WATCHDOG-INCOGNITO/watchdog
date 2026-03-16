### API Contract

본 문서는 백엔드 API 계약서이다.
PostgreSQL + Django ORM 기반으로 동작하며, 데이터는 영구 저장된다.

Base URL
http://127.0.0.1:8000

---

### 기존 엔드포인트

### 기존 엔드포인트

GET /health/

POST /api/scan-runs/
GET /api/scan-runs/{run_id}/
POST /api/scan-runs/{run_id}/start/

GET /api/findings/?run_id={run_id}

POST /api/evidence-blobs/

POST /api/request-catalog/
GET /api/request-catalog/list/?run_id={run_id}

POST /api/candidates/
GET /api/candidates/list/?run_id={run_id}

POST /api/finding-evidence-links/
GET /api/finding-evidence-links/list/?finding_id={finding_id}

POST /api/scan-runs/{run_id}/report/
GET /api/scan-runs/{run_id}/report/
GET /api/scan-runs/{run_id}/report/?export=md

### 신규 엔드포인트 (/api/v1/)

CRUD /api/v1/tasks/
CRUD /api/v1/verification-loops/
CRUD /api/v1/hypotheses/
CRUD /api/v1/vulnerabilities/
CRUD /api/v1/patterns/
CRUD /api/v1/report-archives/

---

### Health Check

Request
GET /health/

Success Response (200)
{ "ok": true, "db_alive": true }

---

### Scan Run 생성

Request
POST /api/scan-runs/
Content-Type: application/json

Request Body 예시
{
  "target_url": "http://test.com",
  "mode": "hybrid-lite",
  "request_budget_total": 50
}

Success Response (201)
{
  "run_id": "f3717605-9dde-4013-b79f-ba54c24a6330",
  "target_url": "http://test.com",
  "status": "queued",
  "message": "scan created"
}

---

### Scan Run 상태 조회

Request
GET /api/scan-runs/{run_id}/

Success Response (200)
전체 ScanRun 객체 반환 (run_id, target_url, mode, status, created_at, llm_cost_usd 등)

Failure Response (404)
{ "error": "run_id not found" }

---

### Findings 조회

Request
GET /api/findings/?run_id={run_id}

Success Response (200)
{
  "run_id": "...",
  "findings": [
    {
      "finding_id": "...",
      "title": "SQL Injection in search param",
      "severity": "high",
      "confidence": 0.85,
      "evidence_ids": ["blob-uuid-1", "blob-uuid-2"]
    }
  ]
}

Failure Response (400)
{ "error": "run_id query param is required" }

---

### Evidence Blob 생성

Request
POST /api/evidence-blobs/
Content-Type: application/json

Request Body 예시
{
  "kind": "log",
  "storage_ref": "local://dummy"
}

Success Response (201)
{
  "blob_id": "...",
  "kind": "log",
  "storage_ref": "local://dummy",
  "sha256": null,
  "byte_size": null
}

---

### 신규 ViewSet 엔드포인트

모든 /api/v1/ 엔드포인트는 DRF ModelViewSet 기반이며 GET, POST, PUT, PATCH, DELETE를 지원한다.

예시: Vulnerability 생성
POST /api/v1/vulnerabilities/
{
  "cwe_id": "CWE-89",
  "title": "SQL Injection",
  "vuln_type": "sqli",
  "severity_default": "high"
}

예시: Pattern 생성
POST /api/v1/patterns/
{
  "name": "SLEEP blind SQLi",
  "vuln_type": "sqli",
  "request_template": "GET /q=1' AND SLEEP(5)--",
  "safety_level": "cautious",
  "times_used": 10,
  "times_succeeded": 8,
  "is_gold": true
}

응답에 success_rate, fp_rate가 자동 계산되어 포함된다.

---

### Scan Run Report (P5)

설명
- run_id 기준으로 리포트를 생성/저장하고, 저장된 리포트를 JSON 또는 Markdown 형식으로 조회한다.
- 산출물은 report.json(머신용) / report.md(사람용) 두 형식이다.

1) Report 생성
Request
POST /api/scan-runs/{run_id}/report/
Content-Type: application/json

Request Body
{}

Success Response (201)
{
  "run_id": "<run_id>",
  "report_id": "<uuid>",
  "created_at": "<iso8601>",
  "updated_at": "<iso8601>",
  "message": "report generated"
}

Failure Response (404)
{ "error": "run_id not found" }

2) Report 조회 (JSON 기본)
Request
GET /api/scan-runs/{run_id}/report/

Success Response (200)
Content-Type: application/json

Response Body 예시
{
  "run_id": "<run_id>",
  "target_url": "http://test-target:8080",
  "status": "completed",
  "generated_at": "<iso8601>",
  "candidates": {
    "count": 1,
    "top": []
  },
  "findings": {
    "count": 0,
    "by_severity": {
      "info": 0,
      "low": 0,
      "medium": 0,
      "high": 0,
      "critical": 0
    },
    "items": []
  },
  "evidence": {
    "count": 0,
    "items": []
  },
  "notes": "generated"
}

Failure Response (404)
{ "detail": "report not generated yet. POST this endpoint first." }

3) Report 조회 (Markdown)
Request
GET /api/scan-runs/{run_id}/report/?export=md

Success Response (200)
Content-Type: text/markdown

Response Body 예시
# Watchdog Report

## Run
- run_id: `<run_id>`
- target_url: `<target_url>`
- status: `<status>`
- generated_at: `<iso8601>`

## Candidates
- count: <number>

## Findings
- count: <number>

## Evidence
- count: <number>

Failure Response (404)
{ "detail": "report not generated yet. POST this endpoint first." }