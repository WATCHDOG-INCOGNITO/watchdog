###API Contract

본 문서는 발표 및 검수용 API 계약서이다.
현재 단계에서는 실제 스캔 로직 없이 Stub(JSON) 응답만 반환한다.

Base URL
http://127.0.0.1:8000

###엔드포인트 목록

GET /health/
POST /api/scan-runs/
GET /api/scan-runs/{run_id}/
GET /api/findings/?run_id={run_id}
POST /api/evidence-blobs/

###Health Check

Request
GET /health/

Success Response (200)
{ "ok": true }

###Scan Run 생성

Request
POST /api/scan-runs/
Content-Type: application/json

Request Body 예시
{ "target_url": "http://test.com
" }

Success Response (201)
{
"run_id": "f3717605-9dde-4013-b79f-ba54c24a6330",
"target_url": "http://test.com
",
"status": "queued",
"message": "stub response: scan started"
}

###Scan Run 상태 조회

Request
GET /api/scan-runs/{run_id}/

Request URL 예시
/api/scan-runs/f3717605-9dde-4013-b79f-ba54c24a6330/

Success Response (200)
{
"run_id": "f3717605-9dde-4013-b79f-ba54c24a6330",
"status": "running",
"progress": 30
}

Failure Response (404)
{ "error": "run_id not found" }

###Findings 조회

Request
GET /api/findings/?run_id={run_id}

Request URL 예시
/api/findings/?run_id=f3717605-9dde-4013-b79f-ba54c24a6330

Success Response (200)
{
"run_id": "f3717605-9dde-4013-b79f-ba54c24a6330",
"findings": [
{
"finding_id": "F-f3717605",
"title": "Dummy SQL Injection",
"severity": "high",
"confidence": 0.3,
"evidence_ids": []
}
]
}

Failure Response (400)
{ "error": "run_id query param is required" }

###Evidence Blob 생성

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
"blob_id": "b6d4a4c7-0f0f-4e19-8f48-7c2f5d0b9a11",
"kind": "log",
"storage_ref": "local://dummy",
"sha256": null,
"byte_size": null
}

###Notes

현재 단계는 실제 스캔, 크롤링, AI 분석 없이 Stub 응답만 반환한다.
모든 데이터는 메모리 기반이며 서버 재시작 시 초기화된다.
본 문서는 API 설계 및 전체 흐름 검증을 위한 계약서이다.
