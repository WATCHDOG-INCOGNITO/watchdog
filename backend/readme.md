# Watchdog Backend (Django/DRF Stub)

`backend/`는 API 계약(스키마 v3) 확정과 E2E smoke를 위한 Stub 구현이다.
DB/스캐너 엔진 연동은 아직 없고, 메모리 기반 더미 데이터로 동작 흐름만 검증한다.

## 빠른 실행 (로컬)

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python manage.py runserver 0.0.0.0:8000
```

## 주요 엔드포인트

- `GET /health/`
- `POST /api/scan-runs/`
- `GET /api/scan-runs/{run_id}/`
- `GET /api/findings/?run_id=...`
- `POST /api/evidence-blobs/`

API 계약은 `backend/API_CONTRACT.md` 참고.

## Docker/E2E

```bash
docker compose -f docker/docker-compose.e2e.yml up -d --build
python3 docker/e2e/smoke.py --base-url http://localhost:8000 --target-url http://test-target:8080 --timeout 60
docker compose -f docker/docker-compose.e2e.yml down -v
```

### 프로젝트 개요

이 프로젝트는 웹 기반 버그바운티 AI Agent의 백엔드 API 초안 구현이다.
실제 취약점 스캔 로직이나 데이터베이스 연동은 아직 구현하지 않았으며,
스키마 v3 기준의 전체 파이프라인 구조를 API 형태로 설계하고
Stub(테스트 응답) 방식으로 동작 흐름을 검증하는 것이 목적이다.

본 구현은 “API 계약 구조 확정”을 목표로 한다.

### 기술 스택

Python
Django
Django REST Framework

현재는 메모리 기반 임시 저장 구조를 사용한다.
(서버 재시작 시 데이터 초기화됨)

### 전체 흐름 구조

이 백엔드는 아래와 같은 단계적 파이프라인을 가진다.

Scan Run 생성

Scan Run 상태 조회

Request Catalog 조회 (구조 확장 예정)

Candidate 생성 및 조회 (구조 확장 예정)

Findings 조회

Evidence Blob 생성

Finding ↔ Evidence Link 연결 및 조회

현재는 DB 없이 메모리 딕셔너리를 이용하여 구조만 구현하였다.

### 주요 엔드포인트 설명

**Health Check**<br>
GET /health/

서버가 정상 동작 중인지 확인하기 위한 엔드포인트이다.
응답 예시:
{ "ok": true }

**Scan Run 생성**<br>
POST /api/scan-runs/

타겟 URL을 받아 새로운 run_id를 생성한다.
상태는 stub으로 "queued"로 고정된다.
동시에 데모용 더미 finding 1개를 자동 생성한다.

응답 예시:
run_id, target_url, status, message 반환

**Scan Run 상태 조회**<br>
GET /api/scan-runs/{run_id}/

해당 run_id의 진행 상태를 조회한다.
현재는 stub이므로 running, progress 30 등 고정 값 반환.

**Findings 조회**<br>
GET /api/findings/?run_id=...

해당 run_id에 연결된 취약점 결과 목록을 조회한다.
finding_id, title, severity, confidence, evidence_ids 포함.

**Evidence Blob 생성**<br>
POST /api/evidence-blobs/

취약점 증거 파일을 나타내는 blob_id를 생성한다.
실제 파일 저장은 하지 않으며 storage_ref만 기록한다.

응답 예시:
blob_id, kind, storage_ref, sha256, byte_size

**Finding ↔ Evidence Link (구조 확장 예정)**<br>

취약점 결과(finding)와 증거(blob)를 연결하는 구조이다.
향후 DB 설계 시 N:M 관계 테이블로 구현 예정이다.

**Evidence를 분리한 이유**<br>

Evidence는 실제 HTTP 요청/응답, 로그, 스크린샷, PoC 코드 등
용량이 큰 원문 데이터를 포함할 수 있다.

따라서 Findings 테이블에 직접 포함하지 않고
별도의 Evidence Blob 구조로 분리하여
참조 형태로 연결하는 구조를 채택하였다.

이 구조는 다음과 같은 장점이 있다.

대용량 데이터와 메타데이터 분리

하나의 Evidence를 여러 Finding이 참조 가능

향후 S3 등 외부 스토리지 연동 용이

스키마 v3의 확장성 유지

### 현재 한계

PostgreSQL 미연동

마이그레이션 미구현

실제 스캔 로직 미구현

모든 응답은 Stub 기반 테스트 데이터

### 향후 계획

PostgreSQL 기반 DB 모델링 및 마이그레이션 적용 예정.
SCAN_RUNS, FINDINGS, EVIDENCE_BLOBS, FINDING_EVIDENCE_LINKS를
실제 테이블로 분리하여 영속성 확보 예정.

이후 실제 스캐너 엔진 및 Agent 로직과 연동하여
실제 취약점 분석 파이프라인으로 확장할 계획이다.
