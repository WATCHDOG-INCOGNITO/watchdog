# Watchdog Backend (Django/DRF)

`backend/backend/`는 버그바운티 AI 에이전트의 백엔드 API이다.
PostgreSQL + Django ORM 기반으로 데이터가 영구 저장된다.

## 기술 스택

- Python 3.12
- Django 6.0 + Django REST Framework
- PostgreSQL 16
- Docker Compose

## 주요 엔드포인트

**기존**
- `GET /health/`
- `POST /api/scan-runs/`
- `GET /api/scan-runs/{run_id}/`
- `GET /api/findings/?run_id=...`
- `POST /api/evidence-blobs/`
- `POST/GET /api/request-catalog/`
- `POST/GET /api/candidates/`
- `POST/GET /api/finding-evidence-links/`

**신규 (/api/v1/)**
- `CRUD /api/v1/tasks/`
- `CRUD /api/v1/verification-loops/`
- `CRUD /api/v1/hypotheses/`
- `CRUD /api/v1/vulnerabilities/`
- `CRUD /api/v1/patterns/`
- `CRUD /api/v1/report-archives/`

API 계약은 `backend/backend/API_CONTRACT.md` 참고.

## DB 테이블 (15개)

**Scan 관련 (6개):** scan_runs, request_catalog, candidates, findings, evidence_blobs, finding_evidence_links

**에이전트/검증 (6개):** agent_tasks, verification_loops, hypotheses, visual_analysis, idor_test_sessions, waf_bypass_attempts

**Knowledge DB (3개):** vulnerability_entries, payload_patterns, report_archives

## 빠른 실행 (Docker Compose)

```bash
docker compose -f docker/docker-compose.e2e.yml up -d --build
```

PostgreSQL 컨테이너가 먼저 뜨고, healthcheck 통과 후 Django가 자동으로 migrate + 서버 시작한다.

종료:

```bash
docker compose -f docker/docker-compose.e2e.yml down -v
```

헬스체크:

```bash
curl -sf http://localhost:8000/health/
# {"ok": true, "db_alive": true}
```

## 빠른 실행 (로컬)

PostgreSQL이 로컬에 설치되어 있어야 한다.

```bash
cd backend/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
```

## 환경변수

| 변수 | 기본값 | 설명 |
| --- | --- | --- |
| DB_NAME | bugbounty_agent | DB 이름 |
| DB_USER | bugbounty | DB 유저 |
| DB_PASSWORD | bugbounty123 | DB 비밀번호 |
| DB_HOST | localhost | DB 호스트 (Docker에서는 db) |
| DB_PORT | 5432 | PostgreSQL 포트 |
| DJANGO_SECRET_KEY | dev-only-not-a-secret | 프로덕션에서 반드시 변경 |
| DJANGO_DEBUG | 1 | 프로덕션에서 0으로 변경 |
