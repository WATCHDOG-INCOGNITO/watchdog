# Watchdog (monorepo)

Watchdog는 “버그바운티 AI Agent” 형태의 시스템을 만들기 위한 모노레포이다. 현재는 **API 계약 고정 + 파이프라인 검증**을 목표로 백엔드 Stub 구현과 CI/CD(E2E smoke 포함)를 먼저 갖춘 상태다.

## 구성(현재)

- `backend/backend/`: Django + DRF 기반 API (PostgreSQL 저장)
- `agent/`: 에이전트 영역 (WIP)
- `docker/`: 로컬 E2E docker compose + smoke 스크립트
- `infra/`: CI/CD 권장안 및 GitHub Environments 운영 가이드

## 동작 흐름(현재)

1. 클라이언트/에이전트가 `POST /api/scan-runs/`로 run을 생성한다.
2. 백엔드는 run을 PostgreSQL에 저장하고, 데모용 더미 finding을 1개 생성한다.
3. `GET /api/scan-runs/{run_id}/`, `GET /api/findings/?run_id=...`로 최소 결과를 확인한다.

API 계약 및 예시는 `backend/backend/API_CONTRACT.md` 참고.

## 실행 방법

### 1) 백엔드 로컬 실행 (Python)

```bash
cd backend/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
```

헬스체크:

```bash
curl -sf http://localhost:8000/health/
```

### 2) E2E smoke (Docker Compose)

PostgreSQL + 백엔드 + 테스트 타겟 컨테이너를 띄우고 “run 생성 → 더미 결과 생성” 최소 동작을 확인한다.

```bash
docker compose -f docker/docker-compose.e2e.yml up -d --build
python3 docker/e2e/smoke.py --base-url http://localhost:8000 --target-url http://test-target:8080 --timeout 60
docker compose -f docker/docker-compose.e2e.yml down -v
```

로컬에서 `8000` 포트가 이미 사용 중이면:

```bash
E2E_BACKEND_PORT=18000 docker compose -f docker/docker-compose.e2e.yml up -d --build
python3 docker/e2e/smoke.py --base-url http://localhost:18000 --target-url http://test-target:8080 --timeout 60
docker compose -f docker/docker-compose.e2e.yml down -v
```

## CI/CD (요약)

- CI: `.github/workflows/ci.yml`
  - gitleaks secret scan
  - Trivy 이미지 스캔(HIGH/CRITICAL fail)
  - Syft SBOM 생성 + 업로드
  - docker compose 기반 E2E smoke
- CD: `.github/workflows/cd.yml`
  - GitHub Environments: `staging` 자동, `production` 승인 기반 권장
  - 배포 후 smoke(환경 변수 `BASE_URL`, `SMOKE_TARGET_URL` 설정 시)

자세한 운영/설정은 `infra/readme.md` 참고.

## 환경 설정

현재 로컬/Docker 실행 시 backend에서 사용하는 주요 환경설정은 다음과 같다.

### 1. 주요 환경변수

- `DB_NAME`
- `DB_USER`
- `DB_PASSWORD`
- `DB_HOST`
- `DB_PORT`
- `ANTHROPIC_API_KEY`
- `GOOGLE_APPLICATION_CREDENTIALS`
- `GCS_BUCKET_NAME`

### 2. Docker Compose 기준 DB 설정

현재 공용 `docker-compose.yml`에서는 backend DB 설정이 아래와 같이 환경변수 확장 문법으로 정의되어 있다.

```yaml
DB_NAME: ${DB_NAME:-bugbounty_agent}
DB_USER: ${DB_USER:-bugbounty}
DB_PASSWORD: ${DB_PASSWORD:-bugbounty123}
DB_HOST: ${DB_HOST:-db}
DB_PORT: ${DB_PORT:-5432}
```

### 3. GCS 사용 시 추가 설정
Evidence 업로드 기능을 사용하려면 아래 설정이 필요하다.

- GOOGLE_APPLICATION_CREDENTIALS
- GCS_BUCKET_NAME

```yaml
GOOGLE_APPLICATION_CREDENTIALS: /app/gcp-key1.json
GCS_BUCKET_NAME: watchdog-evidence
```

### 4. 주의사항
- 실제 API Key, 서비스 계정 키 파일, 운영용 비밀번호는 저장소에 직접 커밋하지 않는 것을 권장
- .env를 사용할 경우 로컬 환경에 맞게 값을 주입하고, 없으면 docker-compose.yml의 기본값이 사용됨
- GCS 기능을 사용하지 않는 경우에도 DB 관련 기본값만으로 backend 기동은 가능