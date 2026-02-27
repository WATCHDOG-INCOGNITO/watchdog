# Watchdog DevOps Pipeline (수정안)

이 문서는 에이전트/백엔드 형태의 프로젝트에서 “필수로 챙겨야 하는 것” 위주로 CI/CD를 업그레이드한 권장안이다.

## 7.1 CI에 추가할 것

- Secret scanning (기본 + 추가)
- GitHub Secret Scanning 활성화(가능하면): GitHub Settings에서 `Secret scanning` + (가능하면) `Push protection` 켜기
- gitleaks로 PR/Push에서 유출 탐지: `.github/workflows/ci.yml`

- SBOM 생성 + 이미지 서명(선택)
- Syft로 SBOM 생성: CI에서 `SPDX-JSON` 생성 후 artifact 업로드
- Cosign 서명: 추후(키/정책 정리 후) 추가 권장

- E2E smoke test(스테이징 대상)
- 로컬 테스트 타겟(테스트용) 컨테이너를 띄우고
- runner가 “run 생성 → 최소 결과 생성”을 확인(타임아웃 포함)

이 리포의 백엔드(`backend/backend/`)는 Django/DRF 기반의 Stub API 구현이며, E2E smoke는 아래 최소 흐름을 검증한다.

- Health check
- Scan Run 생성
- Findings(더미 결과) 생성 확인

## 7.2 CD에 추가할 것

- GitHub Environments 사용
- staging은 자동 배포(권장): `environment: staging`
- prod는 environment protection(승인자 필요) 붙이기: `environment: production`

- 배포 후 자동 smoke
- `GET /health/` (또는 `/healthz`) 체크
- `POST /api/scan-runs/`로 더미 run 만들고, `GET /api/findings/?run_id=...`로 최소 결과 생성 확인(시간 제한)

### GitHub Settings에서 해야 할 것

- Environments 생성: `staging`, `production`
- `production` 환경에 Required reviewers(승인자) 지정
- (권장) 각 환경에 Variables 추가
- `BASE_URL`: 배포된 API의 base URL (예: `https://staging.example.com`)
- `SMOKE_TARGET_URL`: smoke에서 사용할 target URL (예: `http://test-target.internal:8080` 또는 고정 테스트 URL)

## 7.3 GitHub Actions 수정 예시

이 리포는 아래 파일에 핵심 블록을 반영해 두었다.

- CI: `.github/workflows/ci.yml`
- gitleaks (fail)
- Trivy: HIGH/CRITICAL에서 fail
- E2E smoke: docker compose + health check + run 생성 + 최소 결과 확인

- CD: `.github/workflows/cd.yml`
- `deploy-staging`는 `environment: staging`
- `deploy-production`은 `environment: production` (GitHub Settings에서 승인자 지정 필요)

## 로컬에서 E2E smoke 돌리기

```bash
docker compose -f docker/docker-compose.e2e.yml up -d --build
python3 docker/e2e/smoke.py --base-url http://localhost:8000 --target-url http://test-target:8080 --timeout 60
docker compose -f docker/docker-compose.e2e.yml down -v
```

로컬에서 `8000` 포트가 이미 사용 중이면 `E2E_BACKEND_PORT`로 바꿀 수 있다.

```bash
E2E_BACKEND_PORT=18000 docker compose -f docker/docker-compose.e2e.yml up -d --build
python3 docker/e2e/smoke.py --base-url http://localhost:18000 --target-url http://test-target:8080 --timeout 60
docker compose -f docker/docker-compose.e2e.yml down -v
```
