# Docker (E2E / CI)

## E2E Smoke

로컬에서 백엔드 + 테스트 타겟 컨테이너를 띄우고 최소 동작을 확인한다.

```bash
docker compose -f docker/docker-compose.e2e.yml up -d --build
python3 docker/e2e/smoke.py --base-url http://localhost:8000 --target-url http://test-target:8080 --timeout 60
docker compose -f docker/docker-compose.e2e.yml down -v
```

`8000` 포트가 충돌하면 `E2E_BACKEND_PORT`로 변경할 수 있다.

```bash
E2E_BACKEND_PORT=18000 docker compose -f docker/docker-compose.e2e.yml up -d --build
python3 docker/e2e/smoke.py --base-url http://localhost:18000 --target-url http://test-target:8080 --timeout 60
docker compose -f docker/docker-compose.e2e.yml down -v
```
