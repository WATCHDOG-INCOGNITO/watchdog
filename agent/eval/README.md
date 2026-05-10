# Watchdog Eval Harness

에이전트 파이프라인의 phase별 성능 + CTF 문제 풀이를 반복 측정.

## 빠른 실행

```bash
# 1. watchdog 스택 기동
docker compose up -d --build
pip install -r agent/eval/requirements.txt

# 2. CTF 문제 setup (자동)
python agent/eval/run_eval.py --phase test --mcp --setup --teardown

# 또는 단일 target만:
python agent/eval/run_eval.py --phase test --mcp --setup --only codegate2023-warmup
```

## CTF 문제 추가 (새 target)

1. **`targets.yaml`에 항목 추가**:
   ```yaml
   - id: codegate2024-shieldosint
     name: "..."
     target_url: "http://shieldosint:8780"
     scan_timeout_seconds: 1800
     source_root: "/sources/codegate2024-final/jun/web-ShieldOSINT/prob/for_user"
     ctf_for_user: "codegate2024-final/jun/web-ShieldOSINT/prob/for_user"
     ctf_alias: "shieldosint"
     flag_pattern: 'codegate20\d{2}\{[^}]+\}'
     expected_findings: []
   ```

2. **`--setup` 플래그로 실행** — `ctf_setup.sh`가 자동으로:
   - `for_user` 디렉터리에서 `docker compose up -d --build`
   - 웹서버 컨테이너를 `watchdog_default` 네트워크에 `ctf_alias` + `webserver` alias로 join
   - bot 컨테이너 있으면 `bot` alias로 join + DNS refresh
   - backend에서 `http://<alias>/` 도달 확인

3. **--teardown 플래그**면 끝나고 `docker compose down -v` 자동.

## 수동 setup/teardown

```bash
bash agent/eval/ctf_setup.sh codegate2023-fin/general/web-warmup/prob/for_user warmup
bash agent/eval/ctf_teardown.sh codegate2023-fin/general/web-warmup/prob/for_user
```

서비스 이름 자동 감지 실패 시 env로 override:
```bash
WEB_SERVICE=for_user-api-server-1 BOT_SERVICE=for_user-admin-bot-1 \
  bash agent/eval/ctf_setup.sh <path> <alias>
```

## Source 접근 안전망

`docker-compose.yml`은 4개 CodeGate 대회 전체를 `/sources/*` 에 read-only mount.
`tools_source`가 **for_user 경로**만 허용 + 다음 토큰 차단으로 정답/flag 노출 방지:

- `for_organizer` / `/exploit/` / `/exploit.md` / `/exploit.py`
- `/anticheat/` / `/flag.txt` / `/flag` / `info.yaml`

대회 top-level `README.md`는 접근 못 함 (flag + 풀이 포함). `for_user/` 안의 README는 허용 (참가자 문서).

## 출력물

- `history.jsonl` — 매 실행 append (timestamp / phase / git_rev / target별 상세)
- `baseline.json` — `--baseline` 지정 시 갱신. 이후 실행의 Δ 기준.

## 메트릭

- **TP/FP/FN** expected finding vs actual 매칭
- **F1** = 2PR / (P+R)
- **flag_found** + `flag_value` (CTF용 — traces/findings/candidates 텍스트에서 flag pattern 매칭)
- **score** = F1 − cost_penalty·USD − turn_penalty·turns − timeout_penalty + flag_bonus

## history 분석 (compare_history.py)

```bash
# 기본: 최근 10 run + regression 자동 감지
python agent/eval/compare_history.py

# 특정 phase 두 개 비교 (mean F1/score/flag/cost diff)
python agent/eval/compare_history.py --phase 5-tool-parallel oss-baseline

# 단일 target 시계열
python agent/eval/compare_history.py --target oss-juice-shop

# git_rev 두 개 비교 (e.g. before/after refactor)
python agent/eval/compare_history.py --git 4c0b820 614887a
```

regression: 이전 run 들에서 잡았던 flag 를 마지막 run 에서 놓친 target 자동 알림.

## OSS standard targets — XBOW/Shannon 비교용

CodeGate CTF 외에 OSS 표준 타겟 (Juice Shop, DVWA) 을 docker compose
profile `eval-oss` 로 추가. 평소엔 안 뜸, 평가 시에만 띄움.

```bash
# 1. OSS 타겟 컨테이너 띄우기 (한 번만)
docker compose --profile eval-oss up -d juice-shop dvwa

# 2. backend 가 service 이름으로 도달 가능한지 확인
docker compose exec backend wget -qO- http://juice-shop:3000/ | head -c 100
docker compose exec backend wget -qO- http://dvwa/ | head -c 100

# 3. eval 실행 (oss-* target 만)
python agent/eval/run_eval.py --phase oss-baseline --mcp \
  --only oss-juice-shop,oss-dvwa --baseline

# 4. 다음 변경 후 비교
python agent/eval/run_eval.py --phase oss-after-w5 --mcp \
  --only oss-juice-shop,oss-dvwa
python agent/eval/compare_history.py --phase oss-baseline oss-after-w5

# 5. 평가 끝나면 OSS 컨테이너 정리
docker compose --profile eval-oss down
```

호스트 포트:
- juice-shop → `http://localhost:8030` (수동 확인용)
- dvwa → `http://localhost:8082`
- watchdog frontend(3000) / backend(8000) / mcp(8889) 와 충돌 없음

`targets.yaml` 은 `.gitignore` 처리되어 있음 (CTF 풀이 정보 보호용).
OSS target 도 본인 `targets.yaml` 끝에 직접 추가:

```yaml
  - id: oss-juice-shop
    name: "OWASP Juice Shop"
    target_url: "http://juice-shop:3000"
    status: "ready"
    flag_pattern: ''
    scan_timeout_seconds: 2400
    expected_findings:
      - {endpoint: "/rest/user/login", param: "email", vuln_type: "sqli", severity: "critical"}
      - {endpoint: "/rest/products/search", param: "q", vuln_type: "sqli", severity: "high"}
      - {endpoint: "/rest/products/search", param: "q", vuln_type: "xss", severity: "high"}
      - {endpoint: "/ftp/", param: "", vuln_type: "path_traversal", severity: "high"}
      - {endpoint: "/api/Feedbacks", param: "UserId", vuln_type: "idor", severity: "medium"}
      - {endpoint: "/rest/user/change-password", param: "", vuln_type: "csrf", severity: "medium"}
      - {endpoint: "/api/Users", param: "", vuln_type: "auth_bypass", severity: "high"}
      - {endpoint: "/redirect", param: "to", vuln_type: "open_redirect", severity: "low"}

  - id: oss-dvwa
    name: "DVWA (Damn Vulnerable Web Application)"
    target_url: "http://dvwa"
    status: "ready"
    flag_pattern: ''
    scan_timeout_seconds: 1800
    expected_findings:
      - {endpoint: "/vulnerabilities/sqli/", param: "id", vuln_type: "sqli", severity: "high"}
      - {endpoint: "/vulnerabilities/sqli_blind/", param: "id", vuln_type: "sqli", severity: "high"}
      - {endpoint: "/vulnerabilities/xss_r/", param: "name", vuln_type: "xss", severity: "high"}
      - {endpoint: "/vulnerabilities/xss_s/", param: "txtName", vuln_type: "xss", severity: "high"}
      - {endpoint: "/vulnerabilities/exec/", param: "ip", vuln_type: "cmdi", severity: "critical"}
      - {endpoint: "/vulnerabilities/fi/", param: "page", vuln_type: "lfi", severity: "high"}
      - {endpoint: "/vulnerabilities/upload/", param: "uploaded", vuln_type: "file_upload", severity: "high"}
      - {endpoint: "/vulnerabilities/csrf/", param: "", vuln_type: "csrf", severity: "medium"}
```

핵심 vuln 8개씩만 — full Juice Shop 100+ challenges 는 별도 큐레이션.
flag pattern 없으므로 F1/score 기반 평가.
