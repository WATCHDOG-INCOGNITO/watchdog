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
