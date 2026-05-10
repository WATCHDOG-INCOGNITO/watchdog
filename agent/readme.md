# Watchdog Agent

`agent/`는 멀티에이전트 오케스트레이션과 평가 하네스를 담는다.

## 구조

- [eval/](eval/) — 평가 하네스 (`run_eval.py`, `targets.yaml`, `history.jsonl`, `baseline.json`).
- [planner-prompt.md](planner-prompt.md) / [manager-prompt.md](manager-prompt.md) / [scan-agent-prompt.md](scan-agent-prompt.md) — 역할별 프롬프트 설계 메모(레퍼런스).

실제 LLM 시스템 프롬프트와 도구 화이트리스트는 [backend/backend/api/mcp_agent.py](../backend/backend/api/mcp_agent.py)의 `PLANNER_PROMPT` / `EXECUTOR_PROMPT` / `VERIFIER_PROMPT` / `REPORTER_PROMPT`에 정의되어 있다.

## 멀티에이전트 흐름 (mode=multi, default)

```
Planner (정찰 + 가설)
   │ hypotheses[] (JSON)
   ▼
ScanExecutor (페이로드 전송 + record_pattern_use)
   │ attempts[] (JSON)
   ▼
Verifier (false-positive 판정 + confirm_finding/dismiss)
   │ verdicts[] — needs_replan=true 가 있으면 한 번 더 Planner로
   ▼
Reporter (generate_report)
```

토글: `WATCHDOG_AGENT_MODE=multi|single`. `single`은 이전 단일 루프(베이스라인 비교용).

## 하네스로 검증

```bash
docker compose up -d --build              # pgvector 이미지 + backend
docker compose -f docker/docker-compose.e2e.yml up -d wargame
docker compose exec backend python manage.py migrate
docker compose exec backend python manage.py seed_knowledge   # Knowledge DB + embedding 시드

pip install -r agent/eval/requirements.txt

# Phase 0 베이스라인 (single)
WATCHDOG_AGENT_MODE=single python agent/eval/run_eval.py --phase 0-baseline --mcp --baseline

# Phase 1+ (multi + Knowledge + RAG)
python agent/eval/run_eval.py --phase 3-multiagent --mcp
```

`agent/eval/history.jsonl`에 매 실행이 누적되고, `--baseline` 지정 시 `baseline.json`이 갱신된다.
