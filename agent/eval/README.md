# Watchdog Eval Harness

에이전트 파이프라인의 phase별 성능을 반복 측정한다.

## 빠른 실행

```bash
# 1. 테스트 스택 기동 (postgres + backend + wargame)
docker compose -f docker-compose.test.yml up -d --build
# 별도 터미널에서 wargame도 올릴 경우:
docker compose -f docker/docker-compose.e2e.yml up -d --build wargame

# 2. 의존성
pip install -r agent/eval/requirements.txt

# 3. 베이스라인 측정 (단일 MCP 루프, Phase 0)
export ANTHROPIC_API_KEY=sk-...
python agent/eval/run_eval.py --phase 0-baseline --mcp --baseline

# 4. 이후 phase별 반복 — baseline 대비 델타가 요약에 표시됨
python agent/eval/run_eval.py --phase 1-knowledge --mcp
python agent/eval/run_eval.py --phase 2-rag --mcp
python agent/eval/run_eval.py --phase 3-multiagent --mcp
```

## 출력물

- `history.jsonl` — 매 실행마다 append (timestamp / phase / git_rev / 메트릭 / target별 상세)
- `baseline.json` — `--baseline` 지정 시 갱신. 이후 실행의 델타 기준.

## 메트릭

- `TP` expected finding이 실제로 finding/candidate 매칭된 경우
- `FP` expected에 없는 finding
- `FN` expected 중 매칭 안 된 것
- `F1 = 2PR / (P+R)`
- `score = F1 − cost_penalty·USD − turn_penalty·turns − timeout_penalty` (targets.yaml의 `metrics` 섹션에서 조정)

## 타겟 추가

`targets.yaml`에 항목을 추가하면 된다. `endpoint`/`vuln_type`은 `backend/api/models.py::Candidate.vuln_type`과 동일한 enum 값을 사용.
