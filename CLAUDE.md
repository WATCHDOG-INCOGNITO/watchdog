# CLAUDE.md — Watchdog

이 파일은 Claude Code 가 이 repo 에서 작업 시 매 세션 자동 로드하는 컨텍스트.

## 프로젝트 개요

**Watchdog** — AI 멀티에이전트 web pentest 시스템. backend swarm (MLLA:
RouteMap → EntryPoint → Hypothesis → Exploit → Confirmer) + MCP 도구 80+ +
Discovery Tree + Living KB (PayloadPattern / EndpointSpec / TargetProfile /
DeadEnd). 직접 비교군은 XBOW / Shannon.

**6주 로드맵 전부 완료** (인프라 기준):
1. 안전망 + emit_* + oracle (완료)
2. MLLA 5-agent 분해 (완료)
3. SimHash dedup + CVE 시드 + NVD lookup (완료)
4. Pre-exploit critic agent (완료)
5. endpoint-level 병렬 work-unit (완료)
6. OSS 타겟 인프라 (완료 — 실제 batch 실험은 별도)

## 디렉토리 구조

```
watchdog/
├── backend/backend/
│   ├── api/                       # Django models, views, services, scan orchestration
│   │   ├── models.py              # ScanRun, Candidate, Finding, DiscoveryNode,
│   │   │                          # PayloadPattern, TargetProfile, DeadEnd, EndpointSpec
│   │   ├── mcp_agent.py           # 멀티에이전트 루프 (MLLA sub-agents)
│   │   ├── storage_service.py     # confirm/dismiss candidate (안전망 포함)
│   │   ├── dedup.py               # SimHash 64-bit + Hamming
│   │   └── management/commands/techniques/  # KB 기법 .md 파일들 (git 추적)
│   ├── watchdog_mcp/              # MCP 서버 (SSE) — 실제 agent 도구 구현
│   │   ├── tools_knowledge.py     # search_knowledge / check_payload_dedup / ...
│   │   ├── tools_learn.py         # learn_from_finding / record_endpoint_spec / ...
│   │   ├── tools_discovery.py     # push_discovery / store_secret / ...
│   │   ├── tools_security.py      # sqlmap/dalfox/nuclei/multi_http_probe
│   │   └── tools_research.py      # NVD fetch_cve_details / suggest_cves_for_framework
│   └── config/                    # Django settings
├── frontend/src/App.jsx           # React SPA — scan list, tree canvas, NodeDetailPanel,
│                                  # EndpointSpecModal (path tree N-level grouping)
├── agent/
│   ├── eval/                      # run_eval.py + compare_history.py + targets.yaml (gitignored)
│   └── *.md                       # agent prompt/guideline legacy (참고용)
├── .cursor/rules/*.mdc            # Cursor 전용 가이드 (5 files)
├── .claude/skills/watchdog-pentest/  # Claude Code skill (SKILL.md + rules/ 5 copies)
├── watchdog_cli.py                # CLI 전용 도구 (create_scan, record_trace, scan_next, ...)
└── docker-compose.yml             # db(pgvector) + backend + mcp + frontend + eval-oss profile
```

## 핵심 원칙 (반드시 지킬 것)

### 자율성 우선 (memory)
도구는 추가, 강제는 안전망에만. validator warnings, critic verdict, scan_next
recommend 등 advisory 신호는 LLM 판단으로 무시 가능. 단 결과는 selfcheck
warnings 로 누적되어 보고서에 노출.

### Commit 에 AI 기여 표기 금지 (memory)
git commit / PR / 리모트 산출물에 `Co-Authored-By`, `generated-by`, AI 관련
crediting 일체 금지. 사용자 본인(ialleejy) 명의만.

### Claude API only
OpenAI / Gemini 등 다른 vendor 안 씀. 4주차 LiteLLM N-version 포기,
critic agent 단일로 대체. Claude family (Sonnet/Haiku/Opus) 내 voting 은 미결.

## 작업 시 자주 쓰는 경로

- 새 scan 만들기: `POST /api/scan-runs/` — mode default `discovery`, config 에
  `credentials` 또는 `resume_from` 옵션 가능
- 백엔드 rebuild 후 frontend 502 뜨면: `docker compose restart frontend`
  (nginx DNS 캐시 refresh — 영구 fix 는 별도 작업)
- 평가 돌리기: `python agent/eval/run_eval.py --phase <name> --mcp --only <ids>`
- 결과 비교: `python agent/eval/compare_history.py --phase A B` or `--regress`

## Manual pentest 진행 시

Watchdog MCP 를 직접 활용해 scan 돌리는 작업이면 **watchdog-pentest skill**
자동 trigger 후보. `.claude/skills/watchdog-pentest/SKILL.md` + 옆 `rules/`
(5 파일) 을 Read 해 mental model 잡고 시작. TIER A (R1-R10) 반드시 준수:
update_node_status / save_evidence / record_pattern_use 호출 누락 시 vuln
노드 pending stuck + KB 학습 0 (재발 금지).

## 자주 까먹는 사실

- `agent/eval/targets.yaml` 은 **.gitignore** 처리 (CTF 풀이 정보 보호).
  OSS target 은 `agent/eval/README.md` 스니펫 복붙해 본인 targets.yaml 에 추가.
- `techniques/<vuln_type>/*.md` 는 **bind mount** 로 호스트 동기화 —
  learn_from_finding(is_novel=True) 시 자동 dump, git add 하면 영구 자산.
- 루트의 `_*.py`, `_*.php` 는 `.gitignore` 처리 (ad-hoc 디버깅 스크래치).
  `agent/eval/archive/` 에 70개 보존됨 (gitignored).
- `docker-compose.yml` 의 `version: "3.9"` 는 obsolete 경고 — 나중에 제거.
