"""
MCP 에이전트 루프
Claude가 MCP 도구를 자율적으로 선택·체이닝하여 웹 취약점을 탐지한다.
watchdog_mcp(보안 도구) + PostgreSQL MCP(DB 쿼리) 두 서버를 동시 연결한다.
"""

import asyncio
import json
import logging
import os
import shutil
import sys
import time
from contextlib import AsyncExitStack
from decimal import Decimal

from asgiref.sync import sync_to_async
from django.utils import timezone
from anthropic import Anthropic

# 프로젝트의 /app/mcp/ 폴더가 pip의 mcp SDK를 가리므로
# sys.path에서 /app을 임시 제거하고 import한다.
_app_paths = [p for p in sys.path if p in ("/app", "/app/")]
for _p in _app_paths:
    sys.path.remove(_p)
# 캐시된 로컬 mcp 모듈 제거
for _key in list(sys.modules.keys()):
    if _key == "mcp" or _key.startswith("mcp."):
        del sys.modules[_key]

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

# sys.path 원복
for _p in _app_paths:
    if _p not in sys.path:
        sys.path.append(_p)

from .error_utils import summarize_exception  # noqa: E402
from .llm_trace_store import (  # noqa: E402
    build_prompt_preview,
    build_response_preview,
    extract_tool_calls,
    record_llm_trace,
    summarize_tool_results,
)
from .models import ScanRun  # noqa: E402
from .scan_control import (  # noqa: E402
    ScanStopped,
    is_stop_requested,
    mark_scan_stopped,
    raise_if_stop_requested,
    register_scan,
    stop_sleep,
    unregister_scan,
)

logger = logging.getLogger(__name__)

# ── 설정 ──────────────────────────────────────────────
MAX_TURNS = 50
MAX_TURNS_PER_ROLE = 18  # 기본값 (호출부에서 role별 override 가능)
ROLE_TURN_BUDGET = {
    "planner": 18,    # 정찰 + KB lookup + 가설 emit. White-box 소스 분석 시 여유 필요.
    "executor": 18,   # hypothesis당 2~3턴 × 4~6개 + emit. 너무 길면 안전망 트리거.
    "verifier": 18,   # oracle 호출 + 판정.
    "reporter": 4,    # 단순 generate_report.
}
# swarm 모드 — worker가 hypothesis/attempt 단 하나만 처리하므로 turn 짧음.
SWARM_BUDGET = {
    "planner": 18,
    "executor_worker": 12,   # 1 hypothesis: KB lookup + multi-step chain (3-6 HTTP) + emit.
    "verifier_worker": 10,   # 1 attempt만. oracle 1-3회 + confirm/dismiss + learn + emit.
    "reporter": 4,
}
SWARM_EXECUTOR_COUNT = int(os.environ.get("WATCHDOG_SWARM_EXECUTORS", "3"))
SWARM_VERIFIER_COUNT = int(os.environ.get("WATCHDOG_SWARM_VERIFIERS", "2"))
SWARM_QUIESCENCE_S = int(os.environ.get("WATCHDOG_SWARM_QUIESCENCE_S", "30"))
SWARM_MAX_HYPOTHESES = int(os.environ.get("WATCHDOG_SWARM_MAX_HYPOTHESES", "20"))
MAX_PLAN_ITERATIONS = 2  # planner→executor→verifier 사이클 반복 횟수 (replan 포함)
MODEL = "claude-sonnet-4-20250514"
AGENT_MODE_DEFAULT = os.environ.get("WATCHDOG_AGENT_MODE", "multi").lower()

# Sonnet 4 pricing: input $3/MTok, output $15/MTok
INPUT_COST_PER_TOKEN = Decimal("0.000003")
OUTPUT_COST_PER_TOKEN = Decimal("0.000015")

SYSTEM_PROMPT = """\
당신은 웹 애플리케이션 보안 스캐너 에이전트입니다.
주어진 타겟 URL을 분석하여 취약점을 찾아야 합니다.

## 절차
1. `browser_navigate`로 타겟에 접속하고 `browser_extract_api_endpoints`로 API 엔드포인트를 수집하세요.
2. `analyze_endpoint`로 각 엔드포인트를 분석하여 의심 vuln_type을 결정하세요.
3. **공격 전에 반드시 `search_knowledge(vuln_type=...)`를 호출**해 CWE/OWASP 맥락과 검증된 페이로드 패턴을 먼저 가져오세요. KB는 `attack_metadata`에 `technique_steps_md`(단계별 공격 가이드)와 `code_template`(검증된 익스플로잇 코드)를 포함합니다. **이를 읽고 현재 타겟에 맞게 응용하세요.**
4. 필요하면 `retrieve_similar_patterns(query=...)`로 엔드포인트 설명/파라미터명과 의미적으로 가까운 패턴을 추가 조회하세요.
5. 패턴의 `safety_level`이 "destructive"이면 사용 금지. "cautious"는 저빈도로만 사용하세요.
6. **KB의 technique_steps_md가 multi-step chain이면 단계별로 따라하세요.** 예: "Step 1: SSRF로 내부 API 접근 → Step 2: 응답에서 토큰 추출 → Step 3: 토큰으로 플래그 획득". `http_session_request`로 세션을 유지하며 chain을 실행하세요.
7. 시도한 각 패턴에 대해 `record_pattern_use(pattern_id=..., succeeded=..., false_positive=...)`를 호출해 Knowledge DB의 success_rate를 업데이트하세요.
8. 취약점이 확인되면 `confirm_finding`으로 Finding을 생성하고, `auto_collect_evidence`로 증거를 수집하세요.
9. 모든 분석이 완료되면 `generate_report`로 리포트를 생성하세요.

## Knowledge DB 활용
- `search_knowledge`는 vuln_type/keyword 기준 lookup (정확 매칭).
  - vuln_type 카테고리 (27종):
    Injection: sqli, nosqli, xss, cmdi, ssti, ldap_injection, xpath_injection, graphql
    File: lfi, path_traversal, file_upload, xxe
    Server: ssrf, rce, deserialization, http_smuggling, race_condition
    Auth: idor, access_control, auth_bypass, csrf, jwt
    Client: prototype_pollution, cors
    Other: open_redirect, information_disclosure, logic_flaw
  - 각 pattern은 `sub_technique` 필드로 세부 기법 분류 (예: ssrf/loopback, cmdi/newline_injection)
- `retrieve_similar_patterns`는 자연어 query 기준 semantic search (로컬 임베딩).
- 두 도구가 반환하는 `false_positive_hints`와 `evidence_points`를 검증 전략의 기준으로 삼으세요.

## DB 쿼리 (PostgreSQL MCP)
- `pg_query` 도구로 과거 스캔 결과, 기존 취약점 패턴 등을 직접 조회할 수 있습니다.
- 읽기 전용으로만 사용하세요. INSERT/UPDATE/DELETE는 금지됩니다.

## 주의사항
- 타겟 URL 외의 도메인을 공격하지 마세요.
- 파괴적 페이로드(DROP TABLE 등)는 사용하지 마세요.
- 각 단계의 결과를 분석한 후 다음 행동을 결정하세요.
- 더 이상 분석할 것이 없으면 리포트를 생성하고 종료하세요.
"""


def _get_pg_connection_string() -> str:
    """Django DB 설정에서 PostgreSQL 연결 문자열을 생성한다."""
    from django.conf import settings
    db = settings.DATABASES["default"]
    return (
        f"postgresql://{db['USER']}:{db['PASSWORD']}"
        f"@{db['HOST']}:{db['PORT']}/{db['NAME']}"
    )


def _convert_tools_for_anthropic(mcp_tools: list, prefix: str = "") -> list:
    """MCP 도구 목록을 Anthropic tool_use 형식으로 변환한다."""
    tools = []
    for tool in mcp_tools:
        input_schema = tool.inputSchema if hasattr(tool, "inputSchema") else {}
        if not input_schema:
            input_schema = {"type": "object", "properties": {}}
        name = f"{prefix}{tool.name}" if prefix else tool.name
        tools.append({
            "name": name,
            "description": tool.description or tool.name,
            "input_schema": input_schema,
        })
    return tools


# ─────────────────────────────────────────────────────────────
# Multi-agent orchestration (Planner → Executor → Verifier → Reporter)
# ─────────────────────────────────────────────────────────────

PLANNER_PROMPT = """\
You are the Planner. Recon + hypothesis only. No attacks (Executor) or verdicts (Verifier).
Tool choice and call count are your call.

## Tools
- Recon: browser_navigate, browser_extract_api_endpoints, browser_get_dom,
  browser_get_network_log, browser_screenshot, browser_get_console, analyze_endpoint
- Source (white-box): list_source_tree, read_source, grep_source
  (SOURCE_ROOTS env limits safe root; for_organizer/exploit are auto-blocked)
- Knowledge: search_knowledge, retrieve_similar_patterns, retrieve_cve_variants
- Living KB: recall_target, recall_dead_ends, update_target_profile
- DB: pg_* (read-only)
- Exit: emit_hypotheses(hypotheses_json="...")

## Blocked here (use right role)
sqlmap_scan / dalfox_scan / nuclei_scan / http_request (Executor),
confirm_finding / dismiss_candidate (Verifier).

## Flow (recommended, not enforced)

0. Start with `recall_target(target_host)` — prior learned patterns / dead_ends / framework.
0a. If white-box (SOURCE_ROOTS shown in BUDGET line above), call `list_source_tree` first;
    `grep_source` for sinks like `\\$_GET\\[`, `req\\.body`, `params\\[`, etc.
1. Recon endpoints (small target <15 → cover all).
2. analyze_endpoint for suspect vuln_type.
3. update_target_profile when framework/server/WAF identified.
4. **KB lookup (MANDATORY after recon)**:
   - `search_knowledge(vuln_type=...)` for EACH identified vuln_type.
     Available types (27): sqli, nosqli, xss, cmdi, ssti, ssrf, rce, lfi, path_traversal,
     file_upload, xxe, idor, access_control, auth_bypass, csrf, jwt, deserialization,
     http_smuggling, race_condition, prototype_pollution, cors, graphql,
     open_redirect, information_disclosure, logic_flaw.
   - `retrieve_similar_patterns(query="...")` with endpoint description / tech stack.
   - **KB returns patterns with `sub_technique` (e.g., ssrf/loopback, cmdi/newline_injection)
     and `attack_metadata` with `technique_steps_md` and `code_template`**.
     Read these carefully — they contain proven exploit chains.
   - If technique_steps_md describes a multi-step chain (e.g., "Step 1: SSRF → Step 2: pipe
     injection → Step 3: read flag"), create a hypothesis that references the full chain.
   - Include relevant `candidate_pattern_ids` from KB in hypothesis so Executor can look them up.
   - Never repeat same vuln_type query twice.
5. **Mode mix (zero-day matters)**:
   - exploit: KB seed or learned_patterns (fast baseline). Include `technique_steps_md`
     summary in hypothesis rationale so Executor knows the attack plan.
   - explore (≥1/3 of hypotheses): LLM-novel guesses commodity tools won't try
     (framework quirks, logic flaws, composition chains, exotic encoding).
6. **CRITICAL: Call `emit_hypotheses` before budget runs out.**
   Reserve at least 2 turns for hypothesis generation. Don't over-read source files.
   When [BUDGET] shows ≤ 4 remaining, STOP recon and emit immediately.

## Exit JSON

```json
{"hypotheses":[{"endpoint":"/x","method":"GET","param":"id","vuln_type":"sqli",
  "rationale":"...","candidate_pattern_ids":["uuid",...],"mode":"exploit|explore"}]}
```
Max ~8.
"""

EXECUTOR_PROMPT = """\
You are the ScanExecutor. **Send payloads, record. Don't judge** — that's Verifier.
Virtue: fast attempt, fast handoff. ~2-3 LLM turns per hypothesis target.

## Tools
- Stateless: http_request, curl_request, sqlmap_scan, dalfox_scan, nuclei_scan,
  ffuf_scan, nikto_scan, wafw00f_scan, whatweb_scan
- **Stateful HTTP (multi-step CTF)**: http_session_request(session_id, method, url,
  headers_json, body, form_json, files_json) — same session_id chains cookies.
  http_session_cookies / http_session_close
- **OOB callback (XSS bot / SSRF / RCE async)**: oob_register_token(scan_run_id) →
  use callback_url in payload webhook. oob_wait_for_hit(token, timeout_s) /
  oob_get_hits(token).
- Recon aux: browser_navigate, browser_get_dom, browser_get_network_log,
  browser_screenshot, browser_extract_api_endpoints
- Source: list_source_tree, read_source, grep_source
- KB: search_knowledge, retrieve_similar_patterns, record_pattern_use, mutate_payload
- Candidate: create_candidate_manual
- Evidence aux: save_evidence, auto_collect_evidence
- Living KB: recall_dead_ends
- Exit: emit_attempts(attempts_json="...")

## Blocked here
confirm_finding / dismiss_candidate / generate_report (other roles).

## Flow

0. Once: recall_dead_ends(target_host) — skip already-failed (endpoint, vuln_type, pattern).
1. **KB first**: For each new vuln_type, call `search_knowledge(vuln_type=...)` once.
   KB has 27 vuln_type categories and `sub_technique` for fine-grained techniques.
   Use `retrieve_similar_patterns(query="...")` with endpoint + tech description for extras.
   **KB returns patterns with `sub_technique` and `attack_metadata` containing
   `technique_steps_md` and `code_template`** — use them.
2. Per hypothesis:
   - exploit: Read KB's `technique_steps_md` and follow it step-by-step, adapting to this target.
     Use `code_template` as a starting point, not a copy-paste. Multi-step chains →
     use `http_session_request` with same session_id to chain requests.
   - explore: write a payload commodity tools won't try (framework quirk, logic flaw,
     composition chain, exotic encoding) — `mutate_payload` for KB variants.
   - **Don't fire generic payloads**. Craft target-specific attacks using KB + source/recon.
3. record_pattern_use once; matched → create_candidate_manual once; **next immediately**.
4. evidence_summary short (<300 chars).
5. After all hypotheses: emit_attempts. Resist extra tries — Verifier handles depth.
   Empty attempts array OK.

## Critical — emit_attempts aggressively

Budget: 4 hypotheses ≈ ≤10 turns. When [BUDGET] hits half → start preparing emit.
Never repeat same endpoint twice. Never search_knowledge same vuln_type twice.
If create_candidate_manual fails — pass candidate_id=null to Verifier; evidence_summary
alone is enough.

## Exit JSON

```json
{"attempts":[{"endpoint":"/x","vuln_type":"sqli","pattern_id":"uuid|new",
  "matched":true,"candidate_id":"uuid|null","evidence_summary":"...",
  "mode":"exploit|explore"}]}
```
"""

VERIFIER_PROMPT = """\
You are the Verifier. Take Executor's attempts → confirm/dismiss findings.
Tool choice and judgment style are your call; below is the arsenal + recommendations.

## Arsenal

**Deterministic oracles** (use actively, beats guessing):
- oracle_xss(url, payload_param, payload_value) — headless Playwright dialog/sentinel
- oracle_sqli_boolean(url_true, url_false, url_baseline) — len/status diff
- oracle_sqli_time(url_payload, url_baseline, expected_delay_ms, samples) — timing stat
- oracle_lfi(url) — system-file signatures in body
- oracle_ssrf(url) — metadata/internal banner echo
- oracle_response_diff(baseline_url, payload_url, control_url) — generalized diff

**OOB (async XSS bot, SSRF, RCE)**: oob_get_hits(token), oob_wait_for_hit(token, timeout_s).
**Aux**: http_request, http_session_request, get_finding, get_scan_summary,
list_candidates, search_knowledge.
**Source**: list_source_tree, read_source, grep_source (sink confirmation).
**Register**: confirm_finding, dismiss_candidate, save_evidence, auto_collect_evidence,
record_pattern_use.

**Living KB writeback (asset critical)**:
- learn_from_finding(finding_id, target_host, payload_used, is_novel, novelty_reason, ...)
  - **is_novel=True**: LLM/sqlmap/dalfox/nuclei would NOT try this. Examples: explore-mode
    self-generated payload, mutate_payload variant confirmed, framework quirk
    (Flask `?id[]=`, Django `__regex`), WAF bypass chain, logic flaw, multi-endpoint chain.
  - **is_novel=False**: commodity (`1' OR '1'='1`, `<script>alert(1)</script>`,
    `../../../etc/passwd`, `127.0.0.1` SSRF). Skip KB write.
  - Unsure → False.
- learn_dead_end(target_host, endpoint, vuln_type, pattern_id, payload_used, reason)
- update_target_profile(target_host, framework, server, waf, fingerprint_json, notes)

## Petri Judge with citation (recommended)

1. Gather: call oracle_* or cite earlier tool output.
2. Citations: 2-5 short snippets from body/oracle/tool result → verdict basis.
   Weak citations → inconclusive.
3. Decide: confirmed / false_positive / inconclusive. oracle.confirmed=true is strong but
   not sole. false_positive_hints in KB can demote oracle-positive to inconclusive.
4. Register: confirmed → confirm_finding + auto_collect_evidence + **learn_from_finding**.
   false_positive → dismiss_candidate + record_pattern_use(false_positive=True) +
   **learn_dead_end**.

## Class hints (advisory)

- SQLi: error-only ≠ confirmed. Use oracle_sqli_boolean or _time.
- XSS: reflection-only ≠ confirmed. Use oracle_xss dialog/sentinel; OOB hits also strong.
- IDOR: two-persona diff + sensitive field.
- SSRF: oracle_ssrf or OOB hit from victim host.
- LFI: oracle_lfi signature.

## Exit (emit_verdicts or JSON)

```json
{"verdicts":[{"endpoint":"/x","vuln_type":"sqli","verdict":"confirmed|false_positive|inconclusive",
  "finding_id":"uuid|null","candidate_id":"uuid|null","citations":["..."],
  "oracle_used":["oracle_sqli_boolean"],"needs_replan":false,"replan_hint":""}]}
```
"""

REPORTER_PROMPT = """\
당신은 Reporter 에이전트입니다. generate_report(run_id="<...>") 도구만 호출해 최종 리포트를 생성하세요.
다른 도구는 호출하지 마세요.
"""

PLANNER_TOOLS = {
    "browser_navigate", "browser_extract_api_endpoints", "browser_get_dom",
    "browser_get_network_log", "browser_screenshot", "browser_get_console",
    "analyze_endpoint", "search_knowledge", "retrieve_similar_patterns",
    "retrieve_cve_variants", "list_candidates", "get_scan_summary",
    # Living KB — host-specific 회상
    "recall_target", "recall_dead_ends", "update_target_profile",
    # Source code reading (white-box / glass-box CTF)
    "list_source_tree", "read_source", "grep_source",
    "emit_hypotheses",
}
EXECUTOR_TOOLS = {
    "http_request", "curl_request", "sqlmap_scan", "dalfox_scan", "nuclei_scan",
    "ffuf_scan", "nikto_scan", "wafw00f_scan", "whatweb_scan",
    "browser_navigate", "browser_get_dom", "browser_get_network_log",
    "browser_screenshot", "browser_extract_api_endpoints",
    "search_knowledge", "retrieve_similar_patterns", "record_pattern_use",
    "mutate_payload", "create_candidate_manual", "save_evidence",
    "auto_collect_evidence", "list_candidates",
    # Living KB — dead end 사전 조회로 무의미한 시도 회피
    "recall_dead_ends",
    # Source reading — chain composition 시 코드 참고
    "read_source", "grep_source", "list_source_tree",
    # Stateful HTTP — multi-step web flow (login → write → report 등)
    "http_session_request", "http_session_cookies", "http_session_close",
    # OOB callback — XSS bot / SSRF / RCE 비동기 결과 수신
    "oob_register_token", "oob_get_hits", "oob_wait_for_hit", "oob_clear_hits",
    "emit_attempts",
}
VERIFIER_TOOLS = {
    "http_request", "get_finding", "get_scan_summary", "list_candidates",
    "search_knowledge", "confirm_finding", "dismiss_candidate", "reopen_candidate",
    "save_evidence", "auto_collect_evidence", "record_pattern_use",
    "oracle_xss", "oracle_sqli_boolean", "oracle_sqli_time",
    "oracle_lfi", "oracle_ssrf", "oracle_response_diff",
    # Living KB — confirm/dismiss 결과를 누적 자산으로 저장
    "learn_from_finding", "learn_dead_end", "update_target_profile",
    # Source reading — false positive 판정 시 코드 검증
    "read_source", "grep_source", "list_source_tree",
    # OOB — XSS bot 등 비동기 결과 확증 (oracle 보다 강한 증거)
    "oob_get_hits", "oob_wait_for_hit",
    # Verifier도 stateful HTTP 가능 (control vs payload 비교 chain)
    "http_session_request",
    "emit_verdicts",
}
REPORTER_TOOLS = {"generate_report", "get_scan_summary"}


def _filter_tools(anthropic_tools: list, allowed: set[str]) -> list:
    """이름 화이트리스트 기반 필터. pg_ 프리픽스는 모든 role에서 read-only로 허용."""
    out = []
    for t in anthropic_tools:
        name = t["name"]
        if name in allowed or name.startswith("pg_"):
            out.append(t)
    return out


def _extract_json_block(text: str) -> dict | None:
    """assistant 텍스트에서 ```json ... ``` 블록 또는 첫 JSON 객체를 파싱."""
    if not text:
        return None
    import re

    fenced = re.findall(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidates = list(fenced)
    if not candidates:
        # 보조: 가장 큰 {...} 블록
        first = text.find("{")
        last = text.rfind("}")
        if first >= 0 and last > first:
            candidates.append(text[first : last + 1])
    for c in candidates:
        try:
            return json.loads(c)
        except Exception:
            continue
    return None


class _Accumulator:
    """role 호출 간 토큰/콜/비용 집계를 누적."""

    def __init__(self):
        self.input_tokens = 0
        self.output_tokens = 0
        self.calls = 0


def _call_llm_with_retry(anthropic, scan_run, **kwargs):
    response = None
    for retry in range(3):
        try:
            response = anthropic.messages.create(**kwargs)
            return response
        except Exception as api_err:
            msg = str(api_err).lower()
            if any(x in msg for x in ("rate_limit", "429", "529", "overloaded")):
                wait = 30 * (2 ** retry)
                logger.warning(
                    f"[{scan_run.run_id}] Rate limit, {wait}s 대기 ({retry+1}/3)"
                )
                stop_sleep(scan_run, wait)
            else:
                raise
    raise RuntimeError("Rate limit 재시도 3회 초과")


TOOL_RESULT_MAX_CHARS = 2500  # 비용 vs 정보. 큰 도구 결과는 잘라서 messages 부피 감소.
TOOL_RESULT_EXTENDED_CHARS = 4000  # 소스코드/체인 컨텍스트 등 정보 밀도가 높은 도구용.
EXTENDED_LIMIT_TOOLS = {
    "read_source", "grep_source", "list_source_tree",
    "get_chain_context", "get_exploit_chains",
    "get_secrets", "get_scan_notes",
    "http_request", "curl_request", "http_session_request",
}

# 한 LLM 턴에서 동시에 호출돼도 안전한 read-only 도구.
# 상태 변경(write/POST/세션 변형/scanner subprocess)은 전부 제외.
# 자율성 원칙: 강제 직렬화는 안전망에만. 명백한 read-only는 묶어서 대기시간 ↓.
SAFE_PARALLEL_TOOLS = {
    # KB / 검색
    "search_knowledge", "retrieve_similar_patterns", "retrieve_cve_variants",
    # Living KB 회상 (read)
    "recall_target", "recall_dead_ends",
    # 후보/스캔 조회
    "list_candidates", "get_scan_summary", "get_finding",
    "get_chain_context", "get_exploit_chains",
    "get_secrets", "get_scan_notes",
    # 소스 read-only
    "list_source_tree", "read_source", "grep_source",
    # 분석 (해석만, 부수효과 없음)
    "analyze_endpoint",
    # 브라우저 read-only (현재 페이지 상태 조회)
    "browser_get_dom", "browser_get_network_log", "browser_screenshot",
    "browser_get_console", "browser_extract_api_endpoints",
    # OOB read
    "oob_get_hits",
}
# 동시 실행 상한 — read-only라도 백엔드/DB 부하는 줄여둔다.
PARALLEL_TOOL_CONCURRENCY = int(os.environ.get("WATCHDOG_PARALLEL_TOOLS", "4"))


def _truncate_tool_result(text: str, limit: int = TOOL_RESULT_MAX_CHARS) -> str:
    """LLM에 전달할 도구 결과를 cap. JSON 결과는 가능하면 양 끝(시작/끝) 보존 — 본문은 잘림.
    응답 본문이 양 끝 신호(JSON open/close, error message 등)를 보존해야 LLM이 구조 파악 가능.
    """
    if not text or len(text) <= limit:
        return text or ""
    half = (limit - 80) // 2
    if half < 100:
        return text[:limit] + f"\n...[truncated {len(text) - limit} chars]"
    return (
        text[:half]
        + f"\n...[elided {len(text) - 2 * half} chars]...\n"
        + text[-half:]
    )


async def _execute_single_tool(
    scan_run: ScanRun,
    tool_router: dict,
    tb,
) -> dict:
    raise_if_stop_requested(scan_run)
    tool_name = tb.name
    tool_args = tb.input or {}
    logger.info(
        f"[{scan_run.run_id}] tool {tool_name}"
        f"({json.dumps(tool_args, ensure_ascii=False)[:200]})"
    )
    try:
        if tool_name in tool_router:
            session, original = tool_router[tool_name]
            result = await session.call_tool(original, tool_args)
            if result.content:
                text = "\n".join(
                    c.text if hasattr(c, "text") else str(c)
                    for c in result.content
                )
            else:
                text = "(빈 결과)"
            is_error = bool(getattr(result, "isError", False))
        else:
            text = f"도구 {tool_name} 차단 — 이 role 화이트리스트에 없음."
            is_error = True
    except Exception as e:
        logger.error(f"[{scan_run.run_id}] tool error {tool_name}: {e}")
        text = f"도구 오류: {e}"
        is_error = True

    limit = TOOL_RESULT_EXTENDED_CHARS if tool_name in EXTENDED_LIMIT_TOOLS else TOOL_RESULT_MAX_CHARS
    return {
        "type": "tool_result",
        "tool_use_id": tb.id,
        "content": _truncate_tool_result(text, limit),
        "is_error": is_error,
    }


async def _execute_tool_calls(
    scan_run: ScanRun,
    tool_router: dict,
    tool_use_blocks: list,
) -> list[dict]:
    """LLM 한 턴의 tool_use 블록을 실행한다.

    - SAFE_PARALLEL_TOOLS에 속한 read-only 도구는 asyncio.gather로 동시 실행 (concurrency 상한 적용).
    - 그 외(상태변경/스캐너 subprocess/세션 변형)는 호출 순서대로 직렬 실행.
    - tool_result는 LLM에 돌려줄 때 tool_use_id로 매칭되므로 반환 순서는 무관.
    """
    if not tool_use_blocks:
        return []

    parallel_blocks = [tb for tb in tool_use_blocks if tb.name in SAFE_PARALLEL_TOOLS]
    sequential_blocks = [tb for tb in tool_use_blocks if tb.name not in SAFE_PARALLEL_TOOLS]

    results: list[dict] = []

    if parallel_blocks:
        sem = asyncio.Semaphore(max(1, PARALLEL_TOOL_CONCURRENCY))

        async def _bounded(tb):
            async with sem:
                return await _execute_single_tool(scan_run, tool_router, tb)

        gathered = await asyncio.gather(*[_bounded(tb) for tb in parallel_blocks])
        results.extend(gathered)

    for tb in sequential_blocks:
        results.append(await _execute_single_tool(scan_run, tool_router, tb))

    return results


async def _run_role_phase(
    scan_run: ScanRun,
    anthropic,
    role: str,
    system_prompt: str,
    tools: list,
    tool_router: dict,
    initial_user_message: str,
    acc: _Accumulator,
    max_turns: int = MAX_TURNS_PER_ROLE,
) -> tuple[str, list[dict]]:
    """한 role의 conversation을 끝까지 돌리고 (최종 텍스트, 메시지 히스토리) 반환.

    자율성 우선 설계:
    - 매 턴 user message 끝에 [BUDGET] 정보를 echo해 에이전트가 self-pace 하게 함.
      어떻게 페이스를 조절할지(즉시 종료/추가 정찰/요약)는 에이전트가 결정.
    - **마지막 1턴**에 한해 안전망 모드로 진입: tools=[]를 강제해 도구 호출을 차단하고
      "지금 가진 자료로만 종료 출력 내라"는 user 메시지를 주입.
      이 안전망은 에이전트가 budget을 다 써도 빈손으로 끝나지 않게 받쳐주는 바닥일 뿐,
      그 전까지의 모든 결정은 에이전트가 자율적으로 한다.
    """
    messages: list[dict] = [{"role": "user", "content": initial_user_message}]
    last_text = ""

    for turn in range(max_turns):
        raise_if_stop_requested(scan_run)
        remaining = max_turns - turn
        is_last_turn = (remaining <= 1)
        logger.info(f"[{scan_run.run_id}] {role} turn {turn + 1}/{max_turns} (remaining={remaining})")

        # ── 매 턴 budget echo: 마지막 user message에 한 줄만 덧붙인다 ──
        if messages and messages[-1]["role"] == "user":
            content = messages[-1]["content"]
            if isinstance(content, str):
                messages[-1] = {
                    "role": "user",
                    "content": content + f"\n\n[BUDGET] 남은 턴: {remaining}",
                }
            elif isinstance(content, list):
                # tool_results 리스트인 경우 — 끝에 텍스트 블록 추가
                augmented = list(content)
                augmented.append({
                    "type": "text",
                    "text": f"[BUDGET] 남은 턴: {remaining}",
                })
                messages[-1] = {"role": "user", "content": augmented}

        # ── 마지막 턴 안전망: 도구 차단 + finalize 지시 ──
        # Anthropic prompt caching — system + tools를 ephemeral cache로 표시.
        # 같은 prefix가 5분 안에 다시 호출되면 input 90% 할인. 우리 multi-agent의
        # role별 turn loop는 같은 system을 반복 → 큰 절약.
        cached_system = [{
            "type": "text",
            "text": system_prompt,
            "cache_control": {"type": "ephemeral"},
        }]
        call_kwargs = dict(
            model=MODEL, max_tokens=4096,
            system=cached_system, messages=messages,
        )
        if is_last_turn:
            call_kwargs["tools"] = []
            messages.append({
                "role": "user",
                "content": (
                    "[BUDGET] 마지막 턴. 도구 호출 불가. 지금 자료로 종료 JSON만 출력. "
                    "비면 빈 배열도 OK."
                ),
            })
            call_kwargs["messages"] = messages
        else:
            # 마지막 도구에 cache_control 표시 → 그 위의 system + 모든 도구 schema 캐시.
            cached_tools = [dict(t) for t in tools]
            if cached_tools:
                cached_tools[-1] = {
                    **cached_tools[-1],
                    "cache_control": {"type": "ephemeral"},
                }
            call_kwargs["tools"] = cached_tools

        response = _call_llm_with_retry(anthropic, scan_run, **call_kwargs)

        acc.input_tokens += response.usage.input_tokens
        acc.output_tokens += response.usage.output_tokens
        acc.calls += 1
        scan_run.llm_calls_count = acc.calls
        scan_run.llm_tokens_used = acc.input_tokens + acc.output_tokens
        scan_run.llm_cost_usd = (
            Decimal(str(acc.input_tokens)) * INPUT_COST_PER_TOKEN
            + Decimal(str(acc.output_tokens)) * OUTPUT_COST_PER_TOKEN
        )
        await sync_to_async(scan_run.save)(update_fields=[
            "llm_calls_count", "llm_tokens_used", "llm_cost_usd",
        ])

        prompt_preview = build_prompt_preview(messages)
        response_preview = build_response_preview(response.content)
        tool_calls = extract_tool_calls(response.content)

        # 텍스트 블록 집계
        for block in response.content:
            if hasattr(block, "text") and block.text:
                last_text = block.text

        tool_use_blocks = [b for b in response.content if b.type == "tool_use"]

        # ── emit_* 자율 종료 감지 ──
        # 에이전트가 emit_hypotheses/attempts/verdicts 도구를 호출하면 그 입력을
        # last_text에 JSON으로 넣고 즉시 루프 종료. orchestrator가 _extract_json_block
        # 으로 파싱한다. 이는 자유 텍스트 JSON 코드블록과 동등하게 동작.
        emit_block = next(
            (b for b in tool_use_blocks if b.name in {
                "emit_hypotheses", "emit_attempts", "emit_verdicts",
            }),
            None,
        )
        if emit_block is not None:
            # emit_*의 입력은 {"<role>_json": "..."} 한 필드. 그 안의 JSON 문자열을 그대로
            # 코드블록으로 옮겨 _extract_json_block이 hypotheses/attempts/verdicts 키를 직접 보게 한다.
            raw = emit_block.input or {}
            inner = (
                raw.get("hypotheses_json")
                or raw.get("attempts_json")
                or raw.get("verdicts_json")
                or json.dumps(raw, ensure_ascii=False)
            )
            last_text = "```json\n" + str(inner) + "\n```"
            await sync_to_async(record_llm_trace)(
                scan_run=scan_run,
                call_index=acc.calls,
                stage=f"multi:{role}",
                model=MODEL,
                prompt_preview=prompt_preview,
                response_preview=response_preview,
                tool_calls=tool_calls,
                stop_reason=f"emit:{emit_block.name}",
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
                metadata={"role": role, "turn": turn + 1, "emitted": emit_block.name},
            )
            break

        if response.stop_reason == "end_turn" or not tool_use_blocks:
            await sync_to_async(record_llm_trace)(
                scan_run=scan_run,
                call_index=acc.calls,
                stage=f"multi:{role}",
                model=MODEL,
                prompt_preview=prompt_preview,
                response_preview=response_preview,
                tool_calls=tool_calls,
                stop_reason=response.stop_reason,
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
                metadata={"role": role, "turn": turn + 1},
            )
            break

        messages.append({"role": "assistant", "content": response.content})
        tool_results = await _execute_tool_calls(scan_run, tool_router, tool_use_blocks)

        await sync_to_async(record_llm_trace)(
            scan_run=scan_run,
            call_index=acc.calls,
            stage=f"multi:{role}",
            model=MODEL,
            prompt_preview=prompt_preview,
            response_preview=response_preview,
            tool_calls=tool_calls,
            stop_reason=response.stop_reason,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            metadata={
                "role": role,
                "turn": turn + 1,
                "tool_results": summarize_tool_results(tool_results),
            },
        )
        messages.append({"role": "user", "content": tool_results})
    else:
        logger.warning(f"[{scan_run.run_id}] {role} max turns reached")

    return last_text, messages


async def _run_multi_agent_loop(
    scan_run: ScanRun,
    anthropic,
    anthropic_tools: list,
    tool_router: dict,
):
    acc = _Accumulator()

    planner_tools = _filter_tools(anthropic_tools, PLANNER_TOOLS)
    executor_tools = _filter_tools(anthropic_tools, EXECUTOR_TOOLS)
    verifier_tools = _filter_tools(anthropic_tools, VERIFIER_TOOLS)
    reporter_tools = _filter_tools(anthropic_tools, REPORTER_TOOLS)

    logger.info(
        f"[{scan_run.run_id}] multi-agent tool counts: "
        f"planner={len(planner_tools)} executor={len(executor_tools)} "
        f"verifier={len(verifier_tools)} reporter={len(reporter_tools)}"
    )

    scan_config = scan_run.config or {}
    specific_source = scan_config.get("source_root", "")
    source_hint = ""
    if specific_source and os.path.isdir(specific_source):
        source_hint = (
            f"\n[WHITE-BOX] 이 타겟의 소스 코드 위치: {specific_source}\n"
            f"  `list_source_tree(root=\"{specific_source}\")` 로 시작하세요."
        )
    else:
        src_roots = os.environ.get("SOURCE_ROOTS", "").strip()
        if src_roots:
            try:
                existing = []
                for root in src_roots.split(":"):
                    root = root.strip()
                    if root and os.path.isdir(root):
                        sub = [d for d in os.listdir(root) if not d.startswith(".")]
                        if sub:
                            existing.append((root, sub[:10]))
                if existing:
                    lines = ["", "[WHITE-BOX] SOURCE_ROOTS 디렉터리에 코드가 있습니다 — `list_source_tree`/`read_source`/`grep_source` 활용 권장:"]
                    for root, subs in existing:
                        lines.append(f"  - {root}: {', '.join(subs)}")
                    source_hint = "\n".join(lines)
            except Exception:
                pass

    plan_brief = (
        f"타겟 URL: {scan_run.target_url}\n"
        f"스캔 ID: {scan_run.run_id}\n"
        f"{source_hint}\n"
        f"위 타겟을 정찰하고 hypotheses(JSON)를 출력하세요."
    )
    last_replan_hint = ""
    last_verdicts: list[dict] = []

    for iteration in range(MAX_PLAN_ITERATIONS):
        logger.info(
            f"[{scan_run.run_id}] === plan iteration {iteration + 1}/{MAX_PLAN_ITERATIONS} ==="
        )

        # 1) Planner
        planner_user_msg = plan_brief
        if iteration > 0:
            planner_user_msg += (
                "\n\n이전 verdicts 중 needs_replan=true 항목이 있습니다:\n"
                + json.dumps(
                    [v for v in last_verdicts if v.get("needs_replan")],
                    ensure_ascii=False,
                )
                + f"\n\nreplan_hint: {last_replan_hint}\n"
                "이전과 다른 패턴/접근으로 hypotheses를 다시 작성하세요."
            )

        planner_text, _ = await _run_role_phase(
            scan_run, anthropic, "planner", PLANNER_PROMPT,
            planner_tools, tool_router, planner_user_msg, acc,
            max_turns=ROLE_TURN_BUDGET["planner"],
        )
        plan_json = _extract_json_block(planner_text) or {"hypotheses": []}
        hypotheses = plan_json.get("hypotheses", [])
        logger.info(
            f"[{scan_run.run_id}] planner produced {len(hypotheses)} hypotheses"
        )
        if not hypotheses:
            logger.info(f"[{scan_run.run_id}] no hypotheses — abort iteration")
            break

        # 2) Executor
        executor_user_msg = (
            f"스캔 ID: {scan_run.run_id}\n"
            f"타겟: {scan_run.target_url}\n\n"
            f"다음 hypotheses를 실행하세요:\n```json\n"
            + json.dumps({"hypotheses": hypotheses}, ensure_ascii=False, indent=2)
            + "\n```"
        )
        executor_text, _ = await _run_role_phase(
            scan_run, anthropic, "executor", EXECUTOR_PROMPT,
            executor_tools, tool_router, executor_user_msg, acc,
            max_turns=ROLE_TURN_BUDGET["executor"],
        )
        exec_json = _extract_json_block(executor_text) or {"attempts": []}
        attempts = exec_json.get("attempts", [])
        logger.info(f"[{scan_run.run_id}] executor produced {len(attempts)} attempts")

        # 3) Verifier
        verifier_user_msg = (
            f"스캔 ID: {scan_run.run_id}\n"
            f"타겟: {scan_run.target_url}\n\n"
            f"Executor 결과를 검증하고 verdicts(JSON)를 출력하세요:\n```json\n"
            + json.dumps({"attempts": attempts}, ensure_ascii=False, indent=2)
            + "\n```"
        )
        verifier_text, _ = await _run_role_phase(
            scan_run, anthropic, "verifier", VERIFIER_PROMPT,
            verifier_tools, tool_router, verifier_user_msg, acc,
            max_turns=ROLE_TURN_BUDGET["verifier"],
        )
        verdict_json = _extract_json_block(verifier_text) or {"verdicts": []}
        last_verdicts = verdict_json.get("verdicts", [])
        logger.info(f"[{scan_run.run_id}] verifier produced {len(last_verdicts)} verdicts")

        replans = [v for v in last_verdicts if v.get("needs_replan")]
        if not replans:
            break
        last_replan_hint = "; ".join(v.get("replan_hint", "") for v in replans)

    # 4) Reporter
    reporter_user_msg = (
        f"generate_report(run_id=\"{scan_run.run_id}\", format=\"json\") 만 호출해 최종 리포트를 만드세요."
    )
    await _run_role_phase(
        scan_run, anthropic, "reporter", REPORTER_PROMPT,
        reporter_tools, tool_router, reporter_user_msg, acc,
        max_turns=ROLE_TURN_BUDGET["reporter"],
    )

    logger.info(
        f"[{scan_run.run_id}] multi-agent done: "
        f"{acc.calls} LLM calls, {acc.input_tokens + acc.output_tokens} tokens, "
        f"${scan_run.llm_cost_usd}"
    )


# ─────────────────────────────────────────────────────────────
# Swarm — N executor + M verifier 동시 worker + asyncio.Queue 비동기 dispatch
# Living KB(Postgres+pgvector)가 진짜 shared memory. 한 verifier가 confirm하면
# 다음 executor가 recall_target/recall_dead_ends로 즉시 활용 (continuous learning).
# ─────────────────────────────────────────────────────────────

EXECUTOR_WORKER_PROMPT = """\
You are an Executor Worker. Single hypothesis only — fire payload, record, emit.
**Don't judge** (Verifier handles). 3-6 tool calls, then emit_attempts.

## Tools
- Stateful HTTP: http_session_request(session_id, ...) (multipart/cookie chain)
- Stateless: http_request, sqlmap_scan, dalfox_scan, nuclei_scan, ffuf_scan,
  curl_request, wafw00f_scan, whatweb_scan
- OOB: oob_register_token / oob_wait_for_hit / oob_get_hits
- KB recall (Living KB — 다른 worker가 방금 push한 정보 즉시 활용):
  recall_target, recall_dead_ends, search_knowledge, retrieve_similar_patterns,
  read_source, grep_source, list_source_tree
- Mutate: mutate_payload (KB seed 변종)
- Candidate: create_candidate_manual
- Exit: emit_attempts(attempts_json='{"attempts":[{...}]}')

## Flow — KB-driven exploitation

1. **KB lookup**: `search_knowledge(vuln_type=<hypothesis vuln_type>)`.
   KB has 27 categories with `sub_technique` for fine-grained classification.
   The response includes patterns with `attack_metadata` containing:
   - `technique_steps_md`: step-by-step exploit guide — **follow these steps**.
   - `code_template`: working exploit code — **adapt to this target**.
   - `applies_when`: conditions when the technique works — **verify they match**.
   - `prerequisites`: required setup — **check these first**.
2. recall_dead_ends(target_host) once (skip already-failed).
3. **Apply KB knowledge** (this is the key step):
   - If `technique_steps_md` exists, follow its steps sequentially using http_request
     or http_session_request. Adapt URLs, params, payloads to match THIS target.
   - If `code_template` exists, translate it into HTTP requests to the target.
   - If the technique involves a **multi-step chain** (e.g., "Step 1: get token,
     Step 2: use token to access admin, Step 3: exploit admin endpoint"),
     use http_session_request with same session_id to maintain state across steps.
   - Don't just send generic payloads. Read the KB technique and craft a specific
     attack tailored to what source code / recon revealed about this target.
4. record_pattern_use; if matched, create_candidate_manual.
5. emit_attempts immediately.

## Anti-pattern: don't just look up KB and fire a generic payload.
Read technique_steps_md, understand the attack chain, and reproduce it step by step.
"""

VERIFIER_WORKER_PROMPT = """\
You are a Verifier Worker. Single attempt only — call oracle_*, judge, register, learn, emit.

## Tools
- Oracles: oracle_xss / oracle_sqli_boolean / oracle_sqli_time / oracle_lfi /
  oracle_ssrf / oracle_response_diff
- OOB: oob_get_hits / oob_wait_for_hit
- HTTP: http_request, http_session_request (control vs payload diff)
- Source: read_source, grep_source (sink confirm)
- Register: confirm_finding / dismiss_candidate / save_evidence /
  auto_collect_evidence / record_pattern_use
- **Living KB write (shared with all executor workers)**:
  learn_from_finding(finding_id, target_host, payload_used, is_novel, novelty_reason, ...)
    is_novel=True 만 KB에 저장 (commodity sqlmap/dalfox/nuclei 페이로드는 False).
  learn_dead_end(target_host, endpoint, vuln_type, ...) — 다른 executor가 이걸 recall.
  update_target_profile (framework/server/WAF detected).
- Exit: emit_verdicts(verdicts_json='{"verdicts":[{...}]}')

## Flow

1. Decide which oracle(s) fit the vuln_type.
2. Run oracle, gather citations from response/oracle output.
3. confirmed → confirm_finding + auto_collect_evidence + learn_from_finding.
   false_positive → dismiss_candidate + record_pattern_use(false_positive=True) + learn_dead_end.
4. emit_verdicts.
"""

EXECUTOR_WORKER_TOOLS = EXECUTOR_TOOLS  # 같은 도구 — worker는 단지 더 짧은 input만 받음
VERIFIER_WORKER_TOOLS = VERIFIER_TOOLS

# ─────────────────────────────────────────────────────────────
# Discovery mode — 단서 축적형 트리 탐색
# ─────────────────────────────────────────────────────────────

DISCOVERY_WORKER_COUNT = int(os.environ.get("WATCHDOG_DISCOVERY_WORKERS", "3"))
DISCOVERY_WORKER_BUDGET = int(os.environ.get("WATCHDOG_DISCOVERY_WORKER_BUDGET", "14"))
DISCOVERY_EXPLOIT_BUDGET = int(os.environ.get("WATCHDOG_DISCOVERY_EXPLOIT_BUDGET", "22"))
DISCOVERY_CLUE_BUDGET = int(os.environ.get("WATCHDOG_DISCOVERY_CLUE_BUDGET", "18"))
DISCOVERY_RECHECK_BUDGET = int(os.environ.get("WATCHDOG_DISCOVERY_RECHECK_BUDGET", "5"))
DISCOVERY_QUIESCENCE_S = int(os.environ.get("WATCHDOG_DISCOVERY_QUIESCENCE_S", "45"))
DISCOVERY_MAX_CALLS = int(os.environ.get("WATCHDOG_DISCOVERY_MAX_CALLS", "300"))
DISCOVERY_MAX_COST_USD = Decimal(os.environ.get("WATCHDOG_DISCOVERY_MAX_COST_USD", "5.0"))

EXPLORER_PROMPT = """\
You are an Explorer Worker in discovery mode.
You receive a single DiscoveryNode (a clue or discovery from a prior step) and must:
1. Understand the full chain that led here (via get_chain_context).
2. Check for stored secrets/notes from other workers (get_secrets, get_scan_notes).
3. Investigate this node — send requests, run tools, gather evidence.
4. Store any discovered credentials/tokens (store_secret) so other workers can use them.
5. Push new discoveries as children (via push_discovery) for anything interesting found.
6. If this node is a dead end, call mark_dead_end.

## Context
- Each node has a type: target, endpoint, vuln, clue, exploit_step, flag, dead_end.
- You are exploring ONE node. Push child discoveries for anything new you find.
- Other workers are exploring other nodes in parallel — avoid duplicating effort.
  Use get_siblings to see what siblings already exist.

## Discovery Tools
- push_discovery(scan_run_id, parent_node_id, node_type, summary, context_json, endpoint, vuln_type)
  → creates a child node for further exploration
- get_chain_context(node_id) → full ancestor chain (root to current)
- mark_dead_end(node_id, reason) → mark this node as dead end
- get_siblings(node_id) → see sibling nodes to avoid duplication

## Shared State Tools (CRITICAL for multi-step chains)
- store_secret(scan_run_id, key, value, category) → store credential/token for ALL workers
- get_secrets(scan_run_id, category) → retrieve secrets stored by any worker
- add_scan_note(scan_run_id, topic, content) → share observations across workers
- get_scan_notes(scan_run_id, topic) → read observations from other workers

## Attack/Recon Tools (all available)
- HTTP: http_request, http_session_request, curl_request
- Scanners: sqlmap_scan, dalfox_scan, nuclei_scan, ffuf_scan
- Browser: browser_navigate, browser_get_dom, browser_extract_api_endpoints,
  browser_get_network_log, browser_screenshot
- Source: list_source_tree, read_source, grep_source
- KB: search_knowledge, retrieve_similar_patterns, record_pattern_use, mutate_payload
- Oracles: oracle_xss, oracle_sqli_boolean, oracle_sqli_time, oracle_lfi,
  oracle_ssrf, oracle_response_diff
- Evidence: save_evidence, auto_collect_evidence, create_candidate_manual,
  confirm_finding, dismiss_candidate
- Living KB: recall_target, recall_dead_ends, learn_from_finding, learn_dead_end,
  update_target_profile
- OOB: oob_register_token, oob_get_hits, oob_wait_for_hit
- Session: http_session_cookies, http_session_close

## Strategy per node_type

### target (root)
- recall_target(host) to load any prior knowledge about this host (framework, WAF, etc.)
- get_scan_notes to check if other workers left observations.
- CHECK context for "previous_scan": if present, endpoint nodes are already seeded as
  children. You do NOT need to re-discover endpoints — focus on finding NEW endpoints
  or paths that were missed.
- IF source_root is provided: list_source_tree → read_source / grep_source to map
  endpoints, routes, and interesting code FIRST.
  → When reading source: look for authentication logic, hardcoded secrets, internal APIs,
    data flow between components, custom protocols, and request routing chains.
  → Push an add_scan_note("architecture", "<summary of app architecture>")
  → If you find hardcoded credentials or API keys: store_secret immediately.
- THEN browser_navigate to the target URL
- browser_extract_api_endpoints to discover endpoints
- Note the server header, framework signatures, error page style → update_target_profile
- Push EACH NEW found endpoint as a child node (skip endpoints already seeded)
- Even if the root returns 403/404, push discovered paths as endpoint nodes

### endpoint
- CHECK context for "seeded_from": if present, this is from a previous scan.
  Look at prev_vulns and prev_dead_ends. Skip already-failed patterns. Focus on NEW vectors.
- get_secrets to retrieve any credentials discovered by other workers.
- get_scan_notes("architecture") to understand app architecture context.
- Inspect the endpoint: send a few requests, observe response structure, params, headers.
- Based on what you see, think: "What vuln types could apply here?"
  e.g. a URL param → maybe LFI/SSRF, a form field → maybe SQLi/XSS, a JSON body → maybe injection.
- search_knowledge(vuln_type=...) for each suspected type to see what payloads the KB has.
  Also recall_dead_ends to skip patterns that already failed on this host.
- If KB has relevant patterns: push child (node_type="vuln") per suspected vuln_type,
  include the KB pattern_ids in context_json so the vuln worker can use them directly.
- If the endpoint reveals interesting behavior (unusual headers, internal URLs, error
  messages with stack traces): push a "clue" node, add_scan_note, or store_secret.
- If clean after inspection: mark_dead_end

### vuln
- You are investigating a specific vuln_type on a specific endpoint.
- get_secrets — always check for credentials from other workers first.
- IF context has "recheck": true — this vuln was SUCCESSFUL in a previous scan.
  The target may have been patched since then. Your job:
  1. Re-test the exact same attack vector with a quick probe.
  2. If it still works → push exploit_step/flag + confirm_finding (still vulnerable).
  3. If it FAILS (patched) → mark_dead_end with reason "patched since last scan",
     then push a NEW vuln node to try bypass/alternative payloads for the same vuln_type.
     The developer may have done an incomplete fix — test for filter bypasses.
- FIRST: check if parent context_json has pattern_ids from KB. If so, load them.
  Otherwise: search_knowledge(vuln_type=...) to get relevant payloads.
- Try KB payloads first (they are battle-tested). Send each via http_request.
- Use oracle_* tools to verify (oracle_sqli_boolean, oracle_xss, oracle_lfi, etc.)
- After each attempt: record_pattern_use(pattern_id, succeeded=True/False)
- If KB payloads fail but behavior is suspicious: mutate_payload to create variants,
  or craft your own based on the response patterns you observed.
- If confirmed: push child (node_type="exploit_step" or "flag") + confirm_finding
  + learn_from_finding (so future scans benefit)
- If partial success / interesting clue: push child (node_type="clue")
- If all attempts failed: mark_dead_end + learn_dead_end (record what you tried)

### clue
- Investigate the clue (follow redirects, extract tokens, check responses).
- If you discover a credential/token/secret: store_secret IMMEDIATELY.
  Other workers need it for their exploit chains.
- If the clue reveals a new attack surface: search_knowledge for relevant patterns.
- If the clue reveals internal architecture (backend services, internal APIs, custom
  protocols): add_scan_note("architecture", "<details>") for all workers.
- Push children for further exploitation or new endpoints discovered.

### exploit_step
- This is a DEEP exploitation node. You are continuing a multi-step attack chain.
- ALWAYS start with:
  1. get_chain_context — understand the FULL chain that led here. Read every ancestor's
     context carefully, including credentials, intermediate results, and technique details.
  2. get_secrets — load ALL credentials/tokens from the scan's shared store.
  3. get_scan_notes — check for architecture notes and other workers' observations.
- Use http_session_request (same session_id) to maintain cookies across requests.
- THINK about the full picture: Can you combine this with OTHER discovered vulns?
  Check get_siblings and the chain context for other attack vectors that could combine.
- Common chaining patterns:
  * SSRF + LFI → read internal files via server-side request
  * SQLi + file_read → extract secrets then use them for auth bypass
  * Auth bypass + IDOR → access other users' data
  * HTTP Smuggling + SSRF → reach internal services
  * Command Injection via custom protocols → RCE
  * Path traversal + config read → credential extraction → privilege escalation
- IMPORTANT: When you discover intermediate results (leaked data, internal URLs,
  error messages), ALWAYS:
  * store_secret if it's a credential/token
  * add_scan_note if it's architecture info
  * Include it in context_json when pushing the next child node
- If you reach a flag or final exploit: push flag node + confirm_finding + learn_from_finding
- If stuck: search_knowledge or mutate_payload for bypass techniques, then push next step
- If truly stuck after multiple attempts: push the remaining leads as child nodes
  for other workers, describing what you tried and what might work

### flag
- Record the finding: confirm_finding + learn_from_finding + save_evidence
- store_secret(key="flag", value="<the flag>", category="credential")

## Chain Exploitation Strategy (CRITICAL)

Real-world exploits rarely use a single vulnerability. Think like a pentester:

1. **Build the attack surface map mentally**: What components exist? (web server,
   backend API, database, internal services, custom protocols)
2. **Identify primitives**: Each vuln gives you a "primitive" (read, write, execute,
   redirect). Think about what primitives you have and what you need.
3. **Combine primitives**: SSRF gives you "server-side request" primitive. If you also
   have path injection, you can redirect that request anywhere. If you also have a
   custom protocol with command injection, you can chain SSRF → protocol injection → RCE.
4. **Store and share intermediates**: Every discovered credential, internal URL, or
   config value should go into store_secret. Every architecture observation into
   add_scan_note. This is how different workers collaborate on the same chain.
5. **Push detailed context**: When creating exploit_step children, include ALL relevant
   context in context_json: the exact HTTP request that worked, the response, the
   credential used, the intermediate value needed for the next step.

Example multi-step chain (what a successful discovery tree looks like):
```
target → endpoint(/api) → vuln(ssrf) → exploit_step(internal_api_access)
  → clue(credential_leaked) → exploit_step(auth_bypass)
    → exploit_step(admin_panel) → flag(RCE via admin upload)
```

## KB Usage Pattern (natural workflow)
The KB is your arsenal. Use it like a pentester uses their notes:
1. See something suspicious → "Do we have payloads for this?" → search_knowledge
2. Get KB payloads → try them → record_pattern_use (succeeded or not)
3. KB payload works → learn_from_finding (strengthen the KB)
4. KB payload fails → mutate_payload or try your own → learn_dead_end if all fail
5. New host → recall_target first, update_target_profile as you learn about it

## Critical Rules
- ALWAYS call get_chain_context first to understand how you got here.
- ALWAYS call get_siblings to avoid duplicate exploration.
- For exploit_step/clue nodes: ALWAYS call get_secrets and get_scan_notes too.
- You MUST call push_discovery at least once per node unless it is truly a dead end.
  Push discoveries generously — it's better to create nodes that turn out to be
  dead ends than to miss potential attack paths.
- For target nodes: you MUST push at least one endpoint child. Use source code, ffuf,
  manual path probing — whatever it takes to find endpoints.
- Use http_session_request for multi-step chains (same session_id).
- When you find credentials/tokens: store_secret IMMEDIATELY. Do not just put them
  in context_json — other workers on different branches need them too.
- When [BUDGET] shows <= 3 remaining, stop exploring and push remaining leads as nodes.
  Include ALL context needed for the next worker in context_json.
- NEVER just summarize without pushing child nodes or marking dead_end.
"""

EXPLORER_TOOLS = {
    # Discovery-specific
    "push_discovery", "get_chain_context", "mark_dead_end", "get_siblings",
    "get_exploit_chains",
    # Shared state (cross-worker)
    "store_secret", "get_secrets", "add_scan_note", "get_scan_notes",
    # HTTP
    "http_request", "http_session_request", "http_session_cookies",
    "http_session_close", "curl_request",
    # Scanners
    "sqlmap_scan", "dalfox_scan", "nuclei_scan", "ffuf_scan",
    "nikto_scan", "wafw00f_scan", "whatweb_scan",
    # Browser
    "browser_navigate", "browser_get_dom", "browser_extract_api_endpoints",
    "browser_get_network_log", "browser_screenshot",
    # Analysis
    "analyze_endpoint", "list_candidates", "get_scan_summary",
    # Source
    "list_source_tree", "read_source", "grep_source",
    # KB
    "search_knowledge", "retrieve_similar_patterns", "retrieve_cve_variants",
    "record_pattern_use", "mutate_payload",
    # Oracles
    "oracle_xss", "oracle_sqli_boolean", "oracle_sqli_time",
    "oracle_lfi", "oracle_ssrf", "oracle_response_diff",
    # Evidence & Findings
    "save_evidence", "auto_collect_evidence", "create_candidate_manual",
    "confirm_finding", "dismiss_candidate", "reopen_candidate",
    # Living KB
    "recall_target", "recall_dead_ends", "learn_from_finding",
    "learn_dead_end", "update_target_profile",
    # OOB
    "oob_register_token", "oob_get_hits", "oob_wait_for_hit", "oob_clear_hits",
}


async def _executor_worker(
    name: str,
    scan_run: ScanRun,
    anthropic,
    tools: list,
    tool_router: dict,
    hypothesis_q: "asyncio.Queue[dict | None]",
    attempt_q: "asyncio.Queue[dict | None]",
    acc: _Accumulator,
    last_activity_ref: list,
):
    """hypothesis_q에서 한 가설 받아 처리, attempts를 attempt_q에 push.
    last_activity_ref[0]는 quiescence 감지용 (마지막 활동 timestamp).
    """
    import time as _t
    while True:
        try:
            hyp = await hypothesis_q.get()
        except asyncio.CancelledError:
            return
        if hyp is None:  # 종료 신호
            hypothesis_q.task_done()
            return
        last_activity_ref[0] = _t.time()
        logger.info(f"[{scan_run.run_id}] executor[{name}] picked: {hyp.get('endpoint')} {hyp.get('vuln_type')}")
        user_msg = (
            f"target_url: {scan_run.target_url}\n"
            f"scan_id: {scan_run.run_id}\n\n"
            f"한 hypothesis 만 처리하세요:\n```json\n"
            f"{json.dumps(hyp, ensure_ascii=False)}\n```\n"
            f"빠르게 시도 후 emit_attempts."
        )
        try:
            text, _ = await _run_role_phase(
                scan_run, anthropic, f"executor:{name}", EXECUTOR_WORKER_PROMPT,
                tools, tool_router, user_msg, acc,
                max_turns=SWARM_BUDGET["executor_worker"],
            )
            data = _extract_json_block(text) or {}
            for att in data.get("attempts", []):
                await attempt_q.put(att)
        except Exception as e:
            logger.error(f"[{scan_run.run_id}] executor[{name}] error: {e}", exc_info=True)
        finally:
            last_activity_ref[0] = _t.time()
            hypothesis_q.task_done()


async def _verifier_worker(
    name: str,
    scan_run: ScanRun,
    anthropic,
    tools: list,
    tool_router: dict,
    attempt_q: "asyncio.Queue[dict | None]",
    verdicts_collector: list,
    acc: _Accumulator,
    last_activity_ref: list,
):
    """attempt_q에서 한 attempt 받아 oracle 검증, verdicts_collector에 append + Living KB write."""
    import time as _t
    while True:
        try:
            att = await attempt_q.get()
        except asyncio.CancelledError:
            return
        if att is None:
            attempt_q.task_done()
            return
        last_activity_ref[0] = _t.time()
        logger.info(f"[{scan_run.run_id}] verifier[{name}] picked: {att.get('endpoint')} {att.get('vuln_type')}")
        user_msg = (
            f"target_url: {scan_run.target_url}\n"
            f"scan_id: {scan_run.run_id}\n\n"
            f"한 attempt 만 검증:\n```json\n"
            f"{json.dumps(att, ensure_ascii=False)}\n```\n"
            f"oracle 호출 → confirm/dismiss + learn_from_finding/learn_dead_end → emit_verdicts."
        )
        try:
            text, _ = await _run_role_phase(
                scan_run, anthropic, f"verifier:{name}", VERIFIER_WORKER_PROMPT,
                tools, tool_router, user_msg, acc,
                max_turns=SWARM_BUDGET["verifier_worker"],
            )
            data = _extract_json_block(text) or {}
            for v in data.get("verdicts", []):
                verdicts_collector.append(v)
        except Exception as e:
            logger.error(f"[{scan_run.run_id}] verifier[{name}] error: {e}", exc_info=True)
        finally:
            last_activity_ref[0] = _t.time()
            attempt_q.task_done()


async def _run_swarm(
    scan_run: ScanRun,
    anthropic,
    anthropic_tools: list,
    tool_router: dict,
):
    """Continuous swarm — Planner 1회 → N Executor + M Verifier 동시 → quiescence → Reporter.
    Living KB가 shared memory: Verifier가 confirm 시 즉시 KB write,
    그 다음 Executor가 recall_target/recall_dead_ends로 활용.
    """
    import time as _t
    acc = _Accumulator()

    planner_tools = _filter_tools(anthropic_tools, PLANNER_TOOLS)
    executor_tools = _filter_tools(anthropic_tools, EXECUTOR_WORKER_TOOLS)
    verifier_tools = _filter_tools(anthropic_tools, VERIFIER_WORKER_TOOLS)
    reporter_tools = _filter_tools(anthropic_tools, REPORTER_TOOLS)

    logger.info(
        f"[{scan_run.run_id}] swarm: planner=1, executors={SWARM_EXECUTOR_COUNT}, "
        f"verifiers={SWARM_VERIFIER_COUNT}, quiescence={SWARM_QUIESCENCE_S}s, "
        f"max_hypotheses={SWARM_MAX_HYPOTHESES}"
    )

    # ── 1. Planner — 초기 hypotheses 생성 ──
    scan_config = scan_run.config or {}
    specific_source = scan_config.get("source_root", "")
    source_hint = ""
    if specific_source and os.path.isdir(specific_source):
        source_hint = (
            f"\n[WHITE-BOX] 이 타겟의 소스 코드 위치: {specific_source}\n"
            f"  `list_source_tree(root=\"{specific_source}\")` 로 시작하세요."
        )
    else:
        src_roots = os.environ.get("SOURCE_ROOTS", "").strip()
        if src_roots:
            try:
                existing = []
                for root in src_roots.split(":"):
                    root = root.strip()
                    if root and os.path.isdir(root):
                        sub = [d for d in os.listdir(root) if not d.startswith(".")]
                        if sub:
                            existing.append((root, sub[:10]))
                if existing:
                    lines = ["", "[WHITE-BOX] SOURCE_ROOTS:"]
                    for root, subs in existing:
                        lines.append(f"  - {root}: {', '.join(subs)}")
                    source_hint = "\n".join(lines)
            except Exception:
                pass

    plan_brief = (
        f"target_url: {scan_run.target_url}\n"
        f"scan_id: {scan_run.run_id}\n"
        f"{source_hint}\n"
        f"swarm 모드 — 가설을 emit_hypotheses로 풍부하게(권장 6-12개) 출력. "
        f"각 hypothesis는 독립 worker에 분배되어 동시 처리됨."
    )
    planner_text, _ = await _run_role_phase(
        scan_run, anthropic, "planner", PLANNER_PROMPT,
        planner_tools, tool_router, plan_brief, acc,
        max_turns=SWARM_BUDGET["planner"],
    )
    plan_json = _extract_json_block(planner_text) or {"hypotheses": []}
    initial_hyps = plan_json.get("hypotheses", [])[:SWARM_MAX_HYPOTHESES]
    logger.info(f"[{scan_run.run_id}] planner produced {len(initial_hyps)} hypotheses")

    if not initial_hyps:
        logger.warning(f"[{scan_run.run_id}] no hypotheses, fallback to reporter")
    else:
        # ── 2. Queues + worker pool ──
        hypothesis_q: "asyncio.Queue[dict | None]" = asyncio.Queue()
        attempt_q: "asyncio.Queue[dict | None]" = asyncio.Queue()
        verdicts_collector: list = []
        last_activity = [_t.time()]  # mutable ref

        for h in initial_hyps:
            await hypothesis_q.put(h)

        executors = [
            asyncio.create_task(
                _executor_worker(
                    f"E{i+1}", scan_run, anthropic, executor_tools, tool_router,
                    hypothesis_q, attempt_q, acc, last_activity,
                ),
                name=f"exec-{i+1}",
            )
            for i in range(SWARM_EXECUTOR_COUNT)
        ]
        verifiers = [
            asyncio.create_task(
                _verifier_worker(
                    f"V{i+1}", scan_run, anthropic, verifier_tools, tool_router,
                    attempt_q, verdicts_collector, acc, last_activity,
                ),
                name=f"verify-{i+1}",
            )
            for i in range(SWARM_VERIFIER_COUNT)
        ]

        # ── 3. Quiescence loop ──
        # 두 큐 모두 비고 + 마지막 활동 후 SWARM_QUIESCENCE_S 경과 → 종료
        while True:
            await asyncio.sleep(2)
            queues_empty = hypothesis_q.empty() and attempt_q.empty()
            idle_for = _t.time() - last_activity[0]
            if queues_empty and idle_for > SWARM_QUIESCENCE_S:
                logger.info(
                    f"[{scan_run.run_id}] quiescence reached "
                    f"(queues empty, idle for {idle_for:.0f}s)"
                )
                break
            try:
                raise_if_stop_requested(scan_run)
            except Exception:
                logger.info(f"[{scan_run.run_id}] swarm stop requested")
                break

        # ── 4. workers에게 종료 신호 (None) — 각 worker가 받으면 return ──
        for _ in executors:
            await hypothesis_q.put(None)
        for _ in verifiers:
            await attempt_q.put(None)
        await asyncio.gather(*executors, *verifiers, return_exceptions=True)

        logger.info(
            f"[{scan_run.run_id}] swarm done: verdicts={len(verdicts_collector)}, "
            f"executors+verifiers complete"
        )

    # ── 5. Reporter ──
    reporter_msg = (
        f"generate_report(run_id=\"{scan_run.run_id}\", format=\"json\") 만 호출."
    )
    await _run_role_phase(
        scan_run, anthropic, "reporter", REPORTER_PROMPT,
        reporter_tools, tool_router, reporter_msg, acc,
        max_turns=SWARM_BUDGET["reporter"],
    )

    logger.info(
        f"[{scan_run.run_id}] swarm complete: {acc.calls} LLM calls, "
        f"{acc.input_tokens + acc.output_tokens} tokens, ${scan_run.llm_cost_usd}"
    )


async def _explorer_worker(
    name: str,
    scan_run: ScanRun,
    anthropic,
    tools: list,
    tool_router: dict,
    acc: _Accumulator,
    last_activity_ref: list,
    done_event: asyncio.Event,
):
    """Discovery worker — DB queue에서 pending node를 pick, explore, push children."""
    import time as _t
    from asgiref.sync import sync_to_async
    from watchdog_mcp.tools_discovery import pick_next_node

    empty_streak = 0

    while not done_event.is_set():
        try:
            raise_if_stop_requested(scan_run)
        except Exception:
            return

        node = await sync_to_async(pick_next_node)(
            str(scan_run.run_id), name,
        )
        if node is None:
            empty_streak += 1
            await asyncio.sleep(min(2 * empty_streak, 10))
            continue

        empty_streak = 0
        last_activity_ref[0] = _t.time()

        logger.info(
            f"[{scan_run.run_id}] explorer[{name}] picked node "
            f"{node.node_id} depth={node.depth} type={node.node_type} "
            f"endpoint={node.endpoint or 'N/A'}"
        )

        scan_config = scan_run.config or {}
        source_hint = ""
        if scan_config.get("source_root"):
            source_hint = (
                f"\n## Source Code Available\n"
                f"source_root: {scan_config['source_root']}\n"
                f"Use list_source_tree, read_source, grep_source to analyze the app.\n"
            )

        shared_state_hint = ""
        if node.node_type in ("exploit_step", "clue", "vuln") and node.depth >= 2:
            shared_state_hint = (
                "\n## Shared State\n"
                "This is a deep node. Other workers may have discovered credentials or\n"
                "architecture info. Call get_secrets and get_scan_notes EARLY.\n"
                "If YOU discover credentials/tokens, call store_secret immediately.\n"
            )

        user_msg = (
            f"target_url: {scan_run.target_url}\n"
            f"scan_run_id: {scan_run.run_id}\n"
            f"{source_hint}{shared_state_hint}\n"
            f"## Your Node\n"
            f"- node_id: {node.node_id}\n"
            f"- node_type: {node.node_type}\n"
            f"- depth: {node.depth}\n"
            f"- endpoint: {node.endpoint or 'N/A'}\n"
            f"- vuln_type: {node.vuln_type or 'N/A'}\n"
            f"- summary: {node.summary}\n"
            f"- context: {json.dumps(node.context, ensure_ascii=False)[:800]}\n\n"
            f"Start by calling get_chain_context(node_id=\"{node.node_id}\") and "
            f"get_siblings(node_id=\"{node.node_id}\"), then explore this node.\n"
            f"Push child discoveries for anything interesting. "
            f"Mark dead_end if nothing found."
        )

        is_recheck = (node.context or {}).get("recheck", False)
        if is_recheck:
            budget = DISCOVERY_RECHECK_BUDGET
        elif node.node_type in ("exploit_step", "vuln"):
            budget = DISCOVERY_EXPLOIT_BUDGET
        elif node.node_type == "clue":
            budget = DISCOVERY_CLUE_BUDGET
        else:
            budget = DISCOVERY_WORKER_BUDGET

        try:
            await _run_role_phase(
                scan_run, anthropic, f"explorer:{name}", EXPLORER_PROMPT,
                tools, tool_router, user_msg, acc,
                max_turns=budget,
            )
        except Exception as e:
            logger.error(
                f"[{scan_run.run_id}] explorer[{name}] error on node "
                f"{node.node_id}: {e}", exc_info=True,
            )

        # ── Orchestrator validation: SOFT SIGNAL ONLY (자율성 우선 원칙) ──
        # validator는 안전망(diagnostic)이지 강제(gate)가 아니다.
        # 위반이 있어도 fix_phase로 LLM에 재작업을 강제하지 않는다 — 그렇게 하면
        # 진짜 막힌 상황(404/WAF/SPA로 endpoint 부재 등)에서 가짜 노드를 만들도록
        # 잘못된 인센티브를 준다. warnings는 selfcheck/replan 신호로만 활용.
        node.refresh_from_db()
        passed, violations = await sync_to_async(
            lambda: _validate_node_compliance(node)
        )()
        if not passed:
            logger.info(
                f"[{scan_run.run_id}] explorer[{name}] node {node.node_id} "
                f"validator warnings (soft): {violations}"
            )
            await sync_to_async(_record_node_warnings)(node, violations)

        await sync_to_async(
            lambda: _mark_node_explored(node)
        )()
        last_activity_ref[0] = _t.time()


def _record_node_warnings(node, violations: list[str]) -> None:
    """node.context['validator_warnings']에 누적. selfcheck가 합산해서 신호로 활용."""
    if not violations:
        return
    ctx = dict(node.context or {})
    prev = list(ctx.get("validator_warnings") or [])
    prev.extend(violations)
    ctx["validator_warnings"] = prev[-20:]  # bound
    node.context = ctx
    node.save(update_fields=["context"])


def _mark_node_explored(node):
    """Mark node as explored if still in exploring state."""
    from api.models import DiscoveryNode
    DiscoveryNode.objects.filter(
        node_id=node.node_id, status="exploring",
    ).update(status="explored", explored_at=timezone.now())


# ═══════════════════════════════════════════════════════
# Orchestrator — Post-exploration compliance validation
# ═══════════════════════════════════════════════════════

# `must_have_children`은 "권장(suggest)" 의미로만 남긴다.
# 실제 노드 push 강제는 안 한다 — target이 진짜로 endpoint 0개일 수 있다(WAF/404/SPA).
# 안전망 원칙: validator는 진단 신호만, 강제 액션은 없음.
_NODE_REQUIREMENTS = {
    "target": {
        "suggest_children": True,
        "min_children": 1,
        "check_analyze_endpoint": False,
        "check_record_pattern_use": False,
    },
    "endpoint": {
        "suggest_children": False,
        "min_children": 0,
        "check_analyze_endpoint": True,
        "check_record_pattern_use": False,
    },
    "vuln": {
        "suggest_children": False,
        "min_children": 0,
        "check_analyze_endpoint": False,
        "check_record_pattern_use": True,
    },
    "exploit_step": {
        "suggest_children": False,
        "min_children": 0,
        "check_analyze_endpoint": False,
        "check_record_pattern_use": False,
    },
    "clue": {
        "suggest_children": False,
        "min_children": 0,
        "check_analyze_endpoint": False,
        "check_record_pattern_use": False,
    },
}


def _validate_node_compliance(node) -> tuple[bool, list[str]]:
    """Soft diagnostic — node 탐색이 권장 규칙을 만족하는지 점검.

    Returns (passed, list_of_warnings).
    경고 리스트는 강제 fix가 아니라 selfcheck/replan 신호로만 사용된다.
    Runs synchronously — call from sync context or wrap with sync_to_async.
    """
    from api.models import (
        DiscoveryNode, Candidate, Finding, RequestCatalog, DeadEnd,
    )

    violations = []
    sr = node.scan_run
    ntype = node.node_type
    reqs = _NODE_REQUIREMENTS.get(ntype, {})

    children = DiscoveryNode.objects.filter(scan_run=sr, parent=node)
    child_count = children.count()

    # R3/R8 (suggestion only): target/parent에 자식이 없다는 사실 자체는 진짜 막힌
    # 환경(WAF/404/SPA, dead_end로 마킹된 entry 등)일 수 있어 강제하지 않는다.
    if reqs.get("suggest_children") and child_count < reqs.get("min_children", 1):
        violations.append(
            f"R8(suggest): {ntype} node has {child_count} children "
            f"(suggested >= {reqs.get('min_children', 1)}). "
            f"진짜 막혔으면 mark_dead_end로 명시."
        )

    # R8: endpoint should have analyze_endpoint
    if reqs.get("check_analyze_endpoint"):
        ep = node.endpoint or ""
        if not ep:
            import re
            m = re.search(r'((?:GET|POST|PUT|DELETE|PATCH)\s+)?(/\S+)', node.summary)
            if m:
                ep = m.group(2)
        analyzed = False
        if ep:
            ep_norm = ep.split("?", 1)[0].rstrip("/") or "/"
            # 정확 매칭 + trailing-slash 변형. substring icontains는 false-positive
            # (`/api`가 `/api/users/api`와 충돌) 위험이 있어 폐기.
            variants = {ep, ep_norm, ep_norm + "/"}
            analyzed = RequestCatalog.objects.filter(
                scan_run=sr, endpoint__in=variants,
            ).exists()
        if not analyzed and ep:
            violations.append(
                f"R8: No analyze_endpoint found for endpoint '{ep}'. "
                f"Call analyze_endpoint(endpoint=\"{ep}\", method=..., params=...)."
            )

    # Confirmed node must have a finding
    if node.status == "confirmed":
        has_finding = Finding.objects.filter(scan_run=sr).exists()
        if not has_finding:
            violations.append(
                "R9: Node is confirmed but no finding exists. "
                "Call create_finding + save_evidence + confirm_finding."
            )

    # Dead-end node should have learn_dead_end
    if node.status == "dead_end":
        from urllib.parse import urlparse
        host = urlparse(sr.target_url or "").hostname or ""
        has_learned = DeadEnd.objects.filter(
            target_host__icontains=host[:30],
            endpoint__icontains=(node.endpoint or "")[:30],
        ).exists() if host else True
        if not has_learned:
            violations.append(
                "R4: dead_end node without learn_dead_end. "
                "Call learn_dead_end(target_host, endpoint, vuln_type, payloads_tried, reason)."
            )

    # Endpoint with no children and not dead_end → should be marked dead_end or have children
    if ntype == "endpoint" and child_count == 0 and node.status != "dead_end":
        violations.append(
            "R3: Endpoint has 0 child vuln nodes and is not marked dead_end. "
            "Either push_discovery(node_type='vuln') for suspected vulns, "
            "or mark_dead_end if clean."
        )

    return len(violations) == 0, violations


def _scan_selfcheck(scan_run) -> dict:
    """Scan-level compliance check before completion.

    Returns dict with 'passed', 'errors', 'warnings', 'stats'.
    """
    from api.models import (
        DiscoveryNode, Candidate, Finding, RequestCatalog, DeadEnd,
        LLMTrace,
    )
    from urllib.parse import urlparse

    errors = []
    warnings = []

    all_nodes = list(DiscoveryNode.objects.filter(scan_run=scan_run))
    host = urlparse(scan_run.target_url or "").hostname or ""

    pending = [n for n in all_nodes if n.status == "pending"]
    if pending:
        errors.append(f"{len(pending)} pending nodes remain — explore or mark_dead_end.")

    exploring = [n for n in all_nodes if n.status == "exploring"]
    if exploring:
        errors.append(f"{len(exploring)} exploring nodes stuck — finalize them.")

    endpoints = [n for n in all_nodes if n.node_type == "endpoint"]
    if len(endpoints) < 3:
        warnings.append(f"Only {len(endpoints)} endpoint nodes. Push generously (R3).")

    dead_ends = [n for n in all_nodes if n.status == "dead_end"]
    if len(dead_ends) == 0 and len(endpoints) > 3:
        warnings.append("0 dead_end nodes. Were all tests successful?")

    confirmed_nodes = [n for n in all_nodes if n.status == "confirmed"]
    findings_count = Finding.objects.filter(scan_run=scan_run).count()
    if confirmed_nodes and findings_count == 0:
        errors.append("Confirmed nodes exist but 0 findings (R9).")

    analyzed = RequestCatalog.objects.filter(scan_run=scan_run).count()
    if endpoints and analyzed == 0:
        errors.append("R8: 0 analyze_endpoint calls.")

    traces = LLMTrace.objects.filter(scan_run=scan_run).count()

    open_cands = Candidate.objects.filter(scan_run=scan_run, status="open").count()
    if open_cands > 5:
        warnings.append(f"{open_cands} candidates still 'open'.")

    learned_de = DeadEnd.objects.filter(
        target_host__icontains=host[:30],
    ).count() if host else 0

    by_status = {}
    for n in all_nodes:
        by_status[n.status] = by_status.get(n.status, 0) + 1

    return {
        "passed": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "stats": {
            "total_nodes": len(all_nodes),
            "confirmed": len(confirmed_nodes),
            "dead_ends": len(dead_ends),
            "endpoints": len(endpoints),
            "findings": findings_count,
            "candidates_open": open_cands,
            "traces": traces,
            "analyzed": analyzed,
            "learned_dead_ends": learned_de,
            **by_status,
        },
    }


def _collect_node_warnings(scan_run) -> list[dict]:
    """전 스캔의 노드별 validator_warnings 합산 → selfcheck 신호로 사용."""
    from api.models import DiscoveryNode
    out: list[dict] = []
    qs = DiscoveryNode.objects.filter(scan_run=scan_run).only(
        "node_id", "node_type", "endpoint", "context"
    )
    for n in qs:
        ws = (n.context or {}).get("validator_warnings") or []
        if not ws:
            continue
        out.append({
            "node_id": str(n.node_id),
            "node_type": n.node_type,
            "endpoint": n.endpoint or "",
            "warnings": ws[-5:],
        })
    return out


def _persist_selfcheck(scan_run, result: dict) -> None:
    """selfcheck 결과를 ScanRun.config['selfcheck']에 박아 API/UI/eval 에서 조회 가능."""
    cfg = dict(scan_run.config or {})
    cfg["selfcheck"] = {
        "passed": bool(result.get("passed")),
        "errors": list(result.get("errors") or []),
        "warnings": list(result.get("warnings") or []),
        "node_warnings": list(result.get("node_warnings") or []),
        "stats": dict(result.get("stats") or {}),
    }
    scan_run.config = cfg
    scan_run.save(update_fields=["config"])


def _normalize_target_url(url: str) -> str:
    """Normalize target URL for comparison: lowercase scheme+host, strip trailing slash."""
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(url.strip())
    return urlunparse((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path.rstrip("/") or "/",
        parsed.params,
        parsed.query,
        "",
    ))


def _gather_previous_knowledge(target_url: str, current_run_id: str) -> dict | None:
    """Find the most recent completed scan for the same target and extract useful nodes."""
    from api.models import DiscoveryNode

    normalized = _normalize_target_url(target_url)
    candidates = (
        ScanRun.objects
        .filter(status__in=["finished", "failed"])
        .exclude(run_id=current_run_id)
        .order_by("-created_at")[:10]
    )
    prev_run = None
    for run in candidates:
        if _normalize_target_url(run.target_url) == normalized:
            prev_run = run
            break
    if not prev_run:
        return None

    prev_nodes = DiscoveryNode.objects.filter(scan_run=prev_run).order_by("depth", "created_at")
    if not prev_nodes.exists():
        return None

    endpoints = []
    vulns = []
    dead_ends = []
    clues = []

    for node in prev_nodes:
        entry = {
            "node_type": node.node_type,
            "endpoint": node.endpoint or "",
            "vuln_type": node.vuln_type or "",
            "summary": node.summary[:300],
            "status": node.status,
            "depth": node.depth,
        }
        if node.node_type == "endpoint" and node.status != "dead_end":
            endpoints.append(entry)
        elif node.node_type == "vuln":
            vulns.append(entry)
        elif node.node_type == "dead_end" or node.status == "dead_end":
            dead_ends.append(entry)
        elif node.node_type in ("clue", "exploit_step"):
            clues.append(entry)

    if not endpoints and not vulns:
        return None

    return {
        "prev_run_id": str(prev_run.run_id),
        "endpoints": endpoints[:20],
        "vulns": vulns[:15],
        "dead_ends": dead_ends[:20],
        "clues": clues[:10],
    }


SEED_BUDGET_RATIO = 0.3  # max 30% of DISCOVERY_MAX_NODES for seeded nodes

def _seed_from_previous(scan_run, root_node, prev_knowledge: dict) -> int:
    """Seed endpoint + re-verify nodes from previous scan results."""
    from api.models import DiscoveryNode
    from watchdog_mcp.tools_discovery import DISCOVERY_MAX_NODES

    seed_cap = int(DISCOVERY_MAX_NODES * SEED_BUDGET_RATIO)
    seeded = 0
    endpoint_node_map = {}

    for ep in prev_knowledge.get("endpoints", []):
        if seeded >= seed_cap:
            break
        if not ep.get("endpoint"):
            continue
        ep_node = DiscoveryNode.objects.create(
            scan_run=scan_run,
            parent=root_node,
            depth=1,
            node_type="endpoint",
            endpoint=ep["endpoint"],
            vuln_type="",
            summary=f"[seeded] {ep['summary'][:200]}",
            context={
                "seeded_from": prev_knowledge.get("prev_run_id", ""),
                "prev_status": ep.get("status", ""),
            },
            status="pending",
        )
        endpoint_node_map[ep["endpoint"]] = ep_node
        seeded += 1

    for vuln in prev_knowledge.get("vulns", []):
        if seeded >= seed_cap:
            break
        if vuln.get("status") not in ("explored", "confirmed"):
            continue
        ep = vuln.get("endpoint", "")
        parent = endpoint_node_map.get(ep, root_node)
        DiscoveryNode.objects.create(
            scan_run=scan_run,
            parent=parent,
            depth=parent.depth + 1,
            node_type="vuln",
            endpoint=ep,
            vuln_type=vuln.get("vuln_type", ""),
            summary=f"[re-verify] {vuln['summary'][:200]}",
            context={
                "seeded_from": prev_knowledge.get("prev_run_id", ""),
                "recheck": True,
                "prev_status": vuln.get("status", ""),
                "action": "re-verify this vuln — it was successful before but may be patched now",
            },
            status="pending",
        )
        seeded += 1

    return seeded


async def _run_discovery_loop(
    scan_run: ScanRun,
    anthropic,
    anthropic_tools: list,
    tool_router: dict,
):
    """Discovery mode — queue-based tree exploration with concurrent workers.

    1. Create root DiscoveryNode (type=target)
    2. Spawn N explorer workers
    3. Workers pick nodes from DB, explore, push children
    4. Quiescence detection: all workers idle + queue empty → Reporter
    """
    import time as _t
    from asgiref.sync import sync_to_async
    from api.models import DiscoveryNode

    acc = _Accumulator()
    explorer_tools = _filter_tools(anthropic_tools, EXPLORER_TOOLS)
    reporter_tools = _filter_tools(anthropic_tools, REPORTER_TOOLS)

    logger.info(
        f"[{scan_run.run_id}] discovery mode: workers={DISCOVERY_WORKER_COUNT}, "
        f"worker_budget={DISCOVERY_WORKER_BUDGET}, "
        f"quiescence={DISCOVERY_QUIESCENCE_S}s"
    )

    scan_config = scan_run.config or {}
    root_context = {"target_url": scan_run.target_url}
    if scan_config.get("source_root"):
        root_context["source_root"] = scan_config["source_root"]

    prev_knowledge = await sync_to_async(_gather_previous_knowledge)(
        scan_run.target_url, str(scan_run.run_id),
    )
    if prev_knowledge:
        root_context["previous_scan"] = prev_knowledge
        logger.info(
            f"[{scan_run.run_id}] seeded with previous knowledge: "
            f"{len(prev_knowledge.get('endpoints', []))} endpoints, "
            f"{len(prev_knowledge.get('vulns', []))} vulns, "
            f"{len(prev_knowledge.get('dead_ends', []))} dead_ends"
        )

    root_node = await sync_to_async(DiscoveryNode.objects.create)(
        scan_run=scan_run,
        parent=None,
        depth=0,
        node_type="target",
        endpoint=scan_run.target_url,
        vuln_type="",
        summary=f"Root target: {scan_run.target_url}",
        context=root_context,
        status="pending",
    )

    seeded_count = 0
    if prev_knowledge:
        seeded_count = await sync_to_async(_seed_from_previous)(
            scan_run, root_node, prev_knowledge,
        )

    logger.info(
        f"[{scan_run.run_id}] root node created: {root_node.node_id}, "
        f"seeded {seeded_count} nodes from previous scan"
    )

    done_event = asyncio.Event()
    last_activity = [_t.time()]

    workers = [
        asyncio.create_task(
            _explorer_worker(
                f"W{i+1}", scan_run, anthropic, explorer_tools, tool_router,
                acc, last_activity, done_event,
            ),
            name=f"explorer-{i+1}",
        )
        for i in range(DISCOVERY_WORKER_COUNT)
    ]

    while True:
        await asyncio.sleep(3)
        try:
            raise_if_stop_requested(scan_run)
        except Exception:
            logger.info(f"[{scan_run.run_id}] discovery stop requested")
            break

        if acc.calls >= DISCOVERY_MAX_CALLS:
            logger.info(f"[{scan_run.run_id}] discovery hard cap: calls={acc.calls} >= {DISCOVERY_MAX_CALLS}")
            break
        await sync_to_async(scan_run.refresh_from_db)()
        if scan_run.llm_cost_usd >= DISCOVERY_MAX_COST_USD:
            logger.info(f"[{scan_run.run_id}] discovery hard cap: cost=${scan_run.llm_cost_usd} >= ${DISCOVERY_MAX_COST_USD}")
            break

        all_done = all(w.done() for w in workers)
        idle_for = _t.time() - last_activity[0]

        if all_done:
            logger.info(f"[{scan_run.run_id}] all discovery workers finished")
            break

        pending_count = await sync_to_async(
            lambda: DiscoveryNode.objects.filter(
                scan_run=scan_run, status="pending",
            ).count()
        )()
        exploring_count = await sync_to_async(
            lambda: DiscoveryNode.objects.filter(
                scan_run=scan_run, status="exploring",
            ).count()
        )()

        if pending_count == 0 and exploring_count == 0 and idle_for > DISCOVERY_QUIESCENCE_S:
            logger.info(
                f"[{scan_run.run_id}] discovery quiescence reached "
                f"(pending=0, exploring=0, idle={idle_for:.0f}s)"
            )
            break

    done_event.set()
    await asyncio.gather(*workers, return_exceptions=True)

    # ── Orchestrator scan-level selfcheck ──
    # validator warnings(노드별)도 합산해 같이 노출. 다음 단계(2주차 MLLA)에서
    # 이 신호가 re-plan trigger 입력이 된다.
    selfcheck_result = await sync_to_async(
        lambda: _scan_selfcheck(scan_run)
    )()
    node_warnings = await sync_to_async(_collect_node_warnings)(scan_run)
    selfcheck_result["node_warnings"] = node_warnings

    # ScanRun.config 에 박아서 API/UI/eval에서도 조회 가능
    await sync_to_async(_persist_selfcheck)(scan_run, selfcheck_result)

    if selfcheck_result["errors"]:
        logger.warning(
            f"[{scan_run.run_id}] scan selfcheck FAILED: {selfcheck_result['errors']}"
        )
    else:
        logger.info(
            f"[{scan_run.run_id}] scan selfcheck PASSED"
        )

    total_nodes = selfcheck_result["stats"]["total_nodes"]
    confirmed = selfcheck_result["stats"].get("confirmed", 0)
    dead_ends = selfcheck_result["stats"].get("dead_ends", 0)

    logger.info(
        f"[{scan_run.run_id}] discovery tree: "
        f"total={total_nodes}, confirmed={confirmed}, dead_ends={dead_ends}, "
        f"selfcheck={'PASS' if not selfcheck_result['errors'] else 'FAIL'}"
    )

    from watchdog_mcp.tools_discovery import build_exploit_chains
    chains = await sync_to_async(build_exploit_chains)(str(scan_run.run_id))
    chains_json = json.dumps(chains, ensure_ascii=False)[:3000] if chains else "[]"

    # selfcheck 요약을 reporter 프롬프트에 포함 — 보고서가 데이터 결함을 인식
    sc_summary = {
        "errors": selfcheck_result.get("errors", []),
        "warnings": selfcheck_result.get("warnings", []),
        "node_warning_count": len(node_warnings),
        "stats": selfcheck_result.get("stats", {}),
    }
    sc_json = json.dumps(sc_summary, ensure_ascii=False)[:2000]
    reporter_msg = (
        f"generate_report(run_id=\"{scan_run.run_id}\", format=\"json\") 만 호출.\n\n"
        f"## Selfcheck (스캔 품질 진단 — 보고서 'limitations' 또는 'follow_up' 섹션 활용)\n"
        f"```json\n{sc_json}\n```\n\n"
        f"## Exploit Chains (discovery tree에서 재구성)\n```json\n{chains_json}\n```"
    )
    await _run_role_phase(
        scan_run, anthropic, "reporter", REPORTER_PROMPT,
        reporter_tools, tool_router, reporter_msg, acc,
        max_turns=ROLE_TURN_BUDGET["reporter"],
    )

    logger.info(
        f"[{scan_run.run_id}] discovery complete: {acc.calls} LLM calls, "
        f"{acc.input_tokens + acc.output_tokens} tokens, ${scan_run.llm_cost_usd}"
    )


async def _connect_mcp_and_run(scan_run: ScanRun, mode: str):
    """MCP 서버 연결 후 mode에 따라 single/multi/swarm/discovery loop를 실행."""
    anthropic = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))

    # `-m watchdog_mcp.server` 로 띄워야 server.py 의 relative import (`from .tools_*`)
    # 가 정상 동작한다. 파일 경로 직접 전달은 패키지 컨텍스트가 없어서 실패.
    backend_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    watchdog_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "watchdog_mcp.server"],
        env={
            **os.environ,
            "DJANGO_SETTINGS_MODULE": "config.settings",
            "PYTHONPATH": backend_root + os.pathsep + os.environ.get("PYTHONPATH", ""),
        },
    )

    pg_available = shutil.which("npx") is not None
    pg_conn_str = _get_pg_connection_string() if pg_available else ""

    tool_router: dict[str, tuple[ClientSession, str]] = {}

    async with AsyncExitStack() as stack:
        wd_transport = await stack.enter_async_context(stdio_client(watchdog_params))
        wd_session = await stack.enter_async_context(
            ClientSession(wd_transport[0], wd_transport[1])
        )
        await wd_session.initialize()

        wd_tools_result = await wd_session.list_tools()
        anthropic_tools = _convert_tools_for_anthropic(wd_tools_result.tools)
        for tool in wd_tools_result.tools:
            tool_router[tool.name] = (wd_session, tool.name)
        logger.info(
            f"[{scan_run.run_id}] watchdog MCP {len(wd_tools_result.tools)} tools"
        )

        if pg_available and pg_conn_str:
            try:
                pg_params = StdioServerParameters(
                    command="npx",
                    args=["-y", "@modelcontextprotocol/server-postgres", pg_conn_str],
                )
                pg_transport = await stack.enter_async_context(stdio_client(pg_params))
                pg_session = await stack.enter_async_context(
                    ClientSession(pg_transport[0], pg_transport[1])
                )
                await pg_session.initialize()
                pg_tools_result = await pg_session.list_tools()
                pg_tools = _convert_tools_for_anthropic(
                    pg_tools_result.tools, prefix="pg_"
                )
                anthropic_tools.extend(pg_tools)
                for tool in pg_tools_result.tools:
                    tool_router[f"pg_{tool.name}"] = (pg_session, tool.name)
                logger.info(
                    f"[{scan_run.run_id}] PostgreSQL MCP {len(pg_tools_result.tools)} tools"
                )
            except Exception as e:
                logger.warning(f"[{scan_run.run_id}] pg MCP 연결 실패 (계속): {e}")

        logger.info(
            f"[{scan_run.run_id}] total tools={len(anthropic_tools)} mode={mode}"
        )

        if mode == "discovery":
            await _run_discovery_loop(scan_run, anthropic, anthropic_tools, tool_router)
        elif mode == "swarm":
            await _run_swarm(scan_run, anthropic, anthropic_tools, tool_router)
        elif mode == "multi":
            await _run_multi_agent_loop(scan_run, anthropic, anthropic_tools, tool_router)
        else:
            await _run_single_agent_loop(
                scan_run, anthropic, anthropic_tools, tool_router
            )


async def _run_single_agent_loop(
    scan_run: ScanRun,
    anthropic,
    anthropic_tools: list,
    tool_router: dict,
):
    """기존 단일 에이전트 루프 (legacy). messages/turn 관리 인라인."""
    total_input_tokens = 0
    total_output_tokens = 0
    total_calls = 0

    messages = [{
        "role": "user",
        "content": (
            f"타겟 URL: {scan_run.target_url}\n"
            f"스캔 ID: {scan_run.run_id}\n\n"
            f"위 타겟을 스캔하여 취약점을 찾고 리포트를 생성해주세요."
        ),
    }]

    for turn in range(MAX_TURNS):
        raise_if_stop_requested(scan_run)
        logger.info(f"[{scan_run.run_id}] single turn {turn + 1}/{MAX_TURNS}")
        response = _call_llm_with_retry(
            anthropic, scan_run,
            model=MODEL, max_tokens=4096,
            system=SYSTEM_PROMPT, tools=anthropic_tools, messages=messages,
        )

        total_input_tokens += response.usage.input_tokens
        total_output_tokens += response.usage.output_tokens
        total_calls += 1
        scan_run.llm_calls_count = total_calls
        scan_run.llm_tokens_used = total_input_tokens + total_output_tokens
        scan_run.llm_cost_usd = (
            Decimal(str(total_input_tokens)) * INPUT_COST_PER_TOKEN
            + Decimal(str(total_output_tokens)) * OUTPUT_COST_PER_TOKEN
        )
        await sync_to_async(scan_run.save)(update_fields=[
            "llm_calls_count", "llm_tokens_used", "llm_cost_usd",
        ])

        tool_use_blocks = [b for b in response.content if b.type == "tool_use"]
        if response.stop_reason == "end_turn" or not tool_use_blocks:
            break
        messages.append({"role": "assistant", "content": response.content})
        tool_results = await _execute_tool_calls(scan_run, tool_router, tool_use_blocks)
        messages.append({"role": "user", "content": tool_results})


def run_mcp_scan(scan_run: ScanRun):
    """MCP 에이전트 루프로 스캔을 실행한다 (동기 래퍼)."""
    register_scan(scan_run.run_id)
    try:
        if is_stop_requested(scan_run.run_id):
            mark_scan_stopped(scan_run)
            return

        scan_run.status = "running"
        scan_run.finished_at = None
        scan_run.error_log = None
        scan_run.save(update_fields=["status", "finished_at", "error_log"])

        mode = AGENT_MODE_DEFAULT if AGENT_MODE_DEFAULT in ("discovery", "swarm", "multi", "single") else "multi"
        logger.info(f"[{scan_run.run_id}] starting MCP scan (mode={mode})")
        asyncio.run(_connect_mcp_and_run(scan_run, mode=mode))

        if is_stop_requested(scan_run.run_id):
            mark_scan_stopped(scan_run)
            logger.info(f"[{scan_run.run_id}] MCP 스캔 중지")
        else:
            scan_run.status = "finished"
            scan_run.finished_at = timezone.now()
            scan_run.save(update_fields=["status", "finished_at"])
            logger.info(f"[{scan_run.run_id}] MCP 스캔 완료")

    except ScanStopped as e:
        mark_scan_stopped(scan_run, str(e))
        logger.info(f"[{scan_run.run_id}] MCP 스캔 중지: {e}")
    except Exception as e:
        if is_stop_requested(scan_run.run_id):
            mark_scan_stopped(scan_run)
            logger.info(f"[{scan_run.run_id}] MCP 스캔 중지 중 예외 발생: {e}")
        else:
            scan_run.status = "failed"
            scan_run.error_log = summarize_exception(e)
            scan_run.save(update_fields=["status", "error_log"])
            logger.error(f"[{scan_run.run_id}] MCP 스캔 실패: {e}", exc_info=True)
    finally:
        unregister_scan(scan_run.run_id)
