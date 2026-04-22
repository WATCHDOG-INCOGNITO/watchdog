"""
MCP 에이전트 루프
Claude가 MCP 도구를 자율적으로 선택·체이닝하여 웹 취약점을 탐지한다.
watchdog_mcp(보안 도구) + PostgreSQL MCP(DB 쿼리) 두 서버를 동시 연결한다.
"""

import asyncio
import hashlib
import json
import logging
import os
import shutil
import sys
import time
from base64 import b64encode
from contextlib import AsyncExitStack
from decimal import Decimal
from urllib.parse import urlparse

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
MAX_TURNS_PER_ROLE = int(os.environ.get("WATCHDOG_MULTI_MAX_TURNS_PER_ROLE", str(MAX_TURNS_PER_ROLE)))
ROLE_TURN_BUDGET = {
    "planner": int(os.environ.get("WATCHDOG_MULTI_PLANNER_TURNS", "10")),
    "executor": int(os.environ.get("WATCHDOG_MULTI_EXECUTOR_TURNS", "8")),
    "verifier": int(os.environ.get("WATCHDOG_MULTI_VERIFIER_TURNS", "8")),
    "reporter": int(os.environ.get("WATCHDOG_MULTI_REPORTER_TURNS", "2")),
}
ROLE_OUTPUT_TOKEN_BUDGET = {
    "planner": int(os.environ.get("WATCHDOG_MULTI_PLANNER_MAX_TOKENS", "1400")),
    "executor": int(os.environ.get("WATCHDOG_MULTI_EXECUTOR_MAX_TOKENS", "1200")),
    "verifier": int(os.environ.get("WATCHDOG_MULTI_VERIFIER_MAX_TOKENS", "1200")),
    "reporter": int(os.environ.get("WATCHDOG_MULTI_REPORTER_MAX_TOKENS", "700")),
}
ROLE_CONTEXT_TAIL_MESSAGES = {
    "planner": int(os.environ.get("WATCHDOG_MULTI_PLANNER_CONTEXT_TAIL", "6")),
    "executor": int(os.environ.get("WATCHDOG_MULTI_EXECUTOR_CONTEXT_TAIL", "4")),
    "verifier": int(os.environ.get("WATCHDOG_MULTI_VERIFIER_CONTEXT_TAIL", "4")),
    "reporter": int(os.environ.get("WATCHDOG_MULTI_REPORTER_CONTEXT_TAIL", "2")),
}
ROLE_CONTEXT_SUMMARY_CHARS = {
    "planner": int(os.environ.get("WATCHDOG_MULTI_PLANNER_CONTEXT_SUMMARY", "1400")),
    "executor": int(os.environ.get("WATCHDOG_MULTI_EXECUTOR_CONTEXT_SUMMARY", "1100")),
    "verifier": int(os.environ.get("WATCHDOG_MULTI_VERIFIER_CONTEXT_SUMMARY", "1100")),
    "reporter": int(os.environ.get("WATCHDOG_MULTI_REPORTER_CONTEXT_SUMMARY", "700")),
}
# middle 요약의 stable prefix 길이 — 이 앞부분은 턴 간 불변이라 cache_control 로 캐싱.
# middle이 append-only 로만 자라므로 middle[:STABLE_CONTEXT_SIZE]는 프리픽스 동일 → cache hit.
STABLE_CONTEXT_SIZE = int(os.environ.get("WATCHDOG_MULTI_STABLE_CONTEXT_SIZE", "4"))
SWARM_EXECUTOR_COUNT = int(os.environ.get("WATCHDOG_SWARM_EXECUTORS", "3"))
SWARM_VERIFIER_COUNT = int(os.environ.get("WATCHDOG_SWARM_VERIFIERS", "2"))
SWARM_QUIESCENCE_S = int(os.environ.get("WATCHDOG_SWARM_QUIESCENCE_S", "30"))
SWARM_MAX_HYPOTHESES = int(os.environ.get("WATCHDOG_SWARM_MAX_HYPOTHESES", "20"))
MAX_PLAN_ITERATIONS = 2  # planner→executor→verifier 사이클 반복 횟수 (replan 포함)
MODEL = os.environ.get("WATCHDOG_AGENT_MODEL", "claude-sonnet-4-20250514")
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
- Living KB: recall_target, recall_dead_ends, update_target_profile, get_secrets
- DB: pg_* (read-only)
- Exit: emit_hypotheses(hypotheses_json="...")

## Blocked here (use right role)
sqlmap_scan / dalfox_scan / nuclei_scan / http_request (Executor),
confirm_finding / dismiss_candidate (Verifier).

## Flow (recommended, not enforced)

0. Start with `recall_target(target_host)` — prior learned patterns / dead_ends / framework.
0a. If the user message says credentials are available, call `get_secrets(scan_run_id)` once
    and plan both authenticated and unauthenticated paths.
0b. If white-box (SOURCE_ROOTS shown in BUDGET line above), call `list_source_tree` first;
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
   - Do not treat `/login`, generic `/api/*`, or plain auth/routing failures alone as a
     vuln hypothesis. A blocked route is not evidence.
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
- Living KB: recall_dead_ends, get_secrets
- Exit: emit_attempts(attempts_json="...")

## Blocked here
confirm_finding / dismiss_candidate / generate_report (other roles).

## Flow

0. Once: recall_dead_ends(target_host) — skip already-failed (endpoint, vuln_type, pattern).
0a. If credentials are mentioned in the user message, call `get_secrets(scan_run_id)` before
    concluding a protected endpoint is blocked. For bearer/cookie/basic credentials, HTTP tools
    may already have default auth headers applied when you target the same host.
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
   If all you have is 401/403/405, login redirect, CSRF denial, or SPA fallback HTML,
   do NOT create_candidate_manual. Emit matched=false with candidate_id=null, or emit
   an empty attempts array.
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
list_candidates, search_knowledge, get_secrets.
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

   Pure 401/403/405, login redirects, or SPA fallback HTML without a differential signal
   should be dismissed quickly. Do not burn extra turns proving a generic block page.
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
    "retrieve_cve_variants", "fetch_cve_details", "suggest_cves_for_framework",
    "list_candidates", "get_scan_summary",
    # Living KB — host-specific 회상 + endpoint spec
    "recall_target", "recall_dead_ends", "update_target_profile", "get_secrets",
    "recall_endpoint_specs", "record_endpoint_spec",
    # Source code reading (white-box / glass-box CTF)
    "list_source_tree", "read_source", "grep_source",
    "emit_hypotheses",
}
EXECUTOR_TOOLS = {
    "http_request", "multi_http_probe", "curl_request",
    "sqlmap_scan", "dalfox_scan", "nuclei_scan",
    "ffuf_scan", "nikto_scan", "wafw00f_scan", "whatweb_scan",
    "browser_navigate", "browser_get_dom", "browser_get_network_log",
    "browser_screenshot", "browser_extract_api_endpoints",
    "search_knowledge", "retrieve_similar_patterns", "record_pattern_use",
    "mutate_payload", "create_candidate_manual", "save_evidence",
    "auto_collect_evidence", "list_candidates", "get_secrets",
    # SimHash dedup — payload 시도 전 본질 중복 진단
    "check_payload_dedup",
    # Living KB — dead end 사전 조회 + endpoint spec
    "recall_dead_ends", "recall_endpoint_specs", "record_endpoint_spec",
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
    "search_knowledge", "get_secrets", "confirm_finding", "dismiss_candidate", "reopen_candidate",
    "save_evidence", "auto_collect_evidence", "record_pattern_use",
    "oracle_xss", "oracle_sqli_boolean", "oracle_sqli_time",
    "oracle_lfi", "oracle_ssrf", "oracle_response_diff",
    # Living KB — confirm/dismiss 결과를 누적 자산으로 저장
    "learn_from_finding", "learn_dead_end", "update_target_profile",
    "record_endpoint_spec",
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
TOOL_RESULT_MAX_CHARS = int(os.environ.get("WATCHDOG_TOOL_RESULT_MAX_CHARS", "1200"))
TOOL_RESULT_EXTENDED_CHARS = int(os.environ.get("WATCHDOG_TOOL_RESULT_EXTENDED_CHARS", "2200"))
HTTP_TOOL_RESULT_CHARS = int(os.environ.get("WATCHDOG_HTTP_RESULT_MAX_CHARS", "1500"))
HTTP_BODY_PREVIEW_CHARS = int(os.environ.get("WATCHDOG_HTTP_BODY_PREVIEW_CHARS", "700"))
EXTENDED_LIMIT_TOOLS = {
    "read_source", "grep_source", "list_source_tree",
    "get_chain_context", "get_exploit_chains",
    "get_secrets", "get_scan_notes",
}
HTTP_RESULT_TOOLS = {"http_request", "curl_request", "http_session_request"}
AUTO_AUTH_TOOLS = {"http_request", "http_session_request", "curl_request"}
AUTO_AUTH_SKIP_PATHS = ("/login", "/signin", "/sign-in", "/auth/login", "/register")
BUG_BOUNTY_UA_TOOLS = {"http_request", "http_session_request", "curl_request", "multi_http_probe"}
_BUG_BOUNTY_UA_CACHE: dict[str, str | None] = {}
HTTP_HEADERS_TO_KEEP = {
    "content-type", "location", "set-cookie", "server", "cache-control",
    "x-frame-options", "x-content-type-options", "x-xss-protection",
    "www-authenticate", "access-control-allow-origin",
}
_AUTO_AUTH_CACHE: dict[str, dict | None] = {}
SAFE_PARALLEL_TOOLS = {
    # KB / 검색
    "search_knowledge", "retrieve_similar_patterns", "retrieve_cve_variants",
    "check_payload_dedup", "fetch_cve_details", "suggest_cves_for_framework",
    # HTTP probe — stateless. http_session_request 는 cookie jar 공유로 직렬 유지.
    # multi_http_probe 는 자체 내부 동시화. 단일 http_request 도 한 LLM 턴에 N개를
    # 묶어 부르면 _execute_tool_calls 가 asyncio.gather 로 동시 발사.
    "http_request", "multi_http_probe",
    # Living KB 회상 (read)
    "recall_target", "recall_dead_ends", "recall_endpoint_specs",
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


def _tool_result_limit(tool_name: str) -> int:
    if tool_name in HTTP_RESULT_TOOLS:
        return HTTP_TOOL_RESULT_CHARS
    if tool_name in EXTENDED_LIMIT_TOOLS:
        return TOOL_RESULT_EXTENDED_CHARS
    return TOOL_RESULT_MAX_CHARS


def _compact_json(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _content_to_summary_text(content, limit: int = 280) -> str:
    if isinstance(content, str):
        return _truncate_tool_result(content, limit).replace("\n", " ")
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                btype = block.get("type")
                if btype == "tool_use":
                    name = block.get("name", "")
                    keys = sorted((block.get("input") or {}).keys())
                    parts.append(f"tool:{name}({','.join(keys[:4])})")
                elif btype == "tool_result":
                    text = str(block.get("content", "") or "")
                    parts.append(f"result:{_truncate_tool_result(text, 140).replace(chr(10), ' ')}")
                elif btype == "text":
                    parts.append(_truncate_tool_result(str(block.get("text", "")), 140).replace("\n", " "))
            else:
                parts.append(_truncate_tool_result(str(block), 140).replace("\n", " "))
        return _truncate_tool_result(" | ".join(filter(None, parts)), limit)
    return _truncate_tool_result(str(content), limit).replace("\n", " ")


def _has_tool_result_block(msg: dict) -> bool:
    content = msg.get("content")
    if not isinstance(content, list):
        return False
    for block in content:
        if isinstance(block, dict) and block.get("type") == "tool_result":
            return True
        if getattr(block, "type", None) == "tool_result":
            return True
    return False


def _summarize_messages_slice(msgs: list[dict], char_limit: int) -> str:
    summary_lines = []
    for msg in msgs:
        if not isinstance(msg, dict):
            continue
        msg_role = msg.get("role", "unknown")
        summary_lines.append(f"[{msg_role}] {_content_to_summary_text(msg.get('content'))}")
    return _truncate_tool_result("\n".join(summary_lines), char_limit)


def _compact_messages_for_call(messages: list[dict], role: str) -> list[dict]:
    tail_count = ROLE_CONTEXT_TAIL_MESSAGES.get(role)
    if not tail_count or len(messages) <= tail_count + 1:
        return messages

    # tail 경계가 tool_use ↔ tool_result 쌍을 자르면 Anthropic API 400
    # (orphan tool_use_id). tail[0]이 tool_result 담은 user면 직전 assistant를
    # 같이 끌고 오도록 경계를 왼쪽으로 민다.
    effective_tail = tail_count
    while effective_tail < len(messages) - 1:
        candidate = messages[-effective_tail]
        if candidate.get("role") == "user" and _has_tool_result_block(candidate):
            effective_tail += 1
            continue
        break

    head = messages[0]
    tail = messages[-effective_tail:]
    middle = messages[1:-effective_tail]
    if not middle:
        return messages

    # ── Prompt caching 최적화 ────────────────────────────────────────
    # middle은 append-only 로 자라므로 middle[:STABLE_CONTEXT_SIZE] 프리픽스는
    # 턴 간 동일 → 그 요약에 cache_control(ephemeral) 을 붙이면 5분 TTL 안에
    # 90% input 비용 할인. head(초기 user prompt)도 phase 내 불변 → 캐싱.
    # overflow(middle[STABLE:]) 는 매 턴 바뀌므로 캐시 대상 아님.
    # ─────────────────────────────────────────────────────────────────
    summary_budget = ROLE_CONTEXT_SUMMARY_CHARS.get(role, 1200)
    if len(middle) >= STABLE_CONTEXT_SIZE:
        stable_text = _summarize_messages_slice(
            middle[:STABLE_CONTEXT_SIZE], int(summary_budget * 0.75)
        )
        overflow_text = _summarize_messages_slice(
            middle[STABLE_CONTEXT_SIZE:], max(int(summary_budget * 0.25), 300)
        )
    else:
        stable_text = ""
        overflow_text = _summarize_messages_slice(middle, summary_budget)

    head_content = head.get("content")
    if isinstance(head_content, str):
        head_msg = {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": head_content,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
        }
    else:
        head_msg = head

    summary_blocks: list[dict] = []
    if stable_text:
        summary_blocks.append({
            "type": "text",
            "text": f"[Stable prior context]\n{stable_text}",
            "cache_control": {"type": "ephemeral"},
        })
    if overflow_text:
        summary_blocks.append({
            "type": "text",
            "text": f"[Recent prior context]\n{overflow_text}",
        })

    compacted: list[dict] = [head_msg]
    if summary_blocks:
        compacted.append({"role": "user", "content": summary_blocks})
    compacted.extend(tail)
    return compacted


def _normalize_credential_list(raw_creds) -> list[dict]:
    if isinstance(raw_creds, dict) and raw_creds.get("type"):
        return [raw_creds]
    if isinstance(raw_creds, list):
        return [c for c in raw_creds if isinstance(c, dict) and c.get("type")]
    return []


def _select_auto_auth(scan_run: ScanRun) -> dict | None:
    run_id = str(scan_run.run_id)
    if run_id in _AUTO_AUTH_CACHE:
        return _AUTO_AUTH_CACHE[run_id]

    cred_list = _normalize_credential_list((scan_run.config or {}).get("credentials"))
    if len(cred_list) != 1:
        _AUTO_AUTH_CACHE[run_id] = None
        return None

    cred = cred_list[0]
    ctype = str(cred.get("type", "")).strip().lower()
    label = str(cred.get("label") or "default")
    headers = None
    if ctype == "bearer" and cred.get("token"):
        headers = {"Authorization": f"Bearer {cred['token']}"}
    elif ctype == "cookie" and cred.get("cookies"):
        cookies_val = cred["cookies"]
        # 프론트엔드가 dict로 파싱해 보낼 수 있음 ({"token": "..."}). HTTP Cookie
        # 헤더는 문자열이어야 하므로 "k=v; k2=v2" 형태로 직렬화.
        if isinstance(cookies_val, dict):
            cookies_val = "; ".join(f"{k}={v}" for k, v in cookies_val.items() if k)
        headers = {"Cookie": str(cookies_val)}
    elif ctype == "basic" and cred.get("username") and cred.get("password"):
        token = b64encode(f"{cred['username']}:{cred['password']}".encode("utf-8")).decode("ascii")
        headers = {"Authorization": f"Basic {token}"}

    selected = {"label": label, "type": ctype, "headers": headers} if headers else None
    _AUTO_AUTH_CACHE[run_id] = selected
    return selected


def _same_target_host(scan_run: ScanRun, url: str) -> bool:
    try:
        target = urlparse(scan_run.target_url)
        parsed = urlparse(url)
        return bool(parsed.netloc) and parsed.netloc.lower() == target.netloc.lower()
    except Exception:
        return False


def _should_skip_auto_auth(scan_run: ScanRun, url: str) -> bool:
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return True
    if not _same_target_host(scan_run, url):
        return True
    return any(marker in path for marker in AUTO_AUTH_SKIP_PATHS)


def _parse_json_headers(raw_value: str) -> dict:
    if not raw_value:
        return {}
    try:
        value = json.loads(raw_value)
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _parse_curl_headers(raw_value: str) -> dict:
    headers = {}
    for line in (raw_value or "").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def _dump_curl_headers(headers: dict) -> str:
    return "\n".join(f"{key}: {value}" for key, value in headers.items())


def _maybe_inject_auto_auth(scan_run: ScanRun, tool_name: str, tool_args: dict) -> dict:
    if tool_name not in AUTO_AUTH_TOOLS:
        return tool_args

    auth = _select_auto_auth(scan_run)
    if not auth or not auth.get("headers"):
        return tool_args

    url = str(tool_args.get("url") or "")
    if not url or _should_skip_auto_auth(scan_run, url):
        return tool_args

    if tool_name == "curl_request":
        headers = _parse_curl_headers(tool_args.get("headers", ""))
    elif tool_name == "http_session_request":
        headers = _parse_json_headers(tool_args.get("headers_json", "{}"))
    else:
        headers = _parse_json_headers(tool_args.get("headers", "{}"))

    if any(key.lower() in ("authorization", "cookie") for key in headers):
        return tool_args

    headers.update(auth["headers"])
    updated = dict(tool_args)
    if tool_name == "curl_request":
        updated["headers"] = _dump_curl_headers(headers)
    elif tool_name == "http_session_request":
        updated["headers_json"] = _compact_json(headers)
    else:
        updated["headers"] = _compact_json(headers)

    logger.info(
        f"[{scan_run.run_id}] auto-auth applied to {tool_name} using {auth['label']}({auth['type']})"
    )
    return updated


def _build_bug_bounty_ua(scan_run: ScanRun) -> str | None:
    run_id = str(scan_run.run_id)
    if run_id in _BUG_BOUNTY_UA_CACHE:
        return _BUG_BOUNTY_UA_CACHE[run_id]
    bb_id = (scan_run.config or {}).get("bug_bounty_ua", "")
    if not bb_id or not str(bb_id).strip():
        _BUG_BOUNTY_UA_CACHE[run_id] = None
        return None
    ua = f"WatchdogMCP/1.0 (BugBounty: {str(bb_id).strip()})"
    _BUG_BOUNTY_UA_CACHE[run_id] = ua
    return ua


def _maybe_inject_bug_bounty_ua(scan_run: ScanRun, tool_name: str, tool_args: dict) -> dict:
    if tool_name not in BUG_BOUNTY_UA_TOOLS:
        return tool_args

    ua = _build_bug_bounty_ua(scan_run)
    if not ua:
        return tool_args

    updated = dict(tool_args)

    if tool_name == "multi_http_probe":
        try:
            req_list = json.loads(updated.get("requests_json", "[]"))
        except (json.JSONDecodeError, TypeError):
            return updated
        for item in req_list:
            hdrs = item.get("headers") or {}
            if not isinstance(hdrs, dict):
                hdrs = {}
            hdrs["User-Agent"] = ua
            item["headers"] = hdrs
        updated["requests_json"] = json.dumps(req_list, ensure_ascii=False)
    elif tool_name == "curl_request":
        headers = _parse_curl_headers(updated.get("headers", ""))
        headers["User-Agent"] = ua
        updated["headers"] = _dump_curl_headers(headers)
    elif tool_name == "http_session_request":
        headers = _parse_json_headers(updated.get("headers_json", "{}"))
        headers["User-Agent"] = ua
        updated["headers_json"] = _compact_json(headers)
    else:
        headers = _parse_json_headers(updated.get("headers", "{}"))
        headers["User-Agent"] = ua
        updated["headers"] = _compact_json(headers)

    return updated


def _summarize_set_cookie(value: str) -> str:
    parts = [part.strip() for part in value.split(";") if part.strip()]
    if not parts:
        return value
    summary = []
    if "=" in parts[0]:
        summary.append(parts[0].split("=", 1)[0] + "=<redacted>")
    for attr in parts[1:4]:
        summary.append(attr)
    return "; ".join(summary)


def _looks_like_spa_fallback(content_type: str, body: str) -> bool:
    if "html" not in (content_type or "").lower():
        return False
    lowered = (body or "").lower()
    return (
        "<html" in lowered
        and ("<div id=\"root\"" in lowered or "type=\"module\"" in lowered or "<title>" in lowered)
    )


import re as _re

_LINK_EXTRACT_RE_HTML = [
    _re.compile(r'<a\s[^>]*?href\s*=\s*["\']([^"\'#][^"\']*)', _re.I),
    _re.compile(r'<form\s[^>]*?action\s*=\s*["\']([^"\'#][^"\']*)', _re.I),
    _re.compile(r'<link\s[^>]*?href\s*=\s*["\']([^"\'#][^"\']*)', _re.I),
    _re.compile(r'<iframe\s[^>]*?src\s*=\s*["\']([^"\'#][^"\']*)', _re.I),
    _re.compile(r'<script\s[^>]*?src\s*=\s*["\']([^"\'#][^"\']*)', _re.I),
    _re.compile(r'<meta\s[^>]*?content\s*=\s*["\'][^"\']*url\s*=\s*([^"\';\s]+)', _re.I),
    _re.compile(r'(?:window\.location|location\.href)\s*=\s*["\']([^"\']+)', _re.I),
]
_LINK_EXTRACT_RE_JS = [
    _re.compile(r'''(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*[`'"](\/[^`'"]*?)[`'"]'''),
    _re.compile(r'''(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*[`'"](https?://[^`'"]+)[`'"]'''),
    _re.compile(r'''\.open\s*\(\s*[`'"]\w+[`'"]\s*,\s*[`'"](\/[^`'"]+)[`'"]'''),
    _re.compile(r'''\.open\s*\(\s*[`'"]\w+[`'"]\s*,\s*[`'"](https?://[^`'"]+)[`'"]'''),
    _re.compile(r'''[`'"](?:\$\{[^}]+\})?(\/api\/[^`'"]{2,})[`'"]'''),
    _re.compile(r'''[`'"](\/(?:api|v[0-9]+|admin|auth|graphql|rest|internal|private|debug|swagger|docs)[\/][^`'"]{1,})[`'"]'''),
]
# url: key matching uses depth-aware extraction (top-level only, no nested sub-objects)
_LINK_EXTRACT_RE_JS_BASE_URL = _re.compile(r'''baseURL\s*:\s*[`'"](https?://[^`'"]{4,})[`'"]''')
_LINK_EXTRACT_RE_JSON = _re.compile(r'"(?:href|url|uri|link|redirect|next|action|src|endpoint|path)"\s*:\s*"(\/[^"]{2,}|https?://[^"]{4,})"', _re.I)

_STATIC_EXT = frozenset({
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".avif",
    ".mp4", ".mp3", ".pdf",
})


def _extract_links_from_response(
    body: str, content_type: str, response_headers: dict, request_url: str,
) -> list[str]:
    """Extract URLs/paths from an HTTP response (HTML/JSON/headers).

    Returns deduplicated, sorted list of discovered paths/URLs.
    Filters out static assets (images, fonts, CSS) that have no attack surface.
    """
    from urllib.parse import urljoin, urlparse as _urlparse

    found: set[str] = set()
    ct_lower = (content_type or "").lower()

    # 1. Response headers: Location, Link, Refresh
    for hdr_name in ("location", "link", "refresh", "content-location"):
        val = ""
        for k, v in (response_headers or {}).items():
            if k.lower() == hdr_name:
                val = str(v)
                break
        if val:
            if hdr_name == "link":
                for m in _re.findall(r'<([^>]+)>', val):
                    found.add(m)
            elif hdr_name == "refresh" and "url=" in val.lower():
                idx = val.lower().index("url=")
                found.add(val[idx + 4:].strip().strip("'\""))
            else:
                found.add(val.strip())

    # 2. HTML body
    if body and ("html" in ct_lower or body.lstrip()[:15].lower().startswith(("<!doctype", "<html"))):
        for pat in _LINK_EXTRACT_RE_HTML:
            for m in pat.findall(body):
                found.add(m)

    # 3. JSON body
    if body and ("json" in ct_lower or body.lstrip()[:1] in ("{", "[")):
        for m in _LINK_EXTRACT_RE_JSON.findall(body):
            found.add(m)

    # 4. JS patterns (inline scripts or JS content-type)
    js_relative: list[str] = []
    if body and ("javascript" in ct_lower or "html" in ct_lower):
        for pat in _LINK_EXTRACT_RE_JS:
            for m in pat.findall(body):
                found.add(m)
                if m.startswith("/"):
                    js_relative.append(m)

    # 4b. Object-literal depth-aware extraction (top-level keys only)
    if body and ("javascript" in ct_lower or "html" in ct_lower):
        for bu in _LINK_EXTRACT_RE_JS_BASE_URL.findall(body):
            found.add(bu)
        from watchdog_mcp.link_extractor import _extract_baseurl_url_pairs, _extract_depth1_js_urls
        for combined in _extract_baseurl_url_pairs(body):
            found.add(combined)
        for url_val in _extract_depth1_js_urls(body):
            found.add(url_val)

    # Normalize: resolve relative URLs against request_url
    normalized: set[str] = set()
    base = request_url or ""
    for raw in found:
        raw = raw.strip()
        if not raw or raw.startswith(("data:", "javascript:", "mailto:", "tel:", "#")):
            continue
        if raw.startswith("//"):
            raw = "https:" + raw
        if not raw.startswith(("http://", "https://", "/")):
            if base:
                raw = urljoin(base, raw)
            else:
                continue
        # Convert absolute same-origin URLs to paths
        if raw.startswith(("http://", "https://")) and base:
            try:
                raw_p = _urlparse(raw)
                base_p = _urlparse(base)
                if raw_p.netloc.lower() == base_p.netloc.lower():
                    raw = raw_p.path + ("?" + raw_p.query if raw_p.query else "")
            except Exception:
                pass
        # Filter out static assets
        try:
            path_part = _urlparse(raw).path if raw.startswith("http") else raw.split("?")[0]
            ext = "." + path_part.rsplit(".", 1)[-1].lower() if "." in path_part.rsplit("/", 1)[-1] else ""
            if ext in _STATIC_EXT:
                continue
        except Exception:
            pass
        normalized.add(raw)

    return sorted(normalized)[:50]


def _compact_http_tool_result(text: str) -> str:
    try:
        data = json.loads(text)
    except Exception:
        return text
    if not isinstance(data, dict) or "status_code" not in data:
        return text

    headers = data.get("response_headers") if isinstance(data.get("response_headers"), dict) else {}
    filtered_headers = {}
    for key, value in headers.items():
        lowered = key.lower()
        if lowered not in HTTP_HEADERS_TO_KEEP:
            continue
        if lowered == "set-cookie":
            filtered_headers[key] = _summarize_set_cookie(str(value))
        else:
            filtered_headers[key] = _truncate_tool_result(str(value), 160)

    body = str(data.get("body", "") or "")
    content_type = str(data.get("content_type", "") or "")
    preview_limit = 300 if "javascript" in content_type.lower() else HTTP_BODY_PREVIEW_CHARS
    compact = {
        "url": data.get("url", ""),
        "status_code": data.get("status_code"),
        "elapsed": data.get("elapsed"),
        "content_length": data.get("content_length"),
        "content_type": content_type,
        "response_headers": filtered_headers,
    }
    if body:
        compact["body_sha1"] = hashlib.sha1(body.encode("utf-8", "ignore")).hexdigest()[:12]
        compact["body_preview"] = _truncate_tool_result(body, preview_limit)
    if _looks_like_spa_fallback(content_type, body):
        compact["spa_fallback_html"] = True

    # Prefer pre-extracted links from MCP tool (extracted from full body at source).
    # Fall back to re-extracting from the (already truncated) body in compact.
    pre_links = data.get("discovered_links")
    if isinstance(pre_links, list) and pre_links:
        compact["discovered_links"] = pre_links
    else:
        raw_headers = data.get("response_headers") if isinstance(data.get("response_headers"), dict) else {}
        discovered = _extract_links_from_response(body, content_type, raw_headers, data.get("url", ""))
        if discovered:
            compact["discovered_links"] = discovered

    # SPA hash routes — surface to LLM for browser_navigate exploration
    pre_hashes = data.get("hash_routes")
    if isinstance(pre_hashes, list) and pre_hashes:
        compact["hash_routes"] = pre_hashes

    return _compact_json(compact)


_AUTO_PUSH_TOOLS = {"http_request", "http_session_request", "multi_http_probe"}


def _auto_push_discovered_links(
    scan_run: ScanRun, raw_text: str, tool_name: str, current_node_id: str = "",
):
    """Safety net: extract links from raw HTTP response and auto-push as endpoint nodes.

    Runs synchronously (called via sync_to_async). Creates DiscoveryNode objects
    directly with dedup checks, avoiding the need to call the MCP tool function.

    Prefers pre-extracted `discovered_links` from tool responses (extracted at source
    from the full body). Falls back to re-extracting from the truncated body/body_preview.
    Handles formats: http_request ({status_code,body}), multi_http_probe ({results:[...]}),
    http_session_request ({status_code,body}).

    When current_node_id is provided, new endpoints are pushed as children of that node
    (preserving the exploration chain context). Falls back to root node when unavailable.
    """
    from api.models import DiscoveryNode
    from watchdog_mcp.tools_discovery import _normalize_ep, _merge_context, DISCOVERY_MAX_NODES

    root_node_id = (scan_run.config or {}).get("_root_node_id")
    if not root_node_id:
        return

    # Prefer current node as parent to preserve exploration chain context;
    # fall back to root node if current_node_id is unavailable or invalid.
    parent_node = None
    if current_node_id:
        try:
            parent_node = DiscoveryNode.objects.get(node_id=current_node_id)
        except DiscoveryNode.DoesNotExist:
            pass
    if parent_node is None:
        try:
            parent_node = DiscoveryNode.objects.get(node_id=root_node_id)
        except DiscoveryNode.DoesNotExist:
            return

    try:
        data = json.loads(raw_text)
    except Exception:
        return

    # Collect (response_dict, source_url) tuples from various tool output formats
    responses: list[dict] = []
    if isinstance(data, dict):
        if "status_code" in data:
            responses.append(data)
        elif "results" in data and isinstance(data["results"], list):
            for item in data["results"]:
                if isinstance(item, dict) and "status_code" in item:
                    responses.append(item)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and "status_code" in item:
                responses.append(item)

    scan_run_id = str(scan_run.run_id)
    target_url = scan_run.target_url or ""
    all_links: list[tuple[str, str]] = []  # (link, source_ep)
    all_hash_routes: set[str] = set()

    for resp in responses:
        status_code = resp.get("status_code", 0)
        if isinstance(status_code, int) and status_code >= 400:
            ct = str(resp.get("content_type", "") or "").lower()
            has_pre_links = isinstance(resp.get("discovered_links"), list) and resp["discovered_links"]
            if not has_pre_links and "html" not in ct:
                continue

        request_url = str(resp.get("url", "") or "")
        source_ep = request_url
        if source_ep.startswith(("http://", "https://")):
            try:
                source_ep = urlparse(source_ep).path
            except Exception:
                pass

        # Collect hash routes from pre-extracted data
        pre_hashes = resp.get("hash_routes")
        if isinstance(pre_hashes, list):
            for h in pre_hashes:
                if isinstance(h, str):
                    all_hash_routes.add(h)

        # Prefer pre-extracted links (from full body at MCP tool level)
        pre_links = resp.get("discovered_links")
        if isinstance(pre_links, list) and pre_links:
            for link in pre_links:
                if isinstance(link, str):
                    all_links.append((link, source_ep))
        else:
            body = str(resp.get("body") or resp.get("body_preview") or "")
            content_type = str(resp.get("content_type", "") or "")
            raw_headers = resp.get("response_headers") or resp.get("headers") or {}
            if not isinstance(raw_headers, dict):
                raw_headers = {}
            from watchdog_mcp.link_extractor import extract_links_and_hashes
            links, hashes = extract_links_and_hashes(body, content_type, raw_headers, request_url)
            for link in links:
                all_links.append((link, source_ep))
            all_hash_routes.update(hashes)

    if not all_links and not all_hash_routes:
        return

    existing_count = DiscoveryNode.objects.filter(scan_run_id=scan_run_id).count()
    if existing_count >= DISCOVERY_MAX_NODES:
        return

    parent_depth = parent_node.depth if parent_node else 0
    pushed = 0

    # Auto-push discovered endpoint links
    for link, source_ep in all_links[:30]:
        ep_norm = _normalize_ep(link, target_url)
        ep_variants = {link, ep_norm, ep_norm.rstrip("/"), ep_norm + "/",
                       ep_norm.lower()}
        if "?" not in ep_norm:
            ep_variants.add(ep_norm.split("?", 1)[0])
        ep_variants.discard("")

        existing = (
            DiscoveryNode.objects
            .filter(scan_run_id=scan_run_id, node_type="endpoint")
            .filter(endpoint__in=ep_variants)
            .filter(vuln_type="")
            .first()
        )
        if existing:
            _merge_context(existing, {
                "discovered_from": source_ep,
                "source": "auto_link_extraction",
            })
            continue

        try:
            DiscoveryNode.objects.create(
                scan_run_id=scan_run_id,
                parent=parent_node,
                depth=parent_depth + 1,
                node_type="endpoint",
                endpoint=ep_norm,
                vuln_type="",
                summary=f"Auto-discovered via {source_ep}",
                context={
                    "discovered_from": source_ep,
                    "source": "auto_link_extraction",
                    "http_tool": tool_name,
                },
                status="pending",
            )
            pushed += 1
        except Exception:
            pass

        if existing_count + pushed >= DISCOVERY_MAX_NODES:
            break

    # Auto-push SPA hash routes as clue nodes (need browser navigation to trigger APIs)
    for route in sorted(all_hash_routes)[:15]:
        if existing_count + pushed >= DISCOVERY_MAX_NODES:
            break
        route_norm = route.strip()
        if not route_norm or len(route_norm) < 3:
            continue

        existing = (
            DiscoveryNode.objects
            .filter(scan_run_id=scan_run_id, node_type="clue")
            .filter(endpoint=route_norm)
            .first()
        )
        if existing:
            continue

        try:
            DiscoveryNode.objects.create(
                scan_run_id=scan_run_id,
                parent=parent_node,
                depth=parent_depth + 1,
                node_type="clue",
                endpoint=route_norm,
                vuln_type="",
                summary=f"SPA hash route — browser_navigate to discover APIs",
                context={
                    "source": "auto_hash_route_extraction",
                    "http_tool": tool_name,
                    "needs_browser": True,
                },
                status="pending",
            )
            pushed += 1
        except Exception:
            pass

    if pushed:
        logger.info(
            f"[{scan_run.run_id}] auto-pushed {pushed} discovered links/routes "
            f"from {tool_name} ({all_links[0][1] if all_links else 'N/A'})"
        )


async def _execute_single_tool(
    scan_run: ScanRun,
    tool_router: dict,
    tb,
    current_node_id: str = "",
) -> dict:
    raise_if_stop_requested(scan_run)
    tool_name = tb.name
    tool_args = dict(tb.input or {})
    tool_args = _maybe_inject_auto_auth(scan_run, tool_name, tool_args)
    tool_args = _maybe_inject_bug_bounty_ua(scan_run, tool_name, tool_args)
    logger.info(
        f"[{scan_run.run_id}] tool {tool_name}"
        f"({json.dumps(tool_args, ensure_ascii=False)[:200]})"
    )
    raw_text = ""
    try:
        if tool_name in tool_router:
            session, original = tool_router[tool_name]
            result = await session.call_tool(original, tool_args)
            if result.content:
                raw_text = "\n".join(
                    c.text if hasattr(c, "text") else str(c)
                    for c in result.content
                )
            else:
                raw_text = "(빈 결과)"
            is_error = bool(getattr(result, "isError", False))
        else:
            raw_text = f"도구 {tool_name} 차단 — 이 role 화이트리스트에 없음."
            is_error = True
    except Exception as e:
        logger.error(f"[{scan_run.run_id}] tool error {tool_name}: {e}")
        raw_text = f"도구 오류: {e}"
        is_error = True

    # Auto-push discovered links from HTTP responses (safety net)
    if tool_name in _AUTO_PUSH_TOOLS and not is_error:
        try:
            await sync_to_async(_auto_push_discovered_links)(
                scan_run, raw_text, tool_name, current_node_id,
            )
        except Exception as e:
            logger.debug(f"[{scan_run.run_id}] auto-push links error: {e}")

    text = raw_text
    if tool_name in HTTP_RESULT_TOOLS and not is_error:
        text = _compact_http_tool_result(text)
    limit = _tool_result_limit(tool_name)
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
    current_node_id: str = "",
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
                return await _execute_single_tool(scan_run, tool_router, tb, current_node_id)

        gathered = await asyncio.gather(*[_bounded(tb) for tb in parallel_blocks])
        results.extend(gathered)

    for tb in sequential_blocks:
        results.append(await _execute_single_tool(scan_run, tool_router, tb, current_node_id))

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
    current_node_id: str = "",
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
        call_messages = _compact_messages_for_call(messages, role)
        call_kwargs = dict(
            model=MODEL,
            max_tokens=ROLE_OUTPUT_TOKEN_BUDGET.get(role, 4096),
            system=cached_system,
            messages=call_messages,
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
            call_messages = _compact_messages_for_call(messages, role)
            call_kwargs["messages"] = call_messages
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

        prompt_preview = build_prompt_preview(call_messages)
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
                metadata={
                    "role": role,
                    "turn": turn + 1,
                    "emitted": emit_block.name,
                    "message_count": len(call_messages),
                },
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
                metadata={
                    "role": role,
                    "turn": turn + 1,
                    "message_count": len(call_messages),
                },
            )
            break

        messages.append({"role": "assistant", "content": response.content})
        tool_results = await _execute_tool_calls(
            scan_run, tool_router, tool_use_blocks, current_node_id,
        )

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
                "message_count": len(call_messages),
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

    bb_ua = _build_bug_bounty_ua(scan_run)
    bb_hint = ""
    if bb_ua:
        bb_hint = (
            f"\n[BUG-BOUNTY] User-Agent 자동 주입 활성: {bb_ua}\n"
            "  모든 http_request/multi_http_probe/curl_request/http_session_request 에 자동 적용됨.\n"
            "  브라우저 사용 시 browser_set_user_agent 를 먼저 호출하세요."
        )

    cred_list = _normalize_credential_list(scan_config.get("credentials"))
    auth_hint = ""
    if cred_list:
        personas = await sync_to_async(_seed_credentials)(scan_run, cred_list)
        if personas:
            persona_summary = ", ".join(f"{p['label']}({p['type']})" for p in personas)
            auth_hint = (
                "\n[AUTH] User-provided credentials available: "
                + persona_summary
                + "\nUse get_secrets(scan_run_id=\""
                + str(scan_run.run_id)
                + "\") for form or multi-persona auth. Bearer/cookie/basic creds may be auto-attached to same-host HTTP tools."
            )
            logger.info(
                f"[{scan_run.run_id}] multi-mode credentials loaded: {persona_summary}"
            )
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
        f"{auth_hint}\n"
        f"{bb_hint}\n"
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
            + _compact_json({"hypotheses": hypotheses})
            + "\n```"
        )
        if auth_hint:
            executor_user_msg = f"{auth_hint}\n\n" + executor_user_msg
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
            + _compact_json({"attempts": attempts})
            + "\n```"
        )
        if auth_hint:
            verifier_user_msg = f"{auth_hint}\n\n" + verifier_user_msg
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

DISCOVERY_WORKER_COUNT = int(os.environ.get("WATCHDOG_DISCOVERY_WORKERS", "5"))
DISCOVERY_WORKER_BUDGET = int(os.environ.get("WATCHDOG_DISCOVERY_WORKER_BUDGET", "14"))
DISCOVERY_EXPLOIT_BUDGET = int(os.environ.get("WATCHDOG_DISCOVERY_EXPLOIT_BUDGET", "22"))
DISCOVERY_CLUE_BUDGET = int(os.environ.get("WATCHDOG_DISCOVERY_CLUE_BUDGET", "18"))
DISCOVERY_RECHECK_BUDGET = int(os.environ.get("WATCHDOG_DISCOVERY_RECHECK_BUDGET", "5"))
DISCOVERY_QUIESCENCE_S = int(os.environ.get("WATCHDOG_DISCOVERY_QUIESCENCE_S", "120"))
DISCOVERY_MAX_CALLS = int(os.environ.get("WATCHDOG_DISCOVERY_MAX_CALLS", "300"))
DISCOVERY_MAX_COST_USD = Decimal(os.environ.get("WATCHDOG_DISCOVERY_MAX_COST_USD", "5.0"))

# Pre-exploit critic (CodeMender 패턴) — exploit_step 노드 진행 전 1회 평가.
# 단순 verdict + 전제/대안 — 비용 최소화 (2-3 turn).
DISCOVERY_CRITIC_BUDGET = int(os.environ.get("WATCHDOG_DISCOVERY_CRITIC_BUDGET", "3"))
# 환경변수로 전체 critic off 가능 (비용 부담 시).
DISCOVERY_CRITIC_ENABLED = os.environ.get("WATCHDOG_DISCOVERY_CRITIC", "1") not in ("0", "false", "no")

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

# ═══════════════════════════════════════════════════════
# MLLA — 5-에이전트 분해 (Atlantis Multi-Lingual LLM Agents 패턴)
# ═══════════════════════════════════════════════════════
# 한 EXPLORER_PROMPT가 모든 노드 타입을 처리하던 구조 → 노드 타입별 전문화된
# sub-agent prompt로 분해. 각 sub-agent는 책임이 좁고 출력 contract가 명확.
# work-unit 예산도 단계별 차등.
#
# 매핑:
#   target       → ROUTEMAP    (전체 attack surface 매핑 → endpoint 후보 push)
#   endpoint     → ENTRYPOINT  (입력점/sink 분석 → 의심 vuln_type vuln node push)
#   vuln         → HYPOTHESIS  (KB 가설 + 페이로드 시도 → exploit_step / confirmed)
#   exploit_step → EXPLOIT     (chain 깊은 단계, 다단계 페이로드)
#   flag         → CONFIRMER   (oracle 확정 + KB 학습)
#   clue         → ENTRYPOINT  (단서도 입력점 분석과 유사)
#
# 자율성 원칙: 도구는 추가, 강제는 안전망에만. 각 prompt는 책임을 좁히지만
# tool whitelist는 EXPLORER_TOOLS 공통 (단계별 좁힘은 후속 작업).

ROUTEMAP_PROMPT = """\
You are a RouteMap agent. Goal: map the target's attack surface and push every
discovered endpoint as a child node.

## Inputs
A target (root) node: target_url, optional source_root.

## Method (자율적으로 선택, 모두 강제 아님)
1. recall_target(host) — load prior knowledge (framework, WAF, prior vulns).
   반환의 endpoint_specs 가 비어있지 않으면 이미 이 host endpoint 명세 KB 있음
   → 그 endpoint 들은 push_discovery 로 바로 시드 (정찰 단계 최소화). 추가
   recall_endpoint_specs(host) 로 더 자세한 정보 (params/sinks/suspected_vuln_types)
   조회 가능.

   **CHECK ROOT CONTEXT — credentials_available**: 사용자가 로그인 정보를
   제공했으면 root.context.credentials_available 에 personas 배열 표시
   (label, type 의 list). get_secrets() 로 실제 값 회상:

   각 persona 는 secrets 에 label prefix 로 저장:
     auth_<label>_type, auth_<label>_username, auth_<label>_password,
     auth_<label>_login_url, auth_<label>_bearer_token, auth_<label>_cookies, ...

   처리:
     · type=form  → login_url + user/pw 회상 →
       http_session_request(POST login_url, form_json={...},
       session_id="<scan-id>-auth-<label>") 로 로그인 → 이후 worker 가
       label 별 session_id 로 protected endpoint 접근
     · type=bearer → bearer_token → Authorization: Bearer <T> 헤더
     · type=cookie → cookies → Cookie 헤더 attach
     · type=basic  → user/pw → HTTP Basic Auth

   여러 persona (admin / user1 / api 등) → IDOR cross-access, role 별
   권한 차이, admin-only endpoint 접근 등 다양한 vector. 각 persona 별로
   별도 session_id 사용해 cookie jar 분리.

   ⚠ **login endpoint 자체도 attack 대상** — credentials 가 valid 라고 해서
   login 페이지 vuln (sqli/auth_bypass/nosql injection/default cred brute)
   을 skip 하지 말 것. 흐름:
     1. login endpoint 식별 → push_discovery(node_type="vuln", vuln_type="sqli")
        + push_discovery(node_type="vuln", vuln_type="auth_bypass") 등 시드
     2. 그것과 별개로 valid credential 로 로그인 → protected area 정찰
     3. 즉 credential 은 "정찰 보조" 이지 "공격 면제권" 아님.

   credentials 없으면 unauth 영역만 정찰. 있으면 양 트랙 (login 자체 attack
   + 인증 후 protected) 동시 진행.

   ## Expirable artifact 저장 원칙 — refresh_spec 필수

   만료 가능한 secret (session/CSRF/JWT/OTP/API key/업로드 파일 경로 등)
   저장 시 반드시 refresh_spec (JSON recipe) 을 달아둔다. 다음 만료 시
   어떤 worker 든 refresh_spec.kind 읽고 자율 재획득 가능.

   표준 kind: form_login / attack_replay / refetch_html / oauth_refresh /
   otp_request / magic_link / api_key_reissue / reupload / (custom).

   예시:
     # 폼 로그인 세션
     store_secret(key="<label>_session", value=<cookie>, category="session",
                  obtained_via="form_login", auth_label="<label>",
                  chain_summary="login via <label> credentials",
                  refresh_spec='{"kind":"form_login","auth_label":"<label>"}')

     # 공격으로 얻은 세션 (SQLi bypass / JWT forge / XSS cookie steal)
     store_secret(key="<descr>_session", value=<cookie>, category="session",
                  obtained_via="attack", source_vuln_node_id="<vuln uuid>",
                  chain_summary="<공격 한 줄>",
                  refresh_spec='{"kind":"attack_replay",
                                 "source_vuln_node_id":"<vuln uuid>"}')

     # CSRF token (per-request)
     store_secret(key="csrf_token", value=<t>, category="csrf",
                  obtained_via="refetch_html", expires_hint="per_request",
                  refresh_spec='{"kind":"refetch_html","url":"/form",
                                 "regex":"csrf\\" value=\\"([^\\"]+)"}')

   만료 시그널 (401/403, 302→/login, `token expired`, `csrf invalid`,
   `rate limit`, `upload not found`) 감지 시 get_secrets → refresh_spec.kind
   분기 → 재획득 → **같은 key** 로 덮어쓰기. 상세 흐름은 Exploit agent 가
   주로 처리. RouteMap 은 form_login session 저장 + 다른 kind 에 대한
   hint 를 남기는 것이 1차 역할.
2. (white-box) list_source_tree → read_source / grep_source on routes/handlers.
3. (black-box) browser_navigate + browser_extract_api_endpoints + browser_get_dom.
4. update_target_profile with framework/server/WAF when identified.
5. add_scan_note("architecture", ...) to share with later agents.

## Output contract
For EACH discovered endpoint:
  push_discovery(parent_node_id=<this target>, node_type="endpoint",
                 endpoint="/path", summary="...",
                 context_json={"methods":[...], "params":[...], "source_hint":"..."})

Push generously — missed endpoint = missed attack path. Skip already-seeded
endpoints (check `previous_scan` in context).

## Done conditions
- All discovered endpoints pushed as children.
- update_node_status(this_target, "explored").

[BUDGET] 신호를 보고 self-pace. 마지막 1턴은 push 정리에 사용.
"""

ENTRYPOINT_PROMPT = """\
You are an EntryPoint agent. Goal: for ONE endpoint, identify input points (sinks)
and push suspected vuln nodes as children.

## Inputs
An endpoint node: endpoint, methods, params, optional source_hint, optional
seeded_from (= previous scan info).

## Method
1. get_chain_context — see how you got here.
2. analyze_endpoint(endpoint, method, params) — vuln_type score map.
3. (optional) read_source / grep_source the handler if source_root available —
   look at sinks (eval/exec/include/sql template/redirect/file write).
4. (optional) recall_dead_ends(host, vuln_type, endpoint) — skip already-failed.
5. send a baseline + a few probe HTTP requests to confirm the surface exists.
   **PREFER `multi_http_probe`** to send baseline + probes in 1 turn (병렬, 토큰 절감).

## Output contract
For EACH suspected vuln_type:
  push_discovery(parent=<this endpoint>, node_type="vuln", vuln_type=TYPE,
                 endpoint="/path",
                 summary="Suspected <TYPE> via <param/sink>",
                 context_json={"sink":"...", "params":{...}, "evidence":"...",
                               "kb_pattern_hints":[<pattern_id>...]})
  create_candidate_manual(...) — also register Candidate.

For EACH new URL/API discovered in HTTP responses (HTML links, JSON hrefs,
redirect Location headers, form actions, JS fetch/axios URLs, Set-Cookie paths):
  push_discovery(parent_node_id=<this endpoint node_id>, node_type="endpoint",
                 endpoint="/new-path",
                 summary="Discovered via <current-endpoint> response",
                 context_json={"discovered_from":"<current-endpoint>",
                               "methods":[...], "source":"response_link"})
  ⚠ parent 는 현재 탐색 중인 너의 node_id — 체인 컨텍스트(세션, 인증, 발견경로)를
  보존하기 위함. 다음 에이전트가 get_chain_context 로 너의 맥락을 물려받는다.
  dedup 이 자동 처리하므로 이미 있는 endpoint 도 안전하게 push 가능.

If clean after inspection → mark_dead_end. If interesting non-vuln signal
(stack trace, internal URL, leaked token) → push "clue" or store_secret.

## API spec KB (record_endpoint_spec — 다음 scan 비용 절감 자산)
endpoint 분석 끝에 권장 호출:
  record_endpoint_spec(target_host="<host>", method="POST", endpoint="/path",
    params_schema='{"email":{"type":"str","in":"body","required":true}}',
    auth_required=true,
    suspected_vuln_types='["sqli","auth_bypass"]',
    sink_hints='["bcrypt_compare","raw_sql_query"]',
    notes="...")
같은 host 재방문 시 RouteMap 이 이걸 recall 해 정찰을 단축. 누적 자산.

## Done conditions
- 1+ vuln/clue child OR mark_dead_end.
- update_node_status(this_endpoint, "explored").
- (권장) record_endpoint_spec — 명세 KB 누적.
"""

HYPOTHESIS_PROMPT = """\
You are a Hypothesis agent. Goal: for ONE vuln_type on one endpoint, narrow the
hypothesis with KB lookup and try the most promising payloads.

## Inputs
A vuln node: endpoint, vuln_type, summary, context (with possible kb_pattern_hints,
prior recheck, sink info).

## Method
1. get_chain_context + get_secrets — load credentials/state from earlier agents.
2. search_knowledge(vuln_type) — load KB techniques. Read attack_metadata.
   technique_steps_md and code_template carefully.
3. retrieve_similar_patterns(query=<natural language sink>) — semantic search.
4. recall_dead_ends — skip patterns that already failed on this host.
5. For top KB patterns (max 3-5):
   - **PREFER `multi_http_probe`** — baseline + N payloads 를 1턴에 동시 발사.
     토큰/시간 ~N배 절감. stateless GET/POST 만. 예:
     `multi_http_probe(requests_json='[{"url":"<base>","method":"GET"},
       {"url":"<base>?id=1","method":"GET"},
       {"url":"<base>?id=1' OR 1=1--","method":"GET"}]')`
   - 단일 http_request 도 한 턴에 여러 개 부르면 자동 병렬 (SAFE_PARALLEL).
   - stateful flow(login chain 등) 는 http_session_request 직렬.
   - oracle_*(...) — verify deterministically.
   - record_pattern_use(pattern_id, succeeded=True/False) — 매 payload 마다.
6. If KB payloads fail but behavior is suspicious: mutate_payload OR craft your
   own based on observed responses.

## Output contract — TIER A (mandatory data finalize)
다음 도구 호출 누락 시 노드/KB 가 stuck/incomplete 상태로 끝남:

- IF confirmed:
  1. confirm_finding(cand_id, severity, title, summary)  ← finding 생성
  2. save_evidence(finding_id, kind, content)            ← TIER A, 증거 첨부
  3. record_pattern_use(pattern_id, succeeded=True)      ← TIER A, KB 학습
  4. learn_from_finding(finding_id, target_host, payload_used, is_novel)  ← Living KB
  5. update_node_status(this_vuln, "confirmed")          ← TIER A, 노드 상태 전이
  6. (optional) push_discovery(node_type="exploit_step") ← chain follow-up
- IF interesting partial signal: push_discovery(node_type="clue") + update_node_status(explored).
- IF all attempts failed:
  1. record_pattern_use(succeeded=False)                 ← TIER A
  2. learn_dead_end(target_host, endpoint, vuln_type, payload_used, reason)  ← TIER A
  3. mark_dead_end(this_vuln, reason)                    ← 노드 상태 전이

⚠️ 안전망: confirm_finding 호출 시 backend 가 candidate→endpoint+vuln_type 매칭으로
연결된 vuln 노드를 자동으로 confirmed 전이. 그러나 save_evidence/
record_pattern_use 누락은 자동 보완 불가 — 너가 명시 호출해야 KB 누적.

## Recursive endpoint discovery
payload 테스트 중 HTTP 응답에서 새 URL/API 를 발견하면 (redirect, error page 의
link, JSON 내 href, stack trace 경로 등) push_discovery(node_type="endpoint",
parent_node_id=<this vuln node_id>, endpoint="/new-path") 로 등록하라.
parent 를 현재 노드로 해야 체인(세션/인증) 맥락이 보존된다.
vuln 테스트가 주 역할이지만 새 attack surface 발견도 자산이다.

자율성: KB 는 권장이지만 source 분석으로 더 좋은 가설이 있으면 그걸 우선해도 OK.
"""

EXPLOIT_PROMPT = """\
You are an Exploit agent. Goal: continue a multi-step attack chain. The parent
already confirmed a vuln; you are at exploit_step depth.

## Inputs
An exploit_step node: parent vuln context, chain history, scan secrets.

## Method
1. get_chain_context — read EVERY ancestor's context, including credentials,
   intermediate values, technique details. Don't skip this.
2. get_secrets — load ALL credentials/tokens/config from shared store.
3. get_scan_notes("architecture") — what does the app look like internally.
4. get_siblings — see other branches; combinable primitives?
5. Plan the next step using primitives you have:
   - SSRF + LFI → read internal files
   - SQLi + file_read → secret → auth bypass
   - HTTP smuggling + SSRF → reach internal services
   - Command injection via custom protocol → RCE
6. Execute the next step (http_session_request to maintain cookies, or curl_request
   for raw protocol). Use mutate_payload for WAF/filter bypass when needed.

## ★ Expirable artifact 재획득 (session / CSRF / JWT / OTP / API key / upload)

만료 시그널: 401/403, 302→/login, `csrf token invalid`, `token expired`,
`rate limit`, `upload not found` 등. 모든 **expirable secret** 은 저장 시
`refresh_spec` (JSON) 을 달아두면 재획득 자동화됨.

### 만료 감지 → 재획득 흐름

1. get_secrets(category=...) → 해당 key 의 metadata / refresh_spec 조회.
2. metadata.refresh_spec.kind 로 분기 (LLM 자율 판단):
   - form_login → auth_<spec.auth_label>_login_url/username/password 회상 →
     http_session_request(POST login_url, form_json={...}) 재로그인.
   - attack_replay → push_discovery(node_type="vuln",
     parent=<spec.source_vuln_node_id>, context={"recheck":True,
     "reason":"secret expired, replay attack",
     "source_secret_key":"<key>"}) → 다음 iteration confirmer 가 chain 재실행.
   - refetch_html → http_session_request(GET spec.url) → 응답에서 spec.regex
     로 새 CSRF/nonce 추출.
   - oauth_refresh → http_session_request(POST spec.token_endpoint,
     form_json={"grant_type":"refresh_token",
     "refresh_token":<get_secrets[spec.refresh_token_key]>}) → access_token 갱신.
   - otp_request / magic_link → spec.request_endpoint 호출 후
     spec.inbox_key/mailbox_key 로 inbox 크롤 → code/link 추출.
   - api_key_reissue → spec.portal_url 로 재발급 (authenticated session 필요
     시 session refresh 먼저 연쇄).
   - reupload → spec.upload_node_id 의 chain 재실행.
   - 기타 / unknown → LLM 판단: 수동 재시도 or mark_dead_end.
3. 갱신한 값은 **같은 key** 로 store_secret 덮어쓰기 (refresh_spec 유지).

### 새 secret 획득 시 refresh_spec 필수

만료 가능 secret 저장 시 반드시 refresh_spec 동반:
  # 공격으로 session
  store_secret(key="admin_session", value=<cookie>, category="session",
    obtained_via="attack", source_vuln_node_id=<this>,
    chain_summary="SQLi auth bypass at /api/login",
    refresh_spec='{"kind":"attack_replay","source_vuln_node_id":"<this>"}')

  # CSRF token
  store_secret(key="csrf_token", value=<t>, category="csrf",
    obtained_via="refetch_html", expires_hint="per_request",
    refresh_spec='{"kind":"refetch_html","url":"/form",
                   "regex":"name=\\"csrf\\" value=\\"([^\\"]+)"}')

  # OAuth access token
  store_secret(key="access_token", value=<jwt>, category="token",
    obtained_via="oauth_refresh", expires_hint="1h",
    refresh_spec='{"kind":"oauth_refresh","token_endpoint":"/oauth/token",
                   "refresh_token_key":"refresh_token"}')

→ 다음 만료 시 어떤 worker 든 refresh_spec 읽고 자동 복구.

## Output contract
Whenever you discover something:
  - credentials/tokens → store_secret IMMEDIATELY (other workers need it).
  - architecture insight → add_scan_note.
  - new attack surface → push_discovery (endpoint/vuln/exploit_step).
  - flag reached → push_discovery(node_type="flag") + create_finding +
    save_evidence + learn_from_finding (is_novel=True if non-trivial chain).

If truly stuck after multiple turns: push remaining leads as child nodes for
other workers, with FULL context_json (exact request that worked, response,
credential used, intermediate value needed for next step).

자율성: chain의 다음 단계는 너의 판단. KB/도구는 신호일 뿐.
"""

CONFIRMER_PROMPT = """\
You are a Confirmer agent. Goal: ratify (or reject) a candidate confirmation
with a stronger oracle and write the verdict to the Living KB.

## Inputs
A flag/confirm node OR a vuln node marked for re-verification (recheck).

## Method
1. get_chain_context — full chain so the verdict has citation context.
2. Re-run the confirming oracle (oracle_*) with a fresh payload — control vs
   payload comparison. Don't accept the candidate's word; verify yourself.
3. If recheck=True (target may have been patched): if oracle now FAILS, this
   is "patched since last scan" — mark_dead_end + push a NEW vuln node to test
   bypass/incomplete-fix variants for the same vuln_type.

## Output contract
- IF verified:
  - confirm_finding(cand_id) + save_evidence + create_finding (if missing)
  - learn_from_finding(is_novel=<bool>, novelty_reason=<text>) — judge novelty.
    True if not commodity (not in default sqlmap/dalfox; not OWASP cheatsheet).
  - update_node_status(this, "confirmed")
- IF rejected (oracle disagrees):
  - dismiss_candidate(cand_id) + learn_dead_end (record what was tried).
  - mark_dead_end on this node.

자율성: novelty 판단은 너의 책임. commodity 페이로드는 KB에 저장 X (자산 가치 0).
"""

CRITIC_PROMPT = """\
You are a pre-exploit Critic (CodeMender 패턴). Goal: BEFORE the Exploit agent
spends turns trying payloads on this exploit_step, predict if the chain is
likely to work.

## Inputs
The exploit_step node + ancestor chain context (parent vuln + grandparent
endpoint + secrets + scan notes).

## Method
1. Read the chain — parent vuln_type, what was confirmed, what credentials/
   tokens are available, what intermediate values exist.
2. Identify hidden prerequisites that may be missing:
   - Required credential not yet stolen?
   - Required side-channel (OOB, timing) not feasible on this host?
   - Required server config (open_basedir, disable_functions) not verified?
   - Required protocol primitive (smuggling, deserialization sink) not present?
3. Identify logic flaws in the chain:
   - Assumption that fails on first request (e.g. expects file X but path is Y)
   - Race condition that needs concurrent requests (chain step is single-threaded)
   - Encoding mismatch (chain expects UTF-8, server returns latin-1)

## Output contract — SINGLE JSON only, no other text
```json
{
  "verdict": "go" | "soft_go" | "no_go",
  "confidence": 0.0-1.0,
  "reason": "한 줄 요약",
  "missing_prereqs": ["필요한데 없는 전제 1", "..."],
  "suggested_alternative": "no_go 면 다른 접근 방향 한 줄 (없으면 빈 문자열)"
}
```

verdict 의미:
- `go`     — chain 합리적, exploit 시도해라.
- `soft_go` — 일부 우려 있으나 시도 가치 있음. exploit agent가 우려 보고 진행.
- `no_go`  — chain에 명백한 결함. exploit 시도 비용 낭비.

자율성: critic 의 verdict 는 advisory. exploit agent 는 너의 verdict 를 보고
자기가 다시 판단할 자유가 있다 — 너의 일은 *신호 제공* 이지 *결정* 이 아니다.
KB/도구 호출은 최소화. 빠르고 싸게 (~5초, ~$0.01) 끝내라.
"""


# 공통 strategy + critical rules는 각 sub-prompt에 자동으로 prepend된다 (_run_role_phase
# 호출 시 system_prompt = MLLA_COMMON_PROMPT + sub_prompt).
# EXPLORER_PROMPT의 "Chain Exploitation Strategy", "KB Usage Pattern", "Critical Rules"
# 절을 그대로 활용.
MLLA_COMMON_PROMPT = """\
You are a sub-agent in the Watchdog discovery swarm (MLLA decomposition).
Other sub-agents work in parallel on sibling/cousin nodes — collaborate via
shared state (store_secret, add_scan_note, push_discovery).

## Cross-cutting rules
- Always call get_chain_context first to know how you got here.
- Always call get_siblings to avoid duplicate exploration.
- TIER A (mandatory data): R7 (record_trace tool_calls), R10 (record_pattern_use
  every payload), R8/R9 (push + analyze + finding chain). 빠지면 다음 스캔 학습 0.
- TIER B (advisory): scan_next/validate_node/scan_selfcheck는 진단 신호. 무시 가능
  하지만 selfcheck warnings로 누적되어 보고서에 노출.
- When [BUDGET] shows <= 3 remaining, stop exploring and finalize: push remaining
  leads as nodes (with FULL context_json), or mark_dead_end if truly nothing.

## Cross-node knowledge sharing (★ 중요)
다른 브랜치의 에이전트가 이미 유용한 것을 발견했을 수 있다.
탐색 시작 시 반드시:
1. get_secrets() — 다른 워커가 저장한 세션 쿠키, admin 토큰, API 키, 크레덴셜 확인.
2. get_scan_notes("architecture") — 앱 구조, 프레임워크, 인증 방식 등 정보 확인.
3. get_siblings() — 형제 노드의 상태와 발견 요약 확인.

### 발견 공유 규칙
- 세션/토큰/크레덴셜 → store_secret(key="admin_session", value=..., category="credential")
  즉시 저장. 다른 워커가 같은 세션을 바로 사용할 수 있다.
- 아키텍처 발견 → add_scan_note("architecture", "Express.js + MongoDB, JWT auth, ...")
- 비즈니스 로직/레이스 컨디션 단서 → push_discovery(node_type="clue") + context_json에 상세 기록.
- 복합 공격 프리미티브 → store_secret(key="ssrf_internal_<endpoint>", value=..., category="primitive")
  핸드오프 키 네이밍: category는 "credential" | "primitive" | "csrf_token" | "session",
  key 형식은 "<type>_<context>" (예: "admin_jwt", "ssrf_internal_metadata",
  "csrf_token_/transfer", "race_coupon_apply").

### 세션/토큰 유효성 검증
다른 워커의 세션을 재사용할 때는 먼저 간단한 요청으로 유효성을 확인할 것.
만료되었다면:
1. 원래 세션을 얻은 경로를 get_scan_notes 에서 찾아 재획득 시도.
2. 재획득 성공 시 store_secret 으로 갱신 (같은 key에 덮어쓰기).
3. 재획득 실패 시 add_scan_note("stale_secret", "key=admin_session, expired at ...") 기록.

### CSRF 토큰 공유
- CSRF 토큰 발견 시 store_secret(key="csrf_token_<endpoint>", value=..., category="csrf_token").
- CSRF 토큰은 자주 갱신됨. 사용 직전에 get_secrets 로 최신 값을 가져올 것.
- 토큰이 만료/거부되면 해당 endpoint 에 GET 요청해서 새 토큰을 추출, store_secret 갱신.

### Race condition 조율
race condition 공격이 필요한 경우:
1. push_discovery(node_type="clue", summary="Race condition target",
   context_json={"race_endpoints": ["/apply-coupon", "/checkout"],
   "race_method": "POST", "race_body": {...}, "timing_window_ms": 100})
2. 실제 race condition 테스트: multi_http_probe 로 동일 요청을 concurrent 실행.
3. 결과를 add_scan_note("race_result", "...") 로 공유.

### 충돌 정책 (다른 브랜치에서 모순된 정보)
- 세션/토큰이 여러 개 있으면 → 모두 시도, 작동하는 것 사용.
- 아키텍처 노트가 모순되면 → 최신 타임스탬프 우선, 직접 확인 후 판단.
- 판단 불가하면 → 너의 endpoint에서 직접 테스트해서 확인.

### 활용 시나리오 (유연하게 적용)
- 다른 브랜치에서 admin 세션이 발견되었다 → 너의 endpoint에서 admin 권한으로 테스트 가능.
- 다른 endpoint에서 IDOR 패턴이 확인되었다 → 같은 패턴을 너의 endpoint에도 적용.
- SSRF primitive 발견 → store_secret 확인 후 internal endpoint 접근에 활용.
- 레이스 컨디션: 다른 브랜치의 쿠폰 적용 + 너의 결제 요청을 동시에 → push clue with combined context.
- 비즈니스 로직: 회원가입 → 인증 바이패스 → 관리자 기능 접근 체인을 조합.
- privilege escalation: 일반 유저 세션 + admin endpoint 발견 → 권한 상승 시도.
핵심: 위 시나리오는 예시일 뿐. 상황에 맞게 자유롭게 조합하고 창의적으로 활용할 것.

## Recursive endpoint discovery (all agents)
HTTP 응답 (HTML, JSON, redirect, header) 에서 아직 트리에 없는 새 URL/API 를
발견하면 push_discovery(node_type="endpoint", parent_node_id=<your node_id>,
endpoint="/new-path", summary="Discovered via /current-path response") 로 등록하라.
⚠ parent 는 **현재 탐색 중인 너의 node_id** — 이래야 get_chain_context 로
조상의 세션/인증/발견 맥락이 체인으로 보존된다.
(예: register → login → dashboard 체인이면 dashboard 에이전트가 login 의 쿠키를
get_secrets 로 물려받을 수 있다.)
push_discovery dedup 이 중복을 자동 처리하므로 이미 있는 endpoint 를 push 해도 안전하다.
새 endpoint 를 놓치면 = 공격 경로 누락. 적극적으로 push 할 것.

자율성 우선: 도구는 신호 제공, 의사결정은 너.
"""

MLLA_PROMPT_BY_NODE = {
    "target": MLLA_COMMON_PROMPT + "\n\n" + ROUTEMAP_PROMPT,
    "endpoint": MLLA_COMMON_PROMPT + "\n\n" + ENTRYPOINT_PROMPT,
    "vuln": MLLA_COMMON_PROMPT + "\n\n" + HYPOTHESIS_PROMPT,
    "exploit_step": MLLA_COMMON_PROMPT + "\n\n" + EXPLOIT_PROMPT,
    "flag": MLLA_COMMON_PROMPT + "\n\n" + CONFIRMER_PROMPT,
    "clue": MLLA_COMMON_PROMPT + "\n\n" + ENTRYPOINT_PROMPT,  # 단서도 입력점 분석 성격
}

MLLA_ROLE_BY_NODE = {
    "target": "routemap",
    "endpoint": "entrypoint",
    "vuln": "hypothesis",
    "exploit_step": "exploit",
    "flag": "confirmer",
    "clue": "entrypoint",
}


def _select_mlla_prompt(node) -> tuple[str, str]:
    """노드 타입 → (sub-agent role 이름, prompt). 알 수 없는 타입은 통합 EXPLORER_PROMPT fallback."""
    ntype = node.node_type
    # recheck 모드는 confirmer 역할로 처리
    if (node.context or {}).get("recheck"):
        return "confirmer", MLLA_COMMON_PROMPT + "\n\n" + CONFIRMER_PROMPT
    role = MLLA_ROLE_BY_NODE.get(ntype, "explorer")
    prompt = MLLA_PROMPT_BY_NODE.get(ntype, EXPLORER_PROMPT)
    return role, prompt


EXPLORER_TOOLS = {
    # Discovery-specific
    "push_discovery", "get_chain_context", "mark_dead_end", "get_siblings",
    "get_exploit_chains",
    # Shared state (cross-worker)
    "store_secret", "get_secrets", "add_scan_note", "get_scan_notes",
    # HTTP
    "http_request", "http_session_request", "http_session_cookies",
    "http_session_close", "curl_request", "multi_http_probe",
    # Scanners
    "sqlmap_scan", "dalfox_scan", "nuclei_scan", "ffuf_scan",
    "nikto_scan", "wafw00f_scan", "whatweb_scan",
    # Browser
    "browser_navigate", "browser_get_dom", "browser_extract_api_endpoints",
    "browser_get_network_log", "browser_screenshot", "browser_set_user_agent",
    # Analysis
    "analyze_endpoint", "list_candidates", "get_scan_summary",
    # Source
    "list_source_tree", "read_source", "grep_source",
    # KB
    "search_knowledge", "retrieve_similar_patterns", "retrieve_cve_variants",
    "fetch_cve_details", "suggest_cves_for_framework",
    "record_pattern_use", "mutate_payload", "check_payload_dedup",
    # Oracles
    "oracle_xss", "oracle_sqli_boolean", "oracle_sqli_time",
    "oracle_lfi", "oracle_ssrf", "oracle_response_diff",
    # Evidence & Findings
    "save_evidence", "auto_collect_evidence", "create_candidate_manual",
    "confirm_finding", "dismiss_candidate", "reopen_candidate",
    # Living KB
    "recall_target", "recall_dead_ends", "learn_from_finding",
    "learn_dead_end", "update_target_profile",
    "record_endpoint_spec", "recall_endpoint_specs",
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


async def _evaluate_chain_critic(
    scan_run: ScanRun,
    anthropic,
    node,
    acc: _Accumulator,
) -> dict:
    """exploit_step 노드 진행 전 critic LLM 1회 호출 — go/soft_go/no_go 판단.

    advisory 신호 — 호출자(_explorer_worker)는 verdict를 EXPLOIT user_msg context로
    그대로 전달하고, exploit agent가 무시 가능. 강제 abort 안 함.
    오류 / 파싱 실패 시 abstain으로 fallback해 chain 진행 막지 않는다.
    """
    chain_summary = (
        f"node_id: {node.node_id}\n"
        f"node_type: {node.node_type}\n"
        f"depth: {node.depth}\n"
        f"endpoint: {node.endpoint or 'N/A'}\n"
        f"vuln_type: {node.vuln_type or 'N/A'}\n"
        f"summary: {node.summary}\n"
        f"context: {json.dumps(node.context, ensure_ascii=False)[:1500]}"
    )
    user_msg = (
        f"target_url: {scan_run.target_url}\n\n"
        f"## Exploit step to be tried\n{chain_summary}\n\n"
        f"평가 후 SINGLE JSON 한 개만 출력. 도구 호출은 최소 (필요 시 get_chain_context, "
        f"get_secrets 만)."
    )
    try:
        text, _ = await _run_role_phase(
            scan_run, anthropic, "critic:pre-exploit", CRITIC_PROMPT,
            tools=[], tool_router={},  # tool 호출 없이 평가만
            initial_user_message=user_msg, acc=acc,
            max_turns=DISCOVERY_CRITIC_BUDGET,
        )
    except Exception as e:
        logger.warning(
            f"[{scan_run.run_id}] critic error on node {node.node_id}: {e}"
        )
        return {"verdict": "abstain", "reason": f"critic call failed: {e}",
                "missing_prereqs": [], "suggested_alternative": ""}

    data = _extract_json_block(text) or {}
    if "verdict" not in data:
        data["verdict"] = "abstain"
    if "reason" not in data:
        data["reason"] = "critic returned no parseable verdict"
    return data


async def _explorer_worker(
    name: str,
    scan_run: ScanRun,
    anthropic,
    tools: list,
    tool_router: dict,
    acc: _Accumulator,
    last_activity_ref: list,
    done_event: asyncio.Event,
    root_node_id: str = "",
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

        shared_state_hint = (
            "\n## Shared State (cross-node collaboration)\n"
            "Other workers explore in parallel. Before starting:\n"
            "  get_secrets() → check for sessions, tokens, creds from other branches.\n"
            "  get_scan_notes('architecture') → check app structure, auth patterns.\n"
            "If YOU discover credentials/tokens/sessions, call store_secret immediately\n"
            "so other workers can use them.\n"
        )

        user_msg = (
            f"target_url: {scan_run.target_url}\n"
            f"scan_run_id: {scan_run.run_id}\n"
            f"root_target_node_id: {root_node_id}\n"
            f"{source_hint}{shared_state_hint}\n"
            f"## Your Node\n"
            f"- node_id: {node.node_id}\n"
            f"- node_type: {node.node_type}\n"
            f"- depth: {node.depth}\n"
            f"- endpoint: {node.endpoint or 'N/A'}\n"
            f"- vuln_type: {node.vuln_type or 'N/A'}\n"
            f"- summary: {node.summary}\n"
            f"- context: {json.dumps(node.context, ensure_ascii=False)[:800]}\n\n"
            f"Start by calling get_chain_context(node_id=\"{node.node_id}\"), "
            f"get_siblings(node_id=\"{node.node_id}\"), and get_secrets(). "
            f"Check what other workers have already discovered, then explore this node.\n"
            f"Push child discoveries for anything interesting. "
            f"Mark dead_end if nothing found."
        )

        # MLLA — node_type 별 sub-agent prompt 선택. role 이름도 sub-agent로 변경하면
        # log/trace 분석 시 어느 단계가 비용/시간을 많이 쓰는지 즉시 보임.
        sub_role, sub_prompt = _select_mlla_prompt(node)

        # Pre-exploit critic (CodeMender 패턴) — exploit_step 노드 진행 전 1회 평가.
        # advisory: verdict 를 user_msg context에 주입; exploit agent 가 보고 판단.
        # 강제 abort 안 함 (자율성 우선). flag 노드는 confirmer가 직접 oracle 검증하므로 critic 생략.
        if (
            DISCOVERY_CRITIC_ENABLED
            and sub_role == "exploit"
            and not (node.context or {}).get("recheck")
        ):
            critic_result = await _evaluate_chain_critic(scan_run, anthropic, node, acc)
            verdict = critic_result.get("verdict", "abstain")
            logger.info(
                f"[{scan_run.run_id}] critic verdict={verdict} on node "
                f"{node.node_id} reason={(critic_result.get('reason') or '')[:120]}"
            )
            user_msg += (
                f"\n\n## Pre-Exploit Critic (advisory — 무시해도 OK, 단 [BUDGET] 신호처럼 활용)\n"
                f"```json\n{json.dumps(critic_result, ensure_ascii=False)[:1500]}\n```\n"
                f"verdict='no_go' 이면 비용 낭비 위험 — chain 결함을 먼저 점검 후 시도. "
                f"verdict='soft_go' 이면 missing_prereqs 를 먼저 채울지 검토. "
                f"verdict='go' 이면 그대로 진행."
            )

        is_recheck = (node.context or {}).get("recheck", False)
        if is_recheck:
            budget = DISCOVERY_RECHECK_BUDGET
        elif sub_role == "confirmer":
            budget = DISCOVERY_RECHECK_BUDGET
        elif sub_role in ("exploit", "hypothesis"):
            budget = DISCOVERY_EXPLOIT_BUDGET
        elif sub_role == "entrypoint" and node.node_type == "clue":
            budget = DISCOVERY_CLUE_BUDGET
        else:
            budget = DISCOVERY_WORKER_BUDGET  # routemap, entrypoint(endpoint)

        # C: LLM call 직전에도 last_activity 갱신. _run_role_phase 가 길게 (수 분)
        # 돌면 그 사이 quiescence 오판정 위험 — worker 가 "활동 중"임을 명시.
        last_activity_ref[0] = _t.time()
        try:
            await _run_role_phase(
                scan_run, anthropic, f"{sub_role}:{name}", sub_prompt,
                tools, tool_router, user_msg, acc,
                max_turns=budget,
                current_node_id=str(node.node_id),
            )
        except Exception as e:
            logger.error(
                f"[{scan_run.run_id}] {sub_role}[{name}] error on node "
                f"{node.node_id}: {e}", exc_info=True,
            )
        last_activity_ref[0] = _t.time()  # LLM call 직후도 갱신

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

        # _finalize_node: sub-agent 가 finalize 누락 시 안전망 —
        # vuln/exploit_step 은 자동 dead_end + learn_dead_end, 그 외 explored.
        final_status = await sync_to_async(
            lambda: _finalize_node(node, scan_run)
        )()
        if final_status == "dead_end":
            logger.info(
                f"[{scan_run.run_id}] explorer[{name}] node {node.node_id} "
                f"auto-finalized as dead_end (sub-agent unfinalized safety-net)"
            )
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
    """Legacy thin wrapper — 새 코드는 _finalize_node 사용."""
    from api.models import DiscoveryNode
    DiscoveryNode.objects.filter(
        node_id=node.node_id, status="exploring",
    ).update(status="explored", explored_at=timezone.now())


def _finalize_node(node, scan_run) -> str:
    """Sub-agent 종료 시 노드 status 전이 + 실패 누적 안전망.

    LLM sub-agent 가 TIER A finalize 를 빠뜨리면 KB 학습 0 → 다음 scan 이
    같은 시도 반복. 안전망:
      - vuln / exploit_step 이 아직 exploring 이면 → dead_end + learn_dead_end
        (payload_used="", reason="sub-agent unfinalized")
      - 다른 타입 (target/endpoint/clue/flag) 은 기존 explored 전이

    LLM 이 이미 confirmed / dead_end / explored 로 마무리했으면 skip.
    자율성 원칙: 이건 강제 게이트가 아니라 데이터 손실 방지 안전망.

    Returns: 최종 status 문자열 (explored / dead_end / 기존 confirmed / 기존 dead_end).
    """
    from urllib.parse import urlparse
    from api.models import DiscoveryNode

    node.refresh_from_db()
    if node.status in ("confirmed", "dead_end", "explored"):
        return node.status  # 이미 finalized

    now = timezone.now()
    ntype = node.node_type

    if ntype in ("vuln", "exploit_step") and node.endpoint and node.vuln_type:
        # 안전망: 자동 learn_dead_end + dead_end 전이
        try:
            parsed = urlparse(scan_run.target_url or "")
            host = (parsed.netloc or parsed.hostname or "").lower()
            if host:
                from watchdog_mcp.tools_learn import _learn_dead_end
                _learn_dead_end(
                    target_host=host,
                    endpoint=node.endpoint,
                    vuln_type=node.vuln_type,
                    pattern_id="",
                    payload_used="",
                    reason=f"sub-agent unfinalized — {ntype} node left exploring",
                )
                logger.info(
                    f"[{scan_run.run_id}] _finalize_node safety-net: "
                    f"auto learn_dead_end for {ntype} {node.endpoint} ({node.vuln_type})"
                )
        except Exception as e:
            logger.warning(f"[{scan_run.run_id}] _finalize_node learn_dead_end failed: {e}")

        updated = DiscoveryNode.objects.filter(
            node_id=node.node_id, status="exploring",
        ).update(status="dead_end", explored_at=now)
        return "dead_end" if updated else node.status

    # 다른 타입: 기존 explored 전이
    updated = DiscoveryNode.objects.filter(
        node_id=node.node_id, status="exploring",
    ).update(status="explored", explored_at=now)
    return "explored" if updated else node.status


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


def _seed_credentials(scan_run, cred_list: list) -> list:
    """사용자 제공 credentials (여러 persona) 를 ScanRun.config["_secrets"] 에 저장.

    각 credential 의 'label' 로 key prefix → multi-persona (admin/user1/api 등)
    동시 보관. label 미지정 시 'user1', 'user2', ... 자동.

    secret key 형식: auth_<label>_<field>
      예) auth_admin_type, auth_admin_login_url, auth_admin_username,
          auth_admin_password, auth_admin_username_field, ...

    Returns: [{"label": "admin", "type": "form"}, ...]  — root context 노출용 요약
    """
    import json as _json
    import re as _re
    from django.utils import timezone

    config = scan_run.config or {}
    secrets = dict(config.get("_secrets") or {})
    now = str(timezone.now())
    used_labels = set()
    personas = []

    def _make_label(c: dict, idx: int) -> str:
        lbl = (c.get("label") or "").strip()
        if not lbl:
            lbl = f"user{idx + 1}"
        # secret key 안전화 — 영숫자/언더스코어만
        lbl = _re.sub(r"[^a-zA-Z0-9_]", "_", lbl).strip("_") or f"user{idx + 1}"
        # dedup
        base = lbl
        i = 2
        while lbl in used_labels:
            lbl = f"{base}_{i}"; i += 1
        used_labels.add(lbl)
        return lbl

    for idx, creds in enumerate(cred_list):
        ctype = (creds.get("type") or "").strip().lower()
        if ctype not in ("form", "bearer", "cookie", "basic"):
            logger.warning(f"[{scan_run.run_id}] unknown credential type: {ctype}, skip")
            continue
        label = _make_label(creds, idx)
        prefix = f"auth_{label}_"

        def _put(field: str, value, category: str = "credential") -> None:
            secrets[prefix + field] = {
                "value": value if isinstance(value, str) else _json.dumps(value, ensure_ascii=False),
                "category": category,
                "stored_at": now,
                "source": "user_provided",
                "persona_label": label,
                "persona_type": ctype,
            }

        _put("type", ctype, category="config")
        if ctype == "form":
            if creds.get("login_url"): _put("login_url", creds["login_url"], category="config")
            if creds.get("username"):  _put("username", creds["username"])
            if creds.get("password"):  _put("password", creds["password"])
            if creds.get("username_field"): _put("username_field", creds["username_field"], category="config")
            if creds.get("password_field"): _put("password_field", creds["password_field"], category="config")
        elif ctype == "bearer":
            if creds.get("token"): _put("bearer_token", creds["token"])
        elif ctype == "cookie":
            if creds.get("cookies"): _put("cookies", creds["cookies"])
        elif ctype == "basic":
            if creds.get("username"): _put("username", creds["username"])
            if creds.get("password"): _put("password", creds["password"])

        personas.append({"label": label, "type": ctype})

    config["_secrets"] = secrets
    scan_run.config = config
    scan_run.save(update_fields=["config"])
    return personas


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


def _normalize_endpoint_for_dedup(ep: str, target_url: str = "") -> str:
    """Delegate to the shared _normalize_ep in tools_discovery for consistent behavior."""
    from watchdog_mcp.tools_discovery import _normalize_ep
    return _normalize_ep(ep, target_url)


def _gather_previous_knowledge(
    target_url: str,
    current_run_id: str,
    resume_from: str = "",
) -> dict | None:
    """Find a previous scan and extract useful nodes for cold-start avoidance.

    resume_from:
      - "off"        → 자동 resume 끔. None 반환 (신규 cold scan).
      - "<run_id>"   → 그 특정 scan 에서 가져옴 (target 일치 무관).
      - 미지정/"auto"→ 같은 target_url 의 최근 finished/failed scan 자동 탐지 (기본).
    """
    from api.models import DiscoveryNode

    rf = (resume_from or "").strip().lower()
    if rf == "off":
        return None

    prev_run = None
    if resume_from and rf not in ("", "auto"):
        prev_run = ScanRun.objects.filter(run_id=resume_from).exclude(run_id=current_run_id).first()
        if not prev_run:
            return None
    else:
        normalized = _normalize_target_url(target_url)
        recent = (
            ScanRun.objects
            .filter(status__in=["finished", "failed"])
            .exclude(run_id=current_run_id)
            .order_by("-created_at")[:10]
        )
        for run in recent:
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

    # dedup: (normalized_endpoint, vuln_type, node_type_bucket) 기준으로 첫 번째만 수집.
    # 이전 scan 에서 같은 endpoint 노드가 여러 개 있었던 경우 중복 전파 방지.
    _seen_keys: set[tuple[str, str, str]] = set()

    for node in prev_nodes:
        raw_ep = node.endpoint or ""
        ep_norm = _normalize_endpoint_for_dedup(raw_ep, target_url)
        vt = node.vuln_type or ""

        # status=dead_end 가 type 보다 우선
        if node.status == "dead_end" or node.node_type == "dead_end":
            bucket = "dead_end"
        elif node.node_type == "endpoint":
            bucket = "endpoint"
        elif node.node_type == "vuln":
            bucket = "vuln"
        elif node.node_type in ("clue", "exploit_step"):
            bucket = node.node_type
        else:
            continue

        dedup_key = (ep_norm, vt, bucket)
        if ep_norm != "/" and dedup_key in _seen_keys:
            continue
        _seen_keys.add(dedup_key)

        entry = {
            "node_type": node.node_type,
            "endpoint": raw_ep,
            "vuln_type": vt,
            "summary": node.summary[:300],
            "status": node.status,
            "depth": node.depth,
        }
        if bucket == "dead_end":
            dead_ends.append(entry)
        elif bucket == "endpoint":
            endpoints.append(entry)
        elif bucket == "vuln":
            vulns.append(entry)
        else:
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

def _seed_from_previous(scan_run, root_node, prev_knowledge: dict) -> dict:
    """Seed endpoint + re-verify + dead_end + clue nodes from previous scan results.

    Returns: {"endpoints": N, "vulns": N, "dead_ends": N, "clues": N, "total": N}
    """
    from api.models import DiscoveryNode
    from watchdog_mcp.tools_discovery import DISCOVERY_MAX_NODES

    seed_cap = int(DISCOVERY_MAX_NODES * SEED_BUDGET_RATIO)
    counts = {"endpoints": 0, "vulns": 0, "dead_ends": 0, "clues": 0}
    endpoint_node_map: dict[str, DiscoveryNode] = {}
    prev_run_id = prev_knowledge.get("prev_run_id", "")

    # dedup within seeding: (normalized_endpoint, vuln_type, node_type) → skip
    _seeded_keys: set[tuple[str, str, str]] = set()

    def _seeded_total() -> int:
        return sum(counts.values())

    _target_url = scan_run.target_url or ""

    def _check_seeded(ep: str, vt: str, ntype: str) -> bool:
        """Return True if this (ep, vt, ntype) was already seeded → skip."""
        key = (_normalize_endpoint_for_dedup(ep, _target_url), vt, ntype)
        if key in _seeded_keys:
            return True
        _seeded_keys.add(key)
        return False

    def _find_parent_for_ep(ep: str) -> DiscoveryNode:
        """Lookup seeded endpoint parent by normalized path; fallback to root."""
        norm = _normalize_endpoint_for_dedup(ep, _target_url)
        return endpoint_node_map.get(norm, root_node)

    # 1) endpoint nodes — pending 으로 push (worker 가 다시 탐색 + 새 vuln 발견 가능)
    for ep in prev_knowledge.get("endpoints", []):
        if _seeded_total() >= seed_cap:
            break
        raw_ep = ep.get("endpoint", "")
        if not raw_ep:
            continue
        if _check_seeded(raw_ep, "", "endpoint"):
            continue
        ep_node = DiscoveryNode.objects.create(
            scan_run=scan_run,
            parent=root_node,
            depth=1,
            node_type="endpoint",
            endpoint=raw_ep,
            vuln_type="",
            summary=f"[seeded] {ep['summary'][:200]}",
            context={
                "seeded_from": prev_run_id,
                "prev_status": ep.get("status", ""),
            },
            status="pending",
        )
        ep_norm = _normalize_endpoint_for_dedup(raw_ep, _target_url)
        endpoint_node_map[ep_norm] = ep_node
        counts["endpoints"] += 1

    # 2) vuln nodes — explored/confirmed 만 recheck=True 로 push (패치 여부 확인)
    for vuln in prev_knowledge.get("vulns", []):
        if _seeded_total() >= seed_cap:
            break
        if vuln.get("status") not in ("explored", "confirmed"):
            continue
        raw_ep = vuln.get("endpoint", "")
        vt = vuln.get("vuln_type", "")
        if _check_seeded(raw_ep, vt, "vuln"):
            continue
        parent = _find_parent_for_ep(raw_ep)
        DiscoveryNode.objects.create(
            scan_run=scan_run,
            parent=parent,
            depth=parent.depth + 1,
            node_type="vuln",
            endpoint=raw_ep,
            vuln_type=vt,
            summary=f"[re-verify] {vuln['summary'][:200]}",
            context={
                "seeded_from": prev_run_id,
                "recheck": True,
                "prev_status": vuln.get("status", ""),
                "action": "re-verify this vuln — it was successful before but may be patched now",
            },
            status="pending",
        )
        counts["vulns"] += 1

    # 3) dead_end nodes — status=dead_end 로 직접 push.
    from django.utils import timezone as _tz
    for de in prev_knowledge.get("dead_ends", []):
        if _seeded_total() >= seed_cap:
            break
        raw_ep = de.get("endpoint", "")
        if not raw_ep:
            continue
        vt = de.get("vuln_type", "")
        if _check_seeded(raw_ep, vt, "dead_end"):
            continue
        parent = _find_parent_for_ep(raw_ep)
        DiscoveryNode.objects.create(
            scan_run=scan_run,
            parent=parent,
            depth=parent.depth + 1,
            node_type="vuln",
            endpoint=raw_ep,
            vuln_type=vt,
            summary=f"[prev dead_end] {de['summary'][:200]}",
            context={
                "seeded_from": prev_run_id,
                "prev_dead_end": True,
                "skip_reason": de.get("summary", "")[:300],
            },
            status="dead_end",
            explored_at=_tz.now(),
        )
        counts["dead_ends"] += 1

    # 4) clue / exploit_step — 부분 chain 정보 보존.
    for cl in prev_knowledge.get("clues", []):
        if _seeded_total() >= seed_cap:
            break
        raw_ep = cl.get("endpoint", "")
        nt = cl.get("node_type") or "clue"
        if nt not in ("clue", "exploit_step"):
            continue
        vt = cl.get("vuln_type", "")
        if _check_seeded(raw_ep, vt, nt):
            continue
        parent = _find_parent_for_ep(raw_ep)
        DiscoveryNode.objects.create(
            scan_run=scan_run,
            parent=parent,
            depth=parent.depth + 1,
            node_type=nt,
            endpoint=raw_ep,
            vuln_type=vt,
            summary=f"[prev {nt}] {cl['summary'][:200]}",
            context={
                "seeded_from": prev_run_id,
                "prev_status": cl.get("status", ""),
            },
            status="pending",
        )
        counts["clues"] += 1

    counts["total"] = _seeded_total()
    return counts


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

    bb_ua = _build_bug_bounty_ua(scan_run)
    if bb_ua:
        root_context["bug_bounty_ua"] = bb_ua

    # 사용자 제공 credentials 자동 처리 — list 또는 single dict 둘 다 지원.
    # _seed_credentials 가 ScanRun.config["_secrets"] 에 label prefix 로 박음.
    raw_creds = scan_config.get("credentials")
    cred_list = []
    if isinstance(raw_creds, dict) and raw_creds.get("type"):
        cred_list = [raw_creds]  # legacy single dict
    elif isinstance(raw_creds, list):
        cred_list = [c for c in raw_creds if isinstance(c, dict) and c.get("type")]

    if cred_list:
        personas = await sync_to_async(_seed_credentials)(scan_run, cred_list)
        if personas:
            root_context["credentials_available"] = {
                "personas": personas,  # [{label, type}, ...]
                "note": (
                    "User-provided credentials stored via get_secrets() — keys are "
                    "auth_<label>_<field>. For each persona: type=form → "
                    "http_session_request login (session_id='<scan>-auth-<label>'); "
                    "bearer/cookie/basic → attach headers. ⚠ login endpoint 자체도 "
                    "attack 대상 (sqli/auth_bypass), credential 은 정찰 보조일 뿐."
                ),
            }
            logger.info(
                f"[{scan_run.run_id}] user credentials loaded: {len(personas)} persona(s) — "
                + ", ".join(f"{p['label']}({p['type']})" for p in personas)
            )

    resume_from = (scan_config.get("resume_from") or "").strip()
    prev_knowledge = await sync_to_async(_gather_previous_knowledge)(
        scan_run.target_url, str(scan_run.run_id), resume_from,
    )
    if prev_knowledge:
        # B: root context 에는 요약만 박는다 — 매 worker user_msg 의 node.context json
        # 800자에 prev 풀 데이터가 들어가 정작 노드 정보가 잘리는 문제 방지.
        # 풀 데이터는 _seed_from_previous 가 트리에 노드로 직접 박으므로 worker 가
        # get_chain_context / 노드 자체로 접근 가능.
        root_context["previous_scan"] = {
            "prev_run_id": prev_knowledge.get("prev_run_id", ""),
            "summary": {
                "endpoints": len(prev_knowledge.get("endpoints", [])),
                "vulns_to_recheck": len(prev_knowledge.get("vulns", [])),
                "dead_ends": len(prev_knowledge.get("dead_ends", [])),
                "clues": len(prev_knowledge.get("clues", [])),
            },
            "note": "Full data already seeded as child nodes. Use get_siblings or browse tree.",
        }
        logger.info(
            f"[{scan_run.run_id}] seeded with previous knowledge "
            f"(resume_from={resume_from or 'auto'}): "
            f"prev_run={prev_knowledge.get('prev_run_id')} "
            f"endpoints={len(prev_knowledge.get('endpoints', []))} "
            f"vulns={len(prev_knowledge.get('vulns', []))} "
            f"dead_ends={len(prev_knowledge.get('dead_ends', []))} "
            f"clues={len(prev_knowledge.get('clues', []))}"
        )
    elif resume_from.lower() == "off":
        logger.info(f"[{scan_run.run_id}] resume_from=off → cold scan (no prev seeding)")

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

    # Store root_node_id in config so _auto_push_discovered_links can access it
    cfg = dict(scan_run.config or {})
    cfg["_root_node_id"] = str(root_node.node_id)
    scan_run.config = cfg
    await sync_to_async(scan_run.save)(update_fields=["config"])

    seeded = {"total": 0}
    if prev_knowledge:
        seeded = await sync_to_async(_seed_from_previous)(
            scan_run, root_node, prev_knowledge,
        )

    logger.info(
        f"[{scan_run.run_id}] root node created: {root_node.node_id}, seeded "
        f"total={seeded.get('total', 0)} "
        f"endpoints={seeded.get('endpoints', 0)} vulns={seeded.get('vulns', 0)} "
        f"dead_ends={seeded.get('dead_ends', 0)} clues={seeded.get('clues', 0)}"
    )

    done_event = asyncio.Event()
    last_activity = [_t.time()]

    workers = [
        asyncio.create_task(
            _explorer_worker(
                f"W{i+1}", scan_run, anthropic, explorer_tools, tool_router,
                acc, last_activity, done_event,
                root_node_id=str(root_node.node_id),
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
