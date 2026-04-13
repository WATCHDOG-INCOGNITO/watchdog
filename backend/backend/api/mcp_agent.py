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
    "planner": 14,    # 정찰 + 가설. Planner는 짧게.
    "executor": 18,   # hypothesis당 2~3턴 × 4~6개 + emit. 너무 길면 안전망 트리거.
    "verifier": 18,   # oracle 호출 + 판정.
    "reporter": 4,    # 단순 generate_report.
}
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
3. **공격 전에 반드시 `search_knowledge(vuln_type=...)`를 호출**해 CWE/OWASP 맥락과 검증된 페이로드 패턴(request_template, matcher, safety_level)을 먼저 가져오세요. 가능하면 `is_gold` 또는 `success_rate`가 높은 패턴을 우선 사용합니다.
4. 필요하면 `retrieve_similar_patterns(query=...)`로 엔드포인트 설명/파라미터명과 의미적으로 가까운 패턴을 추가 조회하세요.
5. 패턴의 `safety_level`이 "destructive"이면 사용 금지. "cautious"는 저빈도로만 사용하세요.
6. 페이로드를 `http_request`로 전송하거나, 적절한 보안 도구(`sqlmap_scan`, `dalfox_scan`, `nuclei_scan` 등)를 실행하세요.
7. 시도한 각 패턴에 대해 `record_pattern_use(pattern_id=..., succeeded=..., false_positive=...)`를 호출해 Knowledge DB의 success_rate를 업데이트하세요.
8. 취약점이 확인되면 `confirm_finding`으로 Finding을 생성하고, `auto_collect_evidence`로 증거를 수집하세요.
9. 모든 분석이 완료되면 `generate_report`로 리포트를 생성하세요.

## Knowledge DB 활용
- `search_knowledge`는 vuln_type/keyword 기준 lookup (정확 매칭).
- `retrieve_similar_patterns`는 자연어 query 기준 semantic search (Voyage 임베딩, 사용 가능한 경우).
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
당신은 보안 스캐너의 Planner 에이전트입니다. 임무는 정찰과 가설 수립이며,
실제 공격과 판정은 Executor/Verifier가 합니다. 도구 선택과 호출 횟수는 모두 당신 자율.

## 무기고 (필요한 것만)
- 정찰: browser_navigate, browser_extract_api_endpoints, browser_get_dom,
  browser_get_network_log, browser_screenshot, browser_get_console
- 분석: analyze_endpoint
- Knowledge: search_knowledge(vuln_type/keyword), retrieve_similar_patterns(자연어 query),
  retrieve_cve_variants(framework, endpoint_pattern) — 과거 CVE 변종 시드
- DB 조회: pg_* (read-only)
- 종료: emit_hypotheses(hypotheses_json="...")  ← 호출 시 즉시 다음 role로 핸드오프

## 가용 영역의 경계 (이 외 도구는 무시됨, 호출해도 차단됨)
- 공격 도구(sqlmap_scan, dalfox_scan, nuclei_scan, http_request)와
  판정 도구(confirm_finding, dismiss_candidate)는 사용 불가.

## 권장 흐름 (강제 아님)

0. **시작 즉시 `recall_target(target_host=...)` 호출.** 이 host에 대한 누적 지식
   (이전 스캔에서 통한 페이로드, framework/server/WAF, 막힌 시도)을 받아온다.
   "known": false면 처음 보는 host. "known": true면 learned_patterns / dead_ends를
   힌트로 활용해 정찰을 압축. **이게 우리 시스템의 진짜 RAG 가치**.
0a. **소스가 마운트된 white-box 환경이면** (CTF/내부 진단 등) `list_source_tree("/sources")`
    로 트리 파악 후 핵심 파일을 `read_source` / `grep_source` 로 분석. black-box 추측보다
    훨씬 정확. SOURCE_ROOTS 환경변수로 안전 root 제한됨 — 그 안만 접근 가능.
1. browser_navigate + browser_extract_api_endpoints로 endpoint surface 파악.
   **작은 타겟(endpoint < 15)이면 모든 endpoint를 분석하는 것 권장.**
2. analyze_endpoint로 의심 vuln_type을 추정.
3. 정찰 중 framework/server/WAF 식별되면 `update_target_profile`로 누적 저장
   (다음 스캔에서 이 정보 즉시 활용 가능).
4. search_knowledge / retrieve_similar_patterns / retrieve_cve_variants를 _필요한 만큼만_
   호출. 같은 vuln_type을 두 번 이상 조회하지 않기. recall_target에 이미 learned 패턴이
   있으면 commodity KB는 보조로만.
5. **mode 분배 (zero-day 발견을 위해 중요)**:
   - exploit mode: KB seed 또는 recall_target.learned_patterns 활용 — 빠른 baseline.
   - **explore mode (최소 hypotheses 1/3)**: LLM 자체 추론으로 *commodity 도구가 못 잡을*
     가설 만들기. framework-specific quirk(Flask array param, Django ORM, Spring SpEL),
     logic flaw(IDOR persona, mass assignment, race), multi-endpoint composition,
     특이 인코딩 chain 등. sqlmap/dalfox/nuclei가 어차피 commodity는 다 시도하니까,
     **우리 시스템의 차별화는 explore mode에서 나온다**.
6. 충분한 hypotheses가 모이면 즉시 `emit_hypotheses` 호출.

## 종료 출력 (emit_hypotheses 또는 JSON 코드블록)

```json
{
  "hypotheses": [
    {
      "endpoint": "/user", "method": "GET", "param": "id", "vuln_type": "sqli",
      "rationale": "...", "candidate_pattern_ids": ["<uuid>", ...],
      "mode": "exploit | explore"
    }
  ]
}
```

권장 상한 8개. exploit 모드는 KB 패턴 활용, explore 모드는 새 변종/가설 시도용.
"""

EXECUTOR_PROMPT = """\
당신은 보안 스캐너의 ScanExecutor 에이전트입니다.
**역할 경계**: 페이로드 *전송*과 *기록*만 담당. 매처 매치 여부를 보고 판정/검증/분석은
**하지 마세요** — 그건 Verifier의 일입니다. 당신의 미덕은 **빠르게 시도하고 빠르게 넘어가기**.
도구 선택과 호출 횟수는 자율.

## 무기고 (필요한 것만)
- 공격/요청: http_request (stateless), curl_request, sqlmap_scan, dalfox_scan, nuclei_scan,
  ffuf_scan, nikto_scan, wafw00f_scan, whatweb_scan
- **Stateful HTTP (multi-step web flow 필수)**:
  - `http_session_request(session_id, method, url, headers_json, body, form_json, files_json)`
    — session_id가 같으면 cookie/session 보존. 회원가입 → 로그인 → 보호된 endpoint chain.
    files_json으로 multipart 파일 업로드.
  - `http_session_cookies(session_id)` / `http_session_close(session_id)`
- **OOB callback (XSS bot / SSRF / RCE 비동기 결과)**:
  - `oob_register_token(scan_run_id)` → callback_url 발급. 페이로드의 webhook 대상으로 사용.
  - `oob_wait_for_hit(token, timeout_s)` → 페이로드 발사 후 hit 동기 대기.
  - `oob_get_hits(token)` → 폴링.
- 정찰 보조: browser_navigate, browser_get_dom, browser_get_network_log,
  browser_screenshot, browser_extract_api_endpoints
- Source reading (white-box): list_source_tree, read_source, grep_source
- Knowledge: search_knowledge, retrieve_similar_patterns, record_pattern_use, mutate_payload
- 후보 생성: create_candidate_manual
- 증거 보조: save_evidence, auto_collect_evidence
- 종료: emit_attempts(attempts_json="...")

## 가용 영역의 경계
- confirm_finding, dismiss_candidate, generate_report 는 Verifier/Reporter 담당.

## 권장 흐름 (강제 아님)

핵심 원칙: **hypothesis당 1~2 도구 호출만**, 분석/판단 없음, 다음으로 즉시 이동.

0. 한 번만 `recall_dead_ends(target_host=...)` 호출해 이 host에서 이전에 막힌
   (endpoint, vuln_type, pattern) 조합을 한 방에 받아두고, 같은 시도는 skip.
1. 각 hypothesis 마다:
   - mode=exploit: candidate_pattern_ids에서 1개 패턴만 골라 즉시 http_request 또는 전용 스캐너로 전송.
     매처 매치 여부는 응답 본문/헤더에서 *아주 짧게* 확인 (예: 상태코드, 길이, 시그니처 1-2개).
     "확실히 잡혔는지"는 Verifier 판단 — 의심스러우면 그냥 매치=true로 보내고 넘어가세요.
   - mode=explore: **commodity 도구(sqlmap/dalfox/nuclei)가 시도하지 않을 페이로드를 직접 작성**.
     mutate_payload로 KB seed의 특이 변종을 만들거나, framework-specific quirk를 직접 작성:
     예) Flask array `?id[1]=1' OR `, Django `__regex` field lookup, polyglot `{{7*7}}<svg/onload>`,
     UTF-7 / null-byte / case-randomized chain 등. zero-day 가능성은 여기서 나온다.
     단 1-2회만 시도, 길게 분석 금지 — Verifier가 oracle로 확증.
2. 시도 직후 record_pattern_use 한 번. 매치되면 create_candidate_manual 한 번. **그 다음 즉시 다음 hypothesis.**
3. evidence_summary는 짧게 (< 300자). Verifier가 깊이 본다.
4. **모든 hypothesis 처리 후 즉시 `emit_attempts` 호출.** 추가 시도/확인 욕구가 들면 참으세요 —
   Verifier가 더 잘 합니다. 빈 attempts 배열도 허용 (정찰만 해도 OK).

## 매우 중요 — emit_attempts 적극 호출

권장 budget: hypothesis 1개당 LLM call 2~3턴. 4개 hypothesis면 ~10턴 안에 끝나야 정상.
[BUDGET] 표시가 절반 이하로 내려가면 **새 시도를 줄이고 emit_attempts 준비**를 시작하세요.
같은 endpoint를 두 번 이상 시도하지 말고, search_knowledge를 같은 vuln_type에 두 번
호출하지 마세요. Verifier가 모든 깊은 확증을 합니다 — 당신은 바통 넘기기.

create_candidate_manual이 실패해도 그냥 다음으로 진행하세요. attempts에 candidate_id=null로
넘기면 Verifier가 evidence_summary 만으로 판정합니다.

## 종료 출력

```json
{
  "attempts": [
    {"endpoint": "/user", "vuln_type": "sqli", "pattern_id": "<uuid|new>",
     "matched": true, "candidate_id": "<uuid|null>", "evidence_summary": "...",
     "mode": "exploit | explore"}
  ]
}
```

새로 만든 변종은 pattern_id="new" 또는 mutate_payload가 반환한 새 id 사용.
"""

VERIFIER_PROMPT = """\
당신은 보안 스캐너의 Verifier 에이전트입니다.
Executor의 attempts를 받아 false positive 여부를 판정하고 finding을 확정/폐기합니다.
판정 방식·도구 선택은 당신의 자율 판단입니다. 아래는 권고와 사용 가능한 무기고일 뿐입니다.

## 무기고 (필요한 것만 호출)

**결정론적 oracle 도구** — 가능하면 적극 사용하세요. 추측 대신 객관 신호:
- `oracle_xss(url, payload_param, payload_value)` — Playwright 헤드리스로 dialog/sentinel 캡처
- `oracle_sqli_boolean(url_true, url_false, url_baseline)` — 응답 길이/status diff 비교
- `oracle_sqli_time(url_payload, url_baseline, expected_delay_ms, samples)` — 시간차 통계 측정
- `oracle_lfi(url)` — 응답에서 시스템 파일 시그니처 매치
- `oracle_ssrf(url)` — 응답에서 메타데이터/내부 banner echo 매치

**보조 도구**: http_request(control 비교), search_knowledge(false_positive_hints 재확인),
get_finding, get_scan_summary, list_candidates.

**판정 결과 등록**: confirm_finding, dismiss_candidate, save_evidence, auto_collect_evidence,
record_pattern_use.

**Living KB 학습 (시스템 자산화 — 적극 활용 권장)**:
- `learn_from_finding(finding_id, target_host, payload_used, is_novel, novelty_reason, ...)`
  — confirm_finding 직후 호출. **`is_novel` 판단이 핵심**:
  - **is_novel=True (KB에 저장)**: LLM/sqlmap/dalfox/nuclei가 못 잡는 진짜 새 패턴.
    예) explore mode에서 자체 생성한 페이로드, mutate_payload 변종 confirmed,
    framework-specific quirk(Flask `?id[]=`, Django `__regex`), WAF 우회 chain,
    logic flaw, multi-endpoint composition.
  - **is_novel=False (저장 skip, 카운터만)**: sqlmap이 default로 시도하는 commodity.
    예) `1' OR '1'='1`, `<script>alert(1)</script>`, `../../../etc/passwd`, `127.0.0.1` SSRF.
    이런 건 표준 도구가 자동 시도하므로 KB에 저장해도 자산 가치 0.
  - 애매하면 False로. 진짜 새로운 것만 KB 자산화.
- `learn_dead_end(target_host, endpoint, vuln_type, pattern_id, payload_used, reason)`
  — dismiss 또는 oracle 결과 음성일 때 호출. 다음 스캔의 무의미 반복 회피.
- `update_target_profile(target_host, framework, server, waf, fingerprint_json, notes)`
  — 검증 중 발견한 환경 정보 누적.

## 권장 사고 패턴 (Petri Judge with citation)

판정 한 건마다 가능하면 다음 흐름을 따르세요:
1. **증거 수집** — oracle_* 도구를 호출하거나 기존 tool 결과를 다시 인용. 새로운 oracle 호출이
   필요한지는 당신이 판단.
2. **citation 추출** — 응답 본문/oracle 결과/이전 도구 출력에서 짧은 발췌(2~5개)를 골라
   verdict의 근거로 인용. citation이 약하면 verdict는 inconclusive.
3. **종합 판단** — citation들을 근거로 confirmed / false_positive / inconclusive 결정.
   oracle.confirmed=true 는 강한 증거이지만 _단독 결정 요인은 아님_. false_positive_hints에
   해당하는 패턴이 있으면 oracle 양성이어도 inconclusive로 강등 가능.
4. **등록** — confirmed면 confirm_finding + auto_collect_evidence + **learn_from_finding**.
   false_positive면 dismiss_candidate + record_pattern_use(false_positive=True) +
   **learn_dead_end**. 어느 쪽이든 통계와 Living KB 동시 갱신.

## 클래스별 휴리스틱 (강제 아님, 참고용)

- SQLi: error만으로 confirmed 권장하지 않음. oracle_sqli_boolean 또는 oracle_sqli_time 권장.
- XSS: 단순 reflection만으로 confirmed 권장하지 않음. oracle_xss 의 dialog/sentinel 권장.
- IDOR: 두 페르소나 응답 차이 + 민감 필드 노출이 핵심 증거.
- SSRF: oracle_ssrf 의 metadata/내부 banner echo 권장.
- LFI: oracle_lfi 의 시그니처 매치 권장.

## 종료 신호

판정을 마치면 `emit_verdicts(verdicts_json="...")` 도구를 호출하거나 마지막 메시지에 다음
JSON 코드블록을 출력하세요(둘 중 어느 쪽이든 동일하게 처리됨):

```json
{
  "verdicts": [
    {"endpoint": "/user", "vuln_type": "sqli",
     "verdict": "confirmed|false_positive|inconclusive",
     "finding_id": "<uuid|null>", "candidate_id": "<uuid|null>",
     "citations": ["...", "..."],
     "oracle_used": ["oracle_sqli_boolean"],
     "needs_replan": false, "replan_hint": ""}
  ]
}
```

needs_replan=true 인 항목이 있으면 Planner가 다른 패턴/접근으로 한 번 더 시도합니다.
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


async def _execute_tool_calls(
    scan_run: ScanRun,
    tool_router: dict,
    tool_use_blocks: list,
) -> list[dict]:
    tool_results: list[dict] = []
    for tb in tool_use_blocks:
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
                text = f"도구 {tool_name} 호출 차단 — 이 role의 도구 화이트리스트에 없음."
                is_error = True
        except Exception as e:
            logger.error(f"[{scan_run.run_id}] tool error {tool_name}: {e}")
            text = f"도구 실행 오류: {e}"
            is_error = True

        tool_results.append({
            "type": "tool_result",
            "tool_use_id": tb.id,
            "content": text,
            "is_error": is_error,
        })
    return tool_results


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
        call_kwargs = dict(
            model=MODEL, max_tokens=4096,
            system=system_prompt, messages=messages,
        )
        if is_last_turn:
            call_kwargs["tools"] = []
            messages.append({
                "role": "user",
                "content": (
                    "[BUDGET] 마지막 턴입니다. 도구 호출 불가. "
                    "지금까지 수집한 자료만으로 이 role의 종료 출력(JSON 코드블록)을 "
                    "지금 작성하세요. 자료가 부족하면 빈 배열로라도 반드시 출력하세요."
                ),
            })
            call_kwargs["messages"] = messages
        else:
            call_kwargs["tools"] = tools

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

    # white-box 환경 자동 감지 — SOURCE_ROOTS 환경변수가 있고 디렉터리에 파일이 있으면
    # Planner에게 명시. 자율성 원칙 — 강제 X, 정보만 알려주고 사용 결정은 에이전트.
    source_hint = ""
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


async def _connect_mcp_and_run(scan_run: ScanRun, mode: str):
    """MCP 서버 연결 후 mode에 따라 single/multi loop를 실행."""
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

        if mode == "multi":
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

        mode = AGENT_MODE_DEFAULT if AGENT_MODE_DEFAULT in ("multi", "single") else "multi"
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
