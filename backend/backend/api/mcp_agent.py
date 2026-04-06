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
MODEL = "claude-sonnet-4-20250514"

# Sonnet 4 pricing: input $3/MTok, output $15/MTok
INPUT_COST_PER_TOKEN = Decimal("0.000003")
OUTPUT_COST_PER_TOKEN = Decimal("0.000015")

SYSTEM_PROMPT = """\
당신은 웹 애플리케이션 보안 스캐너 에이전트입니다.
주어진 타겟 URL을 분석하여 취약점을 찾아야 합니다.

## 절차
1. `browser_navigate`로 타겟에 접속하고 `browser_extract_api_endpoints`로 API 엔드포인트를 수집하세요.
2. `analyze_endpoint`로 각 엔드포인트를 분석하세요.
3. 위험도가 높은 엔드포인트에 `http_request`로 탐색적 요청을 전송하세요.
4. 취약점이 의심되면 적절한 보안 도구(`sqlmap_scan`, `dalfox_scan`, `nuclei_scan` 등)를 실행하세요.
5. 취약점이 확인되면 `confirm_finding`으로 Finding을 생성하고, `auto_collect_evidence`로 증거를 수집하세요.
6. 모든 분석이 완료되면 `generate_report`로 리포트를 생성하세요.

## DB 쿼리 (PostgreSQL MCP)
- `pg_query` 도구로 과거 스캔 결과, 기존 취약점 패턴 등을 직접 조회할 수 있습니다.
- 읽기 전용으로만 사용하세요. INSERT/UPDATE/DELETE는 금지됩니다.

## 주의사항
- 타겟 URL 외의 도메인을 공격하지 마세요.
- 파괴적 페이로드(DROP TABLE 등)는 사용하지 마세요.
- 각 단계의 결과를 분석한 후 다음 행동을 결정하세요.
- 더 이상 분석할 것이 없으면 리포트를 생성하고 종료하세요.
"""


def _get_mcp_server_path() -> str:
    """watchdog_mcp 서버 스크립트 경로를 반환한다."""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "watchdog_mcp", "server.py")




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


async def _run_agent_loop(scan_run: ScanRun):
    """비동기 MCP 에이전트 루프 실행. watchdog + PostgreSQL 두 서버 동시 연결."""
    anthropic = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))
    server_path = _get_mcp_server_path()

    # watchdog MCP 서버 파라미터
    # server.py 자체가 site-packages 우선 로딩을 처리함
    watchdog_params = StdioServerParameters(
        command=sys.executable,
        args=[server_path],
        env={
            **os.environ,
            "DJANGO_SETTINGS_MODULE": "config.settings",
        },
    )

    # PostgreSQL MCP 서버 파라미터 (npx가 있을 때만)
    pg_available = shutil.which("npx") is not None
    pg_conn_str = _get_pg_connection_string() if pg_available else ""

    total_input_tokens = 0
    total_output_tokens = 0
    total_calls = 0

    # 도구 이름 → (session, 원본 이름) 매핑
    tool_router: dict[str, tuple[ClientSession, str]] = {}

    async with AsyncExitStack() as stack:
        # ── watchdog MCP 서버 연결 ──
        wd_transport = await stack.enter_async_context(
            stdio_client(watchdog_params)
        )
        wd_session = await stack.enter_async_context(
            ClientSession(wd_transport[0], wd_transport[1])
        )
        await wd_session.initialize()

        wd_tools_result = await wd_session.list_tools()
        anthropic_tools = _convert_tools_for_anthropic(wd_tools_result.tools)
        for tool in wd_tools_result.tools:
            tool_router[tool.name] = (wd_session, tool.name)

        logger.info(
            f"[{scan_run.run_id}] watchdog MCP 도구 {len(wd_tools_result.tools)}개 로드"
        )

        # ── PostgreSQL MCP 서버 연결 (선택) ──
        pg_session = None
        if pg_available and pg_conn_str:
            try:
                pg_params = StdioServerParameters(
                    command="npx",
                    args=["-y", "@modelcontextprotocol/server-postgres", pg_conn_str],
                )
                pg_transport = await stack.enter_async_context(
                    stdio_client(pg_params)
                )
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
                    f"[{scan_run.run_id}] PostgreSQL MCP 도구 "
                    f"{len(pg_tools_result.tools)}개 로드"
                )
            except Exception as e:
                logger.warning(
                    f"[{scan_run.run_id}] PostgreSQL MCP 연결 실패 (계속 진행): {e}"
                )

        logger.info(
            f"[{scan_run.run_id}] 총 도구 {len(anthropic_tools)}개: "
            f"{[t['name'] for t in anthropic_tools]}"
        )

        # ── 대화 시작 ──
        messages = [
            {
                "role": "user",
                "content": (
                    f"타겟 URL: {scan_run.target_url}\n"
                    f"스캔 ID: {scan_run.run_id}\n\n"
                    f"위 타겟을 스캔하여 취약점을 찾고 리포트를 생성해주세요."
                ),
            }
        ]

        # ── 에이전트 루프 ──
        for turn in range(MAX_TURNS):
            raise_if_stop_requested(scan_run)
            logger.info(f"[{scan_run.run_id}] 턴 {turn + 1}/{MAX_TURNS}")

            # Rate limit 재시도 (최대 3회, 지수 백오프)
            response = None
            for retry in range(3):
                try:
                    response = anthropic.messages.create(
                        model=MODEL,
                        max_tokens=4096,
                        system=SYSTEM_PROMPT,
                        tools=anthropic_tools,
                        messages=messages,
                    )
                    break
                except Exception as api_err:
                    if (
                        "rate_limit" in str(api_err).lower()
                        or "429" in str(api_err)
                        or "529" in str(api_err)
                        or "overloaded" in str(api_err).lower()
                    ):
                        wait = 30 * (2 ** retry)  # 30s, 60s, 120s
                        logger.warning(
                            f"[{scan_run.run_id}] Rate limit, {wait}s 대기 후 재시도 ({retry+1}/3)"
                        )
                        stop_sleep(scan_run, wait)
                    else:
                        raise
            if response is None:
                raise RuntimeError("Rate limit 재시도 3회 초과")

            # 토큰 사용량 누적
            total_input_tokens += response.usage.input_tokens
            total_output_tokens += response.usage.output_tokens
            total_calls += 1

            # DB 업데이트 (매 턴) — async 컨텍스트에서 ORM 호출
            scan_run.llm_calls_count = total_calls
            scan_run.llm_tokens_used = total_input_tokens + total_output_tokens
            scan_run.llm_cost_usd = (
                Decimal(str(total_input_tokens)) * INPUT_COST_PER_TOKEN
                + Decimal(str(total_output_tokens)) * OUTPUT_COST_PER_TOKEN
            )
            await sync_to_async(scan_run.save)(update_fields=[
                "llm_calls_count", "llm_tokens_used", "llm_cost_usd",
            ])

            prompt_preview = build_prompt_preview(messages)
            response_preview = build_response_preview(response.content)
            tool_calls = extract_tool_calls(response.content)

            # stop_reason이 end_turn이면 종료
            if response.stop_reason == "end_turn":
                for block in response.content:
                    if hasattr(block, "text"):
                        logger.info(
                            f"[{scan_run.run_id}] 에이전트 최종 응답: "
                            f"{block.text[:500]}"
                        )
                await sync_to_async(record_llm_trace)(
                    scan_run=scan_run,
                    call_index=total_calls,
                    stage="mcp_turn",
                    model=MODEL,
                    prompt_preview=prompt_preview,
                    response_preview=response_preview,
                    tool_calls=tool_calls,
                    stop_reason=response.stop_reason,
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    metadata={
                        "turn": turn + 1,
                        "message_count": len(messages),
                    },
                )
                break

            # tool_use 블록 처리
            tool_use_blocks = [
                b for b in response.content if b.type == "tool_use"
            ]
            if not tool_use_blocks:
                await sync_to_async(record_llm_trace)(
                    scan_run=scan_run,
                    call_index=total_calls,
                    stage="mcp_turn",
                    model=MODEL,
                    prompt_preview=prompt_preview,
                    response_preview=response_preview,
                    tool_calls=tool_calls,
                    stop_reason=response.stop_reason,
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    metadata={
                        "turn": turn + 1,
                        "message_count": len(messages),
                    },
                )
                break

            # assistant 메시지 추가
            messages.append({"role": "assistant", "content": response.content})

            # 각 도구 호출을 올바른 MCP 세션으로 라우팅
            tool_results = []
            for tool_block in tool_use_blocks:
                raise_if_stop_requested(scan_run)
                tool_name = tool_block.name
                tool_args = tool_block.input or {}

                logger.info(
                    f"[{scan_run.run_id}] 도구 호출: {tool_name}"
                    f"({json.dumps(tool_args, ensure_ascii=False)[:200]})"
                )

                try:
                    if tool_name in tool_router:
                        session, original_name = tool_router[tool_name]
                        result = await session.call_tool(original_name, tool_args)
                    else:
                        raise ValueError(f"알 수 없는 도구: {tool_name}")

                    # MCP 결과를 텍스트로 변환
                    if result.content:
                        result_text = "\n".join(
                            c.text if hasattr(c, "text") else str(c)
                            for c in result.content
                        )
                    else:
                        result_text = "(빈 결과)"

                    is_error = bool(result.isError) if hasattr(result, "isError") else False
                except Exception as e:
                    logger.error(
                        f"[{scan_run.run_id}] 도구 오류 {tool_name}: {e}"
                    )
                    result_text = f"도구 실행 오류: {e}"
                    is_error = True

                logger.info(
                    f"[{scan_run.run_id}] 도구 결과 ({tool_name}): "
                    f"{result_text[:300]}"
                )

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_block.id,
                    "content": result_text,
                    "is_error": is_error,
                })

            await sync_to_async(record_llm_trace)(
                scan_run=scan_run,
                call_index=total_calls,
                stage="mcp_turn",
                model=MODEL,
                prompt_preview=prompt_preview,
                response_preview=response_preview,
                tool_calls=tool_calls,
                stop_reason=response.stop_reason,
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
                metadata={
                    "turn": turn + 1,
                    "message_count": len(messages),
                    "tool_results": summarize_tool_results(tool_results),
                },
            )

            messages.append({"role": "user", "content": tool_results})

        else:
            logger.warning(
                f"[{scan_run.run_id}] 최대 턴({MAX_TURNS}) 도달, 루프 종료"
            )

    logger.info(
        f"[{scan_run.run_id}] MCP 에이전트 완료: "
        f"{total_calls}회 호출, "
        f"{total_input_tokens + total_output_tokens} tokens, "
        f"${scan_run.llm_cost_usd}"
    )


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

        asyncio.run(_run_agent_loop(scan_run))

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
