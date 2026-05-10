import json

from .models import LLMTrace, ScanRun


def _truncate(value, limit=4000):
    if value is None:
        return ""
    text = str(value)
    if len(text) <= limit:
        return text
    return f"{text[:limit]}...(truncated)"


def _stringify_content(content):
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n\n".join(filter(None, (_stringify_content(item) for item in content)))
    if isinstance(content, dict):
        block_type = content.get("type")
        if block_type == "tool_result":
            preview = _truncate(_stringify_content(content.get("content")), 1200)
            return f"tool_result[{content.get('tool_use_id', '?')}]: {preview}"
        if block_type == "tool_use":
            return json.dumps(
                {
                    "type": "tool_use",
                    "name": content.get("name"),
                    "input": content.get("input", {}),
                },
                ensure_ascii=False,
                indent=2,
            )
        if "text" in content:
            return str(content.get("text", ""))
        return json.dumps(content, ensure_ascii=False, indent=2)

    block_type = getattr(content, "type", "")
    if block_type == "tool_use":
        return json.dumps(
            {
                "type": "tool_use",
                "name": getattr(content, "name", ""),
                "input": getattr(content, "input", {}),
            },
            ensure_ascii=False,
            indent=2,
        )

    text = getattr(content, "text", None)
    if isinstance(text, str):
        return text

    if hasattr(content, "model_dump"):
        return json.dumps(content.model_dump(), ensure_ascii=False, indent=2)

    return str(content)


def build_prompt_preview(messages):
    if not messages:
        return ""

    preview_chunks = []
    for message in messages[-2:]:
        if isinstance(message, dict):
            role = message.get("role", "unknown")
            content = message.get("content")
        else:
            role = "unknown"
            content = message
        preview_chunks.append(f"[{role}] {_stringify_content(content)}")

    return _truncate("\n\n".join(preview_chunks), 6000)


def build_response_preview(content):
    return _truncate(_stringify_content(content), 6000)


def extract_tool_calls(content):
    blocks = content if isinstance(content, list) else [content]
    calls = []

    for block in blocks:
        if isinstance(block, dict) and block.get("type") == "tool_use":
            calls.append({
                "name": block.get("name", ""),
                "input": block.get("input", {}),
            })
            continue

        if getattr(block, "type", None) == "tool_use":
            calls.append({
                "name": getattr(block, "name", ""),
                "input": getattr(block, "input", {}),
            })

    return calls


def summarize_tool_results(tool_results):
    summaries = []
    for result in tool_results or []:
        if not isinstance(result, dict):
            continue
        summaries.append({
            "tool_use_id": result.get("tool_use_id", ""),
            "is_error": bool(result.get("is_error", False)),
            "content": _truncate(_stringify_content(result.get("content")), 1200),
        })
    return summaries


def record_llm_trace(
    *,
    scan_run: ScanRun,
    call_index: int,
    stage: str,
    model: str,
    prompt_preview: str,
    response_preview: str,
    tool_calls=None,
    stop_reason: str = "",
    input_tokens: int = 0,
    output_tokens: int = 0,
    metadata=None,
    error: str = "",
    target_node=None,
):
    LLMTrace.objects.create(
        scan_run=scan_run,
        call_index=max(0, int(call_index or 0)),
        stage=stage,
        model=model or "",
        prompt_preview=_truncate(prompt_preview, 12000),
        response_preview=_truncate(response_preview, 12000),
        tool_calls=tool_calls or [],
        stop_reason=stop_reason or "",
        input_tokens=int(input_tokens or 0),
        output_tokens=int(output_tokens or 0),
        metadata=metadata or {},
        error=_truncate(error, 4000),
        target_node=target_node,
    )
