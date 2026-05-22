import json
import logging
import os
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_PROVIDER = os.environ.get("WATCHDOG_LLM_PROVIDER", "anthropic").strip() or "anthropic"
DEFAULT_MODEL = os.environ.get("WATCHDOG_AGENT_MODEL", "claude-opus-4-7").strip()

PROVIDER_ENV_KEYS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
}


@dataclass(frozen=True)
class ModelSpec:
    provider: str
    model: str

    @property
    def trace_label(self) -> str:
        return f"{self.provider}:{self.model}"


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class TextBlock:
    text: str
    type: str = "text"


@dataclass
class ToolUseBlock:
    id: str
    name: str
    input: dict
    type: str = "tool_use"


@dataclass
class LLMResponse:
    content: list[Any]
    usage: Usage
    stop_reason: str
    provider: str
    model: str
    raw: Any = None


class LLMProviderError(RuntimeError):
    pass


def normalize_provider(value: str | None) -> str:
    provider = (value or DEFAULT_PROVIDER or "anthropic").strip().lower()
    aliases = {
        "claude": "anthropic",
        "anthropic": "anthropic",
        "openai": "openai",
        "codex": "openai",
        "gpt": "openai",
    }
    return aliases.get(provider, provider)


def infer_provider_from_model(model: str, default_provider: str | None = None) -> str:
    name = (model or "").strip().lower()
    if name.startswith("claude-"):
        return "anthropic"
    if name.startswith(("gpt-", "o1", "o3", "o4", "o5", "openai/")):
        return "openai"
    return normalize_provider(default_provider)


def resolve_model_spec(
    value: Any = None,
    *,
    default_model: str | None = None,
    default_provider: str | None = None,
) -> ModelSpec:
    """Resolve legacy string model config or new {provider, model} config."""
    fallback_model = (default_model or DEFAULT_MODEL).strip()
    fallback_provider = normalize_provider(default_provider)

    if isinstance(value, dict):
        model = str(value.get("model") or fallback_model).strip()
        provider = normalize_provider(value.get("provider") or infer_provider_from_model(model, fallback_provider))
        return ModelSpec(provider=provider, model=model)

    text = str(value or "").strip()
    if not text:
        provider = infer_provider_from_model(fallback_model, fallback_provider)
        return ModelSpec(provider=provider, model=fallback_model)

    if ":" in text:
        prefix, model = text.split(":", 1)
        provider = normalize_provider(prefix)
        if provider in PROVIDER_ENV_KEYS and model.strip():
            return ModelSpec(provider=provider, model=model.strip())

    provider = infer_provider_from_model(text, fallback_provider)
    model = text.removeprefix("openai/").strip() if provider == "openai" else text
    return ModelSpec(provider=provider, model=model)


def provider_env_key(provider: str) -> str:
    return PROVIDER_ENV_KEYS.get(normalize_provider(provider), "")


def is_provider_configured(spec: ModelSpec | None = None, provider: str | None = None) -> bool:
    selected = normalize_provider(provider or (spec.provider if spec else None))
    env_key = provider_env_key(selected)
    return bool(env_key and os.environ.get(env_key))


def missing_provider_message(spec: ModelSpec | None = None, provider: str | None = None) -> str:
    selected = normalize_provider(provider or (spec.provider if spec else None))
    env_key = provider_env_key(selected) or f"{selected.upper()}_API_KEY"
    return f"{env_key} not set for provider '{selected}'"


def _decimal_env(name: str, fallback: str) -> Decimal:
    try:
        return Decimal(os.environ.get(name, fallback))
    except Exception:
        return Decimal(fallback)


def estimate_cost_usd(spec: ModelSpec, input_tokens: int, output_tokens: int) -> Decimal:
    """Best-effort provider/model cost estimate.

    Defaults preserve the previous Sonnet pricing behavior. Override with
    WATCHDOG_INPUT_COST_PER_TOKEN and WATCHDOG_OUTPUT_COST_PER_TOKEN if needed.
    """
    provider = normalize_provider(spec.provider)
    model = spec.model.lower()

    default_input = _decimal_env("WATCHDOG_INPUT_COST_PER_TOKEN", "0.000003")
    default_output = _decimal_env("WATCHDOG_OUTPUT_COST_PER_TOKEN", "0.000015")

    if provider == "anthropic":
        input_cost = default_input
        output_cost = default_output
    else:
        # Unknown OpenAI/Codex model pricing is intentionally conservative and
        # configurable until model-specific pricing is added.
        input_cost = _decimal_env("WATCHDOG_OPENAI_INPUT_COST_PER_TOKEN", str(default_input))
        output_cost = _decimal_env("WATCHDOG_OPENAI_OUTPUT_COST_PER_TOKEN", str(default_output))

    if "haiku" in model:
        input_cost = _decimal_env("WATCHDOG_HAIKU_INPUT_COST_PER_TOKEN", str(input_cost))
        output_cost = _decimal_env("WATCHDOG_HAIKU_OUTPUT_COST_PER_TOKEN", str(output_cost))
    if "opus" in model:
        input_cost = _decimal_env("WATCHDOG_OPUS_INPUT_COST_PER_TOKEN", str(input_cost))
        output_cost = _decimal_env("WATCHDOG_OPUS_OUTPUT_COST_PER_TOKEN", str(output_cost))

    return Decimal(str(input_tokens or 0)) * input_cost + Decimal(str(output_tokens or 0)) * output_cost


class AnthropicProvider:
    tool_schema_format = "anthropic"

    def __init__(self):
        try:
            from anthropic import Anthropic
        except Exception as exc:
            raise LLMProviderError("anthropic package is not installed") from exc
        self.client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))

    def call(self, spec: ModelSpec, **kwargs) -> LLMResponse:
        if not is_provider_configured(spec):
            raise LLMProviderError(missing_provider_message(spec))
        response = self.client.messages.create(model=spec.model, **kwargs)
        usage = Usage(
            input_tokens=int(getattr(response.usage, "input_tokens", 0) or 0),
            output_tokens=int(getattr(response.usage, "output_tokens", 0) or 0),
        )
        return LLMResponse(
            content=list(response.content or []),
            usage=usage,
            stop_reason=getattr(response, "stop_reason", "") or "",
            provider=spec.provider,
            model=spec.model,
            raw=response,
        )


class OpenAIProvider:
    tool_schema_format = "openai"

    def __init__(self):
        try:
            from openai import OpenAI
        except Exception as exc:
            raise LLMProviderError("openai package is not installed") from exc
        self.client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", ""))

    def call(self, spec: ModelSpec, **kwargs) -> LLMResponse:
        if not is_provider_configured(spec):
            raise LLMProviderError(missing_provider_message(spec))

        messages = kwargs.get("messages") or []
        tools = kwargs.get("tools") or []
        max_tokens = kwargs.get("max_tokens") or kwargs.get("max_output_tokens") or 1024
        system = kwargs.get("system")

        request = {
            "model": spec.model,
            "input": _to_openai_input(messages),
            "max_output_tokens": max_tokens,
        }
        instructions = _system_to_text(system)
        if instructions:
            request["instructions"] = instructions
        if tools:
            request["tools"] = [_to_openai_tool(t) for t in tools]

        response = self.client.responses.create(**request)
        content = _from_openai_output(response)
        usage_obj = getattr(response, "usage", None)
        usage = Usage(
            input_tokens=int(getattr(usage_obj, "input_tokens", 0) or 0),
            output_tokens=int(getattr(usage_obj, "output_tokens", 0) or 0),
        )
        return LLMResponse(
            content=content,
            usage=usage,
            stop_reason=_openai_stop_reason(response, content),
            provider=spec.provider,
            model=spec.model,
            raw=response,
        )


_PROVIDERS: dict[str, Any] = {}


def get_provider(provider: str):
    selected = normalize_provider(provider)
    if selected not in _PROVIDERS:
        if selected == "anthropic":
            _PROVIDERS[selected] = AnthropicProvider()
        elif selected == "openai":
            _PROVIDERS[selected] = OpenAIProvider()
        else:
            raise LLMProviderError(f"Unsupported LLM provider '{selected}'")
    return _PROVIDERS[selected]


def call_llm(spec: ModelSpec, **kwargs) -> LLMResponse:
    provider = get_provider(spec.provider)
    return provider.call(spec, **kwargs)


def response_text(response: LLMResponse) -> str:
    parts = []
    for block in response.content or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            parts.append(text)
        elif isinstance(block, dict) and isinstance(block.get("text"), str):
            parts.append(block["text"])
    return "\n".join(parts).strip()


def call_text_llm(
    *,
    spec: ModelSpec,
    prompt: str,
    system: str = "",
    max_tokens: int = 1024,
) -> tuple[str, dict]:
    response = call_llm(
        spec,
        max_tokens=max_tokens,
        system=system or None,
        messages=[{"role": "user", "content": prompt}],
    )
    usage = {
        "input_tokens": response.usage.input_tokens,
        "output_tokens": response.usage.output_tokens,
        "provider": response.provider,
        "model": response.model,
        "cost_usd": str(estimate_cost_usd(spec, response.usage.input_tokens, response.usage.output_tokens)),
    }
    return response_text(response), usage


def _system_to_text(system: Any) -> str:
    if not system:
        return ""
    if isinstance(system, str):
        return system
    if isinstance(system, list):
        parts = []
        for item in system:
            if isinstance(item, dict):
                parts.append(str(item.get("text") or ""))
            else:
                parts.append(str(getattr(item, "text", "") or ""))
        return "\n\n".join(p for p in parts if p)
    return str(system)


def _block_type(block: Any) -> str:
    if isinstance(block, dict):
        return str(block.get("type") or "")
    return str(getattr(block, "type", "") or "")


def _block_text(block: Any) -> str:
    if isinstance(block, dict):
        return str(block.get("text") or block.get("content") or "")
    return str(getattr(block, "text", "") or "")


def _to_openai_input(messages: list[dict]) -> list[dict]:
    items: list[dict] = []
    for message in messages:
        role = message.get("role", "user")
        content = message.get("content", "")

        if isinstance(content, str):
            items.append({"role": role, "content": content})
            continue

        if not isinstance(content, list):
            items.append({"role": role, "content": str(content)})
            continue

        text_parts: list[str] = []
        for block in content:
            btype = _block_type(block)
            if btype == "tool_result":
                call_id = block.get("tool_use_id") if isinstance(block, dict) else getattr(block, "tool_use_id", "")
                output = block.get("content") if isinstance(block, dict) else getattr(block, "content", "")
                if text_parts:
                    items.append({"role": role, "content": "\n".join(text_parts)})
                    text_parts = []
                items.append({
                    "type": "function_call_output",
                    "call_id": str(call_id),
                    "output": str(output or ""),
                })
            elif btype == "tool_use":
                call_id = block.get("id") if isinstance(block, dict) else getattr(block, "id", "")
                name = block.get("name") if isinstance(block, dict) else getattr(block, "name", "")
                args = block.get("input") if isinstance(block, dict) else getattr(block, "input", {})
                if text_parts:
                    items.append({"role": role, "content": "\n".join(text_parts)})
                    text_parts = []
                items.append({
                    "type": "function_call",
                    "call_id": str(call_id),
                    "name": str(name),
                    "arguments": json.dumps(args or {}, ensure_ascii=False),
                })
            else:
                text = _block_text(block)
                if text:
                    text_parts.append(text)
        if text_parts:
            items.append({"role": role, "content": "\n".join(text_parts)})
    return items


def _to_openai_tool(tool: dict) -> dict:
    schema = tool.get("input_schema") or tool.get("parameters") or {"type": "object", "properties": {}}
    return {
        "type": "function",
        "name": tool.get("name", ""),
        "description": tool.get("description", "") or tool.get("name", ""),
        "parameters": schema,
    }


def _from_openai_output(response: Any) -> list[Any]:
    content: list[Any] = []
    for item in getattr(response, "output", []) or []:
        item_type = getattr(item, "type", "")
        if item_type == "function_call":
            raw_args = getattr(item, "arguments", "{}") or "{}"
            try:
                args = json.loads(raw_args)
            except Exception:
                args = {"_raw": raw_args}
            content.append(ToolUseBlock(
                id=str(getattr(item, "call_id", "") or getattr(item, "id", "")),
                name=str(getattr(item, "name", "")),
                input=args,
            ))
        elif item_type == "message":
            for block in getattr(item, "content", []) or []:
                text = getattr(block, "text", "") or ""
                if text:
                    content.append(TextBlock(text=text))
        elif item_type == "output_text":
            text = getattr(item, "text", "") or ""
            if text:
                content.append(TextBlock(text=text))

    if not content:
        output_text = getattr(response, "output_text", "") or ""
        if output_text:
            content.append(TextBlock(text=output_text))
    return content


def _openai_stop_reason(response: Any, content: list[Any]) -> str:
    if any(getattr(block, "type", "") == "tool_use" for block in content):
        return "tool_use"
    status = str(getattr(response, "status", "") or "")
    if status in ("completed", "incomplete"):
        return "end_turn" if status == "completed" else status
    return status or "end_turn"
