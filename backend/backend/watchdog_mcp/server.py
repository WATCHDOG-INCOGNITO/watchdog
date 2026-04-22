import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"

import django
django.setup()

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "Watchdog Security Scanner",
    instructions=(
        "AI-powered web vulnerability scanner. "
        "Tools: sqlmap(SQLi), nuclei(templates), dalfox(XSS), "
        "Chrome DevTools(SPA/network), HTTP requests, "
        "crawling, analysis, storage, reporting. "
        "LLM이 도구를 직접 선택하고 체이닝하여 취약점을 탐지·검증한다."
    ),
    host="0.0.0.0",
    port=8889,
)

from .tools_security import register as register_security
from .tools_browser import register as register_browser
from .tools_analysis import register as register_analysis
from .tools_storage import register as register_storage
from .tools_report import register as register_report
from .tools_benchmark import register as register_benchmark
from .tools_knowledge import register as register_knowledge
from .tools_handoff import register as register_handoff
from .tools_oracle import register as register_oracle
from .tools_learn import register as register_learn
from .tools_source import register as register_source
from .tools_session import register as register_session
from .tools_oob import register as register_oob
from .tools_discovery import register as register_discovery

register_security(mcp)
register_browser(mcp)
register_analysis(mcp)
register_storage(mcp)
register_report(mcp)
register_benchmark(mcp)
register_knowledge(mcp)
register_handoff(mcp)
register_oracle(mcp)
register_learn(mcp)
register_source(mcp)
register_session(mcp)
register_oob(mcp)
register_discovery(mcp)

def _truthy(value: str | None) -> bool:
    return bool(value and value.lower() not in {"0", "false", "no", "off"})


def _select_transport(argv: list[str]) -> str:
    for arg in argv:
        if arg.startswith("--transport="):
            return arg.split("=", 1)[1]

    if "--stdio" in argv:
        return "stdio"
    if "--streamable-http" in argv or "--http" in argv:
        return "streamable-http"
    if "--sse" in argv:
        return "sse"

    env_transport = os.environ.get("MCP_TRANSPORT")
    if env_transport:
        return env_transport
    if _truthy(os.environ.get("MCP_STREAMABLE_HTTP")):
        return "streamable-http"
    if _truthy(os.environ.get("MCP_SSE")):
        return "sse"
    return "stdio"


def main():
    import sys

    transport = _select_transport(sys.argv[1:])
    if transport not in {"stdio", "sse", "streamable-http"}:
        raise ValueError(
            "Unsupported MCP transport. Use stdio, sse, or streamable-http."
        )
    mcp.run(transport=transport)

if __name__ == "__main__":
    main()

