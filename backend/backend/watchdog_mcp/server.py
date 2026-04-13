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

register_security(mcp)
register_browser(mcp)
register_analysis(mcp)
register_storage(mcp)
register_report(mcp)
register_benchmark(mcp)
register_knowledge(mcp)
register_handoff(mcp)
register_oracle(mcp)

def main():
    import sys
    if "--sse" in sys.argv or os.environ.get("MCP_SSE"):
        mcp.run(transport="sse")
    else:
        mcp.run()

if __name__ == "__main__":
    main()

