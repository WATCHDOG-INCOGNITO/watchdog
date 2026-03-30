import os
import sys

# /app/mcp/ 로컬 폴더가 pip mcp SDK를 가리는 문제 해결
# 1) cwd를 /tmp으로 변경 (''가 /app을 가리키지 않게)
# 2) sys.path에서 /app 대신 /app을 뒤로 밀고 site-packages 우선
_base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir("/tmp")
sys.path = [p for p in sys.path if p not in ("", ".", _base_dir, _base_dir + "/")]
import site as _site
for _sp in _site.getsitepackages():
    if _sp not in sys.path:
        sys.path.insert(0, _sp)
# 캐시된 로컬 mcp 모듈 제거
for _k in list(sys.modules.keys()):
    if _k == "mcp" or _k.startswith("mcp."):
        del sys.modules[_k]
# pip mcp SDK 로딩
from mcp.server.fastmcp import FastMCP  # noqa: E402

# /app을 path에 다시 추가 (Django ORM 접근용)
if _base_dir not in sys.path:
    sys.path.append(_base_dir)

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django  # noqa: E402
django.setup()

mcp = FastMCP(
    "Watchdog Security Scanner",
    instructions=(
        "AI-powered web vulnerability scanner. "
        "Tools: sqlmap(SQLi), nuclei(templates), dalfox(XSS), "
        "Chrome DevTools(SPA/network), HTTP requests, "
        "crawling, analysis, storage, reporting. "
        "LLM이 도구를 직접 선택하고 체이닝하여 취약점을 탐지·검증한다."
    ),
)

from watchdog_mcp.tools_security import register as register_security
from watchdog_mcp.tools_browser import register as register_browser
from watchdog_mcp.tools_analysis import register as register_analysis
from watchdog_mcp.tools_storage import register as register_storage
from watchdog_mcp.tools_report import register as register_report
from watchdog_mcp.tools_benchmark import register as register_benchmark

register_security(mcp)
register_browser(mcp)
register_analysis(mcp)
register_storage(mcp)
register_report(mcp)
register_benchmark(mcp)

def main():
    mcp.run()

if __name__ == "__main__":
    main()

