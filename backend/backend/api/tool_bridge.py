"""
MCP 도구 브릿지
verifier.py에서 watchdog_mcp 도구를 직접 호출할 수 있게 하는 모듈.
MCP 서버를 거치지 않고 함수를 직접 실행한다.
"""
import json
import subprocess
import shutil
import time
import hashlib
import logging
from urllib.parse import urljoin

import requests

logger = logging.getLogger(__name__)


def _run_cmd(cmd, timeout=120):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"stdout": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "timeout", "returncode": -1}
    except FileNotFoundError:
        return {"stdout": "", "stderr": f"tool not found: {cmd[0]}", "returncode": -2}


def _tool_available(name):
    return shutil.which(name) is not None


def check_tools():
    tools = ["sqlmap", "nuclei", "dalfox", "nmap", "ffuf", "wafw00f",
             "httpx", "katana", "curl", "chromium", "chromium-browser"]
    available = [t for t in tools if _tool_available(t)]
    return {"available": available, "total": len(available)}


def sqlmap_scan(target_url, params="", method="GET", level=1, risk=1, extra_args=""):
    if not _tool_available("sqlmap"):
        return {"error": "sqlmap not installed"}
    cmd = ["sqlmap", "-u", target_url, "--batch", "--output-dir=/tmp/sqlmap_out",
           f"--level={level}", f"--risk={risk}", "--disable-coloring"]
    if method.upper() == "POST" and params:
        cmd.extend(["--method=POST", f"--data={params}"])
    if extra_args:
        cmd.extend(extra_args.split())
    result = _run_cmd(cmd, timeout=180)
    return {
        "output": result["stdout"][-5000:],
        "errors": result["stderr"][-2000:] if result["stderr"] else "",
        "returncode": result["returncode"],
    }


def nuclei_scan(target_url, templates="", severity="", tags="", extra_args=""):
    if not _tool_available("nuclei"):
        return {"error": "nuclei not installed"}
    cmd = ["nuclei", "-u", target_url, "-silent", "-nc"]
    if templates:
        cmd.extend(["-t", templates])
    if severity:
        cmd.extend(["-severity", severity])
    if tags:
        cmd.extend(["-tags", tags])
    if extra_args:
        cmd.extend(extra_args.split())
    result = _run_cmd(cmd, timeout=300)
    findings = [l.strip() for l in result["stdout"].strip().split("\n") if l.strip()]
    return {"findings_count": len(findings), "findings": findings[-50:], "returncode": result["returncode"]}


def dalfox_scan(target_url, params="", extra_args=""):
    if not _tool_available("dalfox"):
        return {"error": "dalfox not installed"}
    cmd = ["dalfox", "url", target_url, "--silence", "--no-color"]
    if params:
        cmd.extend(["--data", params])
    if extra_args:
        cmd.extend(extra_args.split())
    result = _run_cmd(cmd, timeout=180)
    vulns = [l.strip() for l in result["stdout"].strip().split("\n")
             if l.strip() and ("POC" in l or "Vuln" in l or "[V]" in l)]
    return {"vulnerabilities": vulns, "full_output": result["stdout"][-5000:], "returncode": result["returncode"]}


def http_request(url, method="GET", headers="{}", body="", follow_redirects=True):
    try:
        hdrs = json.loads(headers) if headers else {}
    except json.JSONDecodeError:
        hdrs = {}
    hdrs.setdefault("User-Agent", "WatchdogMCP/1.0")
    try:
        start = time.time()
        if method.upper() == "POST":
            try:
                data = json.loads(body)
                resp = requests.post(url, json=data, headers=hdrs, timeout=15,
                                     allow_redirects=follow_redirects)
            except (json.JSONDecodeError, TypeError):
                resp = requests.post(url, data=body, headers=hdrs, timeout=15,
                                     allow_redirects=follow_redirects)
        elif method.upper() == "PUT":
            resp = requests.put(url, data=body, headers=hdrs, timeout=15,
                                allow_redirects=follow_redirects)
        elif method.upper() == "DELETE":
            resp = requests.delete(url, headers=hdrs, timeout=15,
                                   allow_redirects=follow_redirects)
        else:
            resp = requests.get(url, headers=hdrs, timeout=15,
                                allow_redirects=follow_redirects)
        elapsed = round(time.time() - start, 3)
        return {
            "url": resp.url,
            "status_code": resp.status_code,
            "elapsed": elapsed,
            "content_length": len(resp.text),
            "content_type": resp.headers.get("Content-Type", ""),
            "response_headers": dict(resp.headers),
            "body": resp.text[:5000],
        }
    except requests.RequestException as e:
        return {"url": url, "error": str(e)}


def wafw00f_scan(target_url):
    if not _tool_available("wafw00f"):
        return {"error": "wafw00f not installed"}
    cmd = ["wafw00f", target_url, "-o", "-"]
    result = _run_cmd(cmd, timeout=60)
    return {"output": result["stdout"][-3000:], "returncode": result["returncode"]}


def nmap_scan(target, ports="80,443,8080,8443", scan_type="service"):
    if not _tool_available("nmap"):
        return {"error": "nmap not installed"}
    cmd = ["nmap"]
    if scan_type == "service":
        cmd.append("-sV")
    elif scan_type == "quick":
        cmd.append("-F")
    elif scan_type == "vuln":
        cmd.extend(["--script", "vuln"])
    if ports != "top100":
        cmd.extend(["-p", ports])
    cmd.append(target)
    result = _run_cmd(cmd, timeout=300)
    return {"output": result["stdout"][-5000:], "returncode": result["returncode"]}
