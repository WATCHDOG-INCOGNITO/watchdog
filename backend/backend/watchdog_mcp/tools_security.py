import json
import subprocess
import shutil
import tempfile
import os
import time
import hashlib
from urllib.parse import urljoin
import requests

def _run_cmd(cmd: list, timeout: int = 120) -> dict:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"stdout": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "timeout", "returncode": -1}
    except FileNotFoundError:
        return {"stdout": "", "stderr": f"tool not found: {cmd[0]}", "returncode": -2}

def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None

def register(mcp):


    @mcp.tool()
    def check_tools() -> str:
        """설치된 보안 도구 목록을 확인한다."""
        tools = ["sqlmap", "nuclei", "dalfox", "nmap", "ffuf", "nikto",
                 "gobuster", "dirb", "wpscan", "whatweb", "httpx", "katana",
                 "arjun", "paramspider", "wafw00f", "curl", "chromium", "chromium-browser"]
        status = {}
        for t in tools:
            status[t] = _tool_available(t)
        available = [t for t, v in status.items() if v]
        return json.dumps({"available": available, "total": len(available), "all": status})


    @mcp.tool()
    def sqlmap_scan(target_url: str, params: str = "", method: str = "GET",
                    level: int = 1, risk: int = 1, extra_args: str = "") -> str:
        """sqlmap으로 SQL Injection 취약점을 스캔한다.
        target_url: 전체 URL (예: http://testphp.vulnweb.com/listproducts.php?cat=1)
        params: POST일 때 파라미터 (예: "username=admin&password=test")
        method: GET 또는 POST
        level: 테스트 레벨 (1-5, 높을수록 정밀)
        risk: 리스크 레벨 (1-3, 높을수록 공격적)
        extra_args: 추가 인자 (예: "--dbs --batch")
        """
        if not _tool_available("sqlmap"):
            return json.dumps({"error": "sqlmap not installed"})

        cmd = ["sqlmap", "-u", target_url, "--batch", "--output-dir=/tmp/sqlmap_out",
               f"--level={level}", f"--risk={risk}", "--disable-coloring"]

        if method.upper() == "POST" and params:
            cmd.extend(["--method=POST", f"--data={params}"])

        if extra_args:
            cmd.extend(extra_args.split())

        result = _run_cmd(cmd, timeout=180)
        return json.dumps({
            "command": " ".join(cmd),
            "output": result["stdout"][-5000:],
            "errors": result["stderr"][-2000:] if result["stderr"] else "",
            "returncode": result["returncode"],
        })

    @mcp.tool()
    def sqlmap_dump(target_url: str, database: str = "", table: str = "",
                    extra_args: str = "") -> str:
        """sqlmap으로 데이터베이스/테이블 정보를 추출한다.
        target_url: 취약한 URL
        database: 대상 DB명 (비워두면 전체)
        table: 대상 테이블명
        """
        if not _tool_available("sqlmap"):
            return json.dumps({"error": "sqlmap not installed"})

        cmd = ["sqlmap", "-u", target_url, "--batch", "--disable-coloring"]
        if database:
            cmd.extend(["-D", database])
        if table:
            cmd.extend(["-T", table, "--dump"])
        else:
            cmd.append("--dbs")
        if extra_args:
            cmd.extend(extra_args.split())

        result = _run_cmd(cmd, timeout=180)
        return json.dumps({
            "command": " ".join(cmd),
            "output": result["stdout"][-5000:],
            "returncode": result["returncode"],
        })


    @mcp.tool()
    def nuclei_scan(target_url: str, templates: str = "", severity: str = "",
                    tags: str = "", extra_args: str = "") -> str:
        """nuclei로 템플릿 기반 취약점 스캔을 실행한다.
        target_url: 스캔 대상 URL
        templates: 특정 템플릿 경로 (비워두면 기본 템플릿)
        severity: 심각도 필터 (예: "critical,high,medium")
        tags: 태그 필터 (예: "sqli,xss,cve")
        extra_args: 추가 인자
        """
        if not _tool_available("nuclei"):
            return json.dumps({"error": "nuclei not installed"})

        # -jsonl: 한 줄당 하나의 JSON finding. severity / template-id / matched-at 등 구조화 추출.
        cmd = ["nuclei", "-u", target_url, "-silent", "-nc", "-jsonl"]
        if templates:
            cmd.extend(["-t", templates])
        if severity:
            cmd.extend(["-severity", severity])
        if tags:
            cmd.extend(["-tags", tags])
        if extra_args:
            cmd.extend(extra_args.split())

        result = _run_cmd(cmd, timeout=300)
        findings = []
        severity_counts: dict[str, int] = {}
        for line in result["stdout"].splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                # nuclei 구버전이거나 JSON 모드 미지원 시 raw line 보존
                findings.append({"raw": line})
                continue
            info = obj.get("info") or {}
            sev = (info.get("severity") or obj.get("severity") or "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            findings.append({
                "template_id": obj.get("template-id") or obj.get("templateID"),
                "name": info.get("name"),
                "severity": sev,
                "matched_at": obj.get("matched-at") or obj.get("matched"),
                "type": obj.get("type"),
                "tags": info.get("tags"),
                "description": info.get("description"),
                "reference": info.get("reference"),
                "extracted_results": obj.get("extracted-results"),
                "curl_command": obj.get("curl-command"),
            })

        return json.dumps({
            "command": " ".join(cmd),
            "findings_count": len(findings),
            "severity_counts": severity_counts,
            "findings": findings[-50:],
            "errors": result["stderr"][-1000:] if result["stderr"] else "",
            "returncode": result["returncode"],
        })


    @mcp.tool()
    def dalfox_scan(target_url: str, params: str = "", extra_args: str = "") -> str:
        """dalfox로 XSS 취약점을 스캔한다.
        target_url: 대상 URL (쿼리 파라미터 포함, 예: http://test.com/search?q=test)
        params: POST 파라미터 (비워두면 GET 기반)
        extra_args: 추가 인자 (예: "--blind https://your.xss.ht")
        """
        if not _tool_available("dalfox"):
            return json.dumps({"error": "dalfox not installed"})

        cmd = ["dalfox", "url", target_url, "--silence", "--no-color"]
        if params:
            cmd.extend(["--data", params])
        if extra_args:
            cmd.extend(extra_args.split())

        result = _run_cmd(cmd, timeout=180)
        vulns = []
        for line in result["stdout"].strip().split("\n"):
            if line.strip() and ("POC" in line or "Vuln" in line or "[V]" in line):
                vulns.append(line.strip())

        return json.dumps({
            "command": " ".join(cmd),
            "vulnerabilities": vulns,
            "full_output": result["stdout"][-5000:],
            "returncode": result["returncode"],
        })


    @mcp.tool()
    def http_request(url: str, method: str = "GET", headers: str = "{}",
                     body: str = "", follow_redirects: bool = True) -> str:
        """범용 HTTP 요청을 전송한다. LLM이 직접 만든 페이로드를 보낼 때 사용.
        headers: JSON 문자열
        body: POST 요청 본문
        """
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

            return json.dumps({
                "url": resp.url,
                "status_code": resp.status_code,
                "elapsed": elapsed,
                "content_length": len(resp.text),
                "content_type": resp.headers.get("Content-Type", ""),
                "response_headers": dict(resp.headers),
                "body": resp.text[:5000],
            })
        except requests.RequestException as e:
            return json.dumps({"url": url, "error": str(e)})


    @mcp.tool()
    def run_security_tool(command: str, timeout: int = 120) -> str:
        """보안 도구 명령을 직접 실행한다. 설치된 도구만 사용 가능.
        command: 실행할 명령 (예: "nmap -sV -p 80,443 target.com")
        timeout: 최대 실행 시간(초)

        허용 도구: nmap, sqlmap, nuclei, dalfox, nikto, whatweb, wafw00f,
                  gobuster, ffuf, dirb, httpx, katana, arjun, wpscan, curl, dig, whois
        """
        ALLOWED_TOOLS = {
            "nmap", "sqlmap", "nuclei", "dalfox", "nikto", "whatweb", "wafw00f",
            "gobuster", "ffuf", "dirb", "httpx", "katana", "arjun", "wpscan",
            "curl", "dig", "whois", "paramspider", "subfinder", "amass",
        }

        parts = command.strip().split()
        if not parts:
            return json.dumps({"error": "empty command"})

        tool_name = parts[0]
        if tool_name not in ALLOWED_TOOLS:
            return json.dumps({"error": f"tool '{tool_name}' not in allowed list: {sorted(ALLOWED_TOOLS)}"})

        if not _tool_available(tool_name):
            return json.dumps({"error": f"tool '{tool_name}' not installed"})

        result = _run_cmd(parts, timeout=min(timeout, 300))
        return json.dumps({
            "command": command,
            "stdout": result["stdout"][-8000:],
            "stderr": result["stderr"][-2000:] if result["stderr"] else "",
            "returncode": result["returncode"],
        })


    @mcp.tool()
    def ffuf_scan(target_url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                  mode: str = "dir", extra_args: str = "") -> str:
        """ffuf로 디렉터리 또는 파라미터 퍼징을 실행한다.
        target_url: FUZZ 키워드 포함 URL (예: http://target.com/FUZZ)
                    mode=dir이면 자동으로 끝에 /FUZZ 추가
        wordlist: 워드리스트 경로
        mode: dir(디렉터리), param(파라미터), vhost(가상 호스트)
        extra_args: 추가 인자 (예: "-mc 200,301 -fc 404")
        """
        if not _tool_available("ffuf"):
            return json.dumps({"error": "ffuf not installed"})

        if mode == "dir" and "FUZZ" not in target_url:
            target_url = target_url.rstrip("/") + "/FUZZ"

        cmd = ["ffuf", "-u", target_url, "-w", wordlist, "-c", "-noninteractive", "-of", "json"]
        if extra_args:
            cmd.extend(extra_args.split())

        result = _run_cmd(cmd, timeout=180)

        findings = []
        for line in result["stdout"].strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("{") and "FUZZ" not in line:
                findings.append(line)

        return json.dumps({
            "command": " ".join(cmd),
            "findings": findings[-100:],
            "full_output": result["stdout"][-5000:],
            "returncode": result["returncode"],
        })


    @mcp.tool()
    def nikto_scan(target_url: str, extra_args: str = "") -> str:
        """nikto로 웹 서버 취약점을 스캔한다.
        서버 설정 오류, 위험한 파일, 오래된 소프트웨어 등을 탐지.
        """
        if not _tool_available("nikto"):
            return json.dumps({"error": "nikto not installed"})

        cmd = ["nikto", "-h", target_url, "-nointeractive", "-C", "all"]
        if extra_args:
            cmd.extend(extra_args.split())

        result = _run_cmd(cmd, timeout=300)
        return json.dumps({
            "command": " ".join(cmd),
            "output": result["stdout"][-5000:],
            "returncode": result["returncode"],
        })


    @mcp.tool()
    def whatweb_scan(target_url: str) -> str:
        """whatweb으로 타겟의 기술 스택을 탐지한다.
        웹 서버, 프레임워크, CMS, 프로그래밍 언어, JS 라이브러리 등.
        """
        if not _tool_available("whatweb"):
            return json.dumps({"error": "whatweb not installed"})

        cmd = ["whatweb", target_url, "--color=never", "-v"]
        result = _run_cmd(cmd, timeout=60)
        return json.dumps({
            "command": " ".join(cmd),
            "output": result["stdout"][-3000:],
            "returncode": result["returncode"],
        })


    @mcp.tool()
    def wafw00f_scan(target_url: str) -> str:
        """wafw00f로 WAF(Web Application Firewall) 존재 여부를 탐지한다.
        WAF가 있으면 우회 전략을 세워야 한다.
        """
        if not _tool_available("wafw00f"):
            return json.dumps({"error": "wafw00f not installed"})

        cmd = ["wafw00f", target_url, "-o", "-"]
        result = _run_cmd(cmd, timeout=60)
        return json.dumps({
            "command": " ".join(cmd),
            "output": result["stdout"][-3000:],
            "returncode": result["returncode"],
        })


    @mcp.tool()
    def nmap_scan(target: str, ports: str = "80,443,8080,8443",
                  scan_type: str = "service", extra_args: str = "") -> str:
        """nmap으로 포트 및 서비스 스캔을 실행한다.
        target: IP 또는 도메인
        ports: 포트 범위 (예: "80,443", "1-1000", "top100")
        scan_type: service(-sV), quick(-F), vuln(--script vuln)
        """
        if not _tool_available("nmap"):
            return json.dumps({"error": "nmap not installed"})

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
        if extra_args:
            cmd.extend(extra_args.split())

        result = _run_cmd(cmd, timeout=300)
        return json.dumps({
            "command": " ".join(cmd),
            "output": result["stdout"][-5000:],
            "returncode": result["returncode"],
        })


    @mcp.tool()
    def curl_request(url: str, method: str = "GET", headers: str = "",
                     data: str = "", extra_args: str = "") -> str:
        """curl로 HTTP 요청을 보낸다. 쿠키, 인증, 프록시 등 세밀한 제어 가능.
        headers: "Header1: Value1\\nHeader2: Value2" 형태
        data: POST 데이터
        extra_args: curl 추가 옵션 (예: "-k --proxy http://127.0.0.1:8080")
        """
        if not _tool_available("curl"):
            return json.dumps({"error": "curl not installed"})

        cmd = ["curl", "-s", "-S", "-w", "\n---HTTP_CODE:%{http_code}---TIME:%{time_total}---",
               "-X", method.upper()]

        for h in headers.split("\n"):
            h = h.strip()
            if h:
                cmd.extend(["-H", h])

        if data:
            cmd.extend(["-d", data])

        if extra_args:
            cmd.extend(extra_args.split())

        cmd.append(url)

        result = _run_cmd(cmd, timeout=30)
        return json.dumps({
            "command": " ".join(cmd[:10]) + "...",
            "output": result["stdout"][-5000:],
            "errors": result["stderr"][-1000:] if result["stderr"] else "",
            "returncode": result["returncode"],
        })

