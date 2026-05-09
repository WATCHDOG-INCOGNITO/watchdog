import html
import re
from collections import OrderedDict
from urllib.parse import urlparse


MAX_SUMMARY_CHARS = 800
MAX_CONSTRAINTS = 12
MAX_MARKDOWN_CHARS = 4000

SECTION_RULES = (
    (
        "Forbidden",
        (
            "forbidden",
            "prohibited",
            "do not",
            "don't",
            "must not",
            "never",
            "no ",
            "without permission",
            "금지",
            "하지 마",
            "하면 안",
            "허용되지 않",
            "불가",
        ),
    ),
    (
        "Out of Scope",
        (
            "out of scope",
            "out-of-scope",
            "not in scope",
            "excluded",
            "third party",
            "third-party",
            "아웃 오브 스코프",
            "범위 제외",
            "제외 대상",
            "테스트 금지 대상",
        ),
    ),
    (
        "Allowed",
        (
            "allowed",
            "in scope",
            "in-scope",
            "permitted",
            "you may",
            "can test",
            "허용",
            "가능",
            "인스코프",
            "테스트 가능",
            "수행 가능",
        ),
    ),
    (
        "Notes",
        (
            "rate limit",
            "rate-limit",
            "avoid",
            "report",
            "disclose",
            "contact",
            "authentication",
            "login",
            "credential",
            "safe harbor",
            "속도 제한",
            "요청 제한",
            "주의",
            "제보",
            "연락",
            "인증",
            "로그인",
            "자격 증명",
            "세이프 하버",
        ),
    ),
)

NOISE_PATTERNS = (
    r"^\s*(home|menu|search|sign in|log in|log out|register|skip to content)\s*$",
    r"^\s*(privacy policy|terms of service|all rights reserved)\s*$",
    r"^\s*(cookie preferences|accept all cookies|manage cookies)\s*$",
)

HOST_TOKEN_RE = re.compile(
    r"\b(?:localhost|(?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\b",
    re.IGNORECASE,
)
WILDCARD_HOST_RE = re.compile(
    r"(?<![a-z0-9-])\*\.((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\b",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s<>'\"\])]+", re.IGNORECASE)

SCANNER_BLOCK_TOOL_NAMES = (
    "sqlmap_scan",
    "nuclei_scan",
    "dalfox_scan",
    "ffuf_scan",
    "nikto_scan",
    "nmap_scan",
    "whatweb_scan",
    "wafw00f_scan",
)

SCANNER_TOOL_NAMES = SCANNER_BLOCK_TOOL_NAMES + ("multi_http_probe",)
SOFT_SCANNER_HINTS = (
    "automated scanner", "automated scanners", "scanner", "automation", "noisy automation",
    "rate limit", "rate-limit", "slow down", "too many requests",
    "자동화", "스캐너", "과도한 요청", "속도 제한", "요청 제한", "노이즈", "대량 요청",
)
HARD_NEGATION_HINTS = (
    "forbidden", "prohibited", "do not", "don't", "must not", "never", "not allowed",
    "without permission", "금지", "하지 마", "하면 안", "허용되지 않", "불가", "금합니다",
)
BRUTE_FORCE_HINTS = (
    "brute force", "bruteforce", "credential stuffing", "password spraying",
    "무차별 대입", "브루트포스", "크리덴셜 스터핑", "패스워드 스프레이",
)
DOS_HINTS = (
    "denial of service", "dos", "stress test", "stress-testing", "load test", "flood",
    "서비스 거부", "부하 테스트", "스트레스 테스트", "과부하", "플러드",
)
PORT_SCAN_HINTS = (
    "port scan", "port scanning", "network scan", "service scan",
    "포트 스캔", "네트워크 스캔", "서비스 스캔",
)


def _strip_html(raw_text: str) -> str:
    text = html.unescape(raw_text or "")
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", text)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</(p|div|li|tr|section|article|h[1-6])\s*>", "\n", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return text


def _clean_lines(text: str) -> list[str]:
    lines: list[str] = []
    seen = set()

    for raw_line in text.splitlines():
        line = raw_line.replace("\xa0", " ")
        line = re.sub(r"\s+", " ", line).strip(" \t-*\u2022")
        if not line:
            continue
        lowered = line.lower()
        if any(re.match(pattern, lowered) for pattern in NOISE_PATTERNS):
            continue
        if len(line) < 3:
            continue
        if lowered in seen:
            continue
        seen.add(lowered)
        lines.append(line)
    return lines


def _normalize_host(host: str) -> str:
    value = (host or "").strip().strip(".,;:()[]{}<>").lower()
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
        value = (parsed.hostname or parsed.netloc or "").lower()
    if ":" in value and value.count(":") == 1 and not re.match(r"^\d+\.\d+\.\d+\.\d+$", value):
        value = value.split(":", 1)[0]
    return value.strip(".")


def _extract_hosts(text: str) -> list[str]:
    found: list[str] = []
    seen = set()

    for match in URL_RE.findall(text or ""):
        host = _normalize_host(match)
        if host and host not in seen:
            seen.add(host)
            found.append(host)

    for match in HOST_TOKEN_RE.findall(text or ""):
        host = _normalize_host(match)
        if host and host not in seen:
            seen.add(host)
            found.append(host)
    return found


def _extract_scope_hosts(lines: list[str]) -> list[str]:
    hosts: list[str] = []
    seen = set()
    for line in lines:
        for host in _extract_hosts(line):
            if host not in seen:
                seen.add(host)
                hosts.append(host)
    return hosts


def _extract_wildcard_hosts(lines: list[str]) -> list[str]:
    hosts: list[str] = []
    seen = set()
    for line in lines:
        for match in WILDCARD_HOST_RE.findall(line or ""):
            host = _normalize_host(match)
            if host and host not in seen:
                seen.add(host)
                hosts.append(host)
    return hosts


def _extract_url_prefixes(lines: list[str]) -> list[str]:
    prefixes: list[str] = []
    seen = set()
    for line in lines:
        for match in URL_RE.findall(line or ""):
            parsed = urlparse(match)
            if not parsed.scheme or not parsed.netloc:
                continue
            prefix = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path or ''}"
            prefix = prefix.rstrip("/")
            if prefix and prefix not in seen:
                seen.add(prefix)
                prefixes.append(prefix)
    return prefixes


def _has_any(line: str, keywords: tuple[str, ...]) -> bool:
    lowered = (line or "").lower()
    return any(keyword in lowered for keyword in keywords)


def _build_enforcement(sections: OrderedDict[str, list[str]]) -> dict:
    allowed_hosts = _extract_scope_hosts(sections["Allowed"])
    out_of_scope_hosts = _extract_scope_hosts(sections["Out of Scope"])
    allowed_wildcard_hosts = _extract_wildcard_hosts(sections["Allowed"])
    out_of_scope_wildcard_hosts = _extract_wildcard_hosts(sections["Out of Scope"])
    allowed_url_prefixes = _extract_url_prefixes(sections["Allowed"])
    out_of_scope_url_prefixes = _extract_url_prefixes(sections["Out of Scope"])
    blocked_tool_set = set()
    warned_tool_set = set()
    max_parallel_probes = None
    recommended_max_parallel_probes = None
    rationale: list[str] = []

    constraint_lines = sections["Forbidden"] + sections["Out of Scope"] + sections["Notes"]
    for line in constraint_lines:
        hard_negation = _has_any(line, HARD_NEGATION_HINTS)
        scanner_hint = _has_any(line, SOFT_SCANNER_HINTS)
        brute_force_hint = _has_any(line, BRUTE_FORCE_HINTS)
        dos_hint = _has_any(line, DOS_HINTS)
        port_scan_hint = _has_any(line, PORT_SCAN_HINTS)
        rate_limit_hint = _has_any(line, ("rate limit", "rate-limit", "속도 제한", "요청 제한", "과도한 요청", "avoid noisy automation", "노이즈"))

        if scanner_hint and hard_negation:
            blocked_tool_set.update(SCANNER_BLOCK_TOOL_NAMES)
            rationale.append(line)
        elif scanner_hint:
            warned_tool_set.update(SCANNER_TOOL_NAMES)
            rationale.append(line)

        if brute_force_hint and hard_negation:
            blocked_tool_set.add("ffuf_scan")
            rationale.append(line)
        elif brute_force_hint:
            warned_tool_set.add("ffuf_scan")
            rationale.append(line)

        if dos_hint and hard_negation:
            blocked_tool_set.update({"multi_http_probe", "ffuf_scan", "nmap_scan"})
            rationale.append(line)
        elif dos_hint:
            warned_tool_set.update({"multi_http_probe", "ffuf_scan", "nmap_scan"})
            rationale.append(line)

        if port_scan_hint and hard_negation:
            blocked_tool_set.add("nmap_scan")
            rationale.append(line)
        elif port_scan_hint:
            warned_tool_set.add("nmap_scan")
            rationale.append(line)

        if rate_limit_hint and hard_negation:
            max_parallel_probes = 2 if max_parallel_probes is None else min(max_parallel_probes, 2)
            warned_tool_set.add("multi_http_probe")
            rationale.append(line)
        elif rate_limit_hint:
            recommended_max_parallel_probes = (
                3 if recommended_max_parallel_probes is None else min(recommended_max_parallel_probes, 3)
            )
            warned_tool_set.add("multi_http_probe")
            rationale.append(line)

    return {
        "mode": "balanced",
        "allowed_hosts": allowed_hosts,
        "out_of_scope_hosts": out_of_scope_hosts,
        "allowed_wildcard_hosts": allowed_wildcard_hosts,
        "out_of_scope_wildcard_hosts": out_of_scope_wildcard_hosts,
        "allowed_url_prefixes": allowed_url_prefixes,
        "out_of_scope_url_prefixes": out_of_scope_url_prefixes,
        "blocked_tools": sorted(blocked_tool_set),
        "warned_tools": sorted(warned_tool_set - blocked_tool_set),
        "max_parallel_probes": max_parallel_probes,
        "recommended_max_parallel_probes": recommended_max_parallel_probes,
        "rationale": rationale[:12],
    }


def _categorize_line(line: str) -> str:
    lowered = line.lower()
    for section, keywords in SECTION_RULES:
        if any(keyword in lowered for keyword in keywords):
            return section
    return "Summary"


def _build_sections(lines: list[str]) -> OrderedDict[str, list[str]]:
    sections: OrderedDict[str, list[str]] = OrderedDict(
        (name, []) for name in ("Summary", "Allowed", "Forbidden", "Out of Scope", "Notes")
    )
    for line in lines:
        sections[_categorize_line(line)].append(line)
    return sections


def _sentence_summary(lines: list[str]) -> str:
    summary_lines = []
    for line in lines:
        summary_lines.append(line)
        joined = " ".join(summary_lines)
        if len(joined) >= MAX_SUMMARY_CHARS:
            break
    summary = " ".join(summary_lines).strip()
    if len(summary) > MAX_SUMMARY_CHARS:
        summary = summary[: MAX_SUMMARY_CHARS - 3].rstrip() + "..."
    return summary


def _extract_constraints(sections: OrderedDict[str, list[str]]) -> list[str]:
    ordered = sections["Forbidden"] + sections["Out of Scope"] + sections["Notes"]
    constraints: list[str] = []
    seen = set()
    for line in ordered:
        normalized = line.strip()
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        constraints.append(normalized)
        if len(constraints) >= MAX_CONSTRAINTS:
            break
    return constraints


def _to_markdown(sections: OrderedDict[str, list[str]]) -> str:
    chunks: list[str] = []
    for section, lines in sections.items():
        if not lines:
            continue
        chunks.append(f"## {section}")
        for line in lines:
            chunks.append(f"- {line}")
        chunks.append("")
    markdown = "\n".join(chunks).strip()
    if len(markdown) > MAX_MARKDOWN_CHARS:
        markdown = markdown[: MAX_MARKDOWN_CHARS - 3].rstrip() + "..."
    return markdown


def normalize_guardrail_text(raw_text: str) -> dict:
    raw_text = (raw_text or "").strip()
    if not raw_text:
        return {
            "raw": "",
            "cleaned_text": "",
            "markdown": "",
            "summary": "",
            "constraints": [],
            "enforcement": {
                "mode": "balanced",
                "allowed_hosts": [],
                "out_of_scope_hosts": [],
                "allowed_wildcard_hosts": [],
                "out_of_scope_wildcard_hosts": [],
                "allowed_url_prefixes": [],
                "out_of_scope_url_prefixes": [],
                "blocked_tools": [],
                "warned_tools": [],
                "max_parallel_probes": None,
                "recommended_max_parallel_probes": None,
                "rationale": [],
            },
        }

    stripped = _strip_html(raw_text)
    lines = _clean_lines(stripped)
    sections = _build_sections(lines)
    cleaned_text = "\n".join(lines)
    return {
        "raw": raw_text,
        "cleaned_text": cleaned_text,
        "markdown": _to_markdown(sections),
        "summary": _sentence_summary(lines),
        "constraints": _extract_constraints(sections),
        "enforcement": _build_enforcement(sections),
    }
