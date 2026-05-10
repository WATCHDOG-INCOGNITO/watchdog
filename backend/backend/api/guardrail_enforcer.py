import json
from urllib.parse import urlparse


HTTP_URL_TOOLS = {
    "http_request",
    "curl_request",
    "http_session_request",
    "browser_navigate",
    "sqlmap_scan",
    "nuclei_scan",
    "dalfox_scan",
    "ffuf_scan",
    "nikto_scan",
    "whatweb_scan",
    "wafw00f_scan",
}

HOST_TARGET_TOOLS = HTTP_URL_TOOLS | {"nmap_scan"}


def _normalize_guardrail_host(value: str) -> str:
    host = (value or "").strip().lower()
    if not host:
        return ""
    parsed = urlparse(host if "://" in host else f"http://{host}")
    return (parsed.hostname or parsed.netloc or "").strip().lower().strip(".")


def _normalize_guardrail_url(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urlparse(text if "://" in text else f"http://{text}")
    if not parsed.scheme or not parsed.netloc:
        return ""
    path = parsed.path or ""
    normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"
    return normalized.rstrip("/")


def _host_matches_exact(host: str, rule_host: str) -> bool:
    normalized_host = _normalize_guardrail_host(host)
    normalized_rule = _normalize_guardrail_host(rule_host)
    return bool(normalized_host and normalized_rule and normalized_host == normalized_rule)


def _host_matches_wildcard(host: str, wildcard_host: str) -> bool:
    normalized_host = _normalize_guardrail_host(host)
    normalized_rule = _normalize_guardrail_host(wildcard_host)
    if not normalized_host or not normalized_rule:
        return False
    return normalized_host.endswith(f".{normalized_rule}")


def _url_matches_prefix(url: str, prefix: str) -> bool:
    normalized_url = _normalize_guardrail_url(url)
    normalized_prefix = _normalize_guardrail_url(prefix)
    if not normalized_url or not normalized_prefix:
        return False

    url_parsed = urlparse(normalized_url)
    prefix_parsed = urlparse(normalized_prefix)
    if (url_parsed.scheme, url_parsed.netloc) != (prefix_parsed.scheme, prefix_parsed.netloc):
        return False

    prefix_path = (prefix_parsed.path or "").rstrip("/")
    url_path = (url_parsed.path or "").rstrip("/")
    if not prefix_path:
        return True
    return url_path == prefix_path or url_path.startswith(f"{prefix_path}/")


def _extract_tool_hosts(tool_name: str, tool_args: dict) -> list[str]:
    hosts: list[str] = []
    seen = set()

    def add_host_from_value(value):
        host = _normalize_guardrail_host(str(value or ""))
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)

    if tool_name in HOST_TARGET_TOOLS:
        for key in ("url", "target_url", "target"):
            if key in tool_args:
                add_host_from_value(tool_args.get(key))

    if tool_name == "multi_http_probe":
        requests_json = tool_args.get("requests_json") or ""
        try:
            reqs = json.loads(requests_json) if isinstance(requests_json, str) else requests_json
        except Exception:
            reqs = []
        if isinstance(reqs, list):
            for item in reqs:
                if isinstance(item, dict):
                    add_host_from_value(item.get("url"))

    return hosts


def _extract_tool_urls(tool_name: str, tool_args: dict) -> list[str]:
    urls: list[str] = []
    seen = set()

    def add_url(value):
        normalized = _normalize_guardrail_url(value)
        if normalized and normalized not in seen:
            seen.add(normalized)
            urls.append(normalized)

    if tool_name in HTTP_URL_TOOLS:
        for key in ("url", "target_url"):
            if key in tool_args:
                add_url(tool_args.get(key))

    if tool_name == "multi_http_probe":
        requests_json = tool_args.get("requests_json") or ""
        try:
            reqs = json.loads(requests_json) if isinstance(requests_json, str) else requests_json
        except Exception:
            reqs = []
        if isinstance(reqs, list):
            for item in reqs:
                if isinstance(item, dict):
                    add_url(item.get("url"))

    return urls


def guardrail_decision(scan_run, tool_name: str, tool_args: dict) -> dict:
    decision = {"action": "allow", "messages": []}
    try:
        config = scan_run.config or {}
    except Exception:
        config = {}
    if not isinstance(config, dict):
        return decision

    guardrail = config.get("guardrail")
    if not isinstance(guardrail, dict):
        return decision

    enforcement = guardrail.get("enforcement") or {}
    if not isinstance(enforcement, dict):
        return decision

    mode = str(config.get("guardrail_enforcement_mode") or enforcement.get("mode") or "balanced").strip().lower()
    if mode not in {"balanced", "strict"}:
        mode = "balanced"

    blocked_tools = {
        str(name).strip() for name in (enforcement.get("blocked_tools") or []) if str(name).strip()
    }
    warned_tools = {
        str(name).strip() for name in (enforcement.get("warned_tools") or []) if str(name).strip()
    }
    rationale = enforcement.get("rationale") or ["program policy"]

    if tool_name in blocked_tools:
        decision["action"] = "block"
        decision["messages"].append(
            f"Guardrail blocked tool `{tool_name}`. Policy rationale: {rationale[0]}"
        )
        return decision

    allowed_hosts = [
        _normalize_guardrail_host(host) for host in (enforcement.get("allowed_hosts") or [])
        if _normalize_guardrail_host(host)
    ]
    out_of_scope_hosts = [
        _normalize_guardrail_host(host) for host in (enforcement.get("out_of_scope_hosts") or [])
        if _normalize_guardrail_host(host)
    ]
    allowed_wildcard_hosts = [
        _normalize_guardrail_host(host) for host in (enforcement.get("allowed_wildcard_hosts") or [])
        if _normalize_guardrail_host(host)
    ]
    out_of_scope_wildcard_hosts = [
        _normalize_guardrail_host(host) for host in (enforcement.get("out_of_scope_wildcard_hosts") or [])
        if _normalize_guardrail_host(host)
    ]
    allowed_url_prefixes = [
        str(v).rstrip("/") for v in (enforcement.get("allowed_url_prefixes") or []) if str(v).strip()
    ]
    out_of_scope_url_prefixes = [
        str(v).rstrip("/") for v in (enforcement.get("out_of_scope_url_prefixes") or []) if str(v).strip()
    ]
    tool_hosts = _extract_tool_hosts(tool_name, tool_args)
    tool_urls = _extract_tool_urls(tool_name, tool_args)

    for url in tool_urls:
        if any(_url_matches_prefix(url, prefix) for prefix in out_of_scope_url_prefixes):
            decision["action"] = "block"
            decision["messages"].append(
                f"Guardrail blocked URL `{url}` because it matches an out-of-scope policy prefix."
            )
            return decision

    for host in tool_hosts:
        if any(_host_matches_exact(host, blocked_host) for blocked_host in out_of_scope_hosts):
            decision["action"] = "block"
            decision["messages"].append(f"Guardrail blocked host `{host}` because it is marked out of scope.")
            return decision
        if any(_host_matches_wildcard(host, blocked_host) for blocked_host in out_of_scope_wildcard_hosts):
            decision["action"] = "block"
            decision["messages"].append(
                f"Guardrail blocked host `{host}` because it matches an out-of-scope wildcard host."
            )
            return decision

    if allowed_url_prefixes:
        for url in tool_urls:
            if not any(_url_matches_prefix(url, prefix) for prefix in allowed_url_prefixes):
                decision["action"] = "block"
                decision["messages"].append(
                    f"Guardrail blocked URL `{url}` because it is outside the declared in-scope URL prefixes."
                )
                return decision

    if allowed_hosts or allowed_wildcard_hosts:
        for host in tool_hosts:
            if any(_host_matches_exact(host, allowed_host) for allowed_host in allowed_hosts):
                continue
            if any(_host_matches_wildcard(host, allowed_host) for allowed_host in allowed_wildcard_hosts):
                continue
            decision["action"] = "block"
            scope_parts = allowed_hosts + [f"*.{wildcard_host}" for wildcard_host in allowed_wildcard_hosts]
            decision["messages"].append(
                f"Guardrail blocked host `{host}` because it is outside the declared in-scope hosts: "
                f"{', '.join(scope_parts)}"
            )
            return decision

    max_parallel_probes = enforcement.get("max_parallel_probes")
    recommended_max_parallel_probes = enforcement.get("recommended_max_parallel_probes")
    if tool_name == "multi_http_probe":
        try:
            requested = int(tool_args.get("max_concurrent") or 8)
        except Exception:
            requested = 8
        if max_parallel_probes is not None and requested > int(max_parallel_probes):
            decision["action"] = "block"
            decision["messages"].append(
                f"Guardrail blocked `multi_http_probe` with max_concurrent={requested}. "
                f"Policy allows at most {int(max_parallel_probes)} concurrent probes."
            )
            return decision
        if recommended_max_parallel_probes is not None and requested > int(recommended_max_parallel_probes):
            if mode == "strict":
                decision["action"] = "block"
                decision["messages"].append(
                    f"Guardrail blocked `multi_http_probe` with max_concurrent={requested}. "
                    f"Recommended safe limit is {int(recommended_max_parallel_probes)} in this program."
                )
                return decision
            decision["action"] = "warn"
            decision["messages"].append(
                f"Guardrail warning: `multi_http_probe` requested max_concurrent={requested}. "
                f"Program policy suggests staying at or below {int(recommended_max_parallel_probes)}."
            )

    if tool_name in warned_tools and decision["action"] == "allow":
        decision["action"] = "warn"
        decision["messages"].append(
            f"Guardrail warning: `{tool_name}` may be sensitive under this program's policy. "
            f"Reason: {rationale[0]}"
        )

    return decision
