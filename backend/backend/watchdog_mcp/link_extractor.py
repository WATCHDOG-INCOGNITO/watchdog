"""Shared link extraction from HTTP responses.

Used by MCP HTTP tools (full body, at source) and mcp_agent.py (compact fallback).
"""

import re
from urllib.parse import urljoin, urlparse

_RE_HTML = [
    re.compile(r'<a\s[^>]*?href\s*=\s*["\']([^"\'#][^"\']*)', re.I),
    re.compile(r'<form\s[^>]*?action\s*=\s*["\']([^"\'#][^"\']*)', re.I),
    re.compile(r'<link\s[^>]*?href\s*=\s*["\']([^"\'#][^"\']*)', re.I),
    re.compile(r'<iframe\s[^>]*?src\s*=\s*["\']([^"\'#][^"\']*)', re.I),
    re.compile(r'<script\s[^>]*?src\s*=\s*["\']([^"\'#][^"\']*)', re.I),
    re.compile(r'<meta\s[^>]*?content\s*=\s*["\'][^"\']*url\s*=\s*([^"\';\s]+)', re.I),
    re.compile(r'(?:window\.location|location\.href)\s*=\s*["\']([^"\']+)', re.I),
]
_RE_JS = [
    # fetch/axios with relative paths
    re.compile(r'''(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*[`'"](\/[^`'"]*?)[`'"]'''),
    # fetch/axios with absolute URLs
    re.compile(r'''(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*[`'"](https?://[^`'"]+)[`'"]'''),
    # XMLHttpRequest .open("METHOD", "/path")
    re.compile(r'''\.open\s*\(\s*[`'"]\w+[`'"]\s*,\s*[`'"](\/[^`'"]+)[`'"]'''),
    # XMLHttpRequest .open("METHOD", "https://...")
    re.compile(r'''\.open\s*\(\s*[`'"]\w+[`'"]\s*,\s*[`'"](https?://[^`'"]+)[`'"]'''),
    # Template literals: `${baseUrl}/api/...` → capture /api/... portion
    re.compile(r'''[`'"](?:\$\{[^}]+\})?(\/api\/[^`'"]{2,})[`'"]'''),
    # Quoted URL-like strings in JS: "/api/v1/..." or "/admin/..."
    re.compile(r'''[`'"](\/(?:api|v[0-9]+|admin|auth|graphql|rest|internal|private|debug|swagger|docs)[\/][^`'"]{1,})[`'"]'''),
]
# url: key matching is handled by _extract_depth1_js_urls (depth-aware, top-level only)
_RE_JS_BASE_URL = re.compile(
    r'''baseURL\s*:\s*[`'"](https?://[^`'"]{4,})[`'"]''',
)
_RE_JS_KV_BASEURL = re.compile(r'''baseURL\s*:\s*[`'"](https?://[^`'"]{4,})[`'"]''')
_RE_JS_KV_URL = re.compile(r'''(?<!\w)url\s*:\s*[`'"](\/[^`'"]{1,})[`'"]''')


def _extract_baseurl_url_pairs(body: str) -> list[str]:
    """Find {baseURL: "...", url: "/..."} pairs within the same JS object literal.

    Uses brace-depth tracking to isolate object blocks. Collects only the
    depth-1 text (top-level keys, skipping nested sub-objects), then applies
    regex only to that text. This prevents nested sub-object keys from matching.
    Handles key order freedom.
    """
    results: list[str] = []
    i = 0
    length = len(body)
    while i < length:
        if body[i] == "{":
            depth = 1
            block_start = i
            i += 1
            depth1_parts: list[str] = []
            seg_start = i
            in_string = ""
            while i < length and depth > 0:
                ch = body[i]
                if in_string:
                    if ch == "\\" and i + 1 < length:
                        i += 2
                        continue
                    if ch == in_string:
                        in_string = ""
                elif ch in ('"', "'", "`"):
                    in_string = ch
                elif ch == "{":
                    if depth == 1:
                        depth1_parts.append(body[seg_start:i])
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 1:
                        seg_start = i + 1
                i += 1
                if i - block_start > 2000:
                    break
            if depth == 0:
                depth1_parts.append(body[seg_start:i - 1])
            top_text = " ".join(depth1_parts)
            base_urls = _RE_JS_KV_BASEURL.findall(top_text)
            urls = _RE_JS_KV_URL.findall(top_text)
            if base_urls and urls:
                for bu in base_urls:
                    for u in urls:
                        results.append(bu.rstrip("/") + u)
        else:
            i += 1
    return results


def _extract_depth1_js_urls(body: str) -> list[str]:
    """Extract `url: "/path"` values only from depth-1 of JS object literals.

    Prevents nested sub-object keys like `meta:{url:"/nested"}` from being
    treated as endpoints while still capturing top-level `{url:"/path"}`.
    """
    results: list[str] = []
    i = 0
    length = len(body)
    while i < length:
        if body[i] == "{":
            depth = 1
            block_start = i
            i += 1
            depth1_parts: list[str] = []
            seg_start = i
            in_string = ""
            while i < length and depth > 0:
                ch = body[i]
                if in_string:
                    if ch == "\\" and i + 1 < length:
                        i += 2
                        continue
                    if ch == in_string:
                        in_string = ""
                elif ch in ('"', "'", "`"):
                    in_string = ch
                elif ch == "{":
                    if depth == 1:
                        depth1_parts.append(body[seg_start:i])
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 1:
                        seg_start = i + 1
                i += 1
                if i - block_start > 3000:
                    break
            if depth == 0:
                depth1_parts.append(body[seg_start:i - 1])
            top_text = " ".join(depth1_parts)
            for m in _RE_JS_KV_URL.findall(top_text):
                results.append(m)
        else:
            i += 1
    return results

_RE_JSON = re.compile(
    r'"(?:href|url|uri|link|redirect|next|action|src|endpoint|path)"\s*:\s*"(\/[^"]{2,}|https?://[^"]{4,})"',
    re.I,
)

_STATIC_EXT = frozenset({
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".avif",
    ".mp4", ".mp3", ".pdf",
})


_RE_HASH_ROUTE = re.compile(r'(?:href|action|src)\s*=\s*["\']([#/][#/][^"\']{1,})', re.I)


def extract_links(
    body: str,
    content_type: str = "",
    response_headers: dict | None = None,
    request_url: str = "",
    limit: int = 50,
) -> list[str]:
    """Extract URLs/paths from an HTTP response.

    Operates on the FULL response body (call before truncation).
    Returns deduplicated, sorted list of discovered paths/URLs (static assets filtered).
    """
    links, _ = extract_links_and_hashes(body, content_type, response_headers, request_url, limit)
    return links


def extract_links_and_hashes(
    body: str,
    content_type: str = "",
    response_headers: dict | None = None,
    request_url: str = "",
    limit: int = 50,
) -> tuple[list[str], list[str]]:
    """Extract URLs/paths AND SPA hash routes from an HTTP response.

    Returns (links, hash_routes) where:
    - links: server-side paths/URLs suitable for HTTP requests
    - hash_routes: SPA fragment routes (#/admin, /#/settings) that need browser navigation
    """
    found: set[str] = set()
    hash_routes: set[str] = set()
    ct_lower = (content_type or "").lower()

    # 1. Response headers
    for hdr_name in ("location", "link", "refresh", "content-location"):
        val = ""
        for k, v in (response_headers or {}).items():
            if k.lower() == hdr_name:
                val = str(v)
                break
        if val:
            if hdr_name == "link":
                for m in re.findall(r'<([^>]+)>', val):
                    found.add(m)
            elif hdr_name == "refresh" and "url=" in val.lower():
                idx = val.lower().index("url=")
                found.add(val[idx + 4:].strip().strip("'\""))
            else:
                found.add(val.strip())

    # 2. HTML body
    is_html = body and ("html" in ct_lower or body.lstrip()[:15].lower().startswith(("<!doctype", "<html")))
    if is_html:
        for pat in _RE_HTML:
            for m in pat.findall(body):
                found.add(m)

    # 3. JSON body
    if body and ("json" in ct_lower or body.lstrip()[:1] in ("{", "[")):
        for m in _RE_JSON.findall(body):
            found.add(m)

    # 4. JS patterns
    js_relative: list[str] = []
    if body and ("javascript" in ct_lower or "html" in ct_lower):
        for pat in _RE_JS:
            for m in pat.findall(body):
                found.add(m)
                if m.startswith("/"):
                    js_relative.append(m)

    # 4b. Object-literal depth-aware extraction (top-level keys only)
    if body and ("javascript" in ct_lower or "html" in ct_lower):
        for bu in _RE_JS_BASE_URL.findall(body):
            found.add(bu)
        for combined in _extract_baseurl_url_pairs(body):
            found.add(combined)
        for url_val in _extract_depth1_js_urls(body):
            found.add(url_val)

    # 5. SPA hash routes — collect separately from HTML
    if is_html and body:
        for m in _RE_HASH_ROUTE.findall(body):
            m = m.strip()
            if m.startswith(("#/", "/#")):
                route = m.lstrip("/#").lstrip("/")
                if route and len(route) > 1:
                    hash_routes.add("#/" + route)

    # Normalize regular links
    normalized: set[str] = set()
    base = request_url or ""
    for raw in found:
        raw = raw.strip()
        if not raw or raw.startswith(("data:", "javascript:", "mailto:", "tel:")):
            continue
        # Capture hash routes before skipping
        if raw.startswith(("#/", "/#")):
            route = raw.lstrip("/#").lstrip("/")
            if route and len(route) > 1:
                hash_routes.add("#/" + route)
            continue
        if raw.startswith("#"):
            continue
        # Split "path#/route" → path goes to links, hash part to hash_routes
        if "#/" in raw and not raw.startswith(("http://", "https://")):
            path_part_before_hash, frag = raw.split("#", 1)
            if frag.startswith("/") and len(frag) > 2:
                hash_routes.add("#" + frag)
            if path_part_before_hash:
                raw = path_part_before_hash
            else:
                continue
        elif "#/" in raw and raw.startswith(("http://", "https://")):
            url_before_hash, frag = raw.split("#", 1)
            if frag.startswith("/") and len(frag) > 2:
                hash_routes.add("#" + frag)
            raw = url_before_hash
        # Strip remaining non-SPA fragments from URLs
        if "#" in raw:
            raw = raw.split("#", 1)[0]
            if not raw:
                continue
        if raw.startswith("//"):
            raw = "https:" + raw
        if not raw.startswith(("http://", "https://", "/")):
            if base:
                raw = urljoin(base, raw)
            else:
                continue
        # Same-origin absolute → path
        if raw.startswith(("http://", "https://")) and base:
            try:
                raw_p = urlparse(raw)
                base_p = urlparse(base)
                if raw_p.netloc.lower() == base_p.netloc.lower():
                    raw = raw_p.path + ("?" + raw_p.query if raw_p.query else "")
            except Exception:
                pass
        # Filter static assets
        try:
            path_part = urlparse(raw).path if raw.startswith("http") else raw.split("?")[0]
            ext = "." + path_part.rsplit(".", 1)[-1].lower() if "." in path_part.rsplit("/", 1)[-1] else ""
            if ext in _STATIC_EXT:
                continue
        except Exception:
            pass
        normalized.add(raw)

    return sorted(normalized)[:limit], sorted(hash_routes)[:20]
