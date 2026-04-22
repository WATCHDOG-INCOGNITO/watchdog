import json
import time
import hashlib
from asgiref.sync import sync_to_async

_browser = None
_context = None
_page = None
_network_log = []
_custom_user_agent: str | None = None

def _ensure_browser():
    global _browser, _context, _page, _network_log
    if _page is not None:
        return

    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    _browser = pw.chromium.launch(
        headless=True,
        args=["--no-sandbox", "--disable-dev-shm-usage"],
    )
    ua = _custom_user_agent or "WatchdogBrowser/1.0"
    _context = _browser.new_context(
        user_agent=ua,
        ignore_https_errors=True,
        viewport={"width": 1280, "height": 720},
    )
    _page = _context.new_page()
    _network_log = []

    def _on_request(req):
        _network_log.append({
            "type": "request",
            "method": req.method,
            "url": req.url,
            "post_data": req.post_data[:500] if req.post_data else None,
            "resource_type": req.resource_type,
            "timestamp": time.time(),
        })

    def _on_response(resp):
        _network_log.append({
            "type": "response",
            "url": resp.url,
            "status": resp.status,
            "content_type": resp.headers.get("content-type", ""),
            "timestamp": time.time(),
        })

    _page.on("request", _on_request)
    _page.on("response", _on_response)

def register(mcp):

    @mcp.tool()
    async def browser_set_user_agent(user_agent: str) -> str:
        """브라우저의 User-Agent를 변경한다. 버그바운티 식별 등에 사용.
        이미 브라우저가 열려 있으면 새 context 로 재생성한다.
        browser_navigate 전에 호출해야 효과가 있다.
        """
        global _custom_user_agent, _browser, _context, _page, _network_log

        def _sync():
            global _custom_user_agent, _browser, _context, _page, _network_log
            _custom_user_agent = user_agent.strip() if user_agent else None
            if _page is not None:
                _page.close()
                _context.close()
                ua = _custom_user_agent or "WatchdogBrowser/1.0"
                _context = _browser.new_context(
                    user_agent=ua,
                    ignore_https_errors=True,
                    viewport={"width": 1280, "height": 720},
                )
                _page = _context.new_page()
                _network_log = []
            return json.dumps({"user_agent": _custom_user_agent or "WatchdogBrowser/1.0", "applied": True})

        return await sync_to_async(_sync, thread_sensitive=False)()

    @mcp.tool()
    async def browser_navigate(url: str, wait_until: str = "networkidle") -> str:
        """브라우저로 URL에 접속한다. JS가 실행된 후 상태를 반환한다.
        wait_until: load, domcontentloaded, networkidle
        접속 후 네트워크 탭 캡처가 자동으로 시작된다.
        """
        def _sync():
            _ensure_browser()
            _network_log.clear()

            try:
                _page.goto(url, wait_until=wait_until, timeout=30000)
                _page.wait_for_timeout(2000)
                title = _page.title()
                current_url = _page.url

                return json.dumps({
                    "url": current_url,
                    "title": title,
                    "network_requests": len(_network_log),
                })
            except Exception as e:
                return json.dumps({"url": url, "error": str(e)})

        return await sync_to_async(_sync, thread_sensitive=False)()

    @mcp.tool()
    async def browser_get_network_log(filter_type: str = "") -> str:
        """캡처된 네트워크 요청/응답 로그를 반환한다.
        filter_type: 비워두면 전체. "xhr", "fetch", "document", "api" 등으로 필터.
        "api"는 /api/, /v1/, /rest/, /graphql 경로만 반환.

        SPA 사이트에서 API 엔드포인트를 찾을 때 사용한다:
        1. browser_navigate로 접속
        2. browser_get_network_log(filter_type="api")로 API 호출 추출
        """
        def _sync():
            _ensure_browser()

            logs = list(_network_log)

            if filter_type == "api":
                api_patterns = ["/api/", "/v1/", "/v2/", "/rest/", "/graphql", "/gql"]
                logs = [l for l in logs if any(p in l.get("url", "") for p in api_patterns)]
            elif filter_type:
                logs = [l for l in logs if l.get("resource_type", "") == filter_type]

            skip_ext = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                         ".ico", ".woff", ".woff2", ".ttf", ".map")
            logs = [l for l in logs if not any(l.get("url", "").lower().endswith(ext) for ext in skip_ext)]

            return json.dumps({"count": len(logs), "logs": logs[-100:]})

        return await sync_to_async(_sync, thread_sensitive=False)()

    @mcp.tool()
    async def browser_get_dom(selector: str = "body") -> str:
        """렌더링된 DOM에서 요소를 추출한다.
        selector: CSS 선택자 (예: "body", "form", "a[href]", "#app")
        JS 실행 후의 DOM이므로 SPA 콘텐츠도 포함된다.
        """
        def _sync():
            _ensure_browser()
            try:
                if selector == "body":
                    html = _page.content()
                    return json.dumps({"html": html[:10000], "length": len(html)})
                else:
                    elements = _page.eval_on_selector_all(
                        selector,
                        "els => els.map(e => ({tag: e.tagName, text: e.textContent?.substring(0,200), "
                        "href: e.href, action: e.action, method: e.method, "
                        "outerHTML: e.outerHTML?.substring(0,500)}))"
                    )
                    return json.dumps({"selector": selector, "count": len(elements),
                                        "elements": elements[:50]})
            except Exception as e:
                return json.dumps({"selector": selector, "error": str(e)})

        return await sync_to_async(_sync, thread_sensitive=False)()

    @mcp.tool()
    async def browser_click(selector: str) -> str:
        """페이지에서 요소를 클릭한다. 클릭으로 트리거되는 API 호출을 캡처할 수 있다.
        클릭 후 browser_get_network_log로 새 요청을 확인하라.
        """
        def _sync():
            _ensure_browser()
            before_count = len(_network_log)
            try:
                _page.click(selector, timeout=5000)
                _page.wait_for_timeout(1500)
                new_requests = len(_network_log) - before_count
                return json.dumps({"clicked": selector, "new_network_requests": new_requests})
            except Exception as e:
                return json.dumps({"selector": selector, "error": str(e)})

        return await sync_to_async(_sync, thread_sensitive=False)()

    @mcp.tool()
    async def browser_fill_and_submit(selector_map: str, submit_selector: str = "") -> str:
        """폼 필드를 채우고 제출한다.
        selector_map: JSON. 예: '{"#username": "admin", "#password": "test"}'
        submit_selector: 제출 버튼 선택자 (비워두면 Enter)
        """
        def _sync():
            _ensure_browser()
            try:
                fields = json.loads(selector_map) if isinstance(selector_map, str) else selector_map
            except json.JSONDecodeError:
                return json.dumps({"error": "invalid selector_map JSON"})

            before_count = len(_network_log)
            try:
                for sel, value in fields.items():
                    _page.fill(sel, value)

                if submit_selector:
                    _page.click(submit_selector, timeout=5000)
                else:
                    _page.keyboard.press("Enter")

                _page.wait_for_timeout(2000)
                new_requests = len(_network_log) - before_count

                return json.dumps({
                    "filled_fields": list(fields.keys()),
                    "submitted": True,
                    "new_network_requests": new_requests,
                    "current_url": _page.url,
                })
            except Exception as e:
                return json.dumps({"error": str(e)})

        return await sync_to_async(_sync, thread_sensitive=False)()

    @mcp.tool()
    async def browser_execute_js(script: str) -> str:
        """브라우저에서 JavaScript를 실행한다.
        SPA의 내부 상태, localStorage, 쿠키 등을 확인할 때 사용.
        예: "document.cookie", "localStorage.getItem('token')",
            "JSON.stringify(window.__STORE__)"
        """
        def _sync():
            _ensure_browser()
            try:
                result = _page.evaluate(script)
                return json.dumps({"script": script[:200], "result": str(result)[:5000]})
            except Exception as e:
                return json.dumps({"script": script[:200], "error": str(e)})

        return await sync_to_async(_sync, thread_sensitive=False)()

    @mcp.tool()
    async def browser_screenshot() -> str:
        """현재 페이지의 스크린샷을 찍는다. base64로 반환."""
        def _sync():
            _ensure_browser()
            import base64
            try:
                buf = _page.screenshot(type="png")
                b64 = base64.b64encode(buf).decode()
                return json.dumps({"format": "png", "size": len(buf),
                                    "base64": b64[:100] + "...(truncated)"})
            except Exception as e:
                return json.dumps({"error": str(e)})

        return await sync_to_async(_sync, thread_sensitive=False)()

    _STATIC_EXT = frozenset({
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".avif",
        ".mp4", ".mp3", ".pdf",
    })

    @mcp.tool()
    async def browser_extract_api_endpoints() -> str:
        """현재 페이지에서 모든 URL/API를 추출한다.
        네트워크 로그 + DOM 내 스크립트의 API 패턴 + HTML 링크(<a>, <form>, <iframe>, <link>)를 모두 수집.
        api_endpoints (JS/API), page_links (HTML DOM), network_urls (실제 요청) 세 카테고리로 반환.
        """
        def _sync():
            _ensure_browser()
            import re
            from urllib.parse import urlparse

            api_endpoints = set()
            page_links = set()
            network_urls = set()

            # 1. Network log — all requests (not just /api/ patterns)
            api_patterns = ["/api/", "/v1/", "/v2/", "/rest/", "/graphql"]
            for log in _network_log:
                url = log.get("url", "")
                if not url:
                    continue
                try:
                    parsed = urlparse(url)
                    path = parsed.path
                    ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
                    if ext in _STATIC_EXT:
                        continue
                    method = log.get("method", "GET")
                    entry = f"{method} {path}"
                    if any(p in url for p in api_patterns):
                        api_endpoints.add(entry)
                    else:
                        network_urls.add(entry)
                except Exception:
                    pass

            # 2. DOM: <a href>, <form action>, <iframe src>
            # Resolve all relative URLs to absolute via new URL(val, location.href),
            # then convert same-origin to path+query for consistent endpoint format.
            # SPA hash routes (#/admin, /#/settings) collected separately.
            hash_routes = set()
            try:
                dom_result = _page.evaluate("""() => {
                    const base = location.href;
                    const origin = location.origin;
                    const links = new Set();
                    const hashes = new Set();
                    function resolve(raw, method) {
                        if (!raw || raw.startsWith('javascript:')
                            || raw.startsWith('mailto:') || raw.startsWith('data:')
                            || raw.startsWith('tel:')) return;
                        if (raw.startsWith('#/') || raw.startsWith('/#')) {
                            const route = raw.replace(/^[/#]+/, '');
                            if (route.length > 1) hashes.add('#/' + route);
                            return;
                        }
                        if (raw.startsWith('#')) return;
                        try {
                            const u = new URL(raw, base);
                            let path;
                            if (u.origin === origin) {
                                path = u.pathname + u.search;
                            } else {
                                path = u.href;
                            }
                            links.add(method + ' ' + path);
                        } catch(e) {}
                    }
                    document.querySelectorAll('a[href]').forEach(el =>
                        resolve(el.getAttribute('href'), 'GET'));
                    document.querySelectorAll('form[action]').forEach(el =>
                        resolve(el.getAttribute('action'),
                                (el.getAttribute('method') || 'GET').toUpperCase()));
                    document.querySelectorAll('iframe[src]').forEach(el =>
                        resolve(el.getAttribute('src'), 'GET'));
                    return {
                        links: Array.from(links).slice(0, 200),
                        hashes: Array.from(hashes).slice(0, 50)
                    };
                }""")
                for entry in dom_result.get("links", []):
                    parts = entry.split(" ", 1)
                    if len(parts) == 2:
                        url_part = parts[1]
                        try:
                            parsed = urlparse(url_part) if url_part.startswith("http") else None
                            path = parsed.path if parsed else url_part.split("?")[0]
                            ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
                            if ext in _STATIC_EXT:
                                continue
                        except Exception:
                            pass
                    page_links.add(entry)
                for h in dom_result.get("hashes", []):
                    hash_routes.add(h)
            except Exception:
                pass

            # 3. Inline scripts — API/fetch patterns
            try:
                scripts = _page.eval_on_selector_all(
                    "script:not([src])", "els => els.map(e => e.textContent)"
                )
                js_patterns = [
                    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*[`'"](\/[^`'"]*?)[`'"]"""),
                    re.compile(r"""[`'"](\/api\/[^`'"]{2,})[`'"]"""),
                    re.compile(r"""[`'"](\/v\d+\/[^`'"]{2,})[`'"]"""),
                    re.compile(r"""[`'"](\/rest\/[^`'"]{2,})[`'"]"""),
                    re.compile(r"""\.open\s*\(\s*[`'"]\w+[`'"]\s*,\s*[`'"](\/[^`'"]+)[`'"]"""),
                ]
                for script in scripts:
                    if not script or len(script) < 20:
                        continue
                    for pattern in js_patterns:
                        for match in pattern.findall(script):
                            api_endpoints.add(f"GET {match}")
            except Exception:
                pass

            # 4. External bundles
            try:
                src_urls = _page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
                for url in src_urls:
                    if any(kw in url.lower() for kw in ["chunk", "bundle", "main", "app", "vendor"]):
                        try:
                            resp = _page.request.get(url)
                            if resp.ok:
                                js = resp.text()
                                for pattern in js_patterns:
                                    for match in pattern.findall(js):
                                        api_endpoints.add(f"GET {match}")
                        except Exception:
                            pass
            except Exception:
                pass

            return json.dumps({
                "api_endpoints": sorted(api_endpoints),
                "page_links": sorted(page_links)[:100],
                "network_urls": sorted(network_urls)[:50],
                "hash_routes": sorted(hash_routes)[:30],
                "total_count": len(api_endpoints) + len(page_links) + len(network_urls) + len(hash_routes),
                "sources": {
                    "network_log": len([l for l in _network_log if l.get("type") == "request"]),
                    "dom_links": "parsed (a[href], form[action], iframe[src])",
                    "inline_scripts": "parsed",
                    "external_bundles": "parsed",
                }
            })

        return await sync_to_async(_sync, thread_sensitive=False)()
