import base64
import json
import time
import hashlib
from asgiref.sync import sync_to_async

_browser = None
_context = None
_page = None
_network_log = []
_custom_user_agent: str | None = None
_pw_handle = None  # sync_playwright().start() handle — kept alive across calls
# Loaded storage_state (cookies + origin localStorage). Set by
# browser_load_storage_state and re-applied on context recreation so
# authenticated session survives UA changes / context resets.
_loaded_storage_state: dict | None = None


def _install_event_hooks(page):
    """Attach request/response listeners to a Playwright Page."""
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

    page.on("request", _on_request)
    page.on("response", _on_response)


def _recreate_context(storage_state: dict | None = None):
    """Close existing context/page and create a fresh one, optionally seeded
    with a Playwright storage_state (cookies + localStorage). Keeps the
    underlying _browser alive so repeated reloads stay cheap."""
    global _context, _page, _network_log
    if _page is not None:
        try:
            _page.close()
        except Exception:
            pass
    if _context is not None:
        try:
            _context.close()
        except Exception:
            pass
    ua = _custom_user_agent or "WatchdogBrowser/1.0"
    kwargs = {
        "user_agent": ua,
        "ignore_https_errors": True,
        "viewport": {"width": 1280, "height": 720},
    }
    if storage_state:
        kwargs["storage_state"] = storage_state
    _context = _browser.new_context(**kwargs)
    _page = _context.new_page()
    _network_log = []
    _install_event_hooks(_page)


def _ensure_browser():
    global _browser, _pw_handle
    if _page is not None:
        return

    from playwright.sync_api import sync_playwright
    _pw_handle = sync_playwright().start()
    _browser = _pw_handle.chromium.launch(
        headless=True,
        args=["--no-sandbox", "--disable-dev-shm-usage"],
    )
    _recreate_context(storage_state=_loaded_storage_state)

def register(mcp):

    @mcp.tool()
    async def browser_set_user_agent(user_agent: str) -> str:
        """브라우저의 User-Agent를 변경한다. 버그바운티 식별 등에 사용.
        이미 브라우저가 열려 있으면 새 context 로 재생성한다 (로드된
        storage_state 가 있으면 authed 상태 유지).
        browser_navigate 전에 호출해야 효과가 있다.
        """
        global _custom_user_agent

        def _sync():
            global _custom_user_agent
            _custom_user_agent = user_agent.strip() if user_agent else None
            if _page is not None:
                _recreate_context(storage_state=_loaded_storage_state)
            return json.dumps({"user_agent": _custom_user_agent or "WatchdogBrowser/1.0", "applied": True})

        return await sync_to_async(_sync, thread_sensitive=False)()

    @mcp.tool()
    async def browser_load_storage_state(state_json: str, profile_name: str = "") -> str:
        """Playwright storage_state (cookies + localStorage) 를 브라우저에
        적용한다. SSO 로그인된 세션을 headless 브라우저로 주입해 authed
        상태로 탐색 가능하게 하는 핵심 bridge.

        state_json: Playwright `context.storage_state()` 형식의 JSON
          문자열. base64 인코딩도 허용 (자동 감지). 스키마:
          {"cookies":[{name,value,domain,path,expires,httpOnly,secure,sameSite}],
           "origins":[{origin,localStorage:[{name,value}]}]}
        profile_name: optional 식별자 — 로그/에러에 쓰임.

        동작: 기존 context 닫고 storage_state 가 주입된 새 context 생성.
        이후 `browser_navigate` 부터 authed 상태. session state 는 내부에
        캐시돼 UA 변경 등 context 재생성 시에도 유지된다.

        로컬 helper: `python tools/browser_profile_login.py login --target
        <URL> --profile <NAME>` 로 수동 로그인 후 나온 JSON 파일 내용을
        그대로 넘기면 된다.
        """
        global _loaded_storage_state

        def _sync():
            global _loaded_storage_state
            raw = (state_json or "").strip()
            if not raw:
                return json.dumps({"error": "empty state_json"})
            # base64 자동 감지 (JSON 은 '{' 로 시작)
            if not raw.startswith("{"):
                try:
                    raw = base64.b64decode(raw).decode("utf-8")
                except Exception as e:
                    return json.dumps({"error": f"state_json is not JSON nor base64: {e}"})
            try:
                state = json.loads(raw)
            except Exception as e:
                return json.dumps({"error": f"json parse failed: {e}"})
            if not isinstance(state, dict) or "cookies" not in state:
                return json.dumps({"error": "missing 'cookies' key — not a valid Playwright storage_state"})

            _loaded_storage_state = state
            cookies = state.get("cookies") or []
            origins = state.get("origins") or []

            _ensure_browser()
            _recreate_context(storage_state=state)

            return json.dumps({
                "loaded": True,
                "profile": profile_name or "",
                "cookie_count": len(cookies),
                "origin_count": len(origins),
                "cookie_hosts": sorted({c.get("domain", "").lstrip(".") for c in cookies if c.get("domain")}),
                "hint": "context rebuilt with storage_state. browser_navigate is now authed.",
            })

        return await sync_to_async(_sync, thread_sensitive=False)()

    @mcp.tool()
    async def browser_export_storage_state() -> str:
        """현재 브라우저 context 의 storage_state 를 JSON 으로 반환한다.
        refresh 된 쿠키/localStorage 를 수거해 profile 파일을 업데이트하거나
        `browser_sync_cookies_to_secrets` 로 DB 에 박을 때 사용.

        주의: Access-Token 같은 민감 값 포함. 저장 시 gitignored 경로만.
        """
        def _sync():
            _ensure_browser()
            try:
                state = _context.storage_state()
                cookies = state.get("cookies", [])
                origins = state.get("origins", [])
                return json.dumps({
                    "cookie_count": len(cookies),
                    "origin_count": len(origins),
                    "cookie_hosts": sorted({c.get("domain", "").lstrip(".") for c in cookies if c.get("domain")}),
                    "state": state,
                })
            except Exception as e:
                return json.dumps({"error": str(e)})

        return await sync_to_async(_sync, thread_sensitive=False)()

    @mcp.tool()
    async def browser_sync_cookies_to_secrets(scan_run_id: str, host: str = "") -> str:
        """현재 브라우저 context 의 쿠키를 ScanRun.config._secrets 에 저장.

        http_request / multi_http_probe 같은 stateless HTTP 도구가 이 값을
        자동 주입해 브라우저와 curl 이 같은 세션을 공유하게 된다.

        host 필터 — 공백이면 모든 호스트 쿠키를 하나의 Cookie 문자열로
        직렬화해 `cookie_<host>` key 로 각각 저장. 특정 host 만 원하면
        그 값만 필터.

        반환: 저장된 호스트 목록 + per-host cookie count.
        """
        from api.models import ScanRun
        from django.utils import timezone as _tz

        def _sync():
            _ensure_browser()
            try:
                state = _context.storage_state()
            except Exception as e:
                return json.dumps({"error": f"storage_state failed: {e}"})

            cookies = state.get("cookies", [])
            if host:
                host_norm = host.lstrip(".").lower()
                cookies = [c for c in cookies if (c.get("domain") or "").lstrip(".").lower() == host_norm]

            # host 별로 Cookie 문자열 조립
            by_host: dict[str, list[str]] = {}
            for c in cookies:
                h = (c.get("domain") or "").lstrip(".").lower()
                if not h:
                    continue
                name = c.get("name") or ""
                val = c.get("value") or ""
                if name:
                    by_host.setdefault(h, []).append(f"{name}={val}")

            try:
                sr = ScanRun.objects.get(run_id=scan_run_id)
            except ScanRun.DoesNotExist:
                return json.dumps({"error": f"scan_run {scan_run_id} not found"})

            cfg = dict(sr.config or {})
            secrets = dict(cfg.get("_secrets") or {})
            now = _tz.now().isoformat()
            written = {}
            for h, parts in by_host.items():
                cookie_str = "; ".join(parts)
                key = f"cookie_{h}"
                secrets[key] = {
                    "value": cookie_str,
                    "category": "cookie",
                    "stored_at": now,
                    "source": "browser_sync",
                    "host": h,
                    "cookie_count": len(parts),
                }
                written[h] = len(parts)
            cfg["_secrets"] = secrets
            sr.config = cfg
            sr.save(update_fields=["config"])

            return json.dumps({
                "synced": True,
                "scan_run_id": scan_run_id,
                "hosts": written,
                "total_secrets": len(secrets),
            })

        return await sync_to_async(_sync, thread_sensitive=False)()

    @mcp.tool()
    async def browser_navigate(url: str, wait_until: str = "networkidle") -> str:
        """브라우저로 URL에 접속한다. JS가 실행된 후 상태를 반환한다.
        wait_until: load, domcontentloaded, networkidle
        접속 후 네트워크 탭 캡처가 자동으로 시작된다.

        Side effect: navigate 후 현재 storage_state 를 in-memory 에
        snapshot — refresh XHR 로 쿠키가 갱신되면 여기서 자동 수거,
        다음 context 재생성 시 최신 auth 상태로 복원.
        """
        global _loaded_storage_state

        def _sync():
            global _loaded_storage_state
            _ensure_browser()
            _network_log.clear()

            try:
                _page.goto(url, wait_until=wait_until, timeout=30000)
                _page.wait_for_timeout(2000)
                title = _page.title()
                current_url = _page.url

                state_updated = False
                try:
                    new_state = _context.storage_state()
                    if new_state != _loaded_storage_state:
                        _loaded_storage_state = new_state
                        state_updated = True
                except Exception:
                    pass

                return json.dumps({
                    "url": current_url,
                    "title": title,
                    "network_requests": len(_network_log),
                    "storage_state_refreshed": state_updated,
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
