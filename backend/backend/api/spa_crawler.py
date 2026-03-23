"""
SPA 크롤러 모듈 (Playwright 기반)

Headless Chromium으로 JS를 실행한 뒤:
1. Network 탭 모니터링 → 실제 API 호출 캡처
2. 렌더링된 DOM에서 링크/폼 추출
3. JS 번들에서 API 엔드포인트 정규식 추출
4. 클릭 가능한 요소 자동 클릭 → 추가 API 호출 트리거

기존 BFS Crawler와 동일한 output 포맷을 반환하므로
services.py에서 호환 가능.
"""

import logging
import hashlib
import re
import json
import time
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque

logger = logging.getLogger(__name__)

# API 엔드포인트 추출용 정규식
API_PATTERNS = [
    # fetch/axios 호출
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*[`'"](\/[^`'"]*?)[`'"]""", re.I),
    # 문자열 리터럴 내 API 경로
    re.compile(r"""[`'"](\/api\/[^`'"]{2,})[`'"]""", re.I),
    re.compile(r"""[`'"](\/v\d+\/[^`'"]{2,})[`'"]""", re.I),
    re.compile(r"""[`'"](\/rest\/[^`'"]{2,})[`'"]""", re.I),
    re.compile(r"""[`'"](\/graphql[^`'"]*)[`'"]""", re.I),
    # baseURL 설정
    re.compile(r"""baseURL\s*[:=]\s*[`'"](https?:\/\/[^`'"]+)[`'"]""", re.I),
    # Router 경로 (React Router, Vue Router)
    re.compile(r"""path\s*:\s*[`'"](\/[^`'"]{2,})[`'"]""", re.I),
    # XMLHttpRequest.open
    re.compile(r"""\.open\s*\(\s*[`'"]\w+[`'"]\s*,\s*[`'"](\/[^`'"]+)[`'"]""", re.I),
]

# HTTP 메서드 추출
METHOD_PATTERN = re.compile(
    r"""(?:fetch\s*\(\s*[`'"]\/[^`'"]*[`'"]\s*,\s*\{[^}]*method\s*:\s*[`'"](\w+)[`'"])|"""
    r"""(?:axios\.(\w+)\s*\()""",
    re.I | re.S,
)

class SPACrawler:
    """Playwright 기반 SPA 크롤러"""

    def __init__(self, target_url, max_depth=3, max_pages=100, timeout=30,
                 headless=True, click_explore=True):
        self.target_url = target_url.rstrip("/")
        self.base_domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout * 1000  # Playwright는 ms 단위
        self.headless = headless
        self.click_explore = click_explore

        self.visited = set()
        self.results = []
        self.api_calls = []         # Network에서 캡처한 API 호출
        self.js_endpoints = set()   # JS 번들에서 추출한 엔드포인트
        self.seen_endpoints = set() # 중복 방지

    def is_same_domain(self, url):
        """같은 도메인인지 확인"""
        parsed = urlparse(url)
        return parsed.netloc == self.base_domain or parsed.netloc == ""

    def normalize_url(self, url):
        """URL 정규화"""
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized

    def _extract_api_from_js(self, js_content, source_url=""):
        """JS 코드에서 API 엔드포인트 추출"""
        endpoints = set()
        for pattern in API_PATTERNS:
            matches = pattern.findall(js_content)
            for match in matches:
                ep = match.strip()
                if ep and len(ep) > 1 and not ep.endswith(".js") and \
                   not ep.endswith(".css") and not ep.endswith(".map"):
                    endpoints.add(ep)
                    logger.debug(f"JS 번들에서 추출: {ep} (from {source_url})")
        return endpoints

    def _capture_network_request(self, request):
        """Network 요청 캡처 콜백"""
        url = request.url
        parsed = urlparse(url)

        if not self.is_same_domain(url):
            return

        # API 호출만 필터링 (정적 리소스 제외)
        skip_extensions = {".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
                          ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map"}
        if any(parsed.path.lower().endswith(ext) for ext in skip_extensions):
            return

        method = request.method
        endpoint = parsed.path or "/"
        params = parse_qs(parsed.query)

        # POST body 추출 시도
        post_data = {}
        if method == "POST":
            try:
                raw = request.post_data
                if raw:
                    try:
                        post_data = json.loads(raw)
                    except json.JSONDecodeError:
                        # form-urlencoded
                        post_data = dict(parse_qs(raw))
            except Exception:
                pass

        dedup_key = (method, endpoint, tuple(sorted(
            list(params.keys()) + list(post_data.keys())
        )))

        if dedup_key not in self.seen_endpoints:
            self.seen_endpoints.add(dedup_key)
            merged_params = {**params, **post_data}
            self.api_calls.append({
                "endpoint": endpoint,
                "method": method,
                "params": merged_params,
                "full_url": url,
                "source": "network_capture",
            })
            logger.info(f"[Network] {method} {endpoint} (params={list(merged_params.keys())})")

    def _capture_network_response(self, response):
        """Network 응답 캡처 — API 호출의 status_code, content_type 업데이트"""
        url = response.url
        parsed = urlparse(url)
        endpoint = parsed.path or "/"

        for call in self.api_calls:
            if call["endpoint"] == endpoint and call.get("status_code") is None:
                call["status_code"] = response.status
                try:
                    call["content_type"] = response.headers.get("content-type", "")
                except Exception:
                    call["content_type"] = ""
                break

    def _extract_dom_links(self, page):
        """렌더링된 DOM에서 링크/폼 추출"""
        links = set()
        forms = []

        try:
            # <a href>
            hrefs = page.eval_on_selector_all(
                "a[href]",
                "els => els.map(e => e.href)"
            )
            for href in hrefs:
                if href and self.is_same_domain(href):
                    links.add(href)

            # <form>
            form_data = page.eval_on_selector_all(
                "form",
                """els => els.map(f => ({
                    action: f.action || window.location.href,
                    method: (f.method || 'GET').toUpperCase(),
                    inputs: Array.from(f.querySelectorAll('input,textarea,select'))
                        .filter(i => i.name)
                        .map(i => ({name: i.name, type: i.type || 'text', value: i.value || ''}))
                }))"""
            )
            for fd in form_data:
                if fd.get("action") and self.is_same_domain(fd["action"]):
                    forms.append({
                        "action": fd["action"],
                        "method": fd["method"],
                        "params": {i["name"]: {"type": i["type"], "value": i["value"]}
                                   for i in fd.get("inputs", [])},
                    })

            # SPA router 링크 (React Router의 data-*, onClick 등)
            router_links = page.eval_on_selector_all(
                "[data-href], [data-link], [data-to]",
                "els => els.map(e => e.dataset.href || e.dataset.link || e.dataset.to)"
            )
            for rl in router_links:
                if rl:
                    full = urljoin(self.target_url, rl)
                    if self.is_same_domain(full):
                        links.add(full)

        except Exception as e:
            logger.warning(f"DOM 링크 추출 실패: {e}")

        return links, forms

    def _click_interactive_elements(self, page):
        """클릭 가능한 요소를 클릭하여 숨겨진 API 호출 트리거"""
        clickable_selectors = [
            "button:not([disabled]):not([type='submit'])",
            "[role='button']",
            "[role='tab']",
            "[role='menuitem']",
            ".nav-link",
            ".tab",
            "[data-toggle]",
            "[onclick]",
            "details > summary",
        ]

        clicked = 0
        max_clicks = 20

        for selector in clickable_selectors:
            if clicked >= max_clicks:
                break
            try:
                elements = page.query_selector_all(selector)
                for el in elements[:5]:  # 각 셀렉터당 최대 5개
                    if clicked >= max_clicks:
                        break
                    try:
                        # 보이는 요소만 클릭
                        if el.is_visible():
                            el.click(timeout=3000)
                            page.wait_for_timeout(500)  # API 호출 대기
                            clicked += 1
                            logger.debug(f"클릭: {selector} ({clicked}/{max_clicks})")
                    except Exception:
                        continue
            except Exception:
                continue

        logger.info(f"자동 클릭: {clicked}개 요소")

    def _fetch_and_parse_js_bundles(self, page):
        """페이지의 JS 번들을 다운로드하고 API 엔드포인트 추출"""
        try:
            script_urls = page.eval_on_selector_all(
                "script[src]",
                "els => els.map(e => e.src)"
            )

            for url in script_urls:
                if not self.is_same_domain(url):
                    continue
                # chunk/bundle 파일만
                if not any(kw in url.lower() for kw in
                          ["chunk", "bundle", "main", "app", "index", "vendor"]):
                    continue

                try:
                    resp = page.request.get(url)
                    if resp.ok:
                        js_content = resp.text()
                        endpoints = self._extract_api_from_js(js_content, url)
                        self.js_endpoints.update(endpoints)
                        logger.info(f"JS 번들 파싱: {url} → {len(endpoints)}개 엔드포인트")
                except Exception as e:
                    logger.warning(f"JS 번들 다운로드 실패: {url} - {e}")

            # 인라인 스크립트도 파싱
            inline_scripts = page.eval_on_selector_all(
                "script:not([src])",
                "els => els.map(e => e.textContent)"
            )
            for script_content in inline_scripts:
                if script_content and len(script_content) > 50:
                    endpoints = self._extract_api_from_js(script_content, "inline")
                    self.js_endpoints.update(endpoints)

        except Exception as e:
            logger.warning(f"JS 번들 파싱 실패: {e}")

    def crawl(self):
        """
        SPA 크롤링 실행.
        Playwright로 브라우저 띄우고 → Network 감시 + DOM 추출 + JS 파싱.

        Returns:
            list: 기존 Crawler.crawl()과 동일한 포맷의 엔드포인트 목록
        """
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            logger.error("playwright 미설치. pip install playwright && playwright install chromium")
            return []

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=self.headless,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            context = browser.new_context(
                user_agent="WatchdogSPACrawler/1.0",
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 720},
            )
            page = context.new_page()

            # Network 이벤트 리스너
            page.on("request", self._capture_network_request)
            page.on("response", self._capture_network_response)

            # BFS 크롤링 시작
            queue = deque([(self.target_url, 0)])
            self.visited.add(self.target_url)

            while queue and len(self.results) + len(self.api_calls) < self.max_pages:
                url, depth = queue.popleft()

                if depth > self.max_depth:
                    continue

                logger.info(f"[SPA depth={depth}] 크롤링: {url}")

                try:
                    page.goto(url, wait_until="networkidle", timeout=self.timeout)
                    page.wait_for_timeout(2000)  # SPA 렌더링 대기
                except Exception as e:
                    logger.warning(f"페이지 로드 실패: {url} - {e}")
                    continue

                # 1. JS 번들에서 API 엔드포인트 추출 (첫 페이지에서만)
                if depth == 0:
                    self._fetch_and_parse_js_bundles(page)

                # 2. 렌더링된 DOM에서 링크/폼 추출
                dom_links, dom_forms = self._extract_dom_links(page)

                # 3. 클릭 가능한 요소 탐색 (API 호출 트리거)
                if self.click_explore and depth <= 1:
                    self._click_interactive_elements(page)
                    page.wait_for_timeout(1000)

                # DOM 링크 → 큐에 추가
                for link in dom_links:
                    normalized = self.normalize_url(link)
                    if normalized not in self.visited:
                        self.visited.add(normalized)
                        queue.append((link, depth + 1))

                # DOM 폼 → results에 추가
                for form in dom_forms:
                    form_parsed = urlparse(form["action"])
                    form_endpoint = form_parsed.path or "/"
                    form_dedup = (form["method"], form_endpoint,
                                  tuple(sorted(form["params"].keys())))

                    if form_dedup not in self.seen_endpoints:
                        self.seen_endpoints.add(form_dedup)
                        self.results.append({
                            "endpoint": form_endpoint,
                            "method": form["method"],
                            "params": form["params"],
                            "status_code": None,
                            "content_type": None,
                            "headers": None,
                            "body_hash": None,
                            "auth_required": False,
                            "source": "spa_dom_form",
                            "discovered_from": url,
                        })

                # 현재 URL의 렌더링된 페이지 정보 저장
                parsed = urlparse(url)
                endpoint = parsed.path or "/"
                params = parse_qs(parsed.query)
                dedup_key = ("GET", endpoint, tuple(sorted(params.keys())))

                if dedup_key not in self.seen_endpoints:
                    self.seen_endpoints.add(dedup_key)
                    try:
                        body = page.content()
                        body_hash = hashlib.sha256(body.encode()).hexdigest()[:16]
                    except Exception:
                        body_hash = None

                    self.results.append({
                        "endpoint": endpoint,
                        "method": "GET",
                        "params": params,
                        "status_code": 200,
                        "content_type": "text/html",
                        "headers": None,
                        "body_hash": body_hash,
                        "auth_required": False,
                        "source": "spa_crawler",
                        "discovered_from": url,
                    })

            browser.close()

        # Network 캡처 결과 → results에 합치기
        for call in self.api_calls:
            self.results.append({
                "endpoint": call["endpoint"],
                "method": call["method"],
                "params": call.get("params", {}),
                "status_code": call.get("status_code"),
                "content_type": call.get("content_type"),
                "headers": None,
                "body_hash": None,
                "auth_required": call.get("status_code") in (401, 403)
                                 if call.get("status_code") else False,
                "source": "network_capture",
                "discovered_from": call.get("full_url", ""),
            })

        # JS 번들에서 추출한 엔드포인트 → results에 추가
        for ep in self.js_endpoints:
            parsed_ep = urlparse(ep)
            ep_path = parsed_ep.path or ep
            ep_params = parse_qs(parsed_ep.query)
            dedup_key = ("GET", ep_path, tuple(sorted(ep_params.keys())))

            if dedup_key not in self.seen_endpoints:
                self.seen_endpoints.add(dedup_key)
                self.results.append({
                    "endpoint": ep_path,
                    "method": "GET",
                    "params": ep_params,
                    "status_code": None,
                    "content_type": None,
                    "headers": None,
                    "body_hash": None,
                    "auth_required": False,
                    "source": "js_bundle_parse",
                    "discovered_from": "js_static_analysis",
                })

        logger.info(f"SPA 크롤링 완료: {len(self.results)}개 엔드포인트 "
                     f"(DOM: {len(self.results) - len(self.api_calls) - len(self.js_endpoints)}, "
                     f"Network: {len(self.api_calls)}, JS번들: {len(self.js_endpoints)})")

        return self.results

def detect_spa(url, timeout=10):
    """
    URL이 SPA인지 판별.

    Returns:
        bool: True면 SPA
    """
    import requests as req

    try:
        resp = req.get(url, timeout=timeout, headers={"User-Agent": "WatchdogScanner/1.0"})
        html = resp.text
        html_lower = html.lower()

        spa_indicators = 0

        # SPA 마운트 포인트 (React, Vue, Next, Nuxt)
        if 'id="root"' in html_lower or 'id="app"' in html_lower or \
           'id="__next"' in html_lower or 'id="__nuxt"' in html_lower:
            spa_indicators += 2

        # Angular 커스텀 태그 (<app-root>, <app-component> 등)
        import re
        if re.search(r'<app-\w+', html_lower):
            spa_indicators += 2

        # JS 번들/chunk 파일
        chunk_matches = re.findall(r'(?:chunk|bundle|vendor|main|polyfills)[\w.-]*\.js', html_lower)
        if len(chunk_matches) >= 2:
            spa_indicators += 2
        elif len(chunk_matches) >= 1:
            spa_indicators += 1

        # webpack/vite 시그니처
        if "webpack" in html_lower or "vite" in html_lower or "webpackjsonp" in html_lower:
            spa_indicators += 1

        # noscript 경고
        if "<noscript>" in html_lower:
            spa_indicators += 1

        # <a> 태그 적고 <script> 많음
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        a_count = len(soup.find_all("a", href=True))
        script_count = len(soup.find_all("script"))
        if a_count < 5 and script_count > 3:
            spa_indicators += 2
        elif a_count < 10 and script_count > 5:
            spa_indicators += 1

        # React 시그니처
        if "react" in html_lower or "_jsx" in html_lower or "reactdom" in html_lower:
            spa_indicators += 1

        # Vue 시그니처
        if "__vue__" in html_lower or "vue-router" in html_lower or 'data-v-' in html_lower:
            spa_indicators += 1

        # Angular 시그니처
        if "ng-app" in html_lower or "ng-version" in html_lower or \
           "angular" in html_lower or "_ngcontent" in html_lower:
            spa_indicators += 1

        # hash routing (#/) 시그니처
        if "/#/" in html or "hashLocationStrategy" in html_lower:
            spa_indicators += 1

        # body가 거의 비어있음 (JS가 렌더링하는 구조)
        body_tag = soup.find("body")
        if body_tag:
            direct_text = body_tag.get_text(strip=True)
            if len(direct_text) < 100 and script_count > 2:
                spa_indicators += 1

        is_spa = spa_indicators >= 2
        logger.info(f"SPA 판별: {url} → {'SPA' if is_spa else 'Traditional'} "
                     f"(indicators={spa_indicators}, a={a_count}, script={script_count})")
        return is_spa

    except Exception as e:
        logger.warning(f"SPA 판별 실패: {url} - {e}")
        return False

