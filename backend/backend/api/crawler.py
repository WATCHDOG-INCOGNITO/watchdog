"""
BFS 크롤러 모듈
타겟 URL에서 엔드포인트를 수집하고 request_catalog에 저장한다.
JS 번들을 분석하여 SPA 내부의 API 경로도 추출한다.
"""

import logging
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque

import requests
from bs4 import BeautifulSoup

from .js_analyzer import (
    extract_endpoints_from_js,
    expand_parameterized_endpoints,
    detect_auth_endpoints,
)

logger = logging.getLogger(__name__)


class Crawler:
    """BFS 기반 웹 크롤러 + JS 번들 분석"""

    def __init__(self, target_url, max_depth=3, max_pages=100, timeout=10):
        self.target_url = target_url.rstrip("/")
        self.base_domain = urlparse(target_url).netloc
        self.base_path = urlparse(target_url).path.rstrip("/")
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout

        self.visited = set()
        self.results = []          # 수집된 엔드포인트 목록
        self.js_endpoints = []     # JS 분석으로 발견된 엔드포인트
        self.response_headers = {} # 첫 응답 헤더 (보안 헤더 분석용)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "WatchdogScanner/1.0",
        })

    def is_same_domain(self, url):
        """같은 도메인인지 확인"""
        return urlparse(url).netloc == self.base_domain

    def normalize_url(self, url):
        """URL 정규화 (fragment 제거, 트레일링 슬래시 통일)"""
        parsed = urlparse(url)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            normalized += f"?{parsed.query}"
        return normalized

    def extract_links(self, html, current_url):
        """HTML에서 링크, 폼, 스크립트 엔드포인트 추출"""
        soup = BeautifulSoup(html, "html.parser")
        links = set()

        # <a href="...">
        for tag in soup.find_all("a", href=True):
            url = urljoin(current_url, tag["href"])
            if self.is_same_domain(url):
                links.add(self.normalize_url(url))

        # <form action="...">
        for form in soup.find_all("form", action=True):
            url = urljoin(current_url, form["action"])
            if self.is_same_domain(url):
                links.add(self.normalize_url(url))

        # <script src="...">
        for script in soup.find_all("script", src=True):
            url = urljoin(current_url, script["src"])
            if self.is_same_domain(url):
                links.add(self.normalize_url(url))

        # <link href="...">
        for link in soup.find_all("link", href=True):
            url = urljoin(current_url, link["href"])
            if self.is_same_domain(url):
                links.add(self.normalize_url(url))

        return links

    def extract_forms(self, html, current_url):
        """HTML에서 폼 정보 추출 (메서드, 파라미터)"""
        soup = BeautifulSoup(html, "html.parser")
        forms = []

        for form in soup.find_all("form"):
            action = urljoin(current_url, form.get("action", current_url))
            method = form.get("method", "GET").upper()
            params = {}

            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    input_type = inp.get("type", "text")
                    value = inp.get("value", "")
                    params[name] = {
                        "type": input_type,
                        "value": value,
                    }

            if self.is_same_domain(action):
                forms.append({
                    "action": self.normalize_url(action),
                    "method": method,
                    "params": params,
                })

        return forms

    def fetch_page(self, url):
        """페이지 요청 및 결과 반환"""
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            return {
                "url": url,
                "status_code": resp.status_code,
                "content_type": resp.headers.get("Content-Type", ""),
                "headers": dict(resp.headers),
                "body": resp.text,
                "body_hash": hashlib.sha256(resp.text.encode()).hexdigest()[:16],
            }
        except requests.RequestException as e:
            logger.warning(f"요청 실패: {url} - {e}")
            return None

    def _analyze_js_bundle(self, js_url: str, js_body: str):
        """JS 번들을 분석하여 API 엔드포인트를 추출."""
        if len(js_body) < 500:
            return

        try:
            raw_eps = extract_endpoints_from_js(js_body, base_url=self.target_url)
            raw_eps = detect_auth_endpoints(raw_eps)
            expanded = expand_parameterized_endpoints(raw_eps)
            self.js_endpoints.extend(expanded)
            logger.info(f"JS 분석: {js_url} → {len(raw_eps)}개 원본 + "
                        f"{len(expanded) - len(raw_eps)}개 확장 엔드포인트")
        except Exception as e:
            logger.warning(f"JS 분석 실패 ({js_url}): {e}")

    def _probe_js_endpoints(self, seen_endpoints: set):
        """JS에서 발견한 엔드포인트를 실제로 프로빙하여 결과에 추가."""
        if not self.js_endpoints:
            return

        base = f"https://{self.base_domain}"
        probed = 0
        added = 0
        max_probe = 80

        # SPA fallback body_hash 수집 (첫 HTML 응답과 동일하면 fallback)
        spa_hashes = set()
        for r in self.results:
            if (r.get("source") == "crawler"
                    and r.get("content_type", "").startswith("text/html")
                    and r.get("body_hash")):
                spa_hashes.add(r["body_hash"])

        for ep in self.js_endpoints:
            if probed >= max_probe:
                break

            path = ep["endpoint"]
            method = ep.get("method", "GET")
            dedup_key = (method, path, tuple(sorted(ep.get("params", {}).keys())))
            if dedup_key in seen_endpoints:
                continue
            seen_endpoints.add(dedup_key)

            url = f"{base}{path}"
            try:
                if method in ("GET", "HEAD"):
                    resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                else:
                    resp = self.session.request(
                        method, url, timeout=self.timeout,
                        allow_redirects=False, json={},
                    )
                status = resp.status_code
                ct = resp.headers.get("Content-Type", "")
                hdrs = dict(resp.headers)
                body_hash = hashlib.sha256(resp.content).hexdigest()[:16]
                probed += 1
            except requests.RequestException as e:
                logger.debug(f"JS 프로빙 실패: {method} {url} - {e}")
                continue

            # SPA fallback 감지: body_hash가 원본 HTML과 동일하면 건너뜀
            if body_hash in spa_hashes and status == 200 and "text/html" in ct:
                continue

            # 404이면서 text/html이면 SPA의 catch-all → 건너뜀
            if status == 404 and "text/html" in ct:
                continue

            self.results.append({
                "endpoint": path,
                "method": method,
                "params": ep.get("params", {}),
                "status_code": status,
                "content_type": ct,
                "headers": hdrs,
                "body_hash": body_hash,
                "auth_required": status in (401, 403),
                "source": ep.get("source", "js_analysis"),
                "discovered_from": ep.get("discovered_from", ""),
            })
            added += 1

        logger.info(f"JS 프로빙 완료: {probed}개 시도, {added}개 유효, "
                    f"{len(self.results)}개 총 엔드포인트")

    def crawl(self):
        """BFS 크롤링 + JS 번들 분석 실행"""
        queue = deque([(self.target_url, 0)])  # (url, depth)
        self.visited.add(self.normalize_url(self.target_url))
        seen_endpoints = set()  # (method, endpoint, params_key) 중복 방지
        js_urls_analyzed = set()

        while queue and len(self.results) < self.max_pages:
            url, depth = queue.popleft()

            if depth > self.max_depth:
                continue

            logger.info(f"[depth={depth}] 크롤링: {url}")
            page = self.fetch_page(url)
            if not page:
                continue

            # 첫 번째 HTML 응답 헤더 저장 (보안 헤더 분석용)
            if not self.response_headers and "text/html" in page.get("content_type", ""):
                self.response_headers = page["headers"]

            parsed = urlparse(url)
            endpoint = parsed.path or "/"
            params = parse_qs(parsed.query)
            dedup_key = ("GET", endpoint, tuple(sorted(params.keys())))

            # GET 요청 결과 저장 (중복 제거)
            if dedup_key not in seen_endpoints:
                seen_endpoints.add(dedup_key)
                self.results.append({
                    "endpoint": endpoint,
                    "method": "GET",
                    "params": params,
                    "status_code": page["status_code"],
                    "content_type": page["content_type"],
                    "headers": page["headers"],
                    "body_hash": page["body_hash"],
                    "auth_required": page["status_code"] in (401, 403),
                    "source": "crawler",
                    "discovered_from": url,
                })

            # JS 파일이면 번들 분석
            ct = page.get("content_type", "")
            if ("javascript" in ct or endpoint.endswith(".js")) and url not in js_urls_analyzed:
                js_urls_analyzed.add(url)
                self._analyze_js_bundle(url, page["body"])

            # HTML 페이지만 파싱
            if "text/html" not in ct:
                continue

            # 폼 추출 → POST 엔드포인트 저장 (중복 제거)
            forms = self.extract_forms(page["body"], url)
            for form in forms:
                form_parsed = urlparse(form["action"])
                form_endpoint = form_parsed.path or "/"
                form_dedup = (form["method"], form_endpoint, tuple(sorted(form["params"].keys())))

                if form_dedup not in seen_endpoints:
                    seen_endpoints.add(form_dedup)
                    self.results.append({
                        "endpoint": form_endpoint,
                        "method": form["method"],
                        "params": form["params"],
                        "status_code": None,
                        "content_type": None,
                        "headers": None,
                        "body_hash": None,
                        "auth_required": False,
                        "source": "form_discovery",
                        "discovered_from": url,
                    })

            # 링크 추출 → 큐에 추가
            links = self.extract_links(page["body"], url)
            for link in links:
                normalized = self.normalize_url(link)
                if normalized not in self.visited:
                    self.visited.add(normalized)
                    queue.append((link, depth + 1))

        # BFS 완료 후, JS에서 발견한 엔드포인트를 프로빙
        self._probe_js_endpoints(seen_endpoints)

        logger.info(f"크롤링 완료: {len(self.results)}개 엔드포인트 수집 "
                    f"(JS 분석: {len(self.js_endpoints)}개)")
        return self.results
