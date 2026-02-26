"""
BFS 크롤러 모듈
타겟 URL에서 엔드포인트를 수집하고 request_catalog에 저장한다.
"""

import logging
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class Crawler:
    """BFS 기반 웹 크롤러"""

    def __init__(self, target_url, max_depth=3, max_pages=100, timeout=10):
        self.target_url = target_url.rstrip("/")
        self.base_domain = urlparse(target_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout

        self.visited = set()
        self.results = []          # 수집된 엔드포인트 목록
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

    def crawl(self):
        """BFS 크롤링 실행"""
        queue = deque([(self.target_url, 0)])  # (url, depth)
        self.visited.add(self.normalize_url(self.target_url))
        seen_endpoints = set()  # (method, endpoint, params_key) 중복 방지

        while queue and len(self.results) < self.max_pages:
            url, depth = queue.popleft()

            if depth > self.max_depth:
                continue

            logger.info(f"[depth={depth}] 크롤링: {url}")
            page = self.fetch_page(url)
            if not page:
                continue

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

            # HTML 페이지만 파싱
            if "text/html" not in page.get("content_type", ""):
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

        logger.info(f"크롤링 완료: {len(self.results)}개 엔드포인트 수집")
        return self.results
