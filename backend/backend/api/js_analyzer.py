"""
JS 번들 분석 모듈
SPA 사이트의 JavaScript 번들에서 API 엔드포인트, 라우트 경로,
인증 관련 정보를 추출한다.
"""

import logging
import re
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


# 변수 보간 치환용 플레이스홀더
_VAR_PLACEHOLDER = "{param}"

# API 경로로 인식할 최소 조건
_MIN_PATH_SEGMENTS = 2
_MAX_PATH_LENGTH = 200


def _clean_template_literal(raw: str) -> str:
    """템플릿 리터럴에서 ${...} 를 {param}으로 치환."""
    cleaned = re.sub(r"\$\{[^}]+\}", _VAR_PLACEHOLDER, raw)
    cleaned = re.sub(r"\.replace\([^)]*\)", "", cleaned)
    cleaned = cleaned.split("?")[0]
    return cleaned.strip()


def _is_api_path(path: str) -> bool:
    """API 경로로 볼 수 있는지 판정."""
    if not path or len(path) > _MAX_PATH_LENGTH:
        return False
    if not path.startswith("/"):
        return False
    if re.search(r"\.(js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)$", path, re.I):
        return False
    segments = [s for s in path.split("/") if s]
    if len(segments) < _MIN_PATH_SEGMENTS:
        return False
    return True


def _guess_method(context: str) -> str:
    """주변 코드 컨텍스트에서 HTTP 메서드를 추측."""
    ctx_lower = context.lower()
    if "delete" in ctx_lower:
        return "DELETE"
    if any(w in ctx_lower for w in ["post", "create", "submit", "add", "register", "login"]):
        return "POST"
    if any(w in ctx_lower for w in ["put", "update", "edit", "modify"]):
        return "PUT"
    if "patch" in ctx_lower:
        return "PATCH"
    return "GET"


def _guess_params_from_path(path: str) -> dict:
    """경로에서 파라미터 정보를 추출."""
    params = {}
    segments = path.split("/")
    for i, seg in enumerate(segments):
        if seg == _VAR_PLACEHOLDER and i > 0:
            param_name = segments[i - 1].rstrip("s")
            params[param_name + "_id"] = {"type": "path", "value": ""}
    return params


def _extract_query_params(raw: str) -> dict:
    """URL 문자열에서 쿼리 파라미터를 추출."""
    params = {}
    if "?" not in raw:
        return params
    qs = raw.split("?", 1)[1]
    qs = re.sub(r"\$\{[^}]+\}", "PLACEHOLDER", qs)
    for pair in qs.split("&"):
        if "=" in pair:
            key = pair.split("=", 1)[0]
            key = re.sub(r"[^a-zA-Z0-9_]", "", key)
            if key:
                params[key] = {"type": "query", "value": ""}
    return params


def _detect_api_base(js_content: str, site_base_path: str) -> str:
    """
    JS 번들에서 API 베이스 경로를 감지한다.
    예: /lms/api/v1, /api/v2, /api 등
    """
    candidates = []

    # ${window.location.origin}${path}/api/v1 패턴
    for m in re.finditer(r'[`"\'](/[^`"\']*?/api(?:/v\d+)?)[`"\']', js_content):
        p = m.group(1).rstrip("/")
        if p and len(p) < 50:
            candidates.append(p)

    # 문자열 "/api/v1" 등
    for m in re.finditer(r'["\'](/api(?:/v\d+)?)["\']', js_content):
        p = m.group(1).rstrip("/")
        candidates.append(p)

    # ${var}/v1 패턴에서 site_base_path + /api/v1 유추
    if re.search(r'`\$\{[^}]+\}/v\d+`', js_content) and site_base_path:
        candidates.append(f"{site_base_path}/api/v1")

    # 빈도 기반 최적 후보 선택 (가장 긴 것 우선)
    if candidates:
        best = max(set(candidates), key=lambda c: (len(c), candidates.count(c)))
        return best

    if site_base_path:
        return site_base_path

    return ""


def extract_endpoints_from_js(js_content: str, base_url: str = "") -> list[dict]:
    """
    JS 번들 텍스트에서 API 엔드포인트를 추출한다.

    Returns:
        list of dict, 각 항목:
          endpoint, method, params, source, discovered_from, auth_hint
    """
    results = []
    seen = set()
    site_base_path = urlparse(base_url).path.rstrip("/") if base_url else ""
    api_base = _detect_api_base(js_content, site_base_path)

    logger.info(f"API 베이스 경로 감지: '{api_base}' (site: '{site_base_path}')")

    def _resolve_path(raw_path: str) -> str:
        """상대 경로를 API 베이스 기반 절대 경로로 변환."""
        if not raw_path.startswith("/"):
            return raw_path
        # 이미 API 베이스를 포함하면 그대로
        if api_base and raw_path.startswith(api_base):
            return raw_path
        # /api/ 또는 /auth/ 로 시작하면 API 베이스 앞에 붙이기
        if re.match(r"^/(api|auth|v\d)/", raw_path):
            if site_base_path:
                return f"{site_base_path}{raw_path}"
            return raw_path
        # /group, /mentor, /user 등 리소스 경로면 API 베이스 붙이기
        api_resources = (
            "/group", "/mentor", "/mentee", "/user", "/admin",
            "/image", "/notification", "/board", "/upload", "/activity",
            "/assignment", "/attendance", "/plan", "/warn",
        )
        for res in api_resources:
            if raw_path.startswith(res):
                return f"{api_base}{raw_path}" if api_base else raw_path
        return raw_path

    def _add(path: str, method: str, params: dict, source: str, context: str = ""):
        resolved = _resolve_path(path)
        if resolved in seen:
            return
        if not _is_api_path(resolved):
            return
        seen.add(resolved)
        results.append({
            "endpoint": resolved,
            "method": method,
            "params": params,
            "source": source,
            "discovered_from": f"js_analysis:{base_url}",
            "context_hint": context[:200] if context else "",
        })

    # ── 1. 템플릿 리터럴: `...${var}...` ──
    for m in re.finditer(r"`([^`]{5,300})`", js_content):
        raw = m.group(1)
        if "${" not in raw and "/" not in raw:
            continue
        cleaned = _clean_template_literal(raw)
        if not cleaned.startswith("/"):
            # ${baseVar}/path 패턴: {param}/ 로 시작하면 / 이후 사용
            if cleaned.startswith("{param}/"):
                cleaned = cleaned[len("{param}"):]
            elif cleaned.startswith("{param}"):
                continue
            else:
                continue
        qp = _extract_query_params(raw)
        path_part = cleaned.split("?")[0]
        pp = _guess_params_from_path(path_part)
        all_params = {**pp, **qp}
        ctx = js_content[max(0, m.start() - 80):m.end() + 80]
        method = _guess_method(ctx)
        _add(path_part, method, all_params, "js_template_literal", ctx)

    # ── 2. fetch("path") / fetch(`path`) ──
    for m in re.finditer(r'fetch\s*\(\s*[`"\']([^`"\']{3,200})[`"\']', js_content):
        raw = m.group(1)
        cleaned = _clean_template_literal(raw)
        if not cleaned.startswith("/"):
            continue
        path_part = cleaned.split("?")[0]
        qp = _extract_query_params(raw)
        pp = _guess_params_from_path(path_part)
        ctx = js_content[max(0, m.start() - 100):m.end() + 100]
        method = _guess_method(ctx)
        _add(path_part, method, {**pp, **qp}, "js_fetch_call", ctx)

    # ── 3. 문자열 리터럴에서 API 경로 ──
    for m in re.finditer(r'["\'](/(?:api|auth|v[0-9]|lms|admin|group|user|mentor|mentee|board|upload|image|notification|search)[^"\']{0,150})["\']', js_content, re.I):
        raw = m.group(1)
        cleaned = _clean_template_literal(raw)
        path_part = cleaned.split("?")[0]
        if not _is_api_path(path_part):
            continue
        qp = _extract_query_params(raw)
        pp = _guess_params_from_path(path_part)
        ctx = js_content[max(0, m.start() - 80):m.end() + 80]
        method = _guess_method(ctx)
        _add(path_part, method, {**pp, **qp}, "js_string_literal", ctx)

    # ── 4. React Router 경로 정의: path: "/..." ──
    for m in re.finditer(r'path:\s*["\'](/[^"\']{1,100})["\']', js_content):
        route = m.group(1)
        full_path = f"{site_base_path}{route}" if site_base_path else route
        params = {}
        for seg_m in re.finditer(r":(\w+)", route):
            params[seg_m.group(1)] = {"type": "path", "value": ""}
        _add(full_path, "GET", params, "js_route_definition")

    # ── 5. method: "POST"/"DELETE"/etc 가 있는 fetch 호출 ──
    for m in re.finditer(
        r'fetch\s*\([^)]*\)\s*[,;]?\s*\{[^}]{0,300}method:\s*["\'](\w+)["\']',
        js_content,
    ):
        method_found = m.group(1).upper()
        chunk = js_content[max(0, m.start() - 200):m.end()]
        url_m = re.search(r'[`"\']([^`"\']{3,200})[`"\']', chunk)
        if url_m:
            raw = url_m.group(1)
            cleaned = _clean_template_literal(raw)
            path_part = cleaned.split("?")[0]
            if _is_api_path(path_part):
                qp = _extract_query_params(raw)
                pp = _guess_params_from_path(path_part)
                _add(path_part, method_found, {**pp, **qp}, "js_fetch_method")

    # ── 6. Authorization 헤더 패턴 (인증 방식 감지) ──
    auth_patterns = []
    if re.search(r'Authorization.*Bearer', js_content, re.I):
        auth_patterns.append("bearer_token")
    if re.search(r'["\']token["\']', js_content, re.I):
        auth_patterns.append("token_storage")
    if re.search(r'localStorage|sessionStorage', js_content):
        auth_patterns.append("web_storage")

    for r in results:
        r["auth_hint"] = auth_patterns

    logger.info(f"JS 분석 완료: {len(results)}개 엔드포인트 발견 (from {base_url})")
    return results


def expand_parameterized_endpoints(endpoints: list[dict]) -> list[dict]:
    """
    {param} 이 포함된 엔드포인트를 구체적인 ID 값(1~3)으로 확장.
    원본도 유지하면서 실제 프로빙 가능한 변형을 추가한다.
    """
    expanded = []
    test_ids = ["1", "2", "3"]

    for ep in endpoints:
        expanded.append(ep)
        path = ep["endpoint"]
        if _VAR_PLACEHOLDER not in path:
            continue
        for test_id in test_ids:
            concrete_path = path.replace(_VAR_PLACEHOLDER, test_id)
            expanded.append({
                **ep,
                "endpoint": concrete_path,
                "source": ep["source"] + "_expanded",
                "params": {
                    **ep.get("params", {}),
                    "_expanded_id": {"type": "path", "value": test_id},
                },
            })

    return expanded


def detect_auth_endpoints(endpoints: list[dict]) -> list[dict]:
    """인증 관련 엔드포인트를 우선순위 상향 표시."""
    auth_keywords = ["login", "register", "auth", "token", "password", "signup", "forgot"]
    for ep in endpoints:
        path_lower = ep["endpoint"].lower()
        if any(kw in path_lower for kw in auth_keywords):
            ep["is_auth_endpoint"] = True
        else:
            ep["is_auth_endpoint"] = False
    return endpoints
