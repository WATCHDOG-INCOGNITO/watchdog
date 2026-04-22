"""Stateful HTTP session 도구 — multi-step web 공격용 일반 능력.

기존 http_request는 stateless (매 호출마다 새 connection + cookie X). multi-step
CTF (회원가입 → 로그인 → 글쓰기 → ...)는 세션 쿠키 chaining이 필수.

session_id 별로 requests.Session()을 in-process 캐시 (backend 컨테이너 lifetime).
multipart file 업로드도 동시 지원 — files_json으로 base64 첨부.
"""
from __future__ import annotations

import base64
import json
import time
from threading import Lock

import requests

# session_id -> (Session, last_used_ts)
_SESSIONS: dict[str, tuple[requests.Session, float]] = {}
_LOCK = Lock()
_MAX_SESSIONS = 64
_SESSION_TTL = 3600  # 1h


def _get_or_create(session_id: str) -> requests.Session:
    with _LOCK:
        # 만료 정리
        now = time.time()
        stale = [k for k, (_, ts) in _SESSIONS.items() if now - ts > _SESSION_TTL]
        for k in stale:
            _SESSIONS[k][0].close()
            del _SESSIONS[k]
        # LRU 한도
        if session_id not in _SESSIONS and len(_SESSIONS) >= _MAX_SESSIONS:
            oldest = min(_SESSIONS.items(), key=lambda kv: kv[1][1])[0]
            _SESSIONS[oldest][0].close()
            del _SESSIONS[oldest]
        if session_id not in _SESSIONS:
            s = requests.Session()
            s.headers.update({"User-Agent": "WatchdogSession/1.0"})
            _SESSIONS[session_id] = (s, now)
        else:
            sess, _ = _SESSIONS[session_id]
            _SESSIONS[session_id] = (sess, now)
        return _SESSIONS[session_id][0]


def _make_files(files_json: str) -> list:
    """files_json: '[{"name":"file","filename":"a.txt","content_b64":"...","content_type":"text/plain"}]'
    → requests.post 의 files= 형식으로 변환."""
    if not files_json or files_json.strip() in ("", "[]"):
        return []
    try:
        items = json.loads(files_json)
    except Exception:
        return []
    out = []
    for it in items if isinstance(items, list) else []:
        name = it.get("name", "file")
        fn = it.get("filename", "upload.bin")
        b64 = it.get("content_b64", "")
        ct = it.get("content_type", "application/octet-stream")
        try:
            content = base64.b64decode(b64) if b64 else b""
        except Exception:
            content = b""
        out.append((name, (fn, content, ct)))
    return out


def register(mcp):

    @mcp.tool()
    def http_session_request(
        session_id: str,
        method: str,
        url: str,
        headers_json: str = "{}",
        body: str = "",
        form_json: str = "",
        files_json: str = "",
        follow_redirects: bool = True,
        timeout_s: int = 15,
    ) -> str:
        """세션 쿠키 보존하는 HTTP 요청. multi-step web flow에 필수.

        같은 session_id로 호출하면 이전 요청의 Set-Cookie가 자동 적용 (login → 보호된 endpoint chain).

        Args:
            session_id: 임의 식별자 (예: "scan-XXXX-attacker"). 동일 id 끼리 cookie/session 공유.
            method: GET / POST / PATCH / PUT / DELETE 등
            url: 타겟 URL
            headers_json: 추가 헤더 JSON (예: '{"X-CSRF":"abc"}')
            body: raw body (form_json/files_json 우선시 무시)
            form_json: application/x-www-form-urlencoded 또는 multipart 의 텍스트 필드 JSON
                       (예: '{"username":"a","password":"b"}'). files_json 동시 지정 시 multipart.
            files_json: 파일 업로드 (multipart). [{"name":"file","filename":"x.txt",
                       "content_b64":"<base64>","content_type":"text/plain"}, ...]
            follow_redirects: default True
            timeout_s: HTTP timeout
        """
        try:
            hdrs = json.loads(headers_json) if headers_json else {}
        except Exception:
            hdrs = {}
        try:
            form = json.loads(form_json) if form_json else None
        except Exception:
            form = None
        files = _make_files(files_json)

        sess = _get_or_create(session_id)
        kwargs = dict(
            headers=hdrs, allow_redirects=follow_redirects, timeout=timeout_s,
        )
        if files:
            # multipart — form은 data로
            kwargs["data"] = form or {}
            kwargs["files"] = files
        elif form is not None:
            kwargs["data"] = form  # urlencoded
        elif body:
            kwargs["data"] = body

        try:
            t0 = time.time()
            resp = sess.request(method.upper(), url, **kwargs)
            elapsed = round(time.time() - t0, 3)
        except requests.RequestException as e:
            return json.dumps({"session_id": session_id, "url": url, "error": str(e)})

        # 새로 받은 cookies 요약
        new_cookies = {c.name: c.value for c in resp.cookies}
        all_cookies = {c.name: c.value for c in sess.cookies}

        full_body = resp.text
        ct = resp.headers.get("Content-Type", "")
        from watchdog_mcp.link_extractor import extract_links_and_hashes
        links, hashes = extract_links_and_hashes(full_body, ct, dict(resp.headers), resp.url)

        result = {
            "session_id": session_id,
            "url": resp.url,
            "status_code": resp.status_code,
            "elapsed": elapsed,
            "content_length": len(full_body),
            "content_type": ct,
            "response_headers": dict(resp.headers),
            "new_cookies": new_cookies,
            "all_cookies": all_cookies,
            "body": full_body[:5000],
        }
        if links:
            result["discovered_links"] = links
        if hashes:
            result["hash_routes"] = hashes
        return json.dumps(result, ensure_ascii=False)

    @mcp.tool()
    def http_session_cookies(session_id: str) -> str:
        """현재 세션이 보유한 모든 쿠키 조회."""
        with _LOCK:
            entry = _SESSIONS.get(session_id)
        if not entry:
            return json.dumps({"session_id": session_id, "exists": False, "cookies": {}})
        sess, _ = entry
        return json.dumps({
            "session_id": session_id,
            "exists": True,
            "cookies": {c.name: c.value for c in sess.cookies},
        }, ensure_ascii=False)

    @mcp.tool()
    def http_session_close(session_id: str) -> str:
        """세션 종료 + 쿠키 폐기."""
        with _LOCK:
            entry = _SESSIONS.pop(session_id, None)
        if entry:
            entry[0].close()
            return json.dumps({"closed": True, "session_id": session_id})
        return json.dumps({"closed": False, "session_id": session_id})
