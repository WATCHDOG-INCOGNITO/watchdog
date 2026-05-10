"""Browser agent — headful chromium inside Xvfb, controlled via Flask API.

Flow:
  POST /login {target_url, profile_name}
      → launches Playwright chromium on DISPLAY=:99
      → navigates to target
      → waits (up to 10 min) for login completion
           auto-detect: cookie named Access-Token / session / jsessionid
                        is Set-Cookie'd + URL changes away from login page
           manual-fallback: POST /complete/<task_id>
      → exports storage_state, saves to /profiles/<name>.json,
        POSTs to Watchdog backend /api/profiles/import

  GET  /status/<task_id>     → current state dict
  POST /complete/<task_id>   → manual "I'm done" trigger
  POST /stop/<task_id>       → abort task
  GET  /health               → liveness probe

sync_playwright handles are bound to the thread that called .start(),
so we cannot share a browser across Flask request threads. Each login
task spins up its own Playwright + chromium inside its background
worker; _pw_serial_lock enforces "one headful chromium at a time" to
avoid two instances fighting over the same Xvfb display.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from pathlib import Path

import requests
from flask import Flask, jsonify, request
from playwright.sync_api import sync_playwright

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s")
logger = logging.getLogger("browser_agent")

WATCHDOG_API = os.environ.get("WATCHDOG_API", "http://backend:8000").rstrip("/")
PROFILES_DIR = Path(os.environ.get("PROFILES_DIR", "/profiles"))
PROFILES_DIR.mkdir(parents=True, exist_ok=True)
AGENT_PORT = int(os.environ.get("AGENT_PORT", "8891"))
LOGIN_TIMEOUT_SEC = int(os.environ.get("LOGIN_TIMEOUT_SEC", "600"))

app = Flask(__name__)

_tasks: dict[str, dict] = {}
_tasks_lock = threading.Lock()
_pw_serial_lock = threading.Lock()


AUTH_COOKIE_MARKERS = (
    "access-token", "access_token", "accesstoken",
    "refresh-token", "refresh_token", "refreshtoken",
    "session=", "sessionid=", "session_id=",
    "jsessionid=", "phpsessid=",
    "auth=", "authtoken=", "token=",
    "connect.sid=", "sid=",
)


def _run_login_task(task_id: str, target_url: str, profile_name: str):
    state = _tasks[task_id]
    try:
        with _pw_serial_lock:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(
                    headless=False,
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-blink-features=AutomationControlled",
                        "--window-size=1920,1080",
                        "--window-position=0,0",
                        "--start-maximized",
                        "--disable-infobars",
                    ],
                )
                try:
                    context = browser.new_context(
                        viewport={"width": 1920, "height": 1040},
                        ignore_https_errors=True,
                    )
                    try:
                        page = context.new_page()
                        state["state"] = "waiting"
                        state["message"] = "navigate to target"

                        try:
                            page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
                        except Exception as e:
                            state["message"] = f"navigate warning: {e}"

                        from urllib.parse import urlparse as _urlparse
                        target_host = ""
                        try:
                            target_host = _urlparse(target_url).netloc.lower()
                        except Exception:
                            pass

                        # Cookie names that indicate successful auth. Match
                        # both exact (session) and common-prefix (access_token
                        # → accesstoken / access-token / accessToken).
                        _AUTH_NAMES = (
                            "access-token", "access_token", "accesstoken", "accesstoken",
                            "refresh-token", "refresh_token", "refreshtoken",
                            "session", "sessionid", "session_id",
                            "jsessionid", "phpsessid",
                            "auth", "authtoken", "token",
                            "connect.sid", "sid",
                            "authorization",
                        )

                        def _has_target_auth_cookie() -> bool:
                            """Poll context cookies for any auth-like cookie
                            bound to target_host (or its parent). More robust
                            than response.headers.set-cookie which only
                            exposes the first Set-Cookie per response in
                            Playwright Python."""
                            if not target_host:
                                return False
                            try:
                                cookies = context.cookies()
                            except Exception:
                                return False
                            for c in cookies:
                                dom = (c.get("domain") or "").lstrip(".").lower()
                                if not dom:
                                    continue
                                # match target host or its immediate parent
                                if not (dom == target_host
                                        or target_host.endswith("." + dom)
                                        or dom.endswith("." + target_host)):
                                    continue
                                name = (c.get("name") or "").lower().replace("-", "").replace("_", "")
                                for marker in _AUTH_NAMES:
                                    if marker.replace("-", "").replace("_", "") in name or name in marker.replace("-", "").replace("_", ""):
                                        return True
                            return False

                        def _is_interstitial(u: str) -> bool:
                            """True if URL is still in the middle of an auth
                            handshake (3rd-party IdP page or our own login
                            form). /auth/callback is explicitly NOT
                            interstitial — that's the post-OAuth landing where
                            target cookies arrive."""
                            low = u.lower()
                            for marker in (
                                "accounts.google.com",
                                "login.microsoftonline.com",
                                "github.com/login",
                                "appleid.apple.com",
                                "kauth.kakao.com",
                                "nid.naver.com",
                            ):
                                if marker in low:
                                    return True
                            try:
                                u_host = _urlparse(u).netloc.lower()
                                u_path = _urlparse(u).path.lower().rstrip("/")
                            except Exception:
                                return False
                            if target_host and u_host == target_host:
                                if u_path in ("", "/") or u_path.startswith("/auth/callback"):
                                    return False
                                if any(seg in u_path for seg in ("/login", "/signin", "/signup", "/register")):
                                    return True
                            return False

                        def _any_page_on_target():
                            """User may open a new tab or OAuth may use a
                            popup — initial `page` is not the only surface.
                            Walk all context.pages and return the one on
                            target_host if any, else the most-recently-active
                            page's url."""
                            try:
                                pages = list(context.pages)
                            except Exception:
                                pages = [page]
                            chosen_url = ""
                            for p in pages:
                                try:
                                    u = p.url
                                    h = _urlparse(u).netloc.lower()
                                except Exception:
                                    continue
                                if target_host and h == target_host:
                                    return u, h
                                chosen_url = u
                            try:
                                return chosen_url or page.url, _urlparse(chosen_url or page.url).netloc.lower()
                            except Exception:
                                return chosen_url, ""

                        cookie_settle_deadline = 0.0
                        start = time.time()
                        last_url = page.url
                        tick = 0
                        while time.time() - start < LOGIN_TIMEOUT_SEC:
                            time.sleep(1)
                            tick += 1
                            if state.get("stop"):
                                state["state"] = "stopped"
                                break
                            if state.get("manual_done"):
                                state["state"] = "detected"
                                state["detected_via"] = "manual"
                                break

                            cur_url, cur_host = _any_page_on_target()
                            on_target = bool(target_host) and cur_host == target_host
                            # Always poll cookies — auth may arrive via
                            # OAuth popup into the shared context even when
                            # the focused page URL is still google.com.
                            has_auth = _has_target_auth_cookie()
                            is_inter = _is_interstitial(cur_url)

                            # periodic cookie dump for diagnostics
                            if tick % 5 == 0 or has_auth:
                                try:
                                    ck = context.cookies()
                                    state["debug_cookies"] = {
                                        "count": len(ck),
                                        "domains": sorted({(c.get("domain") or "").lstrip(".") for c in ck})[:20],
                                        "target_names": sorted({
                                            c.get("name", "") for c in ck
                                            if target_host and (
                                                (c.get("domain") or "").lstrip(".").lower() == target_host
                                                or target_host.endswith("." + (c.get("domain") or "").lstrip(".").lower())
                                            )
                                        }),
                                    }
                                except Exception as e:
                                    state["debug_cookies"] = {"error": str(e)}

                            state["debug"] = {
                                "tick": tick,
                                "cur_url": cur_url[:180],
                                "cur_host": cur_host,
                                "on_target": on_target,
                                "has_auth_cookie": has_auth,
                                "is_interstitial": is_inter,
                                "page_count": len(context.pages) if context else 0,
                                "cookie_settle_deadline_in": (
                                    round(cookie_settle_deadline - time.time(), 1)
                                    if cookie_settle_deadline > 0 else None
                                ),
                            }
                            # log every 10s to keep container logs useful
                            if tick % 10 == 0:
                                logger.info(
                                    f"task {task_id[:8]} tick={tick} host={cur_host} "
                                    f"on_target={on_target} has_auth={has_auth} "
                                    f"interstitial={is_inter}"
                                )

                            if on_target and has_auth and not is_inter:
                                if cookie_settle_deadline == 0.0:
                                    cookie_settle_deadline = time.time() + 3.0
                                elif time.time() >= cookie_settle_deadline:
                                    state["state"] = "detected"
                                    state["detected_via"] = "auto_cookie_onhost"
                                    break
                            else:
                                cookie_settle_deadline = 0.0
                            last_url = cur_url

                        if state["state"] not in ("detected",):
                            if state["state"] == "waiting":
                                state["state"] = "timeout"
                                state["message"] = f"no login detected within {LOGIN_TIMEOUT_SEC}s"
                            return

                        try:
                            storage = context.storage_state()
                        except Exception as e:
                            state["state"] = "error"
                            state["message"] = f"storage_state export failed: {e}"
                            return

                        cookies = storage.get("cookies") or []
                        origins = storage.get("origins") or []
                        state["cookie_count"] = len(cookies)
                        state["origin_count"] = len(origins)
                        state["cookie_hosts"] = sorted({
                            (c.get("domain") or "").lstrip(".")
                            for c in cookies
                            if c.get("domain")
                        })

                        safe = "".join(c for c in profile_name if c.isalnum() or c in ("-", "_"))[:64] or "profile"
                        out = PROFILES_DIR / f"{safe}.json"
                        wrapper = {
                            "_meta": {
                                "target": target_url,
                                "profile": safe,
                                "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                "detected_via": state.get("detected_via"),
                            },
                            **storage,
                        }
                        try:
                            out.write_text(json.dumps(wrapper, ensure_ascii=False, indent=2), encoding="utf-8")
                            state["profile_file"] = str(out)
                        except Exception as e:
                            state["profile_write_error"] = str(e)

                        try:
                            r = requests.post(
                                f"{WATCHDOG_API}/api/profiles/import/",
                                json={
                                    "profile_name": safe,
                                    "state": storage,
                                    "target": target_url,
                                    "detected_via": state.get("detected_via"),
                                },
                                timeout=15,
                            )
                            state["watchdog_status_code"] = r.status_code
                            try:
                                state["watchdog_response"] = r.json()
                            except Exception:
                                state["watchdog_response"] = r.text[:500]
                        except Exception as e:
                            state["watchdog_error"] = str(e)

                        state["state"] = "done"
                        logger.info(f"task {task_id} done — profile={safe} cookies={len(cookies)}")
                    finally:
                        try:
                            context.close()
                        except Exception:
                            pass
                finally:
                    try:
                        browser.close()
                    except Exception:
                        pass
    except Exception as e:
        logger.exception(f"task {task_id} failed")
        state["state"] = "error"
        state["message"] = str(e)


@app.route("/login", methods=["POST"])
def login():
    body = request.get_json(force=True, silent=True) or {}
    target_url = (body.get("target_url") or "").strip()
    profile_name = (body.get("profile_name") or "").strip()
    if not target_url or not profile_name:
        return jsonify({"error": "target_url + profile_name required"}), 400

    task_id = str(uuid.uuid4())
    with _tasks_lock:
        _tasks[task_id] = {
            "task_id": task_id,
            "state": "pending",
            "target_url": target_url,
            "profile_name": profile_name,
            "created_at": time.time(),
        }
    t = threading.Thread(
        target=_run_login_task,
        args=(task_id, target_url, profile_name),
        daemon=True,
    )
    t.start()
    return jsonify({"task_id": task_id, "state": "pending", "target_url": target_url})


@app.route("/status/<task_id>")
def status(task_id):
    with _tasks_lock:
        s = _tasks.get(task_id)
    if not s:
        return jsonify({"error": "task not found"}), 404
    return jsonify(dict(s))


@app.route("/tasks")
def list_tasks():
    with _tasks_lock:
        rows = [
            {k: v for k, v in s.items() if k not in ("watchdog_response",)}
            for s in _tasks.values()
        ]
    rows.sort(key=lambda r: r.get("created_at", 0), reverse=True)
    return jsonify({"tasks": rows[:20]})


@app.route("/complete/<task_id>", methods=["POST"])
def complete(task_id):
    with _tasks_lock:
        s = _tasks.get(task_id)
    if not s:
        return jsonify({"error": "task not found"}), 404
    s["manual_done"] = True
    return jsonify({"ack": True, "task_id": task_id})


@app.route("/stop/<task_id>", methods=["POST"])
def stop(task_id):
    with _tasks_lock:
        s = _tasks.get(task_id)
    if not s:
        return jsonify({"error": "task not found"}), 404
    s["stop"] = True
    return jsonify({"ack": True, "task_id": task_id})


@app.route("/health")
def health():
    with _tasks_lock:
        active = sum(1 for s in _tasks.values() if s.get("state") in ("pending", "waiting"))
    return jsonify({
        "ok": True,
        "tasks_total": len(_tasks),
        "tasks_active": active,
        "watchdog_api": WATCHDOG_API,
        "profiles_dir": str(PROFILES_DIR),
    })


if __name__ == "__main__":
    logger.info(f"browser_agent listening on 0.0.0.0:{AGENT_PORT}")
    logger.info(f"WATCHDOG_API={WATCHDOG_API}  PROFILES_DIR={PROFILES_DIR}")
    app.run(host="0.0.0.0", port=AGENT_PORT, debug=False, threaded=True)
