#!/usr/bin/env python3

import json
import threading
import time
import uuid
import urllib.request

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


RUNS = {}
RUNS_LOCK = threading.Lock()


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_json(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    raw = handler.rfile.read(length) if length > 0 else b"{}"
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {}


def _run_mapping(run_id: str) -> None:
    with RUNS_LOCK:
        run = RUNS.get(run_id)
        if not run:
            return
        target_url = run.get("target_url", "")

    started_at = time.time()
    try:
        req = urllib.request.Request(target_url, headers={"User-Agent": "watchdog-e2e/0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read(64 * 1024)
            result = {
                "status_code": int(getattr(resp, "status", 0)),
                "content_type": resp.headers.get("content-type", ""),
                "bytes": len(body),
            }
        status = "done"
    except Exception as e:
        result = {"error": str(e)}
        status = "failed"

    finished_at = time.time()
    with RUNS_LOCK:
        run = RUNS.get(run_id)
        if not run:
            return
        run["status"] = status
        run["result"] = result
        run["started_at"] = started_at
        run["finished_at"] = finished_at


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        # Quiet by default; CI logs are noisy enough.
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"ok\n")
            return

        if self.path.startswith("/runs/"):
            run_id = self.path.split("/runs/", 1)[1].strip("/")
            with RUNS_LOCK:
                run = RUNS.get(run_id)
            if not run:
                _json_response(self, 404, {"error": "not_found"})
                return
            _json_response(self, 200, run)
            return

        _json_response(self, 404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/runs":
            _json_response(self, 404, {"error": "not_found"})
            return

        payload = _read_json(self)
        target_url = payload.get("target_url", "")
        if not isinstance(target_url, str) or not target_url:
            _json_response(self, 400, {"error": "target_url_required"})
            return

        run_id = str(uuid.uuid4())
        run = {
            "id": run_id,
            "status": "queued",
            "target_url": target_url,
            "budget": payload.get("budget", {}),
        }
        with RUNS_LOCK:
            RUNS[run_id] = run

        t = threading.Thread(target=_run_mapping, args=(run_id,), daemon=True)
        t.start()

        _json_response(self, 201, {"id": run_id, "status": "queued"})


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 8000), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()

