#!/usr/bin/env python3

import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def _req(method: str, url: str, *, body: dict | None = None, timeout: int = 10) -> tuple[int, dict | str]:
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            ct = resp.headers.get("content-type", "")
            if "application/json" in ct:
                return int(resp.status), json.loads(raw.decode("utf-8"))
            return int(resp.status), raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return int(e.code), json.loads(raw.decode("utf-8"))
        except Exception:
            return int(e.code), raw.decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
        return 0, str(e)


def _healthz(base: str) -> bool:
    for path in ("/healthz", "/health/", "/health"):
        st, _ = _req("GET", f"{base}{path}", timeout=10)
        if st == 200:
            return True
    return False


def _create_run(base: str, target_url: str) -> tuple[str, str] | tuple[None, None]:
    # Legacy-style API (used in early pipeline examples)
    st, body = _req(
        "POST",
        f"{base}/runs",
        body={"target_url": target_url, "budget": {"max_requests": 50}},
        timeout=10,
    )
    if st in (200, 201) and isinstance(body, dict) and "id" in body:
        return "runs", str(body["id"])

    # Django/DRF stub backend API
    st, body = _req("POST", f"{base}/api/scan-runs/", body={"target_url": target_url}, timeout=10)
    if st in (200, 201) and isinstance(body, dict) and "run_id" in body:
        return "scan-runs", str(body["run_id"])

    return None, None


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description=(
            "E2E smoke: health check + create run + verify minimal result.\n"
            "Supports both (/healthz, /runs) and (/health/, /api/scan-runs/) shapes."
        )
    )
    p.add_argument("--base-url", required=True, help="e.g. http://localhost:8000")
    p.add_argument("--target-url", required=True, help="e.g. http://test-target:8080")
    p.add_argument("--timeout", type=int, default=60, help="seconds")
    p.add_argument("--poll-interval", type=float, default=1.0, help="seconds")
    args = p.parse_args(argv)

    base = args.base_url.rstrip("/")

    deadline = time.time() + args.timeout
    while time.time() < deadline:
        if _healthz(base):
            break
        time.sleep(args.poll_interval)
    else:
        print("health check failed", file=sys.stderr)
        return 1

    mode, run_id = None, None
    while time.time() < deadline:
        mode, run_id = _create_run(base, args.target_url)
        if mode and run_id:
            break
        time.sleep(args.poll_interval)

    if not mode or not run_id:
        print("run creation failed (tried /runs and /api/scan-runs/)", file=sys.stderr)
        return 1

    if mode == "runs":
        # poll until done/failed
        while time.time() < deadline:
            st, run = _req("GET", f"{base}/runs/{run_id}", timeout=10)
            if st != 200:
                print(f"GET /runs/{run_id} failed: status={st} body={run}", file=sys.stderr)
                return 1

            if not isinstance(run, dict):
                print(f"GET /runs/{run_id} returned unexpected body: {run}", file=sys.stderr)
                return 1

            status = str(run.get("status", ""))
            if status == "done":
                result = run.get("result")
                if not isinstance(result, dict) or int(result.get("status_code", 0)) != 200:
                    print(f"run done but result is unexpected: {run}", file=sys.stderr)
                    return 1
                return 0

            if status == "failed":
                print(f"run failed: {run}", file=sys.stderr)
                return 1

            time.sleep(args.poll_interval)

    if mode == "scan-runs":
        st, run = _req("GET", f"{base}/api/scan-runs/{run_id}/", timeout=10)
        if st != 200 or not isinstance(run, dict):
            print(f"GET /api/scan-runs/{run_id}/ failed: status={st} body={run}", file=sys.stderr)
            return 1

        # poll findings until at least 1 finding exists
        while time.time() < deadline:
            st, body = _req("GET", f"{base}/api/findings/?run_id={run_id}", timeout=10)
            if st != 200 or not isinstance(body, dict):
                print(f"GET /api/findings failed: status={st} body={body}", file=sys.stderr)
                return 1

            findings = body.get("findings")
            if isinstance(findings, list) and len(findings) >= 1:
                return 0

            time.sleep(args.poll_interval)

    print(f"timed out waiting for smoke checks: mode={mode} run_id={run_id}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
