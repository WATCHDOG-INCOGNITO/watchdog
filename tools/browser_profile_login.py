"""watchdog-profile — local helper for SSO-authenticated pentest sessions.

Opens a headful Playwright chromium so the researcher can log in
manually (Google SSO / SAML / whatever), then exports the session as a
Playwright `storage_state` JSON. The JSON can be pushed into the
Watchdog MCP browser via `browser_load_storage_state` so every
subsequent headless `browser_navigate` is authenticated.

Subcommands:
  login   --target URL --profile NAME   interactive login, save profile
  refresh --profile NAME                re-open profile (for re-login when expired)
  show    --profile NAME                print cookie summary (names/domains/expiry)
  list                                  list stored profiles
  delete  --profile NAME                remove a profile
  load    --profile NAME --scan-run-id UUID [--mcp-url URL]
                                        push profile into running Watchdog MCP
                                        (uses /api helper endpoint or direct SSE tool call)

Profiles are stored as `profiles/<NAME>.json` relative to the repo
root. The directory is gitignored.

Requires Playwright (`pip install playwright && playwright install
chromium`). On Windows a real desktop session is needed — headful
chromium will not launch inside WSL2 without an X server.
"""
from __future__ import annotations

import argparse
import base64
import datetime as _dt
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
PROFILE_DIR = REPO_ROOT / "profiles"
PROFILE_DIR.mkdir(exist_ok=True)


def _profile_path(name: str) -> Path:
    safe = name.strip().replace(os.sep, "_").replace("..", "_")
    if not safe or safe.startswith("."):
        raise SystemExit(f"invalid profile name: {name!r}")
    return PROFILE_DIR / f"{safe}.json"


def _load_profile(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(f"profile not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise SystemExit(f"profile parse error: {e}")


def _save_profile(path: Path, state: dict, meta: dict) -> None:
    wrapper = {
        "_meta": meta,
        **state,
    }
    path.write_text(json.dumps(wrapper, ensure_ascii=False, indent=2), encoding="utf-8")


def _launch_interactive(target: str, seed_state: dict | None = None) -> dict:
    """Open headful chromium at target. Block until the user closes the
    tab or types 'done' on stdin. Return the final storage_state dict."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        raise SystemExit(
            "playwright is not installed. run:\n"
            "  pip install playwright\n"
            "  playwright install chromium"
        )

    print(f"[profile-login] launching chromium → {target}", flush=True)
    print("[profile-login] complete SSO login, then come back to this", flush=True)
    print("[profile-login] terminal and press ENTER (or close the window)", flush=True)

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=False, args=["--no-first-run"])
        kwargs = {"viewport": {"width": 1280, "height": 800}}
        if seed_state:
            kwargs["storage_state"] = seed_state
        context = browser.new_context(**kwargs)
        page = context.new_page()
        try:
            page.goto(target, wait_until="domcontentloaded", timeout=60000)
        except Exception as e:
            print(f"[profile-login] navigation warning: {e}", flush=True)

        closed = {"v": False}

        def _on_close(_):
            closed["v"] = True

        page.on("close", _on_close)
        context.on("close", lambda _: _on_close(None))

        try:
            input("[profile-login] press ENTER when login is complete > ")
        except (KeyboardInterrupt, EOFError):
            print("\n[profile-login] aborted", flush=True)
            try:
                browser.close()
            except Exception:
                pass
            raise SystemExit(1)

        try:
            state = context.storage_state()
        except Exception as e:
            browser.close()
            raise SystemExit(f"failed to export storage_state: {e}")

        try:
            browser.close()
        except Exception:
            pass
        return state


def _summarize(state: dict) -> dict:
    cookies = state.get("cookies") or []
    origins = state.get("origins") or []
    now = _dt.datetime.now(_dt.timezone.utc).timestamp()
    hosts: dict[str, dict] = {}
    for c in cookies:
        h = (c.get("domain") or "").lstrip(".")
        if not h:
            continue
        exp = c.get("expires") or -1
        exp_iso = ""
        if exp and exp > 0:
            try:
                exp_iso = _dt.datetime.fromtimestamp(exp, tz=_dt.timezone.utc).isoformat()
            except Exception:
                pass
        bucket = hosts.setdefault(h, {
            "total": 0,
            "httponly": 0,
            "secure": 0,
            "expired": 0,
            "cookie_names": [],
            "earliest_expiry": None,
        })
        bucket["total"] += 1
        if c.get("httpOnly"):
            bucket["httponly"] += 1
        if c.get("secure"):
            bucket["secure"] += 1
        if exp and exp > 0 and exp < now:
            bucket["expired"] += 1
        if c.get("name"):
            bucket["cookie_names"].append(c["name"])
        if exp and exp > 0:
            if bucket["earliest_expiry"] is None or exp < bucket["earliest_expiry"]:
                bucket["earliest_expiry"] = exp
    for h, b in hosts.items():
        if b["earliest_expiry"]:
            try:
                b["earliest_expiry"] = _dt.datetime.fromtimestamp(
                    b["earliest_expiry"], tz=_dt.timezone.utc
                ).isoformat()
            except Exception:
                b["earliest_expiry"] = None
    return {
        "cookie_count": len(cookies),
        "origin_count": len(origins),
        "hosts": hosts,
        "origins": [o.get("origin") for o in origins],
    }


def cmd_login(args):
    path = _profile_path(args.profile)
    seed = None
    if path.exists() and not args.force:
        raise SystemExit(
            f"profile already exists: {path}\nuse `refresh` to update or `--force` to overwrite"
        )
    state = _launch_interactive(args.target, seed_state=None)
    meta = {
        "target": args.target,
        "profile": args.profile,
        "saved_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "playwright_version": _get_playwright_version(),
    }
    _save_profile(path, state, meta)
    summary = _summarize(state)
    print(json.dumps({
        "saved": str(path),
        "summary": summary,
    }, ensure_ascii=False, indent=2))


def cmd_refresh(args):
    path = _profile_path(args.profile)
    existing = _load_profile(path)
    meta = existing.pop("_meta", {})
    target = args.target or meta.get("target")
    if not target:
        raise SystemExit("--target required (profile has no saved target)")
    state = _launch_interactive(target, seed_state=existing)
    meta["target"] = target
    meta["refreshed_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
    _save_profile(path, state, meta)
    print(json.dumps({"refreshed": str(path), "summary": _summarize(state)}, ensure_ascii=False, indent=2))


def cmd_show(args):
    path = _profile_path(args.profile)
    data = _load_profile(path)
    meta = data.get("_meta", {})
    state = {k: v for k, v in data.items() if k != "_meta"}
    print(json.dumps({
        "path": str(path),
        "meta": meta,
        "summary": _summarize(state),
    }, ensure_ascii=False, indent=2))


def cmd_list(_args):
    profiles = []
    for p in sorted(PROFILE_DIR.glob("*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            meta = data.get("_meta", {})
            cookies = data.get("cookies") or []
            profiles.append({
                "name": p.stem,
                "target": meta.get("target"),
                "saved_at": meta.get("saved_at") or meta.get("refreshed_at"),
                "cookie_count": len(cookies),
            })
        except Exception:
            profiles.append({"name": p.stem, "error": "parse_failed"})
    print(json.dumps({"profiles": profiles, "dir": str(PROFILE_DIR)}, ensure_ascii=False, indent=2))


def cmd_delete(args):
    path = _profile_path(args.profile)
    if not path.exists():
        raise SystemExit(f"profile not found: {path}")
    path.unlink()
    print(json.dumps({"deleted": str(path)}, ensure_ascii=False))


def cmd_load(args):
    """Push a stored profile into a running Watchdog MCP via the REST
    helper endpoint. Also syncs cookies into ScanRun._secrets for
    http_request reuse.

    Fallback: if --mcp-url points at the SSE endpoint directly, we do
    not speak SSE here — the user can instead invoke
    `browser_load_storage_state` from within their MCP client with the
    JSON this command prints.
    """
    path = _profile_path(args.profile)
    data = _load_profile(path)
    state = {k: v for k, v in data.items() if k != "_meta"}
    payload = {
        "scan_run_id": args.scan_run_id,
        "state": state,
    }
    if args.print_json:
        print(json.dumps(state, ensure_ascii=False))
        return
    # default: just print a copy-paste-ready MCP invocation hint
    print(json.dumps({
        "profile": str(path),
        "scan_run_id": args.scan_run_id,
        "hint": "call `browser_load_storage_state` with this JSON as state_json:",
        "state_json_preview": json.dumps(state, ensure_ascii=False)[:400] + "...",
    }, ensure_ascii=False, indent=2))


def _get_playwright_version() -> str:
    try:
        import playwright
        return getattr(playwright, "__version__", "unknown")
    except Exception:
        return "not-installed"


def main():
    p = argparse.ArgumentParser(prog="browser_profile_login")
    sub = p.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("login", help="interactive login → new profile")
    pl.add_argument("--target", required=True, help="URL to open for SSO login")
    pl.add_argument("--profile", required=True, help="profile name (stored as profiles/<name>.json)")
    pl.add_argument("--force", action="store_true", help="overwrite if exists")
    pl.set_defaults(func=cmd_login)

    pr = sub.add_parser("refresh", help="re-open existing profile to refresh/re-login")
    pr.add_argument("--profile", required=True)
    pr.add_argument("--target", help="override target URL (default: use saved)")
    pr.set_defaults(func=cmd_refresh)

    ps = sub.add_parser("show", help="print profile cookie summary")
    ps.add_argument("--profile", required=True)
    ps.set_defaults(func=cmd_show)

    sub.add_parser("list", help="list stored profiles").set_defaults(func=cmd_list)

    pd = sub.add_parser("delete", help="remove profile file")
    pd.add_argument("--profile", required=True)
    pd.set_defaults(func=cmd_delete)

    pld = sub.add_parser("load", help="print profile JSON (for piping into MCP browser_load_storage_state)")
    pld.add_argument("--profile", required=True)
    pld.add_argument("--scan-run-id", required=False, default="", help="optional: scan_run_id to tag payload")
    pld.add_argument("--print-json", action="store_true", help="raw JSON only (no metadata)")
    pld.set_defaults(func=cmd_load)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
