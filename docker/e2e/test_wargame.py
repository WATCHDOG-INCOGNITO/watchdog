#!/usr/bin/env python3
"""
워게임 통합 테스트 — Watchdog 파이프라인 전체를 실행하고 취약점 탐지를 검증한다.

흐름:
  1. health check
  2. POST /api/scan-runs/ → 스캔 생성 (target = wargame)
  3. POST /api/scan-runs/{run_id}/start/ → 크롤링 + 규칙 필터링 + LLM 분석 + 검증
  4. 완료 대기 (polling)
  5. 결과 확인: request_catalog, candidates, findings
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request


EXPECTED_VULN_TYPES = {"sqli", "xss", "idor", "ssrf"}


def req(method, url, body=None, timeout=15):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"

    r = urllib.request.Request(url, method=method, data=data, headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read().decode()
            ct = resp.headers.get("content-type", "")
            return resp.status, json.loads(raw) if "json" in ct else raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw
    except Exception as e:
        return 0, str(e)


def wait_health(base, deadline):
    while time.time() < deadline:
        st, _ = req("GET", f"{base}/health/")
        if st == 200:
            return True
        time.sleep(1)
    return False


def main(argv):
    p = argparse.ArgumentParser(description="Wargame integration test")
    p.add_argument("--base-url", default="http://localhost:8000")
    p.add_argument("--target-url", default="http://wargame:5000")
    p.add_argument("--timeout", type=int, default=180)
    args = p.parse_args(argv)

    base = args.base_url.rstrip("/")
    deadline = time.time() + args.timeout
    passed = 0
    failed = 0

    # -------------------------------------------------------
    print("=" * 60)
    print("Watchdog Wargame Integration Test")
    print("=" * 60)

    # 1. Health
    print("\n[1/6] Health check ...", end=" ")
    if not wait_health(base, min(time.time() + 30, deadline)):
        print("FAIL")
        return 1
    print("OK")

    # 2. Create scan
    print("[2/6] Creating scan run ...", end=" ")
    st, body = req("POST", f"{base}/api/scan-runs/", {"target_url": args.target_url})
    if st not in (200, 201) or not isinstance(body, dict):
        print(f"FAIL (status={st})")
        return 1
    run_id = body.get("run_id")
    if not run_id:
        print(f"FAIL (no run_id in response)")
        return 1
    print(f"OK  run_id={run_id}")

    # 3. Start scan
    print("[3/6] Starting scan (crawl → rule → LLM → verify) ...", end=" ", flush=True)
    st, body = req("POST", f"{base}/api/scan-runs/{run_id}/start/", {})
    if st not in (200, 201):
        print(f"FAIL (status={st} body={body})")
        return 1
    print("triggered")

    # 4. Poll until finished/failed
    print("[4/6] Waiting for scan to finish ...", flush=True)
    last_status = ""
    while time.time() < deadline:
        st, body = req("GET", f"{base}/api/scan-runs/{run_id}/")
        if st == 200 and isinstance(body, dict):
            s = body.get("status", "")
            if s != last_status:
                print(f"       status = {s}")
                last_status = s
            if s == "finished":
                break
            if s == "failed":
                print(f"       ERROR: scan failed — {body.get('error_log', '')}")
                break
        time.sleep(3)
    else:
        print("       TIMEOUT")
        # 타임아웃이어도 중간 결과 확인 계속 진행

    # 5. Check results
    print("\n[5/6] Checking results ...")

    # 5a. Request catalog
    st, body = req("GET", f"{base}/api/request-catalog/list/?run_id={run_id}")
    requests_found = 0
    if st == 200 and isinstance(body, dict):
        items = body.get("requests", [])
        requests_found = len(items)
    print(f"  - Request catalog : {requests_found} endpoints")

    # 5b. Candidates
    st, body = req("GET", f"{base}/api/candidates/list/?run_id={run_id}")
    candidates = []
    if st == 200 and isinstance(body, dict):
        candidates = body.get("candidates", [])
    cand_count = len(candidates)
    vuln_types_found = set()
    for c in candidates:
        vt = c.get("vuln_type", "")
        if vt:
            vuln_types_found.add(vt)
    print(f"  - Candidates      : {cand_count}")
    print(f"  - Vuln types      : {sorted(vuln_types_found)}")

    # 5c. Findings
    st, body = req("GET", f"{base}/api/findings/?run_id={run_id}")
    findings = []
    if st == 200 and isinstance(body, dict):
        findings = body.get("findings", [])
    finding_count = len(findings)
    print(f"  - Findings        : {finding_count}")

    # 5d. LLM usage
    st, body = req("GET", f"{base}/api/scan-runs/{run_id}/")
    if st == 200 and isinstance(body, dict):
        print(f"  - LLM calls       : {body.get('llm_calls_count', 0)}")
        print(f"  - LLM tokens      : {body.get('llm_tokens_used', 0)}")
        print(f"  - LLM cost (USD)  : ${body.get('llm_cost_usd', '0')}")
        print(f"  - Budget used     : {body.get('request_budget_used', 0)}")

    # 6. Assertions
    print(f"\n[6/6] Assertions ...")

    checks = [
        ("endpoints crawled (>= 5)",    requests_found >= 5),
        ("candidates created (>= 3)",   cand_count >= 3),
        ("sqli detected",               "sqli" in vuln_types_found),
        ("xss detected",                "xss" in vuln_types_found),
        ("idor detected",               "idor" in vuln_types_found),
    ]

    for label, ok in checks:
        status_str = "PASS" if ok else "FAIL"
        print(f"  [{status_str}] {label}")
        if ok:
            passed += 1
        else:
            failed += 1

    if finding_count > 0:
        print(f"  [PASS] findings confirmed ({finding_count})")
        passed += 1
    else:
        print(f"  [WARN] no confirmed findings (검증 단계 페이로드가 실제 반응 못 받았을 수 있음)")

    # Detail dump
    if candidates:
        print("\n--- Candidate Detail ---")
        for c in candidates:
            llm = c.get("features", {}).get("llm_analysis", {})
            print(f"  [{c.get('status', '?'):15s}] {c.get('vuln_type', '?'):8s} "
                  f"score={c.get('priority_score', 0):.2f}  "
                  f"stage={c.get('detection_stage', '?')}  "
                  f"llm_risk={llm.get('risk_level', '-')}  "
                  f"llm_action={llm.get('next_action', '-')}")

    if findings:
        print("\n--- Finding Detail ---")
        for f in findings:
            print(f"  [{f.get('severity', '?'):8s}] {f.get('title', '?')}  "
                  f"confidence={f.get('confidence', 0)}")

    print("\n" + "=" * 60)
    print(f"Result: {passed} passed, {failed} failed")
    print("=" * 60)

    return 1 if failed > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
