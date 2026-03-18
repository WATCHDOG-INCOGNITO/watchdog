import json
import sys
import time
import urllib.error
import urllib.request
import argparse


def req(method, url, body=None, timeout=15):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    r = urllib.request.Request(url, method=method, data=data, headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read()
            return int(resp.status), json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return int(e.code), json.loads(raw.decode("utf-8"))
        except Exception:
            return int(e.code), raw.decode("utf-8", errors="replace")
    except Exception as e:
        return 0, str(e)


def main(argv):
    p = argparse.ArgumentParser()
    p.add_argument("--base-url", default="http://backend:8000")
    p.add_argument("--target-url", default="https://mjsec.kr")
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--poll-interval", type=float, default=3.0)
    args = p.parse_args(argv)

    base = args.base_url.rstrip("/")

    # 1. 헬스체크
    print("[1/5] 백엔드 헬스체크...", flush=True)
    deadline = time.time() + 30
    while time.time() < deadline:
        st, body = req("GET", f"{base}/health/")
        if st == 200:
            print(f"      OK: {body}", flush=True)
            break
        time.sleep(1)
    else:
        print("      FAIL: 헬스체크 실패", file=sys.stderr)
        return 1

    # 2. 스캔 런 생성
    print(f"\n[2/5] 스캔 런 생성: {args.target_url}", flush=True)
    st, body = req("POST", f"{base}/api/scan-runs/", {"target_url": args.target_url})
    if st not in (200, 201):
        print(f"      FAIL: {st} {body}", file=sys.stderr)
        return 1
    run_id = body.get("run_id")
    print(f"      run_id: {run_id}", flush=True)

    # 3. 스캔 시작
    print(f"\n[3/5] 스캔 시작 (크롤링 → 규칙 필터 → LLM 분석)...", flush=True)
    st, body = req("POST", f"{base}/api/scan-runs/{run_id}/start/", {})
    if st not in (200, 201):
        print(f"      FAIL: {st} {body}", file=sys.stderr)
        return 1
    print(f"      {body.get('message', 'started')}", flush=True)

    # 4. 완료까지 폴링
    print(f"\n[4/5] 완료 대기 (최대 {args.timeout}초)...", flush=True)
    deadline = time.time() + args.timeout
    last_status = None
    while time.time() < deadline:
        st, run = req("GET", f"{base}/api/scan-runs/{run_id}/")
        if st != 200:
            print(f"      WARN: {st}", flush=True)
            time.sleep(args.poll_interval)
            continue

        status = run.get("status", "")
        if status != last_status:
            elapsed = int(args.timeout - (deadline - time.time()))
            print(f"      [{elapsed:>3}s] status={status}", flush=True)
            last_status = status

        if status == "finished":
            break
        if status == "failed":
            print(f"      FAIL: {run.get('error_log', 'unknown error')}", file=sys.stderr)
            return 1

        time.sleep(args.poll_interval)
    else:
        print("      WARN: timeout — 부분 결과 출력", flush=True)

    # 5. 결과 출력
    print(f"\n[5/5] 결과 수집...", flush=True)

    # request catalog
    st, cat = req("GET", f"{base}/api/request-catalog/list/?run_id={run_id}")
    catalog = cat.get("requests", []) if st == 200 else []
    print(f"\n  크롤링된 엔드포인트: {len(catalog)}개")
    for item in catalog[:20]:
        print(f"    [{item.get('method','?')}] {item.get('endpoint','?')}  status={item.get('status_code','?')}")
    if len(catalog) > 20:
        print(f"    ... ({len(catalog)-20}개 더)")

    # candidates
    st, cands_resp = req("GET", f"{base}/api/candidates/list/?run_id={run_id}")
    candidates = cands_resp.get("candidates", []) if st == 200 else []
    print(f"\n  의심 지점 (candidates): {len(candidates)}개")
    candidates_sorted = sorted(candidates, key=lambda x: x.get("priority_score", 0), reverse=True)
    for c in candidates_sorted[:20]:
        llm = c.get("features", {}).get("llm_analysis", {})
        llm_str = ""
        if llm:
            llm_str = f"  → LLM: risk={llm.get('risk_level','?')} confidence={llm.get('confidence','?')} action={llm.get('next_action','?')}"
        print(f"    [{c.get('vuln_type','?')}] {c.get('hypothesis','?')[:80]}")
        print(f"      score={c.get('priority_score',0):.2f} stage={c.get('detection_stage','?')}{llm_str}")

    # findings
    st, finds = req("GET", f"{base}/api/findings/?run_id={run_id}")
    findings = finds.get("findings", []) if st == 200 else []
    print(f"\n  Findings: {len(findings)}개")
    for f in findings:
        print(f"    [{f.get('severity','?')}] {f.get('title','?')}")

    # 스캔 런 최종 상태
    st, final_run = req("GET", f"{base}/api/scan-runs/{run_id}/")
    if st == 200:
        print(f"\n  스캔 런 요약:")
        print(f"    status         : {final_run.get('status')}")
        print(f"    llm_calls_count: {final_run.get('llm_calls_count', 0)}")
        print(f"    llm_tokens_used: {final_run.get('llm_tokens_used', 0)}")
        print(f"    llm_cost_usd   : {final_run.get('llm_cost_usd', '0')}")

    print("\n완료!", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
