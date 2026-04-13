#!/usr/bin/env python3
"""Watchdog eval harness — phase별 에이전트 성능을 반복 측정한다.

흐름:
  1. targets.yaml 로드
  2. 각 타겟마다 ScanRun 생성 → start (또는 start-mcp) → 완료 대기
  3. candidates/findings/request-catalog 조회
  4. expected vs actual 매칭 → TP/FP/FN → precision/recall/F1
  5. 결과를 agent/eval/history.jsonl 에 append + 콘솔 출력
  6. --baseline 플래그 시 agent/eval/baseline.json 갱신
  7. baseline이 있으면 델타 표기

사용:
  python agent/eval/run_eval.py --phase 0-baseline --mcp
  python agent/eval/run_eval.py --phase 1-knowledge --mcp --baseline
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Any

try:
    import yaml
except ImportError:
    sys.stderr.write(
        "PyYAML이 필요합니다. `pip install -r agent/eval/requirements.txt` 실행하세요.\n"
    )
    raise

EVAL_DIR = pathlib.Path(__file__).resolve().parent
HISTORY_PATH = EVAL_DIR / "history.jsonl"
BASELINE_PATH = EVAL_DIR / "baseline.json"


# ── HTTP helper ────────────────────────────────────────────────

def req(method: str, url: str, body: Any = None, timeout: int = 30):
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
            return resp.status, (json.loads(raw) if "json" in ct else raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw
    except Exception as e:
        return 0, str(e)


def wait_health(base: str, deadline: float) -> bool:
    while time.time() < deadline:
        st, _ = req("GET", f"{base}/health/")
        if st == 200:
            return True
        time.sleep(1)
    return False


def page(url: str) -> list[dict]:
    """DRF 페이지네이션 응답을 전부 읽어 리스트로 반환."""
    items: list[dict] = []
    next_url: str | None = url
    while next_url:
        st, body = req("GET", next_url)
        if st != 200 or not isinstance(body, dict):
            break
        results = body.get("results")
        if results is None:
            for key in ("requests", "candidates", "findings"):
                if key in body:
                    results = body[key]
                    break
        if results is None and isinstance(body, list):
            return body
        if results:
            items.extend(results)
        next_url = body.get("next")
    return items


# ── matching ───────────────────────────────────────────────────

def normalize_path(endpoint: str) -> str:
    if not endpoint:
        return ""
    # strip scheme/host + query
    p = endpoint
    if "://" in p:
        p = p.split("://", 1)[1]
        p = "/" + p.split("/", 1)[1] if "/" in p else "/"
    if "?" in p:
        p = p.split("?", 1)[0]
    return p.rstrip("/") or "/"


@dataclass
class Expected:
    endpoint: str
    param: str
    vuln_type: str
    severity: str
    matched: bool = False
    matched_as: str = ""  # "finding" | "candidate" | ""


@dataclass
class TargetResult:
    target_id: str
    target_url: str
    run_id: str = ""
    status: str = ""
    duration_s: float = 0.0
    llm_calls: int = 0
    llm_tokens: int = 0
    llm_cost_usd: float = 0.0
    turns: int = 0
    endpoints_crawled: int = 0
    candidates: int = 0
    findings: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    score: float = 0.0
    expected: list[dict] = field(default_factory=list)
    extra_findings: list[dict] = field(default_factory=list)


def match_expected(
    expected: list[Expected],
    candidates: list[dict],
    findings: list[dict],
    req_catalog: list[dict],
) -> tuple[int, int, int, list[dict]]:
    req_by_id = {str(r.get("req_id")): r for r in req_catalog}
    cand_by_id = {str(c.get("cand_id")): c for c in candidates}

    # finding 단위로 path/vuln 추출
    finding_signals: list[tuple[str, str]] = []
    for f in findings:
        vt = (f.get("vuln_type") or "").lower()
        cand_id = str(f.get("candidate") or "")
        path = ""
        cand = cand_by_id.get(cand_id)
        if cand:
            req_id = str(cand.get("request") or "")
            rc = req_by_id.get(req_id)
            if rc:
                path = normalize_path(rc.get("endpoint") or "")
        finding_signals.append((path, vt))

    cand_signals: list[tuple[str, str]] = []
    for c in candidates:
        vt = (c.get("vuln_type") or "").lower()
        req_id = str(c.get("request") or "")
        rc = req_by_id.get(req_id)
        path = normalize_path(rc.get("endpoint") or "") if rc else ""
        cand_signals.append((path, vt))

    matched_finding_idx: set[int] = set()
    matched_cand_idx: set[int] = set()

    # 1차: finding 매칭 (full credit)
    for exp in expected:
        exp_path = normalize_path(exp.endpoint)
        for i, (p, vt) in enumerate(finding_signals):
            if i in matched_finding_idx:
                continue
            if p == exp_path and vt == exp.vuln_type.lower():
                exp.matched = True
                exp.matched_as = "finding"
                matched_finding_idx.add(i)
                break

    # 2차: candidate 매칭 (partial credit, 현재는 full로 간주)
    for exp in expected:
        if exp.matched:
            continue
        exp_path = normalize_path(exp.endpoint)
        for i, (p, vt) in enumerate(cand_signals):
            if i in matched_cand_idx:
                continue
            if p == exp_path and vt == exp.vuln_type.lower():
                exp.matched = True
                exp.matched_as = "candidate"
                matched_cand_idx.add(i)
                break

    tp = sum(1 for e in expected if e.matched)
    fn = len(expected) - tp

    # FP: expected에 없는 finding (path, vuln) 조합
    expected_set = {(normalize_path(e.endpoint), e.vuln_type.lower()) for e in expected}
    extra: list[dict] = []
    for i, (p, vt) in enumerate(finding_signals):
        if i in matched_finding_idx:
            continue
        if (p, vt) not in expected_set:
            extra.append({"endpoint": p, "vuln_type": vt})
    fp = len(extra)

    return tp, fp, fn, extra


def f1_score(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return prec, rec, f1


# ── runner ─────────────────────────────────────────────────────

def run_target(base: str, target: dict, use_mcp: bool, deadline: float) -> TargetResult:
    res = TargetResult(target_id=target["id"], target_url=target["target_url"])
    t0 = time.time()

    # 1. create scan run
    st, body = req("POST", f"{base}/api/scan-runs/", {"target_url": target["target_url"]})
    if st not in (200, 201) or not isinstance(body, dict) or not body.get("run_id"):
        res.status = f"create_failed: {st} {body}"
        return res
    res.run_id = body["run_id"]

    # 2. start
    start_path = "start-mcp" if use_mcp else "start"
    st, body = req("POST", f"{base}/api/scan-runs/{res.run_id}/{start_path}/", {})
    if st not in (200, 201, 202):
        res.status = f"start_failed: {st} {body}"
        return res

    # 3. poll
    scan_deadline = min(time.time() + target.get("scan_timeout_seconds", 600), deadline)
    last_status = ""
    while time.time() < scan_deadline:
        st, body = req("GET", f"{base}/api/scan-runs/{res.run_id}/")
        if st == 200 and isinstance(body, dict):
            s = body.get("status", "")
            if s != last_status:
                print(f"       [{target['id']}] status = {s}")
                last_status = s
            if s in ("finished", "failed", "stopped"):
                res.status = s
                break
        time.sleep(3)
    else:
        res.status = "timeout"

    res.duration_s = round(time.time() - t0, 1)

    # 4. collect
    st, body = req("GET", f"{base}/api/scan-runs/{res.run_id}/")
    if st == 200 and isinstance(body, dict):
        res.llm_calls = int(body.get("llm_calls_count", 0) or 0)
        res.llm_tokens = int(body.get("llm_tokens_used", 0) or 0)
        try:
            res.llm_cost_usd = float(body.get("llm_cost_usd", 0) or 0)
        except Exception:
            res.llm_cost_usd = 0.0

    req_catalog = page(f"{base}/api/request-catalog/list/?run_id={res.run_id}")
    candidates = page(f"{base}/api/candidates/list/?run_id={res.run_id}")
    findings = page(f"{base}/api/findings/?run_id={res.run_id}")
    traces = page(f"{base}/api/scan-runs/{res.run_id}/llm-traces/")

    res.endpoints_crawled = len(req_catalog)
    res.candidates = len(candidates)
    res.findings = len(findings)
    res.turns = len(traces)

    expected = [Expected(**e) for e in target["expected_findings"]]
    tp, fp, fn, extra = match_expected(expected, candidates, findings, req_catalog)
    res.tp, res.fp, res.fn = tp, fp, fn
    res.precision, res.recall, res.f1 = f1_score(tp, fp, fn)
    res.expected = [asdict(e) for e in expected]
    res.extra_findings = extra

    return res


def composite_score(res: TargetResult, metrics_cfg: dict) -> float:
    score = res.f1 * float(metrics_cfg.get("f1_weight", 1.0))
    score -= float(metrics_cfg.get("cost_penalty_per_usd", 0.0)) * res.llm_cost_usd
    score -= float(metrics_cfg.get("turn_penalty_per_turn", 0.0)) * res.turns
    if res.status == "timeout":
        score -= float(metrics_cfg.get("timeout_penalty", 0.0))
    return round(score, 4)


# ── history / baseline ─────────────────────────────────────────

def git_rev() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        return "unknown"


def append_history(entry: dict) -> None:
    with HISTORY_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def load_baseline() -> dict | None:
    if not BASELINE_PATH.exists():
        return None
    try:
        return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None


def save_baseline(entry: dict) -> None:
    BASELINE_PATH.write_text(
        json.dumps(entry, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def fmt_delta(current: float, baseline: float | None, digits: int = 3) -> str:
    if baseline is None:
        return ""
    delta = current - baseline
    sign = "+" if delta >= 0 else ""
    return f" (Δ {sign}{delta:.{digits}f} vs baseline)"


# ── main ───────────────────────────────────────────────────────

def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Watchdog eval harness")
    p.add_argument("--base-url", default="http://localhost:8000")
    p.add_argument("--targets", default=str(EVAL_DIR / "targets.yaml"))
    p.add_argument(
        "--phase",
        required=True,
        help="phase 태그 (예: 0-baseline, 1-knowledge, 2-rag, 3-multiagent)",
    )
    p.add_argument(
        "--mcp",
        action="store_true",
        help="MCP 에이전트(start-mcp) 경로로 실행. 미지정 시 classic pipeline(start).",
    )
    p.add_argument(
        "--baseline",
        action="store_true",
        help="이번 실행을 baseline.json 으로 저장",
    )
    p.add_argument("--total-timeout", type=int, default=3600)
    p.add_argument(
        "--target-url",
        default=None,
        help="단일 타겟의 target_url을 오버라이드 (예: localhost)",
    )
    args = p.parse_args(argv)

    cfg = yaml.safe_load(pathlib.Path(args.targets).read_text(encoding="utf-8"))
    targets = cfg.get("targets", [])
    metrics_cfg = cfg.get("metrics", {})

    if args.target_url and targets:
        targets[0]["target_url"] = args.target_url

    base = args.base_url.rstrip("/")
    deadline = time.time() + args.total_timeout

    print("=" * 70)
    print(f"Watchdog eval  phase={args.phase}  mcp={args.mcp}  git={git_rev()}")
    print("=" * 70)

    if not wait_health(base, min(time.time() + 30, deadline)):
        print("health check FAIL — backend이 떠있지 않습니다.")
        return 1

    results: list[TargetResult] = []
    for t in targets:
        print(f"\n[run] {t['id']} → {t['target_url']}")
        r = run_target(base, t, args.mcp, deadline)
        r.score = composite_score(r, metrics_cfg)
        results.append(r)

    # ── baseline 비교 ──
    baseline = load_baseline()
    baseline_by_id: dict[str, dict] = {}
    if baseline:
        for br in baseline.get("results", []):
            baseline_by_id[br["target_id"]] = br

    # ── 요약 출력 ──
    print("\n" + "=" * 70)
    print(f"{'target':14s} {'status':10s} {'P':>5s} {'R':>5s} {'F1':>5s} "
          f"{'score':>7s} {'turns':>5s} {'$':>6s}")
    print("-" * 70)
    overall_f1_sum = 0.0
    overall_score_sum = 0.0
    for r in results:
        b = baseline_by_id.get(r.target_id)
        bf1 = b["f1"] if b else None
        bsc = b["score"] if b else None
        print(
            f"{r.target_id:14s} {r.status:10s} "
            f"{r.precision:>5.2f} {r.recall:>5.2f} {r.f1:>5.2f} "
            f"{r.score:>7.3f} {r.turns:>5d} ${r.llm_cost_usd:>5.3f}"
            + (fmt_delta(r.f1, bf1, 2) if b else "")
        )
        overall_f1_sum += r.f1
        overall_score_sum += r.score

    n = max(len(results), 1)
    mean_f1 = overall_f1_sum / n
    mean_score = overall_score_sum / n
    b_mean_f1 = baseline.get("mean_f1") if baseline else None
    b_mean_score = baseline.get("mean_score") if baseline else None
    print("-" * 70)
    print(f"mean_f1 = {mean_f1:.3f}{fmt_delta(mean_f1, b_mean_f1)}")
    print(f"mean_score = {mean_score:.3f}{fmt_delta(mean_score, b_mean_score)}")

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phase": args.phase,
        "git_rev": git_rev(),
        "mcp": args.mcp,
        "mean_f1": round(mean_f1, 4),
        "mean_score": round(mean_score, 4),
        "results": [asdict(r) for r in results],
    }
    append_history(entry)
    print(f"\nappended → {HISTORY_PATH.name}")

    if args.baseline:
        save_baseline(entry)
        print(f"saved baseline → {BASELINE_PATH.name}")

    return 0 if all(r.status == "finished" for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
