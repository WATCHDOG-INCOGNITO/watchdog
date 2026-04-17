#!/usr/bin/env python3
"""Watchdog eval — history.jsonl 분석 도구.

run_eval.py 가 매 실행마다 한 줄씩 append 하는 history.jsonl 을 읽어
사람이 보기 좋은 형태로 추세/회귀를 보여준다. 측정·기록은 안 한다 (read-only).

기능:
  --last N            최근 N개 run 표 (기본 10)
  --target X          특정 target 의 시계열 (per-run flag/score/cost)
  --regress           이전 run 들에서 잡았던 flag 를 마지막 run 에서 놓친 target 알림
  --phase A B         두 phase 의 mean_f1/mean_score 평균 비교
  --git A B           두 git_rev 비교 (A 이후 / B 이후 의 mean 비교)
  --since YYYY-MM-DD  해당 날짜 이후 run 만 대상

사용 예:
  python agent/eval/compare_history.py --last 5
  python agent/eval/compare_history.py --regress
  python agent/eval/compare_history.py --target 2024-combination
  python agent/eval/compare_history.py --phase 3-multiagent-baseline 4-tool-parallel
"""
from __future__ import annotations

import argparse
import io
import json
import pathlib
import sys
from collections import defaultdict
from datetime import datetime, timezone

# Windows cp949 콘솔에서도 한글/기호가 깨지지 않도록 stdout 강제 UTF-8
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

EVAL_DIR = pathlib.Path(__file__).resolve().parent
HISTORY_PATH = EVAL_DIR / "history.jsonl"


def load_runs(since: str | None = None) -> list[dict]:
    if not HISTORY_PATH.exists():
        print(f"history not found: {HISTORY_PATH}", file=sys.stderr)
        return []
    cutoff: datetime | None = None
    if since:
        try:
            cutoff = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
        except ValueError:
            print(f"--since 형식 오류: {since} (YYYY-MM-DD)", file=sys.stderr)
            return []
    runs = []
    for line in HISTORY_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if cutoff:
            try:
                ts = datetime.fromisoformat(r["timestamp"].replace("Z", "+00:00"))
                if ts < cutoff:
                    continue
            except Exception:
                pass
        runs.append(r)
    return runs


def _short_ts(ts: str) -> str:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%m-%d %H:%M")
    except Exception:
        return ts[:16]


def _flag_count(run: dict) -> int:
    return sum(1 for r in run.get("results", []) if r.get("flag_found"))


def _total_cost(run: dict) -> float:
    return sum(float(r.get("llm_cost_usd", 0) or 0) for r in run.get("results", []))


def _total_turns(run: dict) -> int:
    return sum(int(r.get("turns", 0) or 0) for r in run.get("results", []))


# ── --last ────────────────────────────────────────────────────

def cmd_last(runs: list[dict], n: int) -> None:
    rows = runs[-n:]
    if not rows:
        print("(history 비어있음)")
        return
    print(f"{'when':14s} {'phase':28s} {'git':9s} {'tgt':>4s} "
          f"{'flag':>5s} {'mF1':>5s} {'mScr':>6s} {'$tot':>6s} {'turns':>6s}")
    print("-" * 92)
    for r in rows:
        n_t = len(r.get("results", []))
        print(
            f"{_short_ts(r.get('timestamp','')):14s} "
            f"{(r.get('phase','') or '-')[:28]:28s} "
            f"{(r.get('git_rev','') or '-')[:9]:9s} "
            f"{n_t:>4d} {_flag_count(r):>5d} "
            f"{r.get('mean_f1',0):>5.2f} {r.get('mean_score',0):>6.3f} "
            f"${_total_cost(r):>5.2f} {_total_turns(r):>6d}"
        )


# ── --target X ────────────────────────────────────────────────

def cmd_target(runs: list[dict], tid: str) -> None:
    print(f"target = {tid}")
    print(f"{'when':14s} {'phase':28s} {'git':9s} {'status':10s} "
          f"{'flag':>4s} {'F1':>5s} {'scr':>6s} {'$':>6s} {'turn':>5s}")
    print("-" * 90)
    rows: list[tuple[str, dict, dict]] = []
    for run in runs:
        for tr in run.get("results", []):
            if tr.get("target_id") == tid:
                rows.append((run.get("timestamp", ""), run, tr))
                break
    if not rows:
        print(f"(no runs for target_id={tid})")
        return
    for ts, run, tr in rows:
        flag = "FLAG" if tr.get("flag_found") else "  - "
        print(
            f"{_short_ts(ts):14s} "
            f"{(run.get('phase','') or '-')[:28]:28s} "
            f"{(run.get('git_rev','') or '-')[:9]:9s} "
            f"{(tr.get('status','') or '-')[:10]:10s} "
            f"{flag:>4s} {tr.get('f1',0):>5.2f} {tr.get('score',0):>6.3f} "
            f"${tr.get('llm_cost_usd',0):>5.3f} {tr.get('turns',0):>5d}"
        )
    if rows[-1][2].get("flag_value"):
        print(f"\nlast captured flag: {rows[-1][2]['flag_value']}")


# ── --regress ─────────────────────────────────────────────────

def cmd_regress(runs: list[dict]) -> None:
    """과거에 잡았던 flag/finding 을 마지막 run 에서 놓친 target 알림."""
    if not runs:
        print("(history 비어있음)")
        return

    # target_id → (ever_had_flag, ever_had_finding, max_score)
    history_state: dict[str, dict] = defaultdict(
        lambda: {"ever_flag": False, "ever_finding": False, "max_score": float("-inf")}
    )
    for run in runs[:-1]:
        for tr in run.get("results", []):
            tid = tr.get("target_id", "")
            st = history_state[tid]
            if tr.get("flag_found"):
                st["ever_flag"] = True
            if tr.get("findings", 0) > 0 or tr.get("tp", 0) > 0:
                st["ever_finding"] = True
            st["max_score"] = max(st["max_score"], float(tr.get("score", 0) or 0))

    last = runs[-1]
    last_phase = last.get("phase", "?")
    last_ts = _short_ts(last.get("timestamp", ""))
    print(f"마지막 run: {last_ts}  phase={last_phase}  git={last.get('git_rev','?')}")
    print(f"이전 {len(runs) - 1}개 run 과 비교\n")

    regressions = []
    for tr in last.get("results", []):
        tid = tr.get("target_id", "")
        st = history_state.get(tid)
        if not st:
            continue
        flag_now = bool(tr.get("flag_found"))
        finding_now = (tr.get("findings", 0) > 0 or tr.get("tp", 0) > 0)
        score_now = float(tr.get("score", 0) or 0)

        flags_alert = st["ever_flag"] and not flag_now
        find_alert = st["ever_finding"] and not finding_now
        score_drop = (
            st["max_score"] != float("-inf")
            and score_now < st["max_score"] - 0.05
        )

        if flags_alert or find_alert or score_drop:
            reasons = []
            if flags_alert:
                reasons.append("flag 놓침")
            if find_alert:
                reasons.append("finding 0")
            if score_drop:
                reasons.append(f"score {score_now:.3f} < max {st['max_score']:.3f}")
            regressions.append((tid, " / ".join(reasons)))

    if not regressions:
        print("regression 없음 ✓")
        return
    print(f"[!] regression {len(regressions)}건:")
    for tid, why in regressions:
        print(f"  - {tid:25s}  {why}")


# ── --phase A B ───────────────────────────────────────────────

def _agg_phase(runs: list[dict], phase: str) -> dict | None:
    rs = [r for r in runs if r.get("phase") == phase]
    if not rs:
        return None
    n = len(rs)
    return {
        "phase": phase,
        "runs": n,
        "mean_f1": sum(float(r.get("mean_f1", 0) or 0) for r in rs) / n,
        "mean_score": sum(float(r.get("mean_score", 0) or 0) for r in rs) / n,
        "flag_per_run": sum(_flag_count(r) for r in rs) / n,
        "cost_per_run": sum(_total_cost(r) for r in rs) / n,
        "turns_per_run": sum(_total_turns(r) for r in rs) / n,
        "last_ts": rs[-1].get("timestamp", ""),
    }


def cmd_phase(runs: list[dict], a: str, b: str) -> None:
    aggs = [_agg_phase(runs, a), _agg_phase(runs, b)]
    if not aggs[0] or not aggs[1]:
        for p, ag in zip([a, b], aggs):
            if not ag:
                print(f"phase '{p}' run 없음", file=sys.stderr)
        return
    print(f"{'metric':14s}  {a:>20s}  {b:>20s}  {'Δ (b-a)':>10s}")
    print("-" * 72)
    for key, fmt in [
        ("runs", "{:>20d}"),
        ("mean_f1", "{:>20.3f}"),
        ("mean_score", "{:>20.3f}"),
        ("flag_per_run", "{:>20.2f}"),
        ("cost_per_run", "{:>20.3f}"),
        ("turns_per_run", "{:>20.1f}"),
    ]:
        va, vb = aggs[0][key], aggs[1][key]
        delta = vb - va
        sign = "+" if delta >= 0 else ""
        delta_str = f"{sign}{delta:.3f}" if isinstance(delta, float) else f"{sign}{delta}"
        print(f"{key:14s}  {fmt.format(va)}  {fmt.format(vb)}  {delta_str:>10s}")


# ── --git A B ─────────────────────────────────────────────────

def cmd_git(runs: list[dict], a: str, b: str) -> None:
    """두 git_rev 의 mean 비교 (각 rev 의 모든 run 평균)."""
    def agg(rev: str) -> dict | None:
        rs = [r for r in runs if r.get("git_rev", "").startswith(rev)]
        if not rs:
            return None
        n = len(rs)
        return {
            "rev": rev, "runs": n,
            "mean_f1": sum(float(r.get("mean_f1", 0) or 0) for r in rs) / n,
            "mean_score": sum(float(r.get("mean_score", 0) or 0) for r in rs) / n,
            "flag_per_run": sum(_flag_count(r) for r in rs) / n,
            "cost_per_run": sum(_total_cost(r) for r in rs) / n,
        }
    ga, gb = agg(a), agg(b)
    if not ga or not gb:
        for rev, x in [(a, ga), (b, gb)]:
            if not x:
                print(f"git_rev prefix '{rev}' run 없음", file=sys.stderr)
        return
    print(f"{'metric':14s}  {a:>14s}  {b:>14s}  {'Δ (b-a)':>10s}")
    print("-" * 60)
    for k in ("runs", "mean_f1", "mean_score", "flag_per_run", "cost_per_run"):
        va, vb = ga[k], gb[k]
        delta = vb - va
        sign = "+" if delta >= 0 else ""
        if isinstance(va, float):
            print(f"{k:14s}  {va:>14.3f}  {vb:>14.3f}  {sign}{delta:>9.3f}")
        else:
            print(f"{k:14s}  {va:>14d}  {vb:>14d}  {sign}{delta:>9d}")


# ── main ──────────────────────────────────────────────────────

def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Watchdog eval — history 분석")
    p.add_argument("--last", type=int, metavar="N", help="최근 N개 run 표")
    p.add_argument("--target", metavar="ID", help="특정 target_id 시계열")
    p.add_argument("--regress", action="store_true",
                   help="이전엔 잡았으나 마지막 run 에서 놓친 target 알림")
    p.add_argument("--phase", nargs=2, metavar=("A", "B"),
                   help="두 phase 의 mean 비교")
    p.add_argument("--git", nargs=2, metavar=("A", "B"),
                   help="두 git_rev (prefix) 비교")
    p.add_argument("--since", metavar="YYYY-MM-DD",
                   help="이 날짜 이후 run 만 대상")
    args = p.parse_args(argv)

    runs = load_runs(args.since)
    if not runs:
        return 1

    nothing_picked = not any([args.last, args.target, args.regress, args.phase, args.git])
    if nothing_picked:
        # 기본: last 10 + regress 한 방에
        cmd_last(runs, 10)
        print()
        cmd_regress(runs)
        return 0

    if args.last:
        cmd_last(runs, args.last)
    if args.target:
        cmd_target(runs, args.target)
    if args.regress:
        cmd_regress(runs)
    if args.phase:
        cmd_phase(runs, args.phase[0], args.phase[1])
    if args.git:
        cmd_git(runs, args.git[0], args.git[1])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
