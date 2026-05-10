"""결정론적 oracle 도구 — 취약점 클래스별 객관적 검증.

XBOW/Shannon이 false positive를 잡는 핵심 기법. Verifier 에이전트가 _필요할 때_
호출해 LLM 추측 없이 수치/시그니처/실제 실행 결과로 verdict를 뒷받침한다.

설계 원칙:
- 호출은 자율. 어떤 oracle을 어떤 순서로 쓸지는 Verifier 에이전트가 결정.
- 결과는 {confirmed, evidence, score, ...} 구조. confirmed 가 단독으로 finding을
  확정하지 않는다 — Verifier가 다른 증거와 함께 종합 판단.
- 비파괴적: 시간 기반은 SLEEP 3초 등 짧게, 파일 시스템/DB 변경 없음.
"""
from __future__ import annotations

import json
import hashlib
import re
import secrets as _secrets_mod
import statistics
import time
from urllib.parse import urlparse, urlunparse

import requests

DEFAULT_TIMEOUT = 12
SQLI_TIME_DEFAULT_DELAY = 3
SQLI_TIME_MARGIN_MS = 1500  # baseline 대비 이만큼 더 느려야 양성
SPA_PROBE_SIMILARITY_THRESHOLD = 0.92  # 이보다 높으면 catch-all 의심


def _safe_get(url: str, *, headers: dict | None = None, timeout: int = DEFAULT_TIMEOUT):
    h = {"User-Agent": "WatchdogOracle/1.0"}
    if headers:
        h.update(headers)
    return requests.get(url, headers=h, timeout=timeout, allow_redirects=False)


def _line_similarity(a: str, b: str) -> float:
    """두 응답의 라인 기반 Jaccard similarity (0.0~1.0). SPA catch-all 탐지용.

    동일한 HTML 셸을 뱉는 SPA 의 경우 99% 이상 나옴. 실제로 다른 리소스가
    렌더된 경우 서버가 body 안에 데이터를 박으므로 유사도가 유의하게 떨어짐.
    """
    def _lines(s: str) -> set[str]:
        return {ln.strip() for ln in (s or "").splitlines() if ln.strip()}
    la, lb = _lines(a), _lines(b)
    if not la and not lb:
        return 1.0
    inter = la & lb
    union = la | lb
    return len(inter) / len(union) if union else 0.0


def _body_sha(body: str) -> str:
    return hashlib.sha256((body or "").encode("utf-8", errors="replace")).hexdigest()


def _probe_path_under(target_url: str, rand_token: str) -> str:
    """target_url 의 path prefix 를 유지한 random probe URL 생성.
    target_url=https://mjsec.kr/lms → https://mjsec.kr/lms/__wd_probe_<rand>
    """
    p = urlparse(target_url)
    base_path = (p.path or "/").rstrip("/")
    probe_path = f"{base_path}/__wd_probe_{rand_token}"
    return urlunparse((p.scheme, p.netloc, probe_path, "", "", ""))


def _response_diff_blocks(baseline: str, payload: str, control: str) -> dict:
    """3개 응답을 라인 단위로 비교해 'payload에만 있는' 블록을 추출.
    하드코딩 시그니처 없이 일반화된 oracle — Verifier가 결과 보고 의미 판정.
    """
    def _lines(s: str) -> list[str]:
        return [ln.rstrip() for ln in (s or "").splitlines() if ln.strip()]

    base = set(_lines(baseline))
    ctrl = set(_lines(control)) if control else set()
    pay = _lines(payload)

    # payload에만 등장하는 라인 (baseline + control 양쪽에 모두 없음)
    novel_lines = [ln for ln in pay if ln not in base and ln not in ctrl]
    # 길이/엔트로피로 정렬해 의미 있는 줄 우선
    novel_lines = sorted(novel_lines, key=lambda l: (-len(l), l))[:30]

    return {
        "novel_line_count": len(novel_lines),
        "novel_lines": novel_lines,
        "baseline_line_count": len(base),
        "payload_line_count": len(pay),
        "control_line_count": len(ctrl),
    }


def register(mcp):

    @mcp.tool()
    def oracle_spa_catch_all(
        scan_run_id: str,
        force_refresh: bool = False,
    ) -> str:
        """Probe 2 random non-existent paths under target_url — SPA catch-all 감지.

        React/Vue/Angular SPA 앱은 존재하지 않는 path 에도 서버가 index.html 을
        반환 (클라이언트 라우팅). 이 상태에서 HTTP 200 + HTML 만 보고
        "endpoint accessible" / "IDOR confirmed" 로 판단하는 것은 false positive.

        첫 호출 시 TargetProfile.fingerprint.spa_catch_all 에 baseline 캐시.
        force_refresh=True 면 재프로빙. 이미 캐시된 결과가 있으면 HTTP 호출 없이
        cached 반환.

        Returns JSON:
          {
            "detected": true|false|null,
            "target_host": "...",
            "probe_urls": [...],
            "baseline_status": 200, "baseline_body_len": N, "baseline_body_sha256": "...",
            "similarity_between_probes": 0.99,
            "cached": true|false,
            "hint": "..."
          }

        IDOR/auth bypass 관련 finding 을 confirm 하기 전에 반드시 이 oracle 을
        호출해서 detected=true 이면 body_diff 로 재검증해야 한다.
        """
        from api.models import ScanRun, TargetProfile

        try:
            sr = ScanRun.objects.get(run_id=scan_run_id)
        except Exception as e:
            return json.dumps({"error": f"scan_run not found: {e}"})

        target_url = (sr.target_url or "").strip()
        if not target_url:
            return json.dumps({"error": "scan_run has no target_url"})

        host = urlparse(target_url).netloc.lower()
        if not host:
            return json.dumps({"error": f"cannot parse host from {target_url}"})

        profile, _ = TargetProfile.objects.get_or_create(host=host)
        fp = dict(profile.fingerprint or {})
        cached = fp.get("spa_catch_all")

        if cached and not force_refresh:
            return json.dumps({
                **cached,
                "cached": True,
                "hint": (
                    "Cached baseline. force_refresh=True to re-probe. "
                    "If detected=true, IDOR/auth findings based on HTTP 200+HTML "
                    "alone are false positives — use oracle_idor_diff to validate."
                ),
            }, ensure_ascii=False)

        # 2개 서로 다른 random path probe
        tok_a = _secrets_mod.token_hex(8)
        tok_b = _secrets_mod.token_hex(8)
        url_a = _probe_path_under(target_url, tok_a)
        url_b = _probe_path_under(target_url, tok_b)

        try:
            r_a = _safe_get(url_a)
            r_b = _safe_get(url_b)
        except requests.RequestException as e:
            return json.dumps({"error": f"probe failed: {e}"})

        sim = _line_similarity(r_a.text, r_b.text)
        sha_a = _body_sha(r_a.text)
        sha_b = _body_sha(r_b.text)

        # detected 판정:
        #  - 두 응답 모두 200 + body similarity > threshold → SPA catch-all 확정
        #  - 두 응답 모두 4xx → 정상 서버 (detected=false)
        #  - 혼합/다른 상태 → 불확정 (detected=null)
        detected: bool | None
        if r_a.status_code == 200 and r_b.status_code == 200 and sim >= SPA_PROBE_SIMILARITY_THRESHOLD:
            detected = True
        elif r_a.status_code >= 400 and r_b.status_code >= 400:
            detected = False
        else:
            detected = None

        ctype = (r_a.headers.get("content-type") or "").split(";")[0].strip().lower()
        record = {
            "detected": detected,
            "target_host": host,
            "probe_urls": [url_a, url_b],
            "baseline_status": r_a.status_code,
            "baseline_body_len": len(r_a.text),
            "baseline_body_sha256": sha_a,
            "second_probe_status": r_b.status_code,
            "second_probe_body_len": len(r_b.text),
            "second_probe_body_sha256": sha_b,
            "similarity_between_probes": round(sim, 4),
            "content_type": ctype,
        }

        # TargetProfile 에 캐시 (재프로빙 비용 절약 + 다른 도구가 조회)
        fp["spa_catch_all"] = record
        try:
            TargetProfile.objects.filter(pk=profile.pk).update(fingerprint=fp)
        except Exception:
            pass

        if detected is True:
            hint = (
                "SPA catch-all detected — server returns identical HTML shell for "
                "any non-existent path. IDOR/auth findings based on HTTP status + "
                "HTML body alone are FALSE POSITIVES. Real IDOR requires: "
                "(1) call JSON API endpoint (/api/...), not frontend route, or "
                "(2) use oracle_idor_diff to confirm body content actually differs "
                "between user IDs (not just the SPA shell)."
            )
        elif detected is False:
            hint = (
                "Server returns 4xx for non-existent paths — no SPA catch-all. "
                "Standard server routing active."
            )
        else:
            hint = (
                f"Inconclusive: probe_a={r_a.status_code} probe_b={r_b.status_code}. "
                "Treat 200+HTML on valid-looking paths with caution."
            )

        return json.dumps({**record, "cached": False, "hint": hint}, ensure_ascii=False)


    @mcp.tool()
    def oracle_idor_diff(
        scan_run_id: str,
        baseline_url: str,
        variant_url: str,
        baseline_cookie: str = "",
        variant_cookie: str = "",
    ) -> str:
        """IDOR 확정 전 필수 body-diff oracle — SPA catch-all + same-shell false positive 차단.

        baseline_url: 본인 리소스 URL (예: /lms/admin/group/60201901)
        variant_url:  타인 리소스 URL (예: /lms/admin/group/99999999)
        baseline_cookie / variant_cookie: optional session cookie 헤더 값 (Cookie: ...)

        동작:
        1. TargetProfile 의 spa_catch_all baseline 과 각 응답 비교 → SPA shell 반환
           이면 verdict='spa_catch_all' (IDOR 아님)
        2. baseline vs variant 의 line similarity 계산
           - sim >= 0.95 → verdict='same_shell' (같은 HTML, 실제 데이터 diff 없음)
           - sim < 0.85 + 200+200 → verdict='likely_idor' (body 가 실제로 다름 = 진짜 IDOR 가능)
           - 그 외 → verdict='unclear'

        Returns JSON:
          {
            "verdict": "spa_catch_all|same_shell|likely_idor|unclear",
            "similarity_baseline_variant": 0.97,
            "similarity_baseline_vs_spa": 0.99,
            "similarity_variant_vs_spa": 0.99,
            "baseline_status": 200, "variant_status": 200,
            "baseline_len": N, "variant_len": M,
            "novel_lines_in_variant": [...],  // variant 에만 있는 라인 (IDOR 증거 후보)
            "hint": "..."
          }

        verdict in {'spa_catch_all','same_shell'} → IDOR 로 finding 찍으면 FP.
        verdict='likely_idor' + novel_lines 가 실제 사용자 데이터를 포함해야 진짜.
        """
        from api.models import ScanRun, TargetProfile

        try:
            sr = ScanRun.objects.get(run_id=scan_run_id)
        except Exception as e:
            return json.dumps({"error": f"scan_run not found: {e}"})
        host = urlparse(sr.target_url or "").netloc.lower()

        # SPA baseline 조회
        spa_baseline_body = ""
        spa_detected = None
        try:
            profile = TargetProfile.objects.filter(host=host).first()
            if profile and profile.fingerprint:
                spa = (profile.fingerprint or {}).get("spa_catch_all") or {}
                spa_detected = spa.get("detected")
                # baseline body 는 저장 안 했으니 sha256 만 비교 가능 — live re-probe 하자
                if spa_detected is True:
                    probe_urls = spa.get("probe_urls") or []
                    if probe_urls:
                        try:
                            rr = _safe_get(probe_urls[0])
                            spa_baseline_body = rr.text or ""
                        except requests.RequestException:
                            pass
        except Exception:
            pass

        h_base = {"Cookie": baseline_cookie} if baseline_cookie else None
        h_var = {"Cookie": variant_cookie} if variant_cookie else None
        try:
            r_base = _safe_get(baseline_url, headers=h_base)
            r_var = _safe_get(variant_url, headers=h_var)
        except requests.RequestException as e:
            return json.dumps({"error": f"http error: {e}"})

        sim_bv = _line_similarity(r_base.text, r_var.text)
        sim_b_spa = _line_similarity(r_base.text, spa_baseline_body) if spa_baseline_body else 0.0
        sim_v_spa = _line_similarity(r_var.text, spa_baseline_body) if spa_baseline_body else 0.0

        # verdict 결정
        if spa_detected is True and max(sim_b_spa, sim_v_spa) >= SPA_PROBE_SIMILARITY_THRESHOLD:
            verdict = "spa_catch_all"
            hint = (
                "Both responses match the SPA catch-all baseline — server returns "
                "the SAME HTML shell for any path including random non-existent "
                "ones. This is NOT an IDOR. Probe the JSON API endpoint "
                "(/api/... instead of frontend /admin/... route)."
            )
        elif r_base.status_code >= 400 or r_var.status_code >= 400:
            verdict = "unclear"
            hint = (
                f"Status mismatch or error: baseline={r_base.status_code} "
                f"variant={r_var.status_code}. Cannot infer IDOR."
            )
        elif sim_bv >= 0.95:
            verdict = "same_shell"
            hint = (
                "Responses are near-identical (sim>=0.95) — likely both returning "
                "the same HTML shell without user-specific data. Not an IDOR. "
                "Verify via JSON API."
            )
        elif sim_bv < 0.85:
            verdict = "likely_idor"
            hint = (
                "Response bodies differ substantially — inspect novel_lines_in_variant "
                "for actual user data (names, IDs, emails). If novel lines contain "
                "the OTHER user's data, this is a real IDOR."
            )
        else:
            verdict = "unclear"
            hint = (
                f"Ambiguous similarity ({sim_bv:.2f}) — neither clearly same nor "
                "different. Try different IDs or inspect novel lines manually."
            )

        diff = _response_diff_blocks(r_base.text, r_var.text, spa_baseline_body)

        return json.dumps({
            "verdict": verdict,
            "similarity_baseline_variant": round(sim_bv, 4),
            "similarity_baseline_vs_spa": round(sim_b_spa, 4),
            "similarity_variant_vs_spa": round(sim_v_spa, 4),
            "spa_catch_all_detected": spa_detected,
            "baseline_status": r_base.status_code,
            "variant_status": r_var.status_code,
            "baseline_len": len(r_base.text),
            "variant_len": len(r_var.text),
            "novel_lines_in_variant": diff.get("novel_lines", []),
            "hint": hint,
        }, ensure_ascii=False)


    @mcp.tool()
    def oracle_response_diff(
        baseline_url: str,
        payload_url: str,
        control_url: str = "",
    ) -> str:
        """일반화된 응답 diff oracle — 하드코딩 시그니처 없음.

        baseline (벤치 정상 요청), payload (공격 요청), control (선택적, 다른 정상 요청)을
        호출해 *payload 응답에만 등장한 라인들*을 반환. 어떤 vuln 클래스든 적용 가능.

        Verifier는 반환된 novel_lines를 보고 의미 판정 (예: 비밀스러운 데이터 누출,
        에러 메시지 노출, 새 HTML 요소 삽입 등). 시그니처 매칭 없이 LLM 판단으로 풀어냄.
        """
        try:
            r_base = _safe_get(baseline_url)
            r_pay = _safe_get(payload_url)
            r_ctrl = _safe_get(control_url) if control_url else None
        except requests.RequestException as e:
            return json.dumps({"error": f"http error: {e}"})

        diff = _response_diff_blocks(
            r_base.text, r_pay.text, r_ctrl.text if r_ctrl else ""
        )
        return json.dumps({
            "baseline_status": r_base.status_code,
            "payload_status": r_pay.status_code,
            "control_status": r_ctrl.status_code if r_ctrl else None,
            "len_baseline": len(r_base.text),
            "len_payload": len(r_pay.text),
            **diff,
        }, ensure_ascii=False)


    # ─────────────────────────────────────────────────────────────
    # XSS — Playwright headless에서 dialog/JS 실행 캡처
    # ─────────────────────────────────────────────────────────────

    @mcp.tool()
    async def oracle_xss(url: str, payload_param: str = "", payload_value: str = "") -> str:
        """반사형/저장형 XSS 가설을 헤드리스 브라우저로 실제 검증한다.

        url에 payload_param=payload_value 를 추가해 Playwright로 로드하고:
          1. dialog (alert/confirm/prompt) 발생 여부
          2. window 객체에 watchdog sentinel(__WATCHDOG_XSS__) 노출 여부
          3. 페이지 console.error / pageerror 발생
        를 관찰한다. payload_value에 sentinel을 끼워 보내면 가장 명확.
        예: payload_value='<img src=x onerror="window.__WATCHDOG_XSS__=1">'

        반환: {confirmed, dialog_seen, sentinel_seen, console_errors, final_url, screenshot_b64?}
        """
        from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return json.dumps({"error": "playwright 미설치"})

        # URL에 payload param 합치기
        target = url
        if payload_param:
            parts = urlparse(url)
            q = dict(parse_qsl(parts.query, keep_blank_values=True))
            q[payload_param] = payload_value
            target = urlunparse(parts._replace(query=urlencode(q)))

        dialog_text: list[str] = []
        console_errors: list[str] = []
        page_errors: list[str] = []

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(args=["--no-sandbox"])
                context = await browser.new_context()
                page = await context.new_page()

                async def on_dialog(d):
                    dialog_text.append(f"{d.type}:{d.message}")
                    try:
                        await d.dismiss()
                    except Exception:
                        pass

                page.on("dialog", on_dialog)
                page.on("console", lambda msg: console_errors.append(msg.text)
                        if msg.type == "error" else None)
                page.on("pageerror", lambda e: page_errors.append(str(e)))

                try:
                    await page.goto(target, wait_until="networkidle", timeout=10_000)
                except Exception as e:
                    await browser.close()
                    return json.dumps({"error": f"page.goto 실패: {e}", "target": target})

                # sentinel 검사
                try:
                    sentinel = await page.evaluate("() => window.__WATCHDOG_XSS__ || null")
                except Exception:
                    sentinel = None

                final_url = page.url
                await browser.close()
        except Exception as e:
            return json.dumps({"error": f"playwright 실행 실패: {e}"})

        confirmed = bool(dialog_text) or bool(sentinel)
        return json.dumps({
            "confirmed": confirmed,
            "dialog_seen": dialog_text,
            "sentinel_seen": bool(sentinel),
            "console_errors": console_errors[:5],
            "page_errors": page_errors[:5],
            "final_url": final_url,
            "target_url": target,
        }, ensure_ascii=False)

    # ─────────────────────────────────────────────────────────────
    # SQLi — boolean diff (control vs payload)
    # ─────────────────────────────────────────────────────────────

    @mcp.tool()
    def oracle_sqli_boolean(
        url_true: str,
        url_false: str,
        url_baseline: str = "",
    ) -> str:
        """boolean-based SQLi 검증.

        url_true (예: ?id=1' OR '1'='1)와 url_false (예: ?id=1' AND '1'='2) 를 각각
        호출해 응답 길이/해시/status를 비교. 두 응답이 의미 있게 다르고 baseline과
        url_true 가 비슷하면 양성.

        반환: {confirmed, diff_ratio, status_*, len_*}
        """
        try:
            r_true = _safe_get(url_true)
            r_false = _safe_get(url_false)
            r_base = _safe_get(url_baseline) if url_baseline else r_true
        except requests.RequestException as e:
            return json.dumps({"error": f"http error: {e}"})

        len_true, len_false, len_base = len(r_true.text), len(r_false.text), len(r_base.text)
        diff_tf = abs(len_true - len_false) / max(len_true, len_false, 1)
        diff_tb = abs(len_true - len_base) / max(len_true, len_base, 1)
        diff_fb = abs(len_false - len_base) / max(len_false, len_base, 1)
        # 양성 조건 (여러 신호 중 하나):
        #   (a) true vs false 길이 차 5%+ 또는 status 다름 (전형적 boolean diff)
        #   (b) 어느 한쪽이 baseline과 의미 있게 다름 (10%+) — true=match면 baseline보다 행 추가,
        #       false=miss면 baseline보다 행 적음
        #   (c) status code 다름
        confirmed = (
            diff_tf > 0.05
            or r_true.status_code != r_false.status_code
            or max(diff_tb, diff_fb) > 0.10
        )

        return json.dumps({
            "confirmed": confirmed,
            "diff_true_vs_false": round(diff_tf, 4),
            "diff_true_vs_baseline": round(diff_tb, 4),
            "diff_false_vs_baseline": round(diff_fb, 4),
            "len_true": len_true,
            "len_false": len_false,
            "len_baseline": len_base,
            "status_true": r_true.status_code,
            "status_false": r_false.status_code,
            "status_baseline": r_base.status_code,
            "snippet_true": r_true.text[:300],
            "snippet_false": r_false.text[:300],
        }, ensure_ascii=False)

    # ─────────────────────────────────────────────────────────────
    # SQLi — time-based (SLEEP)
    # ─────────────────────────────────────────────────────────────

    @mcp.tool()
    def oracle_sqli_time(
        url_payload: str,
        url_baseline: str,
        expected_delay_ms: int = SQLI_TIME_DEFAULT_DELAY * 1000,
        samples: int = 3,
    ) -> str:
        """time-based SQLi 검증. 페이로드 응답이 baseline 보다 expected_delay 만큼 느린지 확인.

        url_payload 예: ?id=1 AND SLEEP(3)--
        url_baseline 예: ?id=1
        samples 만큼 반복 측정해 중앙값 비교.
        """
        if samples < 1 or samples > 5:
            samples = 3

        def _measure(u):
            t0 = time.time()
            try:
                r = _safe_get(u, timeout=expected_delay_ms // 1000 + 5)
                ok = r.status_code < 500
            except requests.RequestException:
                ok = False
            return (time.time() - t0) * 1000.0, ok

        baseline_ms = [_measure(url_baseline) for _ in range(samples)]
        payload_ms = [_measure(url_payload) for _ in range(samples)]

        b_med = statistics.median(t for t, _ in baseline_ms)
        p_med = statistics.median(t for t, _ in payload_ms)
        delta = p_med - b_med

        confirmed = delta >= max(expected_delay_ms - SQLI_TIME_MARGIN_MS, 1500)

        return json.dumps({
            "confirmed": confirmed,
            "baseline_median_ms": round(b_med, 1),
            "payload_median_ms": round(p_med, 1),
            "delta_ms": round(delta, 1),
            "expected_delay_ms": expected_delay_ms,
            "samples": samples,
        }, ensure_ascii=False)

    # ─────────────────────────────────────────────────────────────
    # LFI — etc/passwd 등 시스템 파일 시그니처
    # ─────────────────────────────────────────────────────────────

    # 응답이 HTML wrapper 안에 있는 경우(<pre>root:...) 도 매치되도록 anchor 완화.
    LFI_SIGNATURES = [
        (re.compile(r"(?:^|>|\n)\s*root:[^:\n]*:\d+:\d+:"), "/etc/passwd (unix)"),
        (re.compile(r"daemon:[^:]*:\d+:\d+:"), "/etc/passwd (daemon line)"),
        (re.compile(r"\[boot loader\]", re.IGNORECASE), "boot.ini (windows)"),
        (re.compile(r"<\?php\b"), "php source"),
        (re.compile(r"DocumentRoot|ServerName", re.IGNORECASE), "apache config"),
        (re.compile(r"^[A-Za-z0-9+/=]{200,}\s*$", re.MULTILINE), "base64 (php filter)"),
    ]

    @mcp.tool()
    def oracle_lfi(url: str) -> str:
        """LFI 가설 검증. URL을 호출해 응답에서 시스템 파일 시그니처 매치 여부 판정.

        주의: 이 oracle은 traversal payload가 이미 url에 박혀있다고 가정한다.
        예: http://t/read?file=../../../../etc/passwd
        """
        try:
            r = _safe_get(url)
        except requests.RequestException as e:
            return json.dumps({"error": str(e)})

        body = r.text
        matched = []
        for pattern, label in LFI_SIGNATURES:
            if pattern.search(body):
                matched.append(label)

        confirmed = bool(matched)
        return json.dumps({
            "confirmed": confirmed,
            "matched_signatures": matched,
            "status_code": r.status_code,
            "snippet": body[:500],
        }, ensure_ascii=False)

    # ─────────────────────────────────────────────────────────────
    # SSRF — 응답 본문에 내부/메타데이터 banner echo
    # ─────────────────────────────────────────────────────────────

    SSRF_SIGNATURES = [
        (re.compile(r"ami-id|instance-id|iam/security-credentials", re.IGNORECASE), "AWS metadata"),
        (re.compile(r"computeMetadata/v1", re.IGNORECASE), "GCP metadata"),
        (re.compile(r"metadata\.azure", re.IGNORECASE), "Azure metadata"),
        (re.compile(r"<title>.{0,200}localhost", re.IGNORECASE | re.DOTALL), "localhost banner"),
        (re.compile(r"127\.0\.0\.1[:\s]"), "loopback echo"),
        # file:// 프로토콜 — wrapper가 file 읽기까지 허용하면 강한 신호
        (re.compile(r"(?:^|>|\n)\s*root:[^:\n]*:\d+:\d+:"), "file:// /etc/passwd echoed"),
        # gopher/dict/ldap 같은 비-HTTP 프로토콜 echo
        (re.compile(r"^(gopher|dict|ldap|ftp)://", re.IGNORECASE | re.MULTILINE), "non-http scheme echoed"),
    ]

    @mcp.tool()
    def oracle_ssrf(url: str) -> str:
        """SSRF 가설 검증. SSRF payload가 박힌 url을 호출해 응답에 내부/메타데이터 banner가
        echo되었는지 확인. 호출 자체는 외부 → 타겟. 메타데이터는 타겟 → 내부.

        예: http://t/fetch?url=http://169.254.169.254/latest/meta-data/
        """
        try:
            r = _safe_get(url, timeout=DEFAULT_TIMEOUT)
        except requests.RequestException as e:
            return json.dumps({"error": str(e)})

        body = r.text
        matched = [label for pattern, label in SSRF_SIGNATURES if pattern.search(body)]
        confirmed = bool(matched)
        return json.dumps({
            "confirmed": confirmed,
            "matched_signatures": matched,
            "status_code": r.status_code,
            "snippet": body[:500],
        }, ensure_ascii=False)
