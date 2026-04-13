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
import re
import statistics
import time

import requests

DEFAULT_TIMEOUT = 12
SQLI_TIME_DEFAULT_DELAY = 3
SQLI_TIME_MARGIN_MS = 1500  # baseline 대비 이만큼 더 느려야 양성


def _safe_get(url: str, *, headers: dict | None = None, timeout: int = DEFAULT_TIMEOUT):
    h = {"User-Agent": "WatchdogOracle/1.0"}
    if headers:
        h.update(headers)
    return requests.get(url, headers=h, timeout=timeout, allow_redirects=False)


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
