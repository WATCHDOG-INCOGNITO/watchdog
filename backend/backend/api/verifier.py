"""
LLM 주도 검증 루프

흐름:
1. candidate를 받으면 LLM에게 공격 전략 + 페이로드 생성 요청
2. 생성된 페이로드를 실제로 전송
3. 응답을 LLM에게 보내서 분석 + 다음 페이로드 결정
4. LLM이 confirm/abort 판정할 때까지 반복 (최대 N회)
5. 최종 판정 → confirmed면 finding 생성
"""

import logging
import time
import hashlib
import json
import re
from urllib.parse import urljoin, urlparse, parse_qs

import requests

from django.utils import timezone

from .models import Candidate, ScanRun, VerificationLoop
from .storage_service import confirm_candidate
from .llm_router import (
    generate_initial_payloads,
    analyze_response_and_decide,
    mutate_payload_for_bypass,
    make_final_verdict,
)

logger = logging.getLogger(__name__)

MAX_ATTEMPTS = 8
REQUEST_TIMEOUT = 10
DELAY_BETWEEN = 0.5

class AttackExecutor:
    def __init__(self, base_url, timeout=REQUEST_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "WatchdogVerifier/1.0"})

    def execute(self, endpoint, method, param, value, extra_params=None):
        url = urljoin(self.base_url + "/", endpoint.lstrip("/"))
        params = dict(extra_params or {})
        params[param] = value

        try:
            start = time.time()
            if method.upper() == "POST":
                resp = self.session.post(url, data=params, timeout=self.timeout, allow_redirects=True)
            else:
                resp = self.session.get(url, params=params, timeout=self.timeout, allow_redirects=True)
            elapsed = round(time.time() - start, 3)

            return {
                "url": resp.url,
                "status_code": resp.status_code,
                "body": resp.text,
                "body_hash": hashlib.sha256(resp.text.encode()).hexdigest()[:16],
                "elapsed": elapsed,
                "headers": dict(resp.headers),
                "content_length": len(resp.text),
                "error": None,
            }
        except requests.RequestException as e:
            return {"url": url, "status_code": None, "body": "", "elapsed": 0,
                    "content_length": 0, "error": str(e)}

def _check_indicator(response_data, indicator):
    if not indicator:
        return False
    ind_type = indicator.get("type", "")
    ind_value = str(indicator.get("value", ""))

    if ind_type == "body_contains":
        return ind_value.lower() in response_data.get("body", "").lower()
    elif ind_type == "status_code":
        return str(response_data.get("status_code", "")) == ind_value
    elif ind_type == "time_delay":
        try:
            return response_data.get("elapsed", 0) >= float(ind_value)
        except ValueError:
            return False
    elif ind_type == "body_diff":
        return response_data.get("body_hash", "") != ind_value
    elif ind_type == "header_contains":
        headers_str = json.dumps(response_data.get("headers", {})).lower()
        return ind_value.lower() in headers_str
    return False

def _flat_params(params):
    flat = {}
    for k, v in (params or {}).items():
        if isinstance(v, list):
            flat[k] = v[0] if v else ""
        elif isinstance(v, dict):
            flat[k] = v.get("value", "")
        else:
            flat[k] = v
    return flat

def run_verification_loop(candidate, scan_run):
    vuln_type = candidate.vuln_type
    req = candidate.request
    if not req:
        return {"verified": False, "confidence": 0.0, "detail": "No request info",
                "attempts": 0, "finding_id": None}

    endpoint = req.endpoint
    method = req.method
    params = _flat_params(req.params)
    context = candidate.features or {}

    executor = AttackExecutor(scan_run.target_url)

    candidate.status = "verifying"
    candidate.save(update_fields=["status"])

    logger.info(f"[{candidate.cand_id}] LLM 주도 검증 시작: {method} {endpoint} ({vuln_type})")

    # 1단계: LLM에게 초기 페이로드 생성 요청
    plan = generate_initial_payloads(vuln_type, endpoint, method, params, context)
    strategy = plan.get("strategy", "unknown")
    stages = plan.get("stages", [])
    total_tokens = 0

    usage = plan.get("_usage", {})
    total_tokens += usage.get("input_tokens", 0) + usage.get("output_tokens", 0)

    if not stages:
        logger.warning(f"[{candidate.cand_id}] LLM이 페이로드를 생성하지 못함")
        candidate.status = "open"
        candidate.save(update_fields=["status"])
        return {"verified": False, "confidence": 0.0, "detail": "LLM failed to generate payloads",
                "attempts": 0, "finding_id": None}

    # 모든 stage의 payload를 flat list로
    all_payloads = []
    for stage in stages:
        for pl in stage.get("payloads", []):
            pl["_stage"] = stage.get("stage", "unknown")
            all_payloads.append(pl)

    attempt_history = []
    verified = False
    final_confidence = 0.0
    final_detail = ""
    evidence_list = []
    attempt_num = 0

    # 2단계: 페이로드 실행 + LLM 분석 루프
    pending_payloads = list(all_payloads)

    while pending_payloads and attempt_num < MAX_ATTEMPTS:
        pl = pending_payloads.pop(0)
        attempt_num += 1
        param_name = pl.get("param", list(params.keys())[0] if params else "q")
        payload_value = pl.get("value", "")
        pl_method = pl.get("method", method).upper()

        logger.info(f"[{candidate.cand_id}] attempt {attempt_num}/{MAX_ATTEMPTS}: "
                     f"{param_name}={payload_value[:60]}")

        # 실제 요청 전송
        other_params = {k: v for k, v in params.items() if k != param_name}
        resp = executor.execute(endpoint, pl_method, param_name, payload_value, other_params)
        time.sleep(DELAY_BETWEEN)

        if resp.get("error"):
            attempt_history.append({"payload": payload_value, "status_code": None,
                                     "indicator_matched": False, "error": resp["error"]})
            continue

        # 로컬 indicator 체크
        indicator_matched = _check_indicator(resp, pl.get("success_indicator"))

        attempt_record = {
            "payload": payload_value,
            "param": param_name,
            "stage": pl.get("_stage", "unknown"),
            "status_code": resp["status_code"],
            "elapsed": resp["elapsed"],
            "content_length": resp["content_length"],
            "indicator_matched": indicator_matched,
        }

        # LLM에게 응답 분석 + 다음 행동 결정 요청
        decision = analyze_response_and_decide(
            vuln_type, endpoint, pl_method,
            payload_sent=pl,
            response_data=resp,
            attempt_history=attempt_history,
        )

        usage = decision.get("_usage", {})
        total_tokens += usage.get("input_tokens", 0) + usage.get("output_tokens", 0)

        attempt_record["llm_analysis"] = decision.get("analysis", "")
        attempt_record["llm_vulnerable"] = decision.get("vulnerable")
        attempt_record["llm_confidence"] = decision.get("confidence", 0.0)
        attempt_history.append(attempt_record)

        # VerificationLoop 기록
        VerificationLoop.objects.create(
            candidate=candidate,
            attempt_number=attempt_num,
            payload_sent=payload_value[:1000],
            response_status=resp["status_code"],
            response_body_hash=resp["body_hash"],
            analysis_result={
                "indicator_matched": indicator_matched,
                "llm_vulnerable": decision.get("vulnerable"),
                "llm_confidence": decision.get("confidence", 0.0),
                "llm_analysis": decision.get("analysis", "")[:500],
                "next_action": decision.get("next_action", ""),
                "evidence_found": decision.get("evidence_found", ""),
            },
            next_action=decision.get("next_action", "abort"),
        )

        next_action = decision.get("next_action", "abort")

        # 증거 수집
        if decision.get("evidence_found"):
            evidence_list.append({
                "kind": "request",
                "content": json.dumps({
                    "attempt": attempt_num,
                    "param": param_name,
                    "payload": payload_value,
                    "response_status": resp["status_code"],
                    "response_time": resp["elapsed"],
                    "evidence": decision.get("evidence_found", ""),
                    "llm_analysis": decision.get("analysis", ""),
                    "response_snippet": resp["body"][:500],
                }, ensure_ascii=False),
                "role": "primary" if decision.get("vulnerable") else "supporting",
            })

        if next_action == "abort":
            logger.info(f"[{candidate.cand_id}] LLM abort 판정")
            break

        if next_action == "confirm" and decision.get("vulnerable"):
            verified = True
            final_confidence = decision.get("confidence", 0.9)
            final_detail = decision.get("analysis", "LLM confirmed vulnerability")
            break

        # LLM이 생성한 다음 페이로드를 큐에 추가
        next_payloads = decision.get("next_payloads", [])
        for np in next_payloads:
            np["_stage"] = "llm_generated"
            pending_payloads.insert(0, np)

        # WAF 차단 감지 → 우회 시도
        if resp["status_code"] in (403, 406, 429) and payload_value:
            logger.info(f"[{candidate.cand_id}] WAF 차단 감지, 우회 시도")
            bypass = mutate_payload_for_bypass(payload_value, vuln_type, resp["body"][:500])
            usage = bypass.get("_usage", {})
            total_tokens += usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
            for m in bypass.get("mutations", [])[:3]:
                pending_payloads.insert(0, {
                    "param": param_name,
                    "value": m.get("value", ""),
                    "method": pl_method,
                    "description": f"WAF bypass: {m.get('technique', '')}",
                    "success_indicator": pl.get("success_indicator", {}),
                    "_stage": "waf_bypass",
                })

    # 3단계: 최종 판정
    if not verified and attempt_history:
        verdict = make_final_verdict(vuln_type, f"{method} {endpoint}", attempt_history)
        usage = verdict.get("_usage", {})
        total_tokens += usage.get("input_tokens", 0) + usage.get("output_tokens", 0)

        if verdict.get("verdict") == "confirmed":
            verified = True
            final_confidence = verdict.get("confidence", 0.8)
            final_detail = verdict.get("summary", "LLM final verdict: confirmed")
        elif verdict.get("verdict") == "likely":
            final_confidence = verdict.get("confidence", 0.5)
            final_detail = verdict.get("summary", "LLM final verdict: likely")
        else:
            final_confidence = verdict.get("confidence", 0.0)
            final_detail = verdict.get("summary", "LLM final verdict: not vulnerable")

    # 결과 처리
    output = {
        "verified": verified,
        "confidence": final_confidence,
        "detail": final_detail,
        "attempts": attempt_num,
        "finding_id": None,
        "strategy": strategy,
        "total_llm_tokens": total_tokens,
    }

    if verified:
        try:
            confirm_result = confirm_candidate(
                cand_id=candidate.cand_id,
                confidence=final_confidence,
                summary=final_detail,
                evidence_list=evidence_list,
            )
            output["finding_id"] = confirm_result["finding_id"]
            logger.info(f"[{candidate.cand_id}] 취약점 확정: finding={confirm_result['finding_id']}")
        except Exception as e:
            logger.error(f"[{candidate.cand_id}] confirm 실패: {e}")
    else:
        candidate.status = "open"
        candidate.save(update_fields=["status"])

    # LLM 비용 기록
    from decimal import Decimal
    scan_run.llm_calls_count += attempt_num
    scan_run.llm_tokens_used += total_tokens
    scan_run.llm_cost_usd += Decimal(str(round(total_tokens * 0.005 / 1000, 4)))
    scan_run.save(update_fields=["llm_calls_count", "llm_tokens_used", "llm_cost_usd"])

    return output

def run_verification_for_scan(scan_run, max_candidates=10, min_confidence=0.3):
    import os
    if not os.environ.get("ANTHROPIC_API_KEY"):
        logger.warning(f"[{scan_run.run_id}] ANTHROPIC_API_KEY 없음, 검증 건너뜀")
        return []

    candidates = Candidate.objects.filter(
        scan_run=scan_run, status="open", priority_score__gte=min_confidence,
    ).select_related("request").order_by("-priority_score")[:max_candidates]

    logger.info(f"[{scan_run.run_id}] LLM 주도 검증 시작: {len(candidates)}개 candidate")

    results = []
    for i, cand in enumerate(candidates):
        logger.info(f"[{i+1}/{len(candidates)}] {cand.vuln_type}: "
                     f"{cand.request.endpoint if cand.request else '?'}")
        result = run_verification_loop(cand, scan_run)
        results.append({
            "cand_id": str(cand.cand_id),
            "vuln_type": cand.vuln_type,
            "endpoint": cand.request.endpoint if cand.request else None,
            **result,
        })

    verified_count = sum(1 for r in results if r["verified"])
    logger.info(f"[{scan_run.run_id}] 검증 완료: {verified_count}/{len(results)} 확정")
    return results

