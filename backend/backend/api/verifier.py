"""
Verifier 모듈 — 검증 루프 + 공격 에이전트 통합

흐름:
1. candidate를 받음
2. vuln_type에 맞는 페이로드를 단계적으로 실행
3. 응답을 분석해 취약 여부 판정
4. 결과에 따라 retry / escalate / confirm / abort
5. 확정 시 candidate→finding 전환 + evidence 저장
"""

import logging
import time
import hashlib
import json
import re
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from typing import Optional

import requests

from django.utils import timezone

from .models import (
    Candidate, ScanRun, VerificationLoop, Finding,
    EvidenceBlob, FindingEvidenceLink, AgentTask,
)
from .attack_payloads import get_payloads, generate_idor_payload
from .storage_service import confirm_candidate

logger = logging.getLogger(__name__)


# ==========================================================
# 설정
# ==========================================================

MAX_RETRIES = 5          # 단계당 최대 시도 횟수
MAX_STAGES = 3           # 최대 escalation 단계
REQUEST_TIMEOUT = 10     # HTTP 요청 타임아웃
DELAY_BETWEEN = 0.5      # 요청 간 딜레이 (초)
TIME_THRESHOLD = 2.5     # time-based blind 판정 임계값 (초)


# ==========================================================
# 응답 분석기
# ==========================================================

class ResponseAnalyzer:
    """HTTP 응답을 분석하여 취약점 존재 여부를 판정"""

    # SQLi 에러 시그니처
    SQLI_ERROR_PATTERNS = [
        r"(?i)you have an error in your sql syntax",
        r"(?i)warning.*mysql",
        r"(?i)unclosed quotation mark",
        r"(?i)quoted string not properly terminated",
        r"(?i)pg_query\(\).*ERROR",
        r"(?i)SQLite3::query",
        r"(?i)ORA-\d{5}",
        r"(?i)SQLSTATE\[",
        r"(?i)syntax error.*near",
        r"(?i)Incorrect syntax near",
        r"(?i)com\.mysql\.jdbc",
        r"(?i)org\.postgresql",
        r"(?i)microsoft.*odbc.*driver",
        r"(?i)JDBCException",
        r"(?i)SQL.*exception",
        r"(?i)unterminated.*string",
        r"(?i)division by zero",
    ]

    # SSRF 내부 접근 성공 시그니처
    SSRF_SUCCESS_PATTERNS = [
        r"root:.*:\d+:\d+:",          # /etc/passwd
        r"ami-id",                     # AWS metadata
        r"instance-id",
        r"computeMetadata",            # GCP metadata
        r"169\.254\.169\.254",
    ]

    @classmethod
    def check_sqli_error(cls, response_text: str) -> Optional[str]:
        """SQLi 에러 패턴 검출"""
        for pattern in cls.SQLI_ERROR_PATTERNS:
            match = re.search(pattern, response_text)
            if match:
                return match.group(0)
        return None

    @classmethod
    def check_xss_reflection(cls, response_text: str, marker: str) -> bool:
        """XSS 마커가 응답에 반사되었는지 확인"""
        return marker in response_text

    @classmethod
    def check_sqli_boolean(cls, resp_true: str, resp_false: str, resp_normal: str) -> bool:
        """Boolean-based blind SQLi: TRUE/FALSE 응답 차이 확인"""
        # TRUE 응답이 정상과 비슷하고 FALSE가 다르면 취약
        true_sim = _similarity(resp_true, resp_normal)
        false_sim = _similarity(resp_false, resp_normal)
        return true_sim > 0.8 and false_sim < 0.5

    @classmethod
    def check_ssrf_success(cls, response_text: str) -> Optional[str]:
        """SSRF 성공 시그니처 검출"""
        for pattern in cls.SSRF_SUCCESS_PATTERNS:
            match = re.search(pattern, response_text)
            if match:
                return match.group(0)
        return None

    @classmethod
    def check_lfi_success(cls, response_text: str) -> bool:
        """LFI 성공 확인 (passwd 파일 등)"""
        return bool(re.search(r"root:.*:\d+:\d+:", response_text))


# ==========================================================
# HTTP 요청 실행기
# ==========================================================

class AttackExecutor:
    """안전한 HTTP 요청 실행"""

    def __init__(self, base_url: str, timeout: int = REQUEST_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "WatchdogVerifier/1.0",
        })

    def send_get(self, path: str, params: dict = None) -> dict:
        """GET 요청"""
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        try:
            start = time.time()
            resp = self.session.get(url, params=params, timeout=self.timeout, allow_redirects=True)
            elapsed = time.time() - start
            return {
                "url": resp.url,
                "status_code": resp.status_code,
                "body": resp.text,
                "body_hash": hashlib.sha256(resp.text.encode()).hexdigest()[:16],
                "elapsed": round(elapsed, 3),
                "headers": dict(resp.headers),
                "content_length": len(resp.text),
            }
        except requests.RequestException as e:
            return {"url": url, "error": str(e), "status_code": None, "body": "", "elapsed": 0}

    def send_post(self, path: str, data: dict = None, json_data: dict = None) -> dict:
        """POST 요청"""
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        try:
            start = time.time()
            if json_data:
                resp = self.session.post(url, json=json_data, timeout=self.timeout, allow_redirects=True)
            else:
                resp = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True)
            elapsed = time.time() - start
            return {
                "url": resp.url,
                "status_code": resp.status_code,
                "body": resp.text,
                "body_hash": hashlib.sha256(resp.text.encode()).hexdigest()[:16],
                "elapsed": round(elapsed, 3),
                "headers": dict(resp.headers),
                "content_length": len(resp.text),
            }
        except requests.RequestException as e:
            return {"url": url, "error": str(e), "status_code": None, "body": "", "elapsed": 0}

    def inject_param(self, path: str, method: str, params: dict,
                     target_param: str, payload: str) -> dict:
        """특정 파라미터에 페이로드를 주입하고 요청 전송"""
        injected_params = dict(params)
        injected_params[target_param] = payload

        if method.upper() == "POST":
            return self.send_post(path, data=injected_params)
        else:
            return self.send_get(path, params=injected_params)


# ==========================================================
# 취약점별 검증 로직
# ==========================================================

def verify_sqli(executor: AttackExecutor, candidate: Candidate, endpoint: str,
                method: str, params: dict) -> dict:
    """SQLi 검증"""
    results = {"verified": False, "evidence": [], "confidence": 0.0, "detail": ""}

    # 파라미터 중 의심 대상 찾기
    target_params = _get_target_params(candidate, params)
    if not target_params:
        target_params = list(params.keys())[:3]  # 최대 3개

    for target_param in target_params:
        # === Stage 1: Error-based ===
        payloads_s1 = get_payloads("sqli", stage=1)
        baseline_resp = executor.inject_param(endpoint, method, params, target_param, "1")
        time.sleep(DELAY_BETWEEN)

        for pl in payloads_s1:
            resp = executor.inject_param(endpoint, method, params, target_param, pl["payload"])
            time.sleep(DELAY_BETWEEN)

            if resp.get("error"):
                continue

            # 에러 패턴 검출
            error_match = ResponseAnalyzer.check_sqli_error(resp["body"])
            if error_match:
                results["verified"] = True
                results["confidence"] = 0.85
                results["detail"] = f"Error-based SQLi: param={target_param}, error='{error_match}'"
                results["evidence"].append({
                    "kind": "request",
                    "content": json.dumps({
                        "payload": pl["payload"],
                        "param": target_param,
                        "method": method,
                        "endpoint": endpoint,
                        "response_status": resp["status_code"],
                        "error_pattern": error_match,
                        "response_snippet": resp["body"][:500],
                    }, ensure_ascii=False),
                    "role": "primary",
                })
                return results

        # === Stage 2: Time-based Blind ===
        payloads_s2 = get_payloads("sqli", stage=2)
        for pl in payloads_s2:
            expected_delay = pl.get("expected_delay", 3)
            resp = executor.inject_param(endpoint, method, params, target_param, pl["payload"])
            time.sleep(DELAY_BETWEEN)

            if resp.get("error"):
                continue

            if resp["elapsed"] >= TIME_THRESHOLD:
                # 재확인 (오탐 방지)
                baseline_time = executor.inject_param(
                    endpoint, method, params, target_param, "1"
                )["elapsed"]
                time.sleep(DELAY_BETWEEN)

                if resp["elapsed"] - baseline_time >= (expected_delay * 0.7):
                    results["verified"] = True
                    results["confidence"] = 0.80
                    results["detail"] = (
                        f"Time-based Blind SQLi: param={target_param}, "
                        f"delay={resp['elapsed']}s (baseline={baseline_time}s)"
                    )
                    results["evidence"].append({
                        "kind": "request",
                        "content": json.dumps({
                            "payload": pl["payload"],
                            "param": target_param,
                            "response_time": resp["elapsed"],
                            "baseline_time": baseline_time,
                            "expected_delay": expected_delay,
                        }, ensure_ascii=False),
                        "role": "primary",
                    })
                    return results

        # === Stage 3: Boolean-based Blind ===
        payloads_s3 = get_payloads("sqli", stage=3)
        if len(payloads_s3) >= 2:
            resp_true = executor.inject_param(
                endpoint, method, params, target_param, payloads_s3[0]["payload"]
            )
            time.sleep(DELAY_BETWEEN)
            resp_false = executor.inject_param(
                endpoint, method, params, target_param, payloads_s3[1]["payload"]
            )
            time.sleep(DELAY_BETWEEN)

            if not resp_true.get("error") and not resp_false.get("error"):
                if ResponseAnalyzer.check_sqli_boolean(
                    resp_true["body"], resp_false["body"], baseline_resp["body"]
                ):
                    results["verified"] = True
                    results["confidence"] = 0.70
                    results["detail"] = (
                        f"Boolean-based Blind SQLi: param={target_param}, "
                        f"TRUE/FALSE response difference detected"
                    )
                    results["evidence"].append({
                        "kind": "request",
                        "content": json.dumps({
                            "param": target_param,
                            "true_payload": payloads_s3[0]["payload"],
                            "false_payload": payloads_s3[1]["payload"],
                            "true_length": resp_true["content_length"],
                            "false_length": resp_false["content_length"],
                            "baseline_length": baseline_resp["content_length"],
                        }, ensure_ascii=False),
                        "role": "primary",
                    })
                    return results

    return results


def verify_xss(executor: AttackExecutor, candidate: Candidate, endpoint: str,
               method: str, params: dict) -> dict:
    """XSS 검증"""
    results = {"verified": False, "evidence": [], "confidence": 0.0, "detail": ""}

    target_params = _get_target_params(candidate, params)
    if not target_params:
        target_params = list(params.keys())[:3]

    for target_param in target_params:
        # === Stage 1: Reflection Probe ===
        probes = get_payloads("xss", stage=1)
        for pl in probes:
            resp = executor.inject_param(endpoint, method, params, target_param, pl["payload"])
            time.sleep(DELAY_BETWEEN)

            if resp.get("error"):
                continue

            marker = pl.get("marker", pl["payload"])
            if ResponseAnalyzer.check_xss_reflection(resp["body"], marker):
                # 마커가 반사됨 → Stage 2로 escalation
                results["evidence"].append({
                    "kind": "log",
                    "content": json.dumps({
                        "stage": "probe",
                        "param": target_param,
                        "payload": pl["payload"],
                        "marker_reflected": True,
                    }, ensure_ascii=False),
                    "role": "supporting",
                })

                # === Stage 2: Script 실행 시도 ===
                scripts = get_payloads("xss", stage=2)
                for spl in scripts:
                    resp2 = executor.inject_param(
                        endpoint, method, params, target_param, spl["payload"]
                    )
                    time.sleep(DELAY_BETWEEN)

                    if resp2.get("error"):
                        continue

                    s_marker = spl.get("marker", spl["payload"])
                    if ResponseAnalyzer.check_xss_reflection(resp2["body"], s_marker):
                        results["verified"] = True
                        results["confidence"] = 0.90
                        results["detail"] = (
                            f"Reflected XSS: param={target_param}, "
                            f"payload reflected unescaped in response"
                        )
                        results["evidence"].append({
                            "kind": "request",
                            "content": json.dumps({
                                "stage": "script",
                                "param": target_param,
                                "payload": spl["payload"],
                                "marker": s_marker,
                                "reflected": True,
                                "response_snippet": resp2["body"][:500],
                            }, ensure_ascii=False),
                            "role": "primary",
                        })
                        return results

                # Stage 2 실패 → Stage 3: 필터 우회
                bypasses = get_payloads("xss", stage=3)
                for bpl in bypasses:
                    resp3 = executor.inject_param(
                        endpoint, method, params, target_param, bpl["payload"]
                    )
                    time.sleep(DELAY_BETWEEN)

                    if resp3.get("error"):
                        continue

                    # 우회 성공 확인: 페이로드의 핵심 부분이 반사되는지
                    if "onerror=" in resp3["body"] or "onload=" in resp3["body"] or \
                       "ontoggle=" in resp3["body"] or "<script>" in resp3["body"].lower():
                        results["verified"] = True
                        results["confidence"] = 0.85
                        results["detail"] = (
                            f"XSS with filter bypass: param={target_param}, "
                            f"bypass={bpl['desc']}"
                        )
                        results["evidence"].append({
                            "kind": "request",
                            "content": json.dumps({
                                "stage": "bypass",
                                "param": target_param,
                                "payload": bpl["payload"],
                                "bypass_type": bpl["desc"],
                                "response_snippet": resp3["body"][:500],
                            }, ensure_ascii=False),
                            "role": "primary",
                        })
                        return results

    return results


def verify_idor(executor: AttackExecutor, candidate: Candidate, endpoint: str,
                method: str, params: dict) -> dict:
    """IDOR 검증"""
    results = {"verified": False, "evidence": [], "confidence": 0.0, "detail": ""}

    # ID 파라미터 찾기
    id_params = _get_target_params(candidate, params)
    if not id_params:
        id_pattern = re.compile(r"(?i)(id|uid|user_id|account|profile|doc|file|order)")
        id_params = [k for k in params if id_pattern.search(k)]

    if not id_params:
        # 경로에 숫자 ID가 있는 경우
        path_match = re.search(r"/(\d+)(?:/|$|\?)", endpoint)
        if path_match:
            original_id = path_match.group(1)
            new_id = str(int(original_id) + 1)
            new_endpoint = endpoint.replace(f"/{original_id}", f"/{new_id}", 1)

            resp_original = executor.send_get(endpoint) if method == "GET" else executor.send_post(endpoint)
            time.sleep(DELAY_BETWEEN)
            resp_tampered = executor.send_get(new_endpoint) if method == "GET" else executor.send_post(new_endpoint)

            if not resp_tampered.get("error") and resp_tampered["status_code"] == 200:
                if resp_tampered["body_hash"] != resp_original.get("body_hash", ""):
                    results["verified"] = True
                    results["confidence"] = 0.65
                    results["detail"] = f"Path-based IDOR: {endpoint} → {new_endpoint} returned different data"
                    results["evidence"].append({
                        "kind": "request",
                        "content": json.dumps({
                            "original_path": endpoint,
                            "tampered_path": new_endpoint,
                            "original_status": resp_original.get("status_code"),
                            "tampered_status": resp_tampered["status_code"],
                        }, ensure_ascii=False),
                        "role": "primary",
                    })
            return results

    for target_param in id_params:
        original_value = params.get(target_param, "1")
        if isinstance(original_value, list):
            original_value = original_value[0]

        # 정상 응답 baseline
        resp_normal = executor.inject_param(endpoint, method, params, target_param, str(original_value))
        time.sleep(DELAY_BETWEEN)

        if resp_normal.get("error"):
            continue

        # ID 변조 시도
        payloads_s1 = get_payloads("idor", stage=1)
        for pl in payloads_s1:
            tampered_value = generate_idor_payload(original_value, pl["transform"])
            if tampered_value == str(original_value):
                continue

            resp = executor.inject_param(endpoint, method, params, target_param, tampered_value)
            time.sleep(DELAY_BETWEEN)

            if resp.get("error"):
                continue

            # 200 OK + 다른 데이터 = IDOR 가능성
            if resp["status_code"] == 200 and resp["body_hash"] != resp_normal["body_hash"]:
                # 에러 페이지가 아닌지 확인
                if resp["content_length"] > 100 and "error" not in resp["body"].lower()[:200]:
                    results["verified"] = True
                    results["confidence"] = 0.70
                    results["detail"] = (
                        f"IDOR: param={target_param}, "
                        f"original={original_value} → tampered={tampered_value}, "
                        f"different response returned"
                    )
                    results["evidence"].append({
                        "kind": "request",
                        "content": json.dumps({
                            "param": target_param,
                            "original_value": str(original_value),
                            "tampered_value": tampered_value,
                            "transform": pl["transform"],
                            "original_hash": resp_normal["body_hash"],
                            "tampered_hash": resp["body_hash"],
                            "tampered_status": resp["status_code"],
                            "tampered_length": resp["content_length"],
                        }, ensure_ascii=False),
                        "role": "primary",
                    })
                    return results

    return results


def verify_ssrf(executor: AttackExecutor, candidate: Candidate, endpoint: str,
                method: str, params: dict) -> dict:
    """SSRF 검증"""
    results = {"verified": False, "evidence": [], "confidence": 0.0, "detail": ""}

    target_params = _get_target_params(candidate, params)
    if not target_params:
        url_pattern = re.compile(r"(?i)(url|uri|link|src|source|target|dest|redirect|proxy|fetch|load)")
        target_params = [k for k in params if url_pattern.search(k)]

    for target_param in target_params:
        # Stage 1: 내부 접근
        payloads_s1 = get_payloads("ssrf", stage=1)
        for pl in payloads_s1:
            resp = executor.inject_param(endpoint, method, params, target_param, pl["payload"])
            time.sleep(DELAY_BETWEEN)

            if resp.get("error"):
                continue

            ssrf_match = ResponseAnalyzer.check_ssrf_success(resp["body"])
            if ssrf_match:
                results["verified"] = True
                results["confidence"] = 0.90
                results["detail"] = f"SSRF: param={target_param}, internal access confirmed ({ssrf_match})"
                results["evidence"].append({
                    "kind": "request",
                    "content": json.dumps({
                        "param": target_param,
                        "payload": pl["payload"],
                        "ssrf_indicator": ssrf_match,
                        "response_snippet": resp["body"][:500],
                    }, ensure_ascii=False),
                    "role": "primary",
                })
                return results

        # Stage 2: Protocol 변조 (LFI via SSRF)
        payloads_s2 = get_payloads("ssrf", stage=2)
        for pl in payloads_s2:
            resp = executor.inject_param(endpoint, method, params, target_param, pl["payload"])
            time.sleep(DELAY_BETWEEN)

            if resp.get("error"):
                continue

            if ResponseAnalyzer.check_lfi_success(resp["body"]):
                results["verified"] = True
                results["confidence"] = 0.95
                results["detail"] = f"SSRF→LFI: param={target_param}, file read confirmed via {pl['payload']}"
                results["evidence"].append({
                    "kind": "request",
                    "content": json.dumps({
                        "param": target_param,
                        "payload": pl["payload"],
                        "response_snippet": resp["body"][:500],
                    }, ensure_ascii=False),
                    "role": "primary",
                })
                return results

    return results


def verify_upload_lfi(executor: AttackExecutor, candidate: Candidate, endpoint: str,
                      method: str, params: dict) -> dict:
    """LFI / File Upload 검증"""
    results = {"verified": False, "evidence": [], "confidence": 0.0, "detail": ""}

    target_params = _get_target_params(candidate, params)
    if not target_params:
        file_pattern = re.compile(r"(?i)(file|path|src|source|page|include|template|doc)")
        target_params = [k for k in params if file_pattern.search(k)]

    for target_param in target_params:
        payloads = get_payloads("upload", stage=1)
        for pl in payloads:
            resp = executor.inject_param(endpoint, method, params, target_param, pl["payload"])
            time.sleep(DELAY_BETWEEN)

            if resp.get("error"):
                continue

            marker = pl.get("marker")
            if marker and marker in resp["body"]:
                results["verified"] = True
                results["confidence"] = 0.90
                results["detail"] = f"LFI: param={target_param}, payload={pl['payload']}"
                results["evidence"].append({
                    "kind": "request",
                    "content": json.dumps({
                        "param": target_param,
                        "payload": pl["payload"],
                        "marker": marker,
                        "response_snippet": resp["body"][:500],
                    }, ensure_ascii=False),
                    "role": "primary",
                })
                return results

    return results


# ==========================================================
# 검증 루프 메인
# ==========================================================

VERIFY_DISPATCH = {
    "sqli": verify_sqli,
    "xss": verify_xss,
    "idor": verify_idor,
    "ssrf": verify_ssrf,
    "upload": verify_upload_lfi,
}


def run_verification_loop(candidate: Candidate, scan_run: ScanRun) -> dict:
    """
    단일 candidate에 대한 검증 루프 실행.

    Returns:
        dict: {
            "verified": bool,
            "confidence": float,
            "detail": str,
            "attempts": int,
            "finding_id": str or None
        }
    """
    vuln_type = candidate.vuln_type
    verify_func = VERIFY_DISPATCH.get(vuln_type)

    if not verify_func:
        logger.warning(f"[{candidate.cand_id}] 지원하지 않는 vuln_type: {vuln_type}")
        return {"verified": False, "confidence": 0.0, "detail": f"Unsupported vuln_type: {vuln_type}",
                "attempts": 0, "finding_id": None}

    # candidate에서 엔드포인트/파라미터 추출
    req = candidate.request
    if not req:
        logger.warning(f"[{candidate.cand_id}] request 정보 없음")
        return {"verified": False, "confidence": 0.0, "detail": "No request info",
                "attempts": 0, "finding_id": None}

    endpoint = req.endpoint
    method = req.method
    params = req.params or {}

    # 파라미터 정규화 (parse_qs는 리스트로 반환)
    flat_params = {}
    for k, v in params.items():
        if isinstance(v, list):
            flat_params[k] = v[0] if v else ""
        elif isinstance(v, dict):
            flat_params[k] = v.get("value", "")
        else:
            flat_params[k] = v

    # Executor 생성
    executor = AttackExecutor(scan_run.target_url)

    # candidate 상태 → verifying
    candidate.status = "verifying"
    candidate.save(update_fields=["status"])

    # 검증 실행
    logger.info(f"[{candidate.cand_id}] 검증 시작: {method} {endpoint} ({vuln_type})")

    attempt_num = VerificationLoop.objects.filter(candidate=candidate).count() + 1

    result = verify_func(executor, candidate, endpoint, method, flat_params)

    # VerificationLoop 기록
    if result["verified"]:
        next_action = "confirmed"
    elif result.get("evidence"):
        next_action = "escalate"
    else:
        next_action = "abort"

    loop = VerificationLoop.objects.create(
        candidate=candidate,
        attempt_number=attempt_num,
        payload_sent=json.dumps(result.get("evidence", [])[:1], ensure_ascii=False)[:1000],
        response_status=None,
        response_body_hash=None,
        analysis_result={
            "verified": result["verified"],
            "confidence": result["confidence"],
            "detail": result["detail"],
        },
        next_action=next_action,
    )

    # 결과 처리
    output = {
        "verified": result["verified"],
        "confidence": result["confidence"],
        "detail": result["detail"],
        "attempts": attempt_num,
        "finding_id": None,
    }

    if result["verified"]:
        # candidate → finding 전환
        try:
            confirm_result = confirm_candidate(
                cand_id=candidate.cand_id,
                confidence=result["confidence"],
                summary=result["detail"],
                evidence_list=result.get("evidence", []),
            )
            output["finding_id"] = confirm_result["finding_id"]
            logger.info(f"[{candidate.cand_id}] 취약점 확정: finding={confirm_result['finding_id']}")
        except Exception as e:
            logger.error(f"[{candidate.cand_id}] confirm 실패: {e}")
    else:
        # 미확인 → open으로 되돌림
        candidate.status = "open"
        candidate.save(update_fields=["status"])

    return output


def run_verification_for_scan(scan_run: ScanRun, max_candidates: int = 10,
                              min_confidence: float = 0.3) -> list:
    """
    스캔의 전체 candidate를 순회하며 검증 루프 실행.

    Args:
        scan_run: 대상 스캔
        max_candidates: 최대 검증 candidate 수
        min_confidence: 최소 priority_score 임계값

    Returns:
        list of verification results
    """
    candidates = Candidate.objects.filter(
        scan_run=scan_run,
        status="open",
        priority_score__gte=min_confidence,
    ).select_related("request").order_by("-priority_score")[:max_candidates]

    logger.info(f"[{scan_run.run_id}] 검증 루프 시작: {len(candidates)}개 candidate")

    results = []
    for i, cand in enumerate(candidates):
        logger.info(f"[{i+1}/{len(candidates)}] {cand.vuln_type}: {cand.request.endpoint if cand.request else '?'}")
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


# ==========================================================
# LLM 기반 고급 검증 (Claude에게 응답 분석 위임)
# ==========================================================

def llm_verify_response(candidate_data: dict, payload: str,
                        response_data: dict) -> dict:
    """
    Claude에게 공격 결과를 보내서 취약점 여부 판정받기.
    기존 rule-based 검증으로 놓친 경우 보조적으로 사용.
    """
    import os
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return {"verified": False, "confidence": 0.0, "analysis": "API key not set"}

    from .llm_router import get_client

    client = get_client()
    prompt = f"""당신은 웹 보안 전문가입니다.
아래 공격 시도의 결과를 분석하여 취약점이 실제로 존재하는지 판정해주세요.

## 공격 정보
- 엔드포인트: {candidate_data.get('method')} {candidate_data.get('endpoint')}
- 취약점 유형: {candidate_data.get('vuln_type')}
- 사용된 페이로드: {payload}

## 서버 응답
- 상태 코드: {response_data.get('status_code')}
- 응답 시간: {response_data.get('elapsed')}초
- 응답 본문 (처음 1000자):
{response_data.get('body', '')[:1000]}

## 판정 기준
- 페이로드가 응답에 반사/실행되었는가?
- SQL 에러 메시지가 노출되었는가?
- 응답 시간이 비정상적으로 길었는가?
- 내부 리소스에 접근 성공했는가?

JSON으로만 반환:
{{"verified": true/false, "confidence": 0.0~1.0, "analysis": "판정 근거"}}"""

    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1].rsplit("```", 1)[0]
        return json.loads(raw)
    except Exception as e:
        logger.error(f"LLM 검증 실패: {e}")
        return {"verified": False, "confidence": 0.0, "analysis": f"LLM error: {e}"}


# ==========================================================
# 유틸
# ==========================================================

def _get_target_params(candidate: Candidate, params: dict) -> list:
    """candidate의 features에서 의심 파라미터 추출"""
    target_params = []
    features = candidate.features or {}

    # LLM 분석에서 제안된 파라미터
    llm_analysis = features.get("llm_analysis", {})
    suggested = llm_analysis.get("suggested_payloads", [])

    # 규칙 기반에서 탐지된 파라미터
    param_hits = features.get("param_hits", [])
    for hit in param_hits:
        p = hit.get("param")
        if p and p in params and p not in target_params:
            target_params.append(p)

    return target_params


def _similarity(text_a: str, text_b: str) -> float:
    """두 텍스트의 유사도 (0.0~1.0, 길이 기반 간단 비교)"""
    if not text_a or not text_b:
        return 0.0
    len_a, len_b = len(text_a), len(text_b)
    if len_a == 0 and len_b == 0:
        return 1.0
    # 길이 차이 기반 유사도 + 해시 비교
    length_sim = 1.0 - abs(len_a - len_b) / max(len_a, len_b)
    hash_sim = 1.0 if hashlib.sha256(text_a.encode()).hexdigest()[:8] == \
                       hashlib.sha256(text_b.encode()).hexdigest()[:8] else 0.0
    return (length_sim * 0.6) + (hash_sim * 0.4)
