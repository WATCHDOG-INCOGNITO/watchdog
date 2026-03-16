"""
스캔 서비스
크롤링 실행 → JS 분석 → request_catalog 저장 → 규칙 기반 필터링
→ 보안 헤더 점검 → candidates 저장
"""

import logging
import re
from django.utils import timezone

from .models import ScanRun, RequestCatalog, Candidate, Finding
from .crawler import Crawler

logger = logging.getLogger(__name__)


# ==========================================================
# 보안 헤더 점검
# ==========================================================

SECURITY_HEADERS_CHECK = {
    "Strict-Transport-Security": {
        "title": "HSTS 헤더 누락",
        "severity": "medium",
        "summary": "Strict-Transport-Security 헤더가 설정되지 않아 "
                   "HTTPS 다운그레이드 공격에 취약할 수 있습니다.",
    },
    "X-Frame-Options": {
        "title": "X-Frame-Options 헤더 누락",
        "severity": "medium",
        "summary": "X-Frame-Options 헤더가 없어 클릭재킹(Clickjacking) 공격에 "
                   "취약할 수 있습니다.",
    },
    "Content-Security-Policy": {
        "title": "Content-Security-Policy 헤더 누락",
        "severity": "medium",
        "summary": "CSP가 설정되지 않아 XSS 공격의 영향을 완화할 수 없습니다.",
    },
    "X-Content-Type-Options": {
        "title": "X-Content-Type-Options 헤더 누락",
        "severity": "low",
        "summary": "X-Content-Type-Options: nosniff 가 없어 "
                   "MIME 타입 스니핑 공격에 노출될 수 있습니다.",
    },
    "Referrer-Policy": {
        "title": "Referrer-Policy 헤더 누락",
        "severity": "low",
        "summary": "Referrer-Policy가 설정되지 않아 민감한 URL 정보가 "
                   "외부로 유출될 수 있습니다.",
    },
    "Permissions-Policy": {
        "title": "Permissions-Policy 헤더 누락",
        "severity": "info",
        "summary": "Permissions-Policy가 설정되지 않아 브라우저 기능 "
                   "(카메라, 마이크 등) 접근을 제한하지 않습니다.",
    },
}


def run_security_header_check(scan_run: ScanRun, headers: dict):
    """응답 헤더에서 보안 헤더 누락을 점검하여 Finding으로 생성."""
    if not headers:
        logger.info(f"[{scan_run.run_id}] 응답 헤더 없음, 보안 헤더 점검 건너뜀")
        return []

    header_keys_lower = {k.lower(): v for k, v in headers.items()}
    findings = []

    for header_name, info in SECURITY_HEADERS_CHECK.items():
        if header_name.lower() not in header_keys_lower:
            finding = Finding.objects.create(
                scan_run=scan_run,
                title=info["title"],
                vuln_type="security_header",
                severity=info["severity"],
                confidence=1.0,
                summary=info["summary"],
                reproduction_steps=f"응답 헤더에 {header_name}이 없습니다.",
            )
            findings.append(finding)

    server_header = header_keys_lower.get("server", "")
    if server_header and re.search(r"[\d.]+", server_header):
        Finding.objects.create(
            scan_run=scan_run,
            title="서버 버전 정보 노출",
            vuln_type="info_disclosure",
            severity="low",
            confidence=1.0,
            summary=f"Server 헤더에서 버전 정보가 노출됩니다: {server_header}",
            reproduction_steps=f"응답 헤더: Server: {server_header}",
        )

    logger.info(f"[{scan_run.run_id}] 보안 헤더 점검 완료: {len(findings)}개 이슈")
    return findings


# ==========================================================
# 규칙 기반 필터링 (1단계: 비용 제로)
# ==========================================================

    # 파라미터 이름 기반 의심 패턴
SUSPICIOUS_PARAM_PATTERNS = [
    # SQLi 의심
    (r"(?i)^(id|uid|user_id|pid|no|idx|seq|num|page|limit|offset|sort|order|column)$", "sqli"),
    # XSS 의심
    (r"(?i)^(q|query|search|keyword|name|title|msg|message|comment|text|content|input|value|data)$", "xss"),
    # IDOR 의심
    (r"(?i)^(id|uid|user_id|account|profile|doc|order|invoice)$", "idor"),
    # LFI 의심
    (r"(?i)^(file|path|page|include|template|doc|dir|folder|src|source|lang|locale)$", "lfi"),
    # SSRF 의심
    (r"(?i)^(url|uri|link|target|dest|redirect|proxy|fetch|load|request|next|return|callback)$", "ssrf"),
    # 파일 업로드 의심
    (r"(?i)^(upload|attach|image|photo|document|import)$", "upload"),
    # 사용자 열거 의심 (인증 관련 쿼리 파라미터)
    (r"(?i)^(studentNumber|student_id|email|username|phone|phoneNumber)$", "idor"),
]

# 엔드포인트 경로 기반 의심 패턴
SUSPICIOUS_PATH_PATTERNS = [
    (r"(?i)/admin", "idor"),
    (r"(?i)/api/", "sqli"),
    (r"(?i)/login", "sqli"),
    (r"(?i)/search", "xss"),
    (r"(?i)/upload", "upload"),
    (r"(?i)/profile", "idor"),
    (r"(?i)/user", "idor"),
    (r"(?i)/redirect", "ssrf"),
    (r"(?i)/callback", "ssrf"),
    (r"(?i)/download", "lfi"),
    (r"(?i)/export", "ssrf"),
    (r"(?i)/read", "lfi"),
    (r"(?i)/fetch", "ssrf"),
    (r"(?i)/include", "lfi"),
    (r"(?i)/file", "lfi"),
    # SPA API 패턴
    (r"(?i)/auth/", "sqli"),
    (r"(?i)/auth/login", "sqli"),
    (r"(?i)/auth/register", "sqli"),
    (r"(?i)/auth/check", "idor"),
    (r"(?i)/group/\d+", "idor"),
    (r"(?i)/member", "idor"),
    (r"(?i)/mentee", "idor"),
    (r"(?i)/mentor", "idor"),
    (r"(?i)/image/", "lfi"),
    (r"(?i)/notification", "idor"),
    (r"(?i)/activity", "idor"),
    (r"(?i)/assignment", "idor"),
    (r"(?i)/v[0-9]/", "sqli"),
    (r"(?i)/delete", "idor"),
    (r"(?i)/create", "idor"),
    (r"(?i)/update", "idor"),
]


def analyze_params(params):
    """파라미터 이름 분석 → 의심 유형 반환"""
    hits = []
    if not params:
        return hits

    param_names = []
    if isinstance(params, dict):
        param_names = list(params.keys())
    elif isinstance(params, list):
        param_names = params

    for name in param_names:
        for pattern, vuln_type in SUSPICIOUS_PARAM_PATTERNS:
            if re.search(pattern, name):
                hits.append({
                    "param": name,
                    "vuln_type": vuln_type,
                    "rule": pattern,
                })
    return hits


def analyze_path(endpoint):
    """경로 분석 → 의심 유형 반환"""
    hits = []
    for pattern, vuln_type in SUSPICIOUS_PATH_PATTERNS:
        if re.search(pattern, endpoint):
            hits.append({
                "path": endpoint,
                "vuln_type": vuln_type,
                "rule": pattern,
            })
    return hits


def calculate_priority(param_hits, path_hits):
    """히트 수 기반 우선순위 점수 계산 (0.0 ~ 1.0)"""
    total = len(param_hits) + len(path_hits)
    if total == 0:
        return 0.0
    score = (len(param_hits) * 0.25) + (len(path_hits) * 0.15)
    if total >= 2:
        score += 0.10
    return min(score, 1.0)


# ==========================================================
# 스캔 서비스
# ==========================================================

def run_crawl(scan_run: ScanRun):
    """크롤링 + JS 분석 실행 → request_catalog에 저장"""
    logger.info(f"[{scan_run.run_id}] 크롤링 시작: {scan_run.target_url}")

    crawler = Crawler(
        target_url=scan_run.target_url,
        max_depth=3,
        max_pages=200,
        timeout=10,
    )
    endpoints = crawler.crawl()

    # DB에 저장
    catalog_items = []
    for ep in endpoints:
        item = RequestCatalog(
            scan_run=scan_run,
            endpoint=ep["endpoint"],
            method=ep["method"],
            params=ep["params"],
            status_code=ep.get("status_code"),
            content_type=ep.get("content_type"),
            headers=ep.get("headers"),
            body_hash=ep.get("body_hash"),
            auth_required=ep.get("auth_required", False),
            source=ep.get("source", "crawler"),
            discovered_from=ep.get("discovered_from", ""),
        )
        catalog_items.append(item)

    RequestCatalog.objects.bulk_create(catalog_items)

    js_count = sum(1 for ep in endpoints if "js_" in ep.get("source", ""))
    logger.info(f"[{scan_run.run_id}] {len(catalog_items)}개 엔드포인트 저장 "
                f"(BFS: {len(catalog_items) - js_count}, JS 분석: {js_count})")

    return catalog_items, crawler.response_headers


def run_rule_filter(scan_run: ScanRun):
    """규칙 기반 필터링 → candidates에 저장"""
    logger.info(f"[{scan_run.run_id}] 규칙 기반 필터링 시작")

    catalog_items = RequestCatalog.objects.filter(scan_run=scan_run)
    candidates = []

    for item in catalog_items:
        param_hits = analyze_params(item.params)
        path_hits = analyze_path(item.endpoint)

        if not param_hits and not path_hits:
            continue

        # 의심 유형별로 candidate 생성
        vuln_types_seen = set()
        all_hits = param_hits + path_hits

        for hit in all_hits:
            vt = hit["vuln_type"]
            if vt in vuln_types_seen:
                continue
            vuln_types_seen.add(vt)

            priority = calculate_priority(
                [h for h in param_hits if h["vuln_type"] == vt],
                [h for h in path_hits if h["vuln_type"] == vt],
            )

            cand = Candidate(
                scan_run=scan_run,
                request=item,
                vuln_type=vt,
                hypothesis=f"규칙 기반 탐지: {item.endpoint} ({item.method}) - {vt} 의심",
                priority_score=priority,
                detection_stage="rule",
                features={
                    "signal_rules_hit": [h["rule"] for h in all_hits if h["vuln_type"] == vt],
                    "param_hits": [h for h in param_hits if h["vuln_type"] == vt],
                    "path_hits": [h for h in path_hits if h["vuln_type"] == vt],
                },
            )
            candidates.append(cand)

    Candidate.objects.bulk_create(candidates)
    logger.info(f"[{scan_run.run_id}] {len(candidates)}개 candidate 생성 완료")

    return candidates


def run_scan(scan_run: ScanRun):
    """전체 스캔 파이프라인 (크롤링 → JS분석 → 필터링 → 보안헤더 → LLM → 검증)"""
    try:
        scan_run.status = "running"
        scan_run.save(update_fields=["status"])

        # 1. 크롤링 + JS 번들 분석
        _catalog, response_headers = run_crawl(scan_run)

        # 2. 보안 헤더 점검
        run_security_header_check(scan_run, response_headers)

        # 3. 규칙 기반 필터링
        run_rule_filter(scan_run)

        # 4. LLM 분석 (2단계: llm_screen)
        run_llm_screen(scan_run)

        # 5. 검증 루프 (3단계: 실제 페이로드 전송)
        run_verify(scan_run)

        # 6. 완료
        scan_run.status = "finished"
        scan_run.finished_at = timezone.now()
        scan_run.save(update_fields=["status", "finished_at"])

        logger.info(f"[{scan_run.run_id}] 스캔 완료")

    except Exception as e:
        scan_run.status = "failed"
        scan_run.error_log = str(e)
        scan_run.save(update_fields=["status", "error_log"])
        logger.error(f"[{scan_run.run_id}] 스캔 실패: {e}")
        raise


def run_llm_screen(scan_run: ScanRun, max_candidates=20):
    """
    규칙 기반으로 뽑힌 candidate 중 상위 N개를 Claude로 분석한다.
    결과에 따라 candidate의 detection_stage, priority_score, features를 업데이트.
    """
    import os
    if not os.environ.get("ANTHROPIC_API_KEY"):
        logger.warning(f"[{scan_run.run_id}] ANTHROPIC_API_KEY 없음, LLM 분석 건너뜀")
        return

    from .llm_router import batch_analyze_candidates

    logger.info(f"[{scan_run.run_id}] LLM 스크리닝 시작")

    # priority 높은 순으로 candidate 가져오기
    candidates = Candidate.objects.filter(
        scan_run=scan_run,
        detection_stage="rule",
        status="open",
    ).select_related("request").order_by("-priority_score")[:max_candidates]

    if not candidates:
        logger.info(f"[{scan_run.run_id}] 분석할 candidate 없음")
        return

    # candidate → dict 변환
    cand_data_list = []
    cand_objects = []
    for cand in candidates:
        cand_data_list.append({
            "endpoint": cand.request.endpoint if cand.request else "/",
            "method": cand.request.method if cand.request else "GET",
            "params": cand.request.params if cand.request else {},
            "vuln_type": cand.vuln_type,
            "hypothesis": cand.hypothesis,
            "features": cand.features,
        })
        cand_objects.append(cand)

    # Claude 분석
    results = batch_analyze_candidates(cand_data_list, max_count=max_candidates)

    # 결과 반영
    total_tokens = 0
    for result, cand in zip(results, cand_objects):
        risk = result.get("risk_level", "unknown")
        action = result.get("next_action", "escalate")
        llm_confidence = result.get("confidence", 0.0)

        # detection_stage 업데이트
        cand.detection_stage = "llm_screen"

        # LLM 분석 결과를 features에 추가
        cand.features["llm_analysis"] = {
            "risk_level": risk,
            "confidence": llm_confidence,
            "analysis": result.get("analysis", ""),
            "suggested_payloads": result.get("suggested_payloads", []),
            "next_action": action,
            "reasoning": result.get("reasoning", ""),
        }

        # priority_score 재계산 (규칙 점수 + LLM 점수 가중 평균)
        rule_score = cand.priority_score
        cand.priority_score = (rule_score * 0.4) + (llm_confidence * 0.6)

        # dismiss 판정이면 상태 변경
        if action == "dismiss" or risk == "none":
            cand.status = "false_positive"

        cand.save(update_fields=["detection_stage", "features", "priority_score", "status"])

        usage = result.get("_usage", {})
        total_tokens += usage.get("input_tokens", 0) + usage.get("output_tokens", 0)

    # LLM 비용 기록
    from decimal import Decimal
    scan_run.llm_calls_count += len(results)
    scan_run.llm_tokens_used += total_tokens
    # 대략적 비용 계산 (Sonnet 기준: input $3/MTok, output $15/MTok)
    scan_run.llm_cost_usd += Decimal(str(round(total_tokens * 0.005 / 1000, 4)))
    scan_run.save(update_fields=["llm_calls_count", "llm_tokens_used", "llm_cost_usd"])

    logger.info(f"[{scan_run.run_id}] LLM 스크리닝 완료: "
                f"{len(results)}개 분석, {total_tokens} tokens")


def run_verify(scan_run: ScanRun, max_candidates=10):
    """
    검증 루프: LLM 스크리닝 통과한 candidate에 실제 페이로드를 보내서 검증한다.
    """
    from .verifier import run_verification_for_scan

    logger.info(f"[{scan_run.run_id}] 검증 루프 시작")
    results = run_verification_for_scan(
        scan_run=scan_run,
        max_candidates=max_candidates,
        min_confidence=0.15,
    )
    verified = sum(1 for r in results if r["verified"])
    logger.info(f"[{scan_run.run_id}] 검증 완료: {verified}/{len(results)} 확정")

    # request_budget_used 업데이트 (대략적으로)
    scan_run.request_budget_used += len(results) * 5  # candidate당 평균 5 요청
    scan_run.save(update_fields=["request_budget_used"])

    return results
