"""
스캔 서비스
크롤링 실행 → request_catalog 저장 → 규칙 기반 필터링 → candidates 저장
"""

import logging
import re
from django.utils import timezone

from .error_utils import summarize_exception
from .llm_trace_store import record_llm_trace
from .models import ScanRun, RequestCatalog, Candidate
from .scan_control import (
    ScanStopped,
    is_stop_requested,
    mark_scan_stopped,
    raise_if_stop_requested,
    register_scan,
    unregister_scan,
)
from .crawler import Crawler

logger = logging.getLogger(__name__)

# 규칙 기반 필터링 (1단계: 비용 제로)

# 파라미터 이름 기반 의심 패턴
SUSPICIOUS_PARAM_PATTERNS = [
    # SQLi 의심
    (r"(?i)(id|uid|user_id|pid|no|idx|seq|num|page|limit|offset|sort|order|column)", "sqli"),
    # XSS 의심
    (r"(?i)(q|query|search|keyword|name|title|msg|message|comment|text|content|input|value|data|redirect|url|next|return|callback)", "xss"),
    # IDOR 의심
    (r"(?i)(id|uid|user_id|account|profile|doc|file|order|invoice)", "idor"),
    # SSRF 의심
    (r"(?i)(url|uri|link|src|source|target|dest|redirect|proxy|fetch|load|request|path|file)", "ssrf"),
    # 파일 업로드 의심
    (r"(?i)(file|upload|attach|image|photo|document|import)", "file_upload"),
]

# 엔드포인트 경로 기반 의심 패턴
SUSPICIOUS_PATH_PATTERNS = [
    (r"(?i)/admin", "idor"),
    (r"(?i)/api/", "sqli"),
    (r"(?i)/login", "sqli"),
    (r"(?i)/search", "xss"),
    (r"(?i)/upload", "file_upload"),
    (r"(?i)/profile", "idor"),
    (r"(?i)/user", "idor"),
    (r"(?i)/redirect", "ssrf"),
    (r"(?i)/callback", "ssrf"),
    (r"(?i)/download", "ssrf"),
    (r"(?i)/export", "ssrf"),
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
    # 파라미터 히트가 더 가중치 높음
    score = (len(param_hits) * 0.15) + (len(path_hits) * 0.1)
    return min(score, 1.0)

# 스캔 서비스

def run_crawl(scan_run: ScanRun):
    """크롤링 실행 → request_catalog에 저장 (SPA 자동 감지)"""
    raise_if_stop_requested(scan_run)
    logger.info(f"[{scan_run.run_id}] 크롤링 시작: {scan_run.target_url}")

    # config에서 force_spa 옵션 확인
    config = scan_run.config or {}
    force_spa = config.get("force_spa", False)

    # SPA 감지
    from .spa_crawler import detect_spa, SPACrawler

    is_spa = force_spa or detect_spa(scan_run.target_url)

    if is_spa:
        logger.info(f"[{scan_run.run_id}] SPA {'(강제)' if force_spa else '(자동 감지)'} → Playwright 크롤러 사용")
        crawler = SPACrawler(
            target_url=scan_run.target_url,
            max_depth=3,
            max_pages=100,
            timeout=30,
            headless=True,
            click_explore=True,
        )
    else:
        logger.info(f"[{scan_run.run_id}] Traditional 사이트 → BFS 크롤러 사용")
        crawler = Crawler(
            target_url=scan_run.target_url,
            max_depth=3,
            max_pages=100,
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
            status_code=ep["status_code"],
            content_type=ep["content_type"],
            headers=ep["headers"],
            body_hash=ep["body_hash"],
            auth_required=ep["auth_required"],
            source=ep["source"],
            discovered_from=ep["discovered_from"],
        )
        catalog_items.append(item)

    RequestCatalog.objects.bulk_create(catalog_items)
    from .realtime import broadcast_scan_update
    broadcast_scan_update(scan_run.run_id)
    logger.info(f"[{scan_run.run_id}] {len(catalog_items)}개 엔드포인트 저장 완료")

    return catalog_items

def run_rule_filter(scan_run: ScanRun):
    """규칙 기반 필터링 → candidates에 저장"""
    raise_if_stop_requested(scan_run)
    logger.info(f"[{scan_run.run_id}] 규칙 기반 필터링 시작")

    catalog_items = RequestCatalog.objects.filter(scan_run=scan_run)
    candidates = []

    for item in catalog_items:
        raise_if_stop_requested(scan_run)
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
    from .realtime import broadcast_scan_update
    broadcast_scan_update(scan_run.run_id)
    logger.info(f"[{scan_run.run_id}] {len(candidates)}개 candidate 생성 완료")

    return candidates

def run_scan(scan_run: ScanRun):
    """전체 스캔 파이프라인 (크롤링 → 필터링 → LLM 분석)"""
    # MCP 모드 분기
    config = scan_run.config or {}
    if config.get("mode") == "mcp":
        from .mcp_agent import run_mcp_scan
        return run_mcp_scan(scan_run)

    register_scan(scan_run.run_id)
    try:
        if is_stop_requested(scan_run.run_id):
            mark_scan_stopped(scan_run)
            return

        scan_run.status = "running"
        scan_run.finished_at = None
        scan_run.error_log = None
        scan_run.save(update_fields=["status", "finished_at", "error_log"])

        # 1. 크롤링
        run_crawl(scan_run)
        raise_if_stop_requested(scan_run)

        # 2. 규칙 기반 필터링
        run_rule_filter(scan_run)
        raise_if_stop_requested(scan_run)

        # 3. LLM 분석 (2단계: llm_screen)
        run_llm_screen(scan_run)
        raise_if_stop_requested(scan_run)

        # 4. 검증 루프 (3단계: 실제 페이로드 전송)
        run_verify(scan_run)
        raise_if_stop_requested(scan_run)

        # 5. 완료
        if is_stop_requested(scan_run.run_id):
            mark_scan_stopped(scan_run)
            logger.info(f"[{scan_run.run_id}] 스캔 중지")
        else:
            scan_run.status = "finished"
            scan_run.finished_at = timezone.now()
            scan_run.save(update_fields=["status", "finished_at"])
            logger.info(f"[{scan_run.run_id}] 스캔 완료")

    except ScanStopped as e:
        mark_scan_stopped(scan_run, str(e))
        logger.info(f"[{scan_run.run_id}] 스캔 중지: {e}")
    except Exception as e:
        if is_stop_requested(scan_run.run_id):
            mark_scan_stopped(scan_run)
            logger.info(f"[{scan_run.run_id}] 스캔 중지 중 예외 발생: {e}")
        else:
            scan_run.status = "failed"
            scan_run.error_log = summarize_exception(e)
            scan_run.save(update_fields=["status", "error_log"])
            logger.error(f"[{scan_run.run_id}] 스캔 실패: {e}")
            raise
    finally:
        unregister_scan(scan_run.run_id)

def run_llm_screen(scan_run: ScanRun, max_candidates=9999):
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
    raise_if_stop_requested(scan_run)

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
    call_base = scan_run.llm_calls_count
    results = batch_analyze_candidates(cand_data_list, max_count=max_candidates)

    # 결과 반영
    total_tokens = 0
    for offset, (result, cand, cand_data) in enumerate(zip(results, cand_objects, cand_data_list), start=1):
        raise_if_stop_requested(scan_run)
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

        record_llm_trace(
            scan_run=scan_run,
            call_index=call_base + offset,
            stage="llm_screen",
            model="claude-sonnet-4-20250514",
            prompt_preview=result.get("_trace_prompt", ""),
            response_preview=result.get("_trace_response_preview", ""),
            stop_reason="end_turn",
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            metadata={
                "endpoint": cand_data.get("endpoint"),
                "method": cand_data.get("method"),
                "vuln_type": cand_data.get("vuln_type"),
                "candidate_id": str(cand.cand_id),
                "candidate_action": action,
                "candidate_risk": risk,
            },
            error="LLM analysis failed" if risk == "unknown" and result.get("analysis") == "LLM analysis failed" else "",
        )

    # LLM 비용 기록
    from decimal import Decimal
    scan_run.llm_calls_count += len(results)
    scan_run.llm_tokens_used += total_tokens
    # 대략적 비용 계산 (Sonnet 기준: input $3/MTok, output $15/MTok)
    scan_run.llm_cost_usd += Decimal(str(round(total_tokens * 0.005 / 1000, 4)))
    scan_run.save(update_fields=["llm_calls_count", "llm_tokens_used", "llm_cost_usd"])

    logger.info(f"[{scan_run.run_id}] LLM 스크리닝 완료: "
                f"{len(results)}개 분석, {total_tokens} tokens")

def run_verify(scan_run: ScanRun, max_candidates=9999):
    """
    검증 루프: LLM 스크리닝 통과한 candidate에 실제 페이로드를 보내서 검증한다.
    """
    from .verifier import run_verification_for_scan

    logger.info(f"[{scan_run.run_id}] 검증 루프 시작")
    raise_if_stop_requested(scan_run)
    results = run_verification_for_scan(
        scan_run=scan_run,
        max_candidates=max_candidates,
        min_confidence=0.3,
    )
    verified = sum(1 for r in results if r["verified"])
    logger.info(f"[{scan_run.run_id}] 검증 완료: {verified}/{len(results)} 확정")

    # request_budget_used 업데이트 (대략적으로)
    scan_run.request_budget_used += len(results) * 5  # candidate당 평균 5 요청
    scan_run.save(update_fields=["request_budget_used"])

    return results
