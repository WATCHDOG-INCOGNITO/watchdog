"""
스캔 서비스
크롤링 실행 → request_catalog 저장 → 규칙 기반 필터링 → candidates 저장
"""

import logging
import re
from django.utils import timezone

from .models import ScanRun, RequestCatalog, Candidate
from .crawler import Crawler

logger = logging.getLogger(__name__)


# ==========================================================
# 규칙 기반 필터링 (1단계: 비용 제로)
# ==========================================================

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
    (r"(?i)(file|upload|attach|image|photo|document|import)", "upload"),
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


# ==========================================================
# 스캔 서비스
# ==========================================================

def run_crawl(scan_run: ScanRun):
    """크롤링 실행 → request_catalog에 저장"""
    logger.info(f"[{scan_run.run_id}] 크롤링 시작: {scan_run.target_url}")

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
    logger.info(f"[{scan_run.run_id}] {len(catalog_items)}개 엔드포인트 저장 완료")

    return catalog_items


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
    """전체 스캔 파이프라인 (크롤링 → 필터링)"""
    try:
        scan_run.status = "running"
        scan_run.save(update_fields=["status"])

        # 1. 크롤링
        run_crawl(scan_run)

        # 2. 규칙 기반 필터링
        run_rule_filter(scan_run)

        # 3. 완료
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
