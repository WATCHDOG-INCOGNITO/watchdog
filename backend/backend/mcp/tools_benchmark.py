import json
from django.db.models import Count, Sum, Avg, F, Q
from api.models import (
    ScanRun, Candidate, Finding, EvidenceBlob,
    FindingEvidenceLink, VerificationLoop,
)

def register(mcp):

    @mcp.tool()
    def benchmark_scan(run_id: str) -> str:
        """스캔의 전체 벤치마크를 출력한다.
        확정 취약점 수, 유형별 분포, 총 토큰/비용, finding당 평균 비용,
        오탐률, 검증 성공률, 소요 시간 등.
        """
        scan = ScanRun.objects.get(run_id=run_id)
        candidates = Candidate.objects.filter(scan_run_id=run_id)
        findings = Finding.objects.filter(scan_run_id=run_id)
        loops = VerificationLoop.objects.filter(candidate__scan_run_id=run_id)

        total_candidates = candidates.count()
        confirmed = candidates.filter(status="confirmed").count()
        false_positive = candidates.filter(status="false_positive").count()
        dismissed = candidates.filter(status="dismissed").count()
        open_count = candidates.filter(status="open").count()

        total_findings = findings.count()
        total_evidence = EvidenceBlob.objects.filter(finding__scan_run_id=run_id).count()
        total_attempts = loops.count()

        # severity 분포
        severity_dist = {}
        for row in findings.values("severity").annotate(c=Count("finding_id")):
            severity_dist[row["severity"]] = row["c"]

        # vuln_type 분포
        vuln_type_dist = {}
        for row in findings.values("vuln_type").annotate(c=Count("finding_id")):
            vuln_type_dist[row["vuln_type"] or "unknown"] = row["c"]

        # 소요 시간
        duration = None
        if scan.finished_at and scan.created_at:
            duration = (scan.finished_at - scan.created_at).total_seconds()

        # finding당 평균 토큰
        tokens_per_finding = round(scan.llm_tokens_used / total_findings, 1) if total_findings > 0 else 0
        cost_per_finding = round(float(scan.llm_cost_usd) / total_findings, 4) if total_findings > 0 else 0

        # 검증 성공률
        verified_candidates = candidates.filter(status="confirmed").count()
        attempted_candidates = candidates.exclude(status="open").count()
        verification_rate = round(verified_candidates / attempted_candidates * 100, 1) if attempted_candidates > 0 else 0

        # 오탐률
        fp_rate = round(false_positive / (confirmed + false_positive) * 100, 1) if (confirmed + false_positive) > 0 else 0

        return json.dumps({
            "run_id": str(scan.run_id),
            "target_url": scan.target_url,
            "status": scan.status,
            "duration_seconds": duration,

            "candidates": {
                "total": total_candidates,
                "confirmed": confirmed,
                "false_positive": false_positive,
                "dismissed": dismissed,
                "open": open_count,
            },

            "findings": {
                "total": total_findings,
                "by_severity": severity_dist,
                "by_vuln_type": vuln_type_dist,
                "total_evidence": total_evidence,
            },

            "verification": {
                "total_attempts": total_attempts,
                "verification_rate_pct": verification_rate,
                "false_positive_rate_pct": fp_rate,
            },

            "llm_usage": {
                "total_calls": scan.llm_calls_count,
                "total_tokens": scan.llm_tokens_used,
                "total_cost_usd": float(scan.llm_cost_usd),
                "tokens_per_finding": tokens_per_finding,
                "cost_per_finding_usd": cost_per_finding,
            },

            "requests": {
                "budget_total": scan.request_budget_total,
                "budget_used": scan.request_budget_used,
            },
        })

    @mcp.tool()
    def benchmark_finding_detail(run_id: str) -> str:
        """각 확정 취약점(finding)별 상세 벤치마크.
        finding별 사용된 검증 시도 수, 증거 수, 관련 candidate의 LLM 분석 정보.
        """
        findings = Finding.objects.filter(scan_run_id=run_id).select_related("candidate")
        results = []

        for f in findings:
            cand = f.candidate
            loops = VerificationLoop.objects.filter(candidate=cand) if cand else VerificationLoop.objects.none()
            evidence_count = FindingEvidenceLink.objects.filter(finding=f).count()

            # 검증 시도 이력
            attempt_summary = []
            for loop in loops.order_by("attempt_number"):
                ar = loop.analysis_result or {}
                attempt_summary.append({
                    "attempt": loop.attempt_number,
                    "payload": (loop.payload_sent or "")[:100],
                    "response_status": loop.response_status,
                    "next_action": loop.next_action,
                    "llm_confidence": ar.get("llm_confidence", 0),
                })

            results.append({
                "finding_id": str(f.finding_id),
                "title": f.title,
                "vuln_type": f.vuln_type,
                "severity": f.severity,
                "confidence": f.confidence,
                "evidence_count": evidence_count,
                "verification_attempts": loops.count(),
                "attempts_detail": attempt_summary,
                "candidate_id": str(cand.cand_id) if cand else None,
                "candidate_priority_score": cand.priority_score if cand else None,
                "candidate_detection_stage": cand.detection_stage if cand else None,
            })

        return json.dumps({"run_id": run_id, "findings": results})

    @mcp.tool()
    def benchmark_compare(run_ids: str) -> str:
        """여러 스캔 결과를 비교한다.
        run_ids: 콤마로 구분된 run_id 목록 (예: "uuid1,uuid2,uuid3")
        같은 타겟에 다른 설정으로 돌린 결과 비교에 사용.
        """
        ids = [r.strip() for r in run_ids.split(",") if r.strip()]
        comparisons = []

        for rid in ids:
            try:
                scan = ScanRun.objects.get(run_id=rid)
            except ScanRun.DoesNotExist:
                comparisons.append({"run_id": rid, "error": "not found"})
                continue

            findings = Finding.objects.filter(scan_run_id=rid)
            candidates = Candidate.objects.filter(scan_run_id=rid)

            duration = None
            if scan.finished_at and scan.created_at:
                duration = (scan.finished_at - scan.created_at).total_seconds()

            total_findings = findings.count()

            severity_dist = {}
            for row in findings.values("severity").annotate(c=Count("finding_id")):
                severity_dist[row["severity"]] = row["c"]

            comparisons.append({
                "run_id": str(scan.run_id),
                "target_url": scan.target_url,
                "mode": scan.mode,
                "status": scan.status,
                "duration_seconds": duration,
                "candidates_total": candidates.count(),
                "candidates_confirmed": candidates.filter(status="confirmed").count(),
                "candidates_fp": candidates.filter(status="false_positive").count(),
                "findings_total": total_findings,
                "findings_by_severity": severity_dist,
                "llm_tokens": scan.llm_tokens_used,
                "llm_cost_usd": float(scan.llm_cost_usd),
                "tokens_per_finding": round(scan.llm_tokens_used / total_findings, 1) if total_findings > 0 else 0,
                "cost_per_finding_usd": round(float(scan.llm_cost_usd) / total_findings, 4) if total_findings > 0 else 0,
            })

        return json.dumps({"scans": comparisons})

    @mcp.tool()
    def benchmark_token_breakdown(run_id: str) -> str:
        """스캔의 LLM 토큰 사용 내역을 단계별로 분석한다.
        크롤링/필터링은 토큰 0, LLM 스크리닝/검증 루프에서 토큰 사용.
        """
        scan = ScanRun.objects.get(run_id=run_id)
        candidates = Candidate.objects.filter(scan_run_id=run_id)

        # LLM 스크리닝 단계 토큰 추정 (candidate features에서)
        screen_tokens = 0
        screen_count = 0
        for c in candidates.filter(detection_stage="llm_screen"):
            llm_analysis = (c.features or {}).get("llm_analysis", {})
            if llm_analysis:
                screen_count += 1

        # 검증 루프 단계
        loops = VerificationLoop.objects.filter(candidate__scan_run_id=run_id)
        verify_count = loops.count()

        # 대략적 비율 추정 (정확한 per-call 토큰은 VerificationLoop.analysis_result에 있을 수 있음)
        total_tokens = scan.llm_tokens_used
        total_calls = scan.llm_calls_count

        return json.dumps({
            "run_id": str(scan.run_id),
            "total_tokens": total_tokens,
            "total_llm_calls": total_calls,
            "total_cost_usd": float(scan.llm_cost_usd),
            "breakdown": {
                "screening": {
                    "candidates_screened": screen_count,
                    "estimated_calls": screen_count,
                },
                "verification": {
                    "total_attempts": verify_count,
                    "estimated_calls": verify_count,
                },
            },
            "efficiency": {
                "findings_count": Finding.objects.filter(scan_run_id=run_id).count(),
                "tokens_per_finding": round(total_tokens / max(Finding.objects.filter(scan_run_id=run_id).count(), 1), 1),
                "cost_per_finding_usd": round(float(scan.llm_cost_usd) / max(Finding.objects.filter(scan_run_id=run_id).count(), 1), 4),
                "attempts_per_finding": round(verify_count / max(Finding.objects.filter(scan_run_id=run_id).count(), 1), 1),
            },
        })

