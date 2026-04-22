import json
from asgiref.sync import sync_to_async
from api.models import ScanRun, RequestCatalog, Candidate
from api.services import analyze_params, analyze_path, calculate_priority

def register(mcp):

    @mcp.tool()
    def analyze_endpoint(run_id: str, endpoint: str, method: str, params: str) -> str:
        """엔드포인트를 규칙 기반으로 분석하여 의심 취약점 유형과 점수를 반환한다.
        params는 JSON 문자열로 전달한다. 예: '{"id": "1", "name": "test"}'
        """
        try:
            params_dict = json.loads(params) if isinstance(params, str) else params
        except json.JSONDecodeError:
            params_dict = {}

        param_hits = analyze_params(params_dict)
        path_hits = analyze_path(endpoint)
        score = calculate_priority(param_hits, path_hits)

        vuln_types = list(set(h["vuln_type"] for h in param_hits + path_hits))

        return json.dumps({
            "endpoint": endpoint,
            "method": method,
            "vuln_types": vuln_types,
            "priority_score": round(score, 3),
            "param_hits": param_hits,
            "path_hits": path_hits,
        })

    @mcp.tool()
    async def run_rule_filter(run_id: str) -> str:
        """스캔의 모든 엔드포인트에 규칙 기반 필터링을 실행하고 candidate를 생성한다."""
        from api.services import run_rule_filter as _run_rule_filter

        def _query():
            scan_run = ScanRun.objects.get(run_id=run_id)
            candidates = _run_rule_filter(scan_run)
            return len(candidates)

        count = await sync_to_async(_query, thread_sensitive=False)()
        return json.dumps({
            "run_id": run_id,
            "candidates_created": count,
        })

    @mcp.tool()
    async def list_candidates(run_id: str, status: str = "", vuln_type: str = "") -> str:
        """스캔의 후보(candidate) 목록을 조회한다.
        status: open, verifying, confirmed, false_positive, dismissed
        vuln_type: sqli, xss, idor, ssrf, file_upload, cmdi, ssti, nosqli, rce, etc.
        """
        def _query():
            qs = Candidate.objects.filter(scan_run_id=run_id).select_related("request")
            if status:
                qs = qs.filter(status=status)
            if vuln_type:
                qs = qs.filter(vuln_type=vuln_type)

            results = []
            for c in qs.order_by("-priority_score")[:30]:
                results.append({
                    "cand_id": str(c.cand_id),
                    "vuln_type": c.vuln_type,
                    "status": c.status,
                    "priority_score": round(c.priority_score, 3),
                    "detection_stage": c.detection_stage,
                    "hypothesis": c.hypothesis,
                    "endpoint": c.request.endpoint if c.request else None,
                    "method": c.request.method if c.request else None,
                    "params": c.request.params if c.request else {},
                })
            return results

        results = await sync_to_async(_query, thread_sensitive=False)()
        return json.dumps({"count": len(results), "candidates": results})

    @mcp.tool()
    async def reopen_candidate(cand_id: str) -> str:
        """이전에 검증 실패했거나 dismiss된 candidate를 다시 open 상태로 되돌린다.
        다른 도구/전략으로 재검증할 때 사용.
        """
        def _reopen():
            try:
                cand = Candidate.objects.get(cand_id=cand_id)
            except Candidate.DoesNotExist:
                return {"error": "candidate not found"}

            if cand.status == "confirmed":
                return {"error": "confirmed candidate cannot be reopened"}

            old_status = cand.status
            cand.status = "open"
            cand.save(update_fields=["status"])
            return {"cand_id": str(cand.cand_id), "old_status": old_status, "new_status": "open"}

        result = await sync_to_async(_reopen, thread_sensitive=False)()
        return json.dumps(result)

    @mcp.tool()
    async def create_candidate_manual(run_id: str, endpoint: str, method: str,
                                 vuln_type: str, params: str = "{}",
                                 hypothesis: str = "") -> str:
        """수동으로 candidate를 생성한다.
        LLM이 브라우저/도구로 발견한 의심 지점을 등록할 때 사용.
        """
        try:
            params_dict = json.loads(params) if isinstance(params, str) else params
        except json.JSONDecodeError:
            params_dict = {}

        def _create():
            from api.models import DiscoveryNode
            scan_run = ScanRun.objects.get(run_id=run_id)
            hypothesis_text = (hypothesis or "").lower()
            blocked_only_evidence = any(
                marker in hypothesis_text
                for marker in (
                    "403", "401", "405", "csrf", "authentication", "auth layer",
                    "blocked", "cannot be tested", "login redirect", "routing",
                    "method not allowed", "requires authentication",
                )
            )
            existing = (
                Candidate.objects
                .filter(scan_run=scan_run, vuln_type=vuln_type, request__endpoint=endpoint)
                .exclude(status="confirmed")
                .order_by("-created_at")
                .first()
            )
            if existing:
                return str(existing.cand_id), None
            req = RequestCatalog.objects.create(
                scan_run=scan_run,
                endpoint=endpoint,
                method=method.upper(),
                params=params_dict,
                source="llm_manual",
            )
            param_hits = analyze_params(params_dict)
            path_hits = analyze_path(endpoint)
            score = calculate_priority(param_hits, path_hits)

            # 안전망 — 같은 scan에 endpoint(+vuln_type) 매칭되는 최근 vuln/endpoint 노드를
            # features.discovery_node_id 로 자동 link. 그래야 confirm_finding 시
            # 노드 status 가 자동 confirmed 로 전이 (storage_service line 80-84).
            node_id = None
            ep_norm = (endpoint or "").split("?", 1)[0].rstrip("/") or "/"
            cand_qs = (
                DiscoveryNode.objects
                .filter(scan_run=scan_run)
                .filter(node_type__in=["vuln", "endpoint"])
                .filter(endpoint__in=[endpoint, ep_norm, ep_norm + "/"])
            )
            # vuln_type 일치 우선 (없으면 endpoint 매칭만)
            preferred = cand_qs.filter(vuln_type=vuln_type).order_by("-created_at").first()
            picked = preferred or cand_qs.order_by("-created_at").first()
            if picked:
                node_id = str(picked.node_id)

            features = {"source": "llm_manual", "params": params_dict, "endpoint": endpoint}
            if node_id:
                features["discovery_node_id"] = node_id
            if blocked_only_evidence:
                features["blocked_only_evidence"] = True

            priority = max(score, 0.45)
            if blocked_only_evidence:
                priority = min(priority, 0.25)

            cand = Candidate.objects.create(
                scan_run=scan_run,
                request=req,
                vuln_type=vuln_type,
                hypothesis=hypothesis or f"LLM 수동 등록: {method} {endpoint} ({vuln_type})",
                priority_score=priority,
                detection_stage="llm_screen",
                status="open",
                features=features,
            )
            return str(cand.cand_id), node_id

        # thread_sensitive=True 가 async event loop 내 ORM 호출에서 안전.
        # 다른 도구들(record_pattern_use 등)이 우연히 통과하는 건 호출 빈도/타이밍 차이.
        try:
            cand_id, node_id = await sync_to_async(_create, thread_sensitive=True)()
        except Exception as e:
            return json.dumps({"error": f"create_candidate_manual failed: {e}"})
        return json.dumps({
            "cand_id": cand_id,
            "vuln_type": vuln_type,
            "endpoint": endpoint,
            "status": "open",
            "linked_node_id": node_id,
        })
