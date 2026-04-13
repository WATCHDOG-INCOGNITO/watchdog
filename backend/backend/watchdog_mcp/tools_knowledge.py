"""Knowledge DB 조회/업데이트 MCP 도구.

에이전트가 공격 전 `search_knowledge`로 취약점 정의와 검증된 페이로드 패턴을 조회하고,
공격 후 `record_pattern_use`로 해당 패턴의 성공/실패 통계를 업데이트한다.
"""
from __future__ import annotations

import json
import logging

from asgiref.sync import sync_to_async

logger = logging.getLogger("watchdog.kb")


def _search(vuln_type: str | None, keyword: str | None, limit: int) -> dict:
    from django.db.models import Q

    from api.models import PayloadPattern, VulnerabilityEntry

    vulns = VulnerabilityEntry.objects.all()
    patterns = PayloadPattern.objects.filter(is_active=True)

    if vuln_type:
        vt = vuln_type.strip().lower()
        vulns = vulns.filter(vuln_type=vt)
        patterns = patterns.filter(vuln_type=vt)

    if keyword:
        kw = keyword.strip()
        vulns = vulns.filter(
            Q(title__icontains=kw)
            | Q(description__icontains=kw)
            | Q(vuln_type__icontains=kw)
            | Q(cwe_id__icontains=kw)
        )
        patterns = patterns.filter(
            Q(name__icontains=kw)
            | Q(vuln_type__icontains=kw)
            | Q(request_template__icontains=kw)
            # technique 의 attack_metadata JSON 본문(applies_when, steps, examples 등) 까지 검색.
            # JSONField __icontains는 Postgres serialized JSON text에 대한 LIKE.
            | Q(attack_metadata__icontains=kw)
            | Q(safety_notes__icontains=kw)
            | Q(tags__icontains=kw)
        )

    patterns = patterns.order_by("-is_gold", "-times_succeeded", "-times_used")[:limit]

    def _vuln_dict(v: VulnerabilityEntry) -> dict:
        return {
            "vuln_id": str(v.vuln_id),
            "vuln_type": v.vuln_type,
            "title": v.title,
            "cwe_id": v.cwe_id,
            "owasp_category": v.owasp_category,
            "severity_default": v.severity_default,
            "description": v.description,
            "preconditions": v.preconditions,
            "impact": v.impact,
            "false_positive_hints": v.false_positive_hints,
            "evidence_points": v.evidence_points,
            "tags": v.tags,
        }

    def _pattern_dict(p: PayloadPattern) -> dict:
        return {
            "pattern_id": str(p.pattern_id),
            "vuln_type": p.vuln_type,
            "name": p.name,
            "category": p.category,
            "safety_level": p.safety_level,
            "request_template": p.request_template,
            "matcher": p.matcher,
            "safety_notes": p.safety_notes,
            "request_cost": p.request_cost,
            "times_used": p.times_used,
            "times_succeeded": p.times_succeeded,
            "false_positive_count": p.false_positive_count,
            "success_rate": round(p.success_rate, 3),
            "is_gold": p.is_gold,
            "tags": p.tags,
        }

    vuln_list = [_vuln_dict(v) for v in vulns[:limit]]
    pat_list = [_pattern_dict(p) for p in patterns]
    logger.info(
        "search_knowledge called: vuln_type=%r keyword=%r → %d vulns, %d patterns",
        vuln_type, keyword, len(vuln_list), len(pat_list),
    )
    return {
        "query": {"vuln_type": vuln_type, "keyword": keyword, "limit": limit},
        "vulnerabilities": vuln_list,
        "patterns": pat_list,
        "pattern_count": len(pat_list),
    }


def _retrieve_similar(query: str, k: int, vuln_type: str | None) -> dict:
    from api.embedding_service import embed_query, is_available

    from api.models import PayloadPattern

    logger.info(
        "retrieve_similar_patterns called: query=%r k=%d vuln_type=%r",
        query, k, vuln_type,
    )

    if not is_available():
        logger.warning("retrieve_similar_patterns: embedding model not available")
        return {
            "available": False,
            "reason": "embedding model not available (sentence-transformers not installed or load failed)",
            "patterns": [],
        }

    vec = embed_query(query)
    if vec is None:
        return {
            "available": False,
            "reason": "embed_query returned None (api error)",
            "patterns": [],
        }

    qs = PayloadPattern.objects.filter(is_active=True).exclude(embedding=None)
    if vuln_type:
        qs = qs.filter(vuln_type=vuln_type.strip().lower())

    try:
        from pgvector.django import CosineDistance

        qs = qs.annotate(distance=CosineDistance("embedding", vec)).order_by("distance")[:k]
        results = []
        for p in qs:
            results.append({
                "pattern_id": str(p.pattern_id),
                "vuln_type": p.vuln_type,
                "name": p.name,
                "category": p.category,
                "safety_level": p.safety_level,
                "request_template": p.request_template,
                "matcher": p.matcher,
                "safety_notes": p.safety_notes,
                "success_rate": round(p.success_rate, 3),
                "is_gold": p.is_gold,
                "tags": p.tags,
                "distance": round(float(p.distance), 4),
                "similarity": round(1.0 - float(p.distance), 4),
            })
        logger.info(
            "retrieve_similar_patterns result: query=%r → %d patterns (top sim=%.4f)",
            query, len(results), results[0]["similarity"] if results else 0.0,
        )
        return {
            "available": True,
            "query": query,
            "vuln_type": vuln_type,
            "k": k,
            "patterns": results,
        }
    except ImportError:
        return {
            "available": False,
            "reason": "pgvector package not installed",
            "patterns": [],
        }
    except Exception as e:
        return {
            "available": False,
            "reason": f"vector search failed: {e}",
            "patterns": [],
        }


def _mutate_payload(seed_pattern_id: str, mutation_type: str, hint: str) -> dict:
    """기존 PayloadPattern 을 베이스로 새 변종을 만들어 KB에 저장한다.

    이 도구는 변종을 _저장만_ 한다. 실제 페이로드 문자열 생성은 LLM(에이전트) 측이
    한다 — hint 인자로 새 template 을 직접 넣거나, mutation_type 으로 기본 변환 적용.

    mutation_type 권장값:
      - encoding_url: URL 인코딩 추가 (% 변환)
      - case_swap: 대소문자 임의 변경 (SQL 키워드 등)
      - polyglot: 여러 컨텍스트에서 동시 동작하는 페이로드
      - waf_bypass_comment: SQL 주석/공백 변형
      - double_encoding: 이중 인코딩
      - custom: hint 의 template 을 그대로 사용
    """
    from api.models import PayloadPattern

    try:
        seed = PayloadPattern.objects.get(pattern_id=seed_pattern_id)
    except PayloadPattern.DoesNotExist:
        return {"error": f"seed pattern {seed_pattern_id} not found"}

    base_template = seed.request_template or ""
    new_template = base_template
    mt = (mutation_type or "custom").lower()

    if mt == "custom" and hint:
        new_template = hint
    elif mt == "encoding_url":
        from urllib.parse import quote
        new_template = quote(base_template, safe="={}&?")
    elif mt == "case_swap":
        new_template = "".join(
            c.upper() if i % 2 else c.lower() for i, c in enumerate(base_template)
        )
    elif mt == "double_encoding":
        from urllib.parse import quote
        new_template = quote(quote(base_template, safe=""), safe="")
    elif mt == "waf_bypass_comment":
        # SQL: 공백 → /**/, SELECT → SE/**/LECT 등
        new_template = (
            base_template
            .replace(" ", "/**/")
            .replace("SELECT", "SE/**/LECT")
            .replace("UNION", "UN/**/ION")
        )
    elif mt == "polyglot" and hint:
        new_template = hint  # polyglot 은 LLM이 직접 작성
    else:
        new_template = hint or base_template

    # 새 패턴 저장 (source=mutation, parent=seed)
    new_p = PayloadPattern.objects.create(
        vulnerability=seed.vulnerability,
        name=f"{seed.name} [{mt}]",
        vuln_type=seed.vuln_type,
        category=seed.category,
        request_template=new_template,
        matcher=seed.matcher,
        safety_level=seed.safety_level,
        safety_notes=seed.safety_notes,
        request_cost=seed.request_cost,
        mutation_type=mt,
        parent_pattern=seed,
        source="mutation",
        tags=(seed.tags or []) + ["mutation", mt],
    )
    return {
        "pattern_id": str(new_p.pattern_id),
        "vuln_type": new_p.vuln_type,
        "name": new_p.name,
        "request_template": new_template,
        "parent_pattern_id": str(seed.pattern_id),
        "mutation_type": mt,
    }


def _retrieve_cve_variants(framework: str, endpoint_pattern: str, k: int) -> dict:
    """과거 CVE의 취약 패턴을 시드로 반환 (Naptime variant analysis 패턴).

    현재는 skeleton — Knowledge DB의 vulnerability_entries 에서 framework/endpoint 키워드로
    매칭되는 항목을 반환. 후속 작업에서 실제 CVE feed 와 코드 스니펫을 큐레이션 예정.
    """
    from django.db.models import Q

    from api.models import VulnerabilityEntry

    qs = VulnerabilityEntry.objects.all()
    if framework:
        qs = qs.filter(
            Q(description__icontains=framework)
            | Q(tags__icontains=framework)
            | Q(affected_components__icontains=framework)
        )
    if endpoint_pattern:
        qs = qs.filter(
            Q(description__icontains=endpoint_pattern)
            | Q(evidence_points__icontains=endpoint_pattern)
        )

    items = []
    for v in qs[:k]:
        items.append({
            "vuln_id": str(v.vuln_id),
            "title": v.title,
            "vuln_type": v.vuln_type,
            "cwe_id": v.cwe_id,
            "preconditions": v.preconditions,
            "evidence_points": v.evidence_points,
            "false_positive_hints": v.false_positive_hints,
            "tags": v.tags,
        })
    return {
        "query": {"framework": framework, "endpoint_pattern": endpoint_pattern, "k": k},
        "variants": items,
        "note": (
            "skeleton 구현. 실제 CVE 코드 스니펫/트리거 request 시드는 후속 작업에서 추가 예정."
        ),
    }


def _record_use(pattern_id: str, succeeded: bool, false_positive: bool) -> dict:
    from api.models import PayloadPattern

    try:
        p = PayloadPattern.objects.get(pattern_id=pattern_id)
    except PayloadPattern.DoesNotExist:
        return {"error": f"pattern {pattern_id} not found"}

    p.times_used += 1
    if succeeded:
        p.times_succeeded += 1
    if false_positive:
        p.false_positive_count += 1
    p.save(update_fields=["times_used", "times_succeeded", "false_positive_count"])
    return {
        "pattern_id": str(p.pattern_id),
        "times_used": p.times_used,
        "times_succeeded": p.times_succeeded,
        "false_positive_count": p.false_positive_count,
        "success_rate": round(p.success_rate, 3),
    }


def register(mcp):

    @mcp.tool()
    async def search_knowledge(
        vuln_type: str = "",
        keyword: str = "",
        limit: int = 10,
    ) -> str:
        """Knowledge DB에서 취약점 정의와 검증된 페이로드 패턴을 조회한다.

        공격 페이로드를 만들기 전에 반드시 호출해서 기존 성공 패턴을 우선 사용하라.

        Args:
            vuln_type: 예 "sqli", "xss", "idor", "ssrf", "lfi", "open_redirect", "cmdi"
            keyword: title/description/template에서 부분 일치 검색
            limit: 반환 항목 수 (기본 10)

        Returns:
            {vulnerabilities: [...], patterns: [...]} JSON.
            각 pattern은 request_template / matcher / safety_level / success_rate 포함.
        """
        try:
            result = await sync_to_async(_search, thread_sensitive=False)(
                vuln_type=(vuln_type or None),
                keyword=(keyword or None),
                limit=int(limit) if limit else 10,
            )
            return json.dumps(result, ensure_ascii=False, default=str)
        except Exception as e:
            return json.dumps({"error": f"search_knowledge failed: {e}"})

    @mcp.tool()
    async def retrieve_similar_patterns(
        query: str,
        k: int = 5,
        vuln_type: str = "",
    ) -> str:
        """자연어 query 와 의미적으로 가까운 PayloadPattern 을 코사인 유사도로 검색한다.

        Knowledge DB의 RAG 단계. 엔드포인트 설명/파라미터/응답 발췌 등 자유 텍스트로 호출.
        임베딩이 비활성이면 `available: False` 와 reason을 반환한다.

        Args:
            query: 자연어 검색 쿼리. 예 "URL 파라미터로 외부 호스트 fetch하는 엔드포인트"
            k: 반환할 최대 패턴 수 (기본 5)
            vuln_type: 특정 vuln_type으로 사전 필터 (선택)
        """
        try:
            result = await sync_to_async(_retrieve_similar, thread_sensitive=False)(
                query=query,
                k=int(k) if k else 5,
                vuln_type=(vuln_type or None),
            )
            return json.dumps(result, ensure_ascii=False, default=str)
        except Exception as e:
            return json.dumps({"error": f"retrieve_similar_patterns failed: {e}"})

    @mcp.tool()
    async def mutate_payload(
        seed_pattern_id: str,
        mutation_type: str = "custom",
        hint: str = "",
    ) -> str:
        """기존 KB 패턴을 베이스로 새 변종을 만들어 KB에 저장한다 (zero-day 탐색용).

        실제 새 페이로드 문자열은 LLM(당신)이 만들어 hint로 넘겨주거나, mutation_type의
        기본 변환 규칙을 사용. 새 패턴은 source='mutation', parent_pattern=seed로 저장되어
        이후 retrieve_similar_patterns / search_knowledge에서 함께 검색된다.

        Args:
            seed_pattern_id: 베이스가 될 PayloadPattern ID
            mutation_type: encoding_url | case_swap | polyglot | waf_bypass_comment
                | double_encoding | custom (custom이면 hint 가 새 template)
            hint: custom/polyglot에서 직접 작성한 새 페이로드 template
        """
        try:
            result = await sync_to_async(_mutate_payload, thread_sensitive=False)(
                seed_pattern_id=seed_pattern_id,
                mutation_type=mutation_type or "custom",
                hint=hint,
            )
            return json.dumps(result, ensure_ascii=False, default=str)
        except Exception as e:
            return json.dumps({"error": f"mutate_payload failed: {e}"})

    @mcp.tool()
    async def retrieve_cve_variants(
        framework: str = "",
        endpoint_pattern: str = "",
        k: int = 5,
    ) -> str:
        """과거 CVE 변종을 시드로 가져온다 (Naptime variant analysis 패턴).

        framework/endpoint_pattern 키워드로 매칭되는 vulnerability_entries 를 반환.
        Planner가 hypothesis 생성 시 새 가설의 영감으로 활용 가능.

        현재 skeleton — 실제 CVE 코드 스니펫/트리거 request 시드는 후속 작업에서 추가 예정.
        """
        try:
            result = await sync_to_async(_retrieve_cve_variants, thread_sensitive=False)(
                framework=framework,
                endpoint_pattern=endpoint_pattern,
                k=int(k) if k else 5,
            )
            return json.dumps(result, ensure_ascii=False, default=str)
        except Exception as e:
            return json.dumps({"error": f"retrieve_cve_variants failed: {e}"})

    @mcp.tool()
    async def record_pattern_use(
        pattern_id: str,
        succeeded: bool = False,
        false_positive: bool = False,
    ) -> str:
        """페이로드 패턴 사용 결과를 기록하여 knowledge DB의 success_rate를 갱신한다.

        페이로드를 타겟에 실제 전송한 뒤 1회씩 호출하라.
        - succeeded=True: 취약점이 확인됨
        - false_positive=True: 매처는 맞았지만 실제 취약은 아님
        둘 다 False면 단순 실패(무반응)로 기록된다.
        """
        try:
            result = await sync_to_async(_record_use, thread_sensitive=False)(
                pattern_id=pattern_id,
                succeeded=bool(succeeded),
                false_positive=bool(false_positive),
            )
            return json.dumps(result, ensure_ascii=False, default=str)
        except Exception as e:
            return json.dumps({"error": f"record_pattern_use failed: {e}"})
