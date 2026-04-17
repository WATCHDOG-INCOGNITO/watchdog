"""Knowledge DB 조회/업데이트 MCP 도구.

에이전트가 공격 전 `search_knowledge`로 취약점 정의와 검증된 페이로드 패턴을 조회하고,
공격 후 `record_pattern_use`로 해당 패턴의 성공/실패 통계를 업데이트한다.
"""
from __future__ import annotations

import json
import logging

from asgiref.sync import sync_to_async

logger = logging.getLogger("watchdog.kb")


VULN_TYPE_ALIASES: dict[str, list[str]] = {
    "cmdi": ["command_injection"],
    "command_injection": ["cmdi"],

    "sqli": ["sql_injection"],
    "sql_injection": ["sqli"],

    "nosqli": ["nosql_injection"],
    "nosql_injection": ["nosqli"],

    "xss": ["cross_site_scripting"],
    "cross_site_scripting": ["xss"],

    "lfi": ["local_file_inclusion"],
    "local_file_inclusion": ["lfi"],

    "path_traversal": ["directory_traversal"],
    "directory_traversal": ["path_traversal"],

    "rfi": ["remote_file_inclusion"],
    "remote_file_inclusion": ["rfi"],

    "ssti": ["server_side_template_injection"],
    "server_side_template_injection": ["ssti"],
    "code_injection": ["rce", "ssti"],

    "http_smuggling": ["http_request_smuggling"],
    "http_request_smuggling": ["http_smuggling"],

    "jwt": ["jwt_attack"],
    "jwt_attack": ["jwt"],

    "upload": ["file_upload"],
    "file_upload": ["upload"],
}


def _search(vuln_type: str | None, keyword: str | None, limit: int) -> dict:
    from django.db.models import Q

    from api.models import PayloadPattern, VulnerabilityEntry

    vulns = VulnerabilityEntry.objects.all()
    patterns = PayloadPattern.objects.filter(is_active=True)

    if vuln_type:
        vt = vuln_type.strip().lower()
        vt_set = {vt} | set(VULN_TYPE_ALIASES.get(vt, []))
        vulns = vulns.filter(vuln_type__in=vt_set)
        patterns = patterns.filter(vuln_type__in=vt_set)

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
            | Q(attack_metadata__icontains=kw)
            | Q(safety_notes__icontains=kw)
            | Q(tags__icontains=kw)
        )

    from django.db.models import Case, When, Value, IntegerField
    patterns = patterns.annotate(
        has_metadata=Case(
            When(attack_metadata__isnull=False, then=Value(1)),
            default=Value(0),
            output_field=IntegerField(),
        )
    ).order_by("-has_metadata", "-is_gold", "-times_succeeded", "-times_used")[:limit]

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
        d = {
            "pattern_id": str(p.pattern_id),
            "vuln_type": p.vuln_type,
            "sub_technique": p.sub_technique,
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
        if p.attack_metadata:
            d["attack_metadata"] = p.attack_metadata
        return d

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
        vt = vuln_type.strip().lower()
        vt_set = {vt} | set(VULN_TYPE_ALIASES.get(vt, []))
        qs = qs.filter(vuln_type__in=vt_set)

    try:
        from pgvector.django import CosineDistance

        qs = qs.annotate(distance=CosineDistance("embedding", vec)).order_by("distance")[:k]
        results = []
        for p in qs:
            entry = {
                "pattern_id": str(p.pattern_id),
                "vuln_type": p.vuln_type,
                "sub_technique": p.sub_technique,
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
            }
            if p.attack_metadata:
                entry["attack_metadata"] = p.attack_metadata
            results.append(entry)
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
        sub_technique=seed.sub_technique,
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
    """CVE 시드 기반 variant analysis (Naptime 패턴).

    두 자원에서 동시에 검색:
      1. PayloadPattern(source="cve") — `techniques/cve/<cve_id>.md` 에서 적재된 CVE 시드.
         attack_metadata에 cve_id, frameworks, trigger_request, code_snippet 포함.
      2. VulnerabilityEntry — OWASP/CWE 카탈로그 (legacy fallback).

    LLM은 같은 framework / endpoint pattern 의 과거 CVE를 받아 variant 작성에 활용.
    """
    from django.db.models import Q

    from api.models import PayloadPattern, VulnerabilityEntry

    framework_norm = (framework or "").strip().lower()
    endpoint_norm = (endpoint_pattern or "").strip()

    # 1) CVE PayloadPattern (techniques/cve/*.md 에서 적재된 시드)
    cve_qs = PayloadPattern.objects.filter(source="cve", is_active=True)
    if framework_norm:
        cve_qs = cve_qs.filter(
            Q(name__icontains=framework_norm)
            | Q(tags__icontains=framework_norm)
            | Q(attack_metadata__icontains=framework_norm)
        )
    if endpoint_norm:
        cve_qs = cve_qs.filter(
            Q(request_template__icontains=endpoint_norm)
            | Q(attack_metadata__icontains=endpoint_norm)
        )

    cve_items = []
    for p in cve_qs[:k]:
        meta = p.attack_metadata or {}
        cve_items.append({
            "pattern_id": str(p.pattern_id),
            "cve_id": meta.get("cve_id"),
            "name": p.name,
            "vuln_type": p.vuln_type,
            "frameworks": meta.get("frameworks") or [],
            "applies_when": meta.get("applies_when", ""),
            "trigger_request": meta.get("trigger_request"),
            "code_snippet": (meta.get("code_snippet") or "")[:1500],
            "technique_steps_md": (meta.get("technique_steps_md") or "")[:1500],
            "references": meta.get("references") or [],
            "tags": p.tags,
        })

    # 2) VulnerabilityEntry (legacy 카탈로그)
    vuln_qs = VulnerabilityEntry.objects.all()
    if framework_norm:
        vuln_qs = vuln_qs.filter(
            Q(description__icontains=framework_norm)
            | Q(tags__icontains=framework_norm)
            | Q(affected_components__icontains=framework_norm)
        )
    if endpoint_norm:
        vuln_qs = vuln_qs.filter(
            Q(description__icontains=endpoint_norm)
            | Q(evidence_points__icontains=endpoint_norm)
        )
    vuln_items = []
    for v in vuln_qs[:k]:
        vuln_items.append({
            "vuln_id": str(v.vuln_id),
            "title": v.title,
            "vuln_type": v.vuln_type,
            "cwe_id": v.cwe_id,
            "preconditions": v.preconditions,
            "evidence_points": v.evidence_points,
            "false_positive_hints": v.false_positive_hints,
            "tags": v.tags,
        })

    note = (
        f"cve seeds: {len(cve_items)} (techniques/cve/*.md 에서 적재). "
        f"vulnerability catalog: {len(vuln_items)}."
    )
    if not cve_items:
        note += (
            " CVE 시드를 추가하려면 backend/backend/api/management/commands/techniques/cve/<cve_id>.md "
            "양식 (frontmatter: source=cve, attack_metadata.cve_id/frameworks/trigger_request/"
            "code_snippet) 으로 작성 후 seed_techniques --reset 실행."
        )
    return {
        "query": {"framework": framework, "endpoint_pattern": endpoint_pattern, "k": k},
        "cve_seeds": cve_items,
        "variants": vuln_items,  # backward-compat: 기존 호출자가 'variants' 참조
        "note": note,
    }


def _check_payload_dedup(
    payload: str,
    target_host: str,
    vuln_type: str,
    threshold: int,
    limit: int,
) -> dict:
    """SimHash 기반 — 이 payload가 본질적으로 같은 시도가 이미 있는지 조회.

    XBOW SimHash 패턴: 같은 본질의 페이로드를 변형만 바꿔 100번 시도하는 낭비를 줄인다.
    LLM이 자율 호출 (강제 아님). 결과를 보고 "그래도 시도할지" LLM이 판단.
    """
    from urllib.parse import urlparse

    from api.dedup import simhash, hamming
    from api.models import DeadEnd, PayloadPattern

    if not payload:
        return {"error": "payload is required"}

    fp = simhash(payload)

    host = ""
    if target_host:
        s = target_host.strip()
        host = urlparse(s).netloc.lower() if "://" in s else s.lower()

    # 후보군 — host 우선, vuln_type 매칭. 너무 큰 결과 회피 위해 LIMIT.
    de_qs = DeadEnd.objects.exclude(simhash__isnull=True)
    if host:
        de_qs = de_qs.filter(target_host=host)
    if vuln_type:
        de_qs = de_qs.filter(vuln_type=vuln_type)
    de_pool = list(de_qs.only("dead_end_id", "endpoint", "vuln_type", "payload_used", "simhash", "times_seen")[:500])

    pp_qs = PayloadPattern.objects.exclude(simhash__isnull=True).filter(is_active=True)
    if vuln_type:
        pp_qs = pp_qs.filter(vuln_type=vuln_type)
    if host:
        # learned for this host OR seed/technique (host=null)
        from django.db.models import Q
        pp_qs = pp_qs.filter(Q(target_host=host) | Q(target_host__isnull=True))
    pp_pool = list(pp_qs.only("pattern_id", "name", "source", "simhash", "times_used", "times_succeeded")[:500])

    near_dead_ends = []
    for d in de_pool:
        dist = hamming(fp, d.simhash)
        if dist <= threshold:
            near_dead_ends.append({
                "dead_end_id": str(d.dead_end_id),
                "endpoint": d.endpoint,
                "vuln_type": d.vuln_type,
                "payload_preview": (d.payload_used or "")[:200],
                "times_seen": d.times_seen,
                "hamming_distance": dist,
            })
    near_dead_ends.sort(key=lambda x: x["hamming_distance"])
    near_dead_ends = near_dead_ends[:limit]

    near_patterns = []
    for p in pp_pool:
        dist = hamming(fp, p.simhash)
        if dist <= threshold:
            near_patterns.append({
                "pattern_id": str(p.pattern_id),
                "name": p.name,
                "source": p.source,
                "times_used": p.times_used,
                "times_succeeded": p.times_succeeded,
                "hamming_distance": dist,
            })
    near_patterns.sort(key=lambda x: x["hamming_distance"])
    near_patterns = near_patterns[:limit]

    if near_dead_ends:
        recommendation = (
            "본질이 동일한 시도가 이미 dead_end로 기록됨. 다른 sink/encoding/sub-technique 으로 "
            "변경 권장 — 단, 변경한 vector가 정말 다르면 시도해도 OK (자율 판단)."
        )
    elif near_patterns and any(p["times_succeeded"] > 0 for p in near_patterns):
        recommendation = (
            "유사한 패턴이 이전에 성공한 적 있음 (learned/technique). "
            "이 payload 그대로 시도하거나 record_pattern_use로 통계만 갱신해도 좋다."
        )
    else:
        recommendation = (
            "유사한 시도/패턴 없음 (novel). 그대로 시도하라."
        )

    return {
        "payload_simhash": fp,
        "host": host,
        "vuln_type": vuln_type,
        "threshold": threshold,
        "near_dead_ends": near_dead_ends,
        "near_patterns": near_patterns,
        "recommendation": recommendation,
    }


def _record_use(pattern_id: str, succeeded: bool, false_positive: bool) -> dict:
    from django.db.models import F
    from api.models import PayloadPattern

    # F() 표현식으로 동시 스캔 시 손실 없이 atomic 증가.
    updated = PayloadPattern.objects.filter(pattern_id=pattern_id).update(
        times_used=F("times_used") + 1,
        times_succeeded=F("times_succeeded") + (1 if succeeded else 0),
        false_positive_count=F("false_positive_count") + (1 if false_positive else 0),
    )
    if not updated:
        return {"error": f"pattern {pattern_id} not found"}

    p = PayloadPattern.objects.get(pattern_id=pattern_id)
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
            vuln_type: 취약점 카테고리. 예:
              Injection: "sqli", "nosqli", "xss", "cmdi", "ssti", "ldap_injection",
                         "xpath_injection", "graphql"
              File:      "lfi", "path_traversal", "file_upload", "xxe"
              Server:    "ssrf", "rce", "deserialization", "http_smuggling", "race_condition"
              Auth:      "idor", "access_control", "auth_bypass", "csrf", "jwt"
              Client:    "prototype_pollution", "cors"
              Other:     "open_redirect", "information_disclosure", "logic_flaw"
            keyword: title/description/template에서 부분 일치 검색
            limit: 반환 항목 수 (기본 10)

        Returns:
            {vulnerabilities: [...], patterns: [...]} JSON.
            각 pattern은 vuln_type / sub_technique / request_template /
            attack_metadata (technique_steps_md, code_template) 포함.
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
    async def check_payload_dedup(
        payload: str,
        target_host: str = "",
        vuln_type: str = "",
        threshold: int = 8,
        limit: int = 5,
    ) -> str:
        """SimHash로 payload 가 본질적으로 같은 시도와 겹치는지 진단 (XBOW 패턴).

        🛡️ Advisory — 강제 게이트 아님. 결과를 보고 LLM이 판단.
        같은 본질의 변형(`1' OR '1'='1` ↔ `1' OR '2'='2`)을 100번 시도하는 낭비를 줄인다.

        Args:
            payload: 시도하려는 payload 문자열 (HTTP body, query string, header value 등)
            target_host: 대상 host (있으면 그 host의 dead_end/learned 우선 매칭)
            vuln_type: vuln_type 필터 (있으면 같은 카테고리만 비교)
            threshold: Hamming distance 임계값 (기본 8 / 64-bit) — 작을수록 strict
            limit: 반환 후보 개수 (기본 5)

        Returns:
            {payload_simhash, near_dead_ends[], near_patterns[], recommendation}.
            near_dead_ends: 본질 동일한 과거 실패 시도 → 다른 vector 권장
            near_patterns: 유사한 KB/learned pattern → 그대로 시도/통계 갱신
            recommendation: 텍스트 권고 (하지만 LLM이 무시 가능)

        예) `check_payload_dedup("' OR 1=1 --", "wargame:5000", "sqli")` →
            과거 dead_end에 `' OR '1'='1` 있으면 본질 동일로 매칭, 다른 sub-technique 권장.
        """
        try:
            result = await sync_to_async(_check_payload_dedup, thread_sensitive=False)(
                payload=payload,
                target_host=target_host,
                vuln_type=vuln_type,
                threshold=int(threshold) if threshold else 8,
                limit=int(limit) if limit else 5,
            )
            return json.dumps(result, ensure_ascii=False, default=str)
        except Exception as e:
            return json.dumps({"error": f"check_payload_dedup failed: {e}"})

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
