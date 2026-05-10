"""Living KB 도구 — 이 시스템이 스캔에서 학습한 host-specific 지식.

Seed KB(commodity OWASP/CWE 패턴)는 LLM이 이미 알고 있어 RAG 가치가 작다.
진짜 가치는 (a) 이 host에서 *실제로 통한* 페이로드, (b) 막힌 경로(dead ends),
(c) 타겟 fingerprint(framework/server/WAF). 이 모듈은 그것을 저장·재사용한다.

자율성 원칙: 저장은 결과 기록(에이전트 자율 호출), 호출 시점은 에이전트 결정.
"""
from __future__ import annotations

import json
from urllib.parse import urlparse

from asgiref.sync import sync_to_async


def _host_of(url_or_host: str) -> str:
    """URL 또는 host 문자열에서 host:port 만 추출."""
    if not url_or_host:
        return ""
    s = url_or_host.strip()
    if "://" in s:
        return urlparse(s).netloc.lower()
    return s.lower()


# ─────────────────────────────────────────────────────────────
# 학습 (write)
# ─────────────────────────────────────────────────────────────

def _learn_from_finding(
    finding_id: str,
    target_host: str,
    payload_used: str,
    oracle_signature: str,
    pattern_id: str,
    notes: str,
    is_novel: bool,
    novelty_reason: str,
) -> dict:
    """confirmed finding을 host-specific PayloadPattern + TargetProfile 누적.

    **novelty 판단은 Verifier 에이전트(LLM) 책임.** 이 함수는 단순히 is_novel 플래그를
    신뢰한다. is_novel=False면 KB 저장 skip하고 TargetProfile 카운터만 갱신.

    Why Verifier가 판단해야 하나: commodity 페이로드 패턴은 (a) sqlmap/dalfox/nuclei가
    자동 시도하는 표준 변형, (b) OWASP/PortSwigger 치트시트에 있는 것, (c) LLM이 사전
    학습으로 알고 있는 것. 하드코딩 휴리스틱은 변형/인코딩 차이를 못 잡고 유지보수 지옥.
    LLM은 이미 그 모든 commodity를 알고 있으므로 직접 판단 가능.

    pattern_id가 있으면 그 seed의 host-specific 변종으로 새 row 생성 (parent=seed).
    """
    from django.utils import timezone

    from api.models import Finding, PayloadPattern, TargetProfile

    host = _host_of(target_host)
    if not host:
        return {"error": "target_host 필수"}

    try:
        finding = Finding.objects.select_related("candidate", "candidate__request").get(
            finding_id=finding_id
        )
    except Finding.DoesNotExist:
        return {"error": f"finding {finding_id} not found"}

    vuln_type = finding.vuln_type or (finding.candidate.vuln_type if finding.candidate else "")
    endpoint = ""
    if finding.candidate and finding.candidate.request:
        endpoint = finding.candidate.request.endpoint or ""

    template_value = payload_used or ""

    # ── novelty filter: Verifier가 commodity 판정한 것은 KB 저장 skip ──
    if not is_novel:
        profile, _ = TargetProfile.objects.get_or_create(host=host)
        profile.confirmed_findings_count += 1
        profile.last_scan_at = timezone.now()
        profile.save()
        return {
            "skipped": True,
            "skip_reason": novelty_reason or "verifier marked is_novel=False (commodity payload)",
            "host": host,
            "vuln_type": vuln_type,
            "endpoint": endpoint,
            "payload_preview": template_value[:120],
            "profile_findings_count": profile.confirmed_findings_count,
            "hint": "novel 판단 기준: sqlmap/dalfox/nuclei가 못 잡거나, LLM/OWASP cheat sheet에 "
                    "없는 페이로드. 예: 특이 인코딩 chain, framework-specific quirk, logic flaw, "
                    "multi-endpoint composition.",
        }

    # seed 추정
    seed = None
    if pattern_id:
        try:
            seed = PayloadPattern.objects.get(pattern_id=pattern_id)
        except PayloadPattern.DoesNotExist:
            seed = None

    # host-specific learned 패턴 생성 (중복 방지)
    if not template_value and seed:
        template_value = seed.request_template
    existing = PayloadPattern.objects.filter(
        target_host=host,
        vuln_type=vuln_type,
        request_template=template_value,
        source="learned",
    ).first()
    # SimHash 사전 계산 — 새 row 생성 시 같이 저장. 의존성 없음.
    from api.dedup import simhash as _simhash
    payload_simhash = _simhash(template_value or "")

    if existing:
        from django.db.models import F
        # 카운터는 F()로 atomic 증가 (동시 스캔 race 방지). attack_metadata는 일반 save.
        PayloadPattern.objects.filter(pk=existing.pk).update(
            times_succeeded=F("times_succeeded") + 1,
            times_used=F("times_used") + 1,
        )
        if oracle_signature:
            meta = existing.attack_metadata or {}
            sigs = set(meta.get("oracle_signatures") or [])
            sigs.add(oracle_signature)
            meta["oracle_signatures"] = sorted(sigs)
            meta["last_endpoint"] = endpoint
            existing.attack_metadata = meta
            existing.save(update_fields=["attack_metadata"])
        existing.refresh_from_db(fields=["times_succeeded", "times_used"])
        learned = existing
        created = False
    else:
        learned = PayloadPattern.objects.create(
            vulnerability=seed.vulnerability if seed else None,
            name=f"[novel@{host}] {vuln_type} {endpoint or ''}".strip()[:256],
            vuln_type=vuln_type,
            sub_technique=seed.sub_technique if seed else None,
            category="learned",
            request_template=template_value,
            matcher=seed.matcher if seed else None,
            safety_level=seed.safety_level if seed else "safe",
            safety_notes=notes or (seed.safety_notes if seed else None),
            request_cost=seed.request_cost if seed else 1,
            mutation_type="learned",
            parent_pattern=seed,
            target_host=host,
            attack_metadata={
                "endpoint": endpoint,
                "oracle_signatures": [oracle_signature] if oracle_signature else [],
                "finding_id": str(finding_id),
                "notes": notes,
                "novelty_reason": novelty_reason,
                "is_novel": True,
            },
            source="learned",
            tags=(["learned", "novel", vuln_type, host]),
            times_used=1,
            times_succeeded=1,
            simhash=payload_simhash,
            is_active=True,
        )
        created = True

    from django.db.models import F
    profile, _ = TargetProfile.objects.get_or_create(host=host)
    TargetProfile.objects.filter(pk=profile.pk).update(
        confirmed_findings_count=F("confirmed_findings_count") + 1,
        learned_patterns_count=F("learned_patterns_count") + (1 if created else 0),
        last_scan_at=timezone.now(),
    )
    profile.refresh_from_db()

    # Auto-embed so retrieve_similar finds this pattern immediately
    embedded = False
    if learned.embedding is None:
        embedded = _embed_learned_pattern(learned)

    # Auto-export to techniques/<vuln_type>/<name>.md so the pattern survives
    # docker rebuild / volume wipe (host bind mount + git commit).
    # best-effort: 실패해도 DB는 살아 있으므로 다음 export_learned --write로 복구 가능.
    md_exported = _export_learned_to_md(learned)

    return {
        "learned_pattern_id": str(learned.pattern_id),
        "created": created,
        "embedded": embedded,
        "md_exported": md_exported,
        "host": host,
        "vuln_type": vuln_type,
        "endpoint": endpoint,
        "novelty_reason": novelty_reason,
        "profile_findings_count": profile.confirmed_findings_count,
        "profile_learned_count": profile.learned_patterns_count,
    }


def _export_learned_to_md(pattern) -> bool:
    """Dump a learned PayloadPattern to techniques/<vuln_type>/<name>.md.

    Dedup 정책 (둘 중 하나라도 해당하면 write skip):
      1. 이 pattern이 이미 export된 적 있고 (`exported_to_md=True`) 같은 경로에 파일 존재
         → 같은 패턴 재confirm 시 disk/git noise 방지
      2. 같은 clean_name으로 `source="technique"` 행이 이미 있음
         → 검증되어 promote된 자산을 learned 버전이 덮어쓰지 못하게 보호

    `export_learned.pattern_to_md` 재사용으로 포맷 일관성 유지.
    """
    try:
        from datetime import date
        from api.management.commands.export_learned import (
            TECHNIQUES_DIR,
            _clean_name,
            pattern_to_md,
        )
        from api.models import PayloadPattern
    except Exception:
        return False

    try:
        meta = pattern.attack_metadata or {}

        # (1) 이미 같은 패턴이 dump되어 있으면 no-op
        if meta.get("exported_to_md"):
            existing_rel = meta.get("exported_path") or ""
            if existing_rel and (TECHNIQUES_DIR / existing_rel).exists():
                return False

        # (2) 같은 이름으로 검증된 technique이 이미 있으면 skip (덮어쓰기 방지)
        clean_name = _clean_name(pattern.name, pattern.vuln_type, str(pattern.pattern_id))
        if PayloadPattern.objects.filter(source="technique", name=clean_name).exists():
            return False

        filename, vuln_type, md_content = pattern_to_md(pattern)
        if not vuln_type:
            return False
        target_dir = TECHNIQUES_DIR / vuln_type
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / filename).write_text(md_content, encoding="utf-8")

        meta["exported_to_md"] = True
        meta["exported_date"] = str(date.today())
        meta["exported_path"] = f"{vuln_type}/{filename}"
        pattern.attack_metadata = meta
        pattern.save(update_fields=["attack_metadata"])
        return True
    except Exception:
        return False


def _embed_learned_pattern(pattern) -> bool:
    """Generate embedding for a single learned pattern."""
    try:
        from api.embedding_service import (
            EMBEDDING_MODEL, embed_documents, is_available as embeddings_available,
        )
        if not embeddings_available():
            return False
    except ImportError:
        return False

    meta = pattern.attack_metadata or {}
    text = "\n".join([
        f"name: {meta.get('name', pattern.name)}",
        f"vuln_type: {pattern.vuln_type}",
        f"applies_when: {meta.get('applies_when', meta.get('novelty_reason', ''))}",
        f"endpoint: {meta.get('endpoint', '')}",
        f"payload: {(pattern.request_template or '')[:300]}",
        f"tags: {', '.join(pattern.tags or [])}",
    ])

    vectors = embed_documents([text])
    if vectors and vectors[0]:
        pattern.embedding = vectors[0]
        pattern.embedding_model = EMBEDDING_MODEL
        pattern.save(update_fields=["embedding", "embedding_model"])
        return True
    return False


def _learn_dead_end(
    target_host: str,
    endpoint: str,
    vuln_type: str,
    pattern_id: str,
    payload_used: str,
    reason: str,
) -> dict:
    """dismiss/oracle 실패 시 dead end로 등록. 다음 스캔에서 회피용."""
    from api.models import DeadEnd, TargetProfile

    host = _host_of(target_host)
    if not host or not endpoint or not vuln_type:
        return {"error": "target_host, endpoint, vuln_type 필수"}

    pid = pattern_id or None
    from api.dedup import simhash as _simhash
    payload_simhash = _simhash(payload_used or "")
    obj, created = DeadEnd.objects.get_or_create(
        target_host=host,
        endpoint=endpoint,
        vuln_type=vuln_type,
        pattern_id=pid,
        defaults={
            "payload_used": payload_used,
            "reason": reason,
            "simhash": payload_simhash,
        },
    )
    if not created:
        from django.db.models import F
        DeadEnd.objects.filter(pk=obj.pk).update(times_seen=F("times_seen") + 1)
        if reason or (obj.simhash is None and payload_simhash):
            updates = {}
            if reason:
                updates["reason"] = reason
            if obj.simhash is None and payload_simhash:
                updates["simhash"] = payload_simhash
            DeadEnd.objects.filter(pk=obj.pk).update(**updates)
        obj.refresh_from_db()

    # profile counter
    profile, _ = TargetProfile.objects.get_or_create(host=host)
    if created:
        profile.dead_ends_count += 1
        profile.save()

    return {
        "dead_end_id": str(obj.dead_end_id),
        "created": created,
        "times_seen": obj.times_seen,
        "host": host,
    }


def _update_target_profile(
    target_host: str,
    framework: str,
    server: str,
    waf: str,
    fingerprint_json: str,
    notes: str,
) -> dict:
    """정찰 단계에서 발견한 framework/server/WAF 등을 TargetProfile에 누적 저장."""
    from api.models import TargetProfile

    host = _host_of(target_host)
    if not host:
        return {"error": "target_host 필수"}

    profile, created = TargetProfile.objects.get_or_create(host=host)
    changed = False
    if framework and framework != profile.framework:
        profile.framework = framework
        changed = True
    if server and server != profile.server:
        profile.server = server
        changed = True
    if waf and waf != profile.waf:
        profile.waf = waf
        changed = True
    if fingerprint_json:
        try:
            fp = json.loads(fingerprint_json)
            merged = (profile.fingerprint or {}).copy()
            merged.update(fp)
            profile.fingerprint = merged
            changed = True
        except Exception:
            pass
    if notes:
        existing = profile.notes or ""
        profile.notes = (existing + "\n" + notes).strip()[:4000]
        changed = True
    if changed or created:
        profile.save()
    return {
        "host": host,
        "created": created,
        "framework": profile.framework,
        "server": profile.server,
        "waf": profile.waf,
        "fingerprint_keys": list((profile.fingerprint or {}).keys()),
    }


# ─────────────────────────────────────────────────────────────
# 회상 (read)
# ─────────────────────────────────────────────────────────────

def _recall_target(target_host: str) -> dict:
    """이 host에 대해 이전 스캔에서 누적된 모든 지식 한 방에 반환.

    포함: profile (framework/server/WAF/fingerprint), learned_patterns, dead_ends,
          endpoint_specs (KB 화된 API 명세 — 같은 host 재방문 시 정찰 단축).
    """
    from api.models import DeadEnd, EndpointSpec, PayloadPattern, TargetProfile

    host = _host_of(target_host)
    if not host:
        return {"error": "target_host 필수"}

    try:
        profile = TargetProfile.objects.get(host=host)
    except TargetProfile.DoesNotExist:
        # profile 없어도 EndpointSpec 은 있을 수 있음 (다른 흐름으로 누적됐을 때)
        spec_count = EndpointSpec.objects.filter(target_host=host).count()
        if spec_count == 0:
            return {
                "host": host,
                "known": False,
                "note": "이 host는 처음 스캔. living KB 비어있음.",
            }
        profile = None

    learned = PayloadPattern.objects.filter(
        target_host=host, source="learned", is_active=True
    ).order_by("-times_succeeded")[:20]

    dead = DeadEnd.objects.filter(target_host=host).order_by("-times_seen")[:20]

    specs = EndpointSpec.objects.filter(target_host=host).order_by("-last_seen_at")[:30]

    return {
        "host": host,
        "known": True,
        "profile": {
            "framework": profile.framework if profile else None,
            "server": profile.server if profile else None,
            "waf": profile.waf if profile else None,
            "fingerprint": profile.fingerprint if profile else None,
            "notes": profile.notes if profile else None,
            "confirmed_findings_count": profile.confirmed_findings_count if profile else 0,
            "learned_patterns_count": profile.learned_patterns_count if profile else 0,
            "dead_ends_count": profile.dead_ends_count if profile else 0,
            "last_scan_at": (str(profile.last_scan_at) if profile and profile.last_scan_at else None),
        },
        "learned_patterns": [
            {
                "pattern_id": str(p.pattern_id),
                "vuln_type": p.vuln_type,
                "name": p.name,
                "request_template": p.request_template,
                "endpoint": (p.attack_metadata or {}).get("endpoint"),
                "oracle_signatures": (p.attack_metadata or {}).get("oracle_signatures", []),
                "times_succeeded": p.times_succeeded,
            }
            for p in learned
        ],
        "dead_ends": [
            {
                "endpoint": d.endpoint,
                "vuln_type": d.vuln_type,
                "reason": d.reason,
                "times_seen": d.times_seen,
            }
            for d in dead
        ],
        # KB 화된 API 명세 — RouteMap 이 정찰 skip + EntryPoint 가 sink_hints 로 가설 좁힘
        "endpoint_specs": [
            {
                "spec_id": str(s.spec_id),
                "method": s.method,
                "endpoint": s.endpoint,
                "params_schema": s.params_schema,
                "auth_required": s.auth_required,
                "suspected_vuln_types": s.suspected_vuln_types or [],
                "sink_hints": s.sink_hints or [],
                "times_seen": s.times_seen,
                "last_seen_at": str(s.last_seen_at) if s.last_seen_at else None,
            }
            for s in specs
        ],
    }


# ─────────────────────────────────────────────────────────────
# EndpointSpec — API 명세 KB (host 별 endpoint 메타 누적)
# ─────────────────────────────────────────────────────────────

def _record_endpoint_spec(
    target_host: str,
    method: str,
    endpoint: str,
    params_schema: str = "",
    headers_required: str = "",
    auth_required: bool = False,
    response_shape: str = "",
    suspected_vuln_types: str = "",
    sink_hints: str = "",
    notes: str = "",
) -> dict:
    """endpoint 명세를 KB 에 기록 (같은 host 재방문 시 정찰 단축용).

    같은 (host, method, endpoint) 가 있으면 기존 spec 갱신 — params/sinks/vuln_types 는
    union 합집합 (정보 누적), times_seen += 1.
    """
    import json as _json
    from django.db.models import F
    from api.models import EndpointSpec

    host = _host_of(target_host)
    if not host or not endpoint or not method:
        return {"error": "target_host, method, endpoint 필수"}

    method = method.upper()

    def _parse_json(s, default):
        if not s:
            return default
        if isinstance(s, (dict, list)):
            return s
        try:
            return _json.loads(s)
        except (_json.JSONDecodeError, TypeError):
            return default

    new_params = _parse_json(params_schema, {}) if params_schema else None
    new_headers = _parse_json(headers_required, []) if headers_required else None
    new_response = _parse_json(response_shape, {}) if response_shape else None
    new_suspected = _parse_json(suspected_vuln_types, []) if suspected_vuln_types else []
    new_sinks = _parse_json(sink_hints, []) if sink_hints else []
    if isinstance(new_suspected, str):
        new_suspected = [new_suspected]
    if isinstance(new_sinks, str):
        new_sinks = [new_sinks]

    existing = EndpointSpec.objects.filter(
        target_host=host, method=method, endpoint=endpoint,
    ).first()

    if existing:
        # 정보 누적 — 새 데이터 들어오면 union/덮어쓰기
        if new_params:
            merged_p = dict(existing.params_schema or {})
            merged_p.update(new_params)
            existing.params_schema = merged_p
        if new_headers:
            merged_h = list(set((existing.headers_required or []) + new_headers))
            existing.headers_required = merged_h
        if auth_required and not existing.auth_required:
            existing.auth_required = True
        if new_response:
            merged_r = dict(existing.response_shape or {})
            merged_r.update(new_response)
            existing.response_shape = merged_r
        if new_suspected:
            existing.suspected_vuln_types = sorted(set((existing.suspected_vuln_types or []) + new_suspected))
        if new_sinks:
            existing.sink_hints = sorted(set((existing.sink_hints or []) + new_sinks))
        if notes:
            existing.notes = ((existing.notes or "") + "\n" + notes).strip()[:4000]
        existing.save(update_fields=[
            "params_schema", "headers_required", "auth_required",
            "response_shape", "suspected_vuln_types", "sink_hints", "notes",
        ])
        EndpointSpec.objects.filter(pk=existing.pk).update(times_seen=F("times_seen") + 1)
        existing.refresh_from_db()
        return {
            "spec_id": str(existing.spec_id),
            "created": False,
            "times_seen": existing.times_seen,
            "host": host,
            "endpoint": endpoint,
        }

    spec = EndpointSpec.objects.create(
        target_host=host,
        method=method,
        endpoint=endpoint,
        params_schema=new_params,
        headers_required=new_headers,
        auth_required=bool(auth_required),
        response_shape=new_response,
        suspected_vuln_types=new_suspected,
        sink_hints=new_sinks,
        notes=notes or None,
    )
    return {
        "spec_id": str(spec.spec_id),
        "created": True,
        "times_seen": 1,
        "host": host,
        "endpoint": endpoint,
    }


def _recall_endpoint_specs(target_host: str, vuln_type: str = "", limit: int = 30) -> dict:
    """특정 host (선택: vuln_type) 의 endpoint 명세 목록 조회."""
    from api.models import EndpointSpec
    host = _host_of(target_host)
    if not host:
        return {"error": "target_host 필수"}
    qs = EndpointSpec.objects.filter(target_host=host)
    if vuln_type:
        qs = qs.filter(suspected_vuln_types__icontains=vuln_type)
    specs = list(qs.order_by("-last_seen_at")[:limit])
    return {
        "host": host,
        "vuln_type_filter": vuln_type or None,
        "count": len(specs),
        "specs": [
            {
                "spec_id": str(s.spec_id),
                "method": s.method,
                "endpoint": s.endpoint,
                "params_schema": s.params_schema,
                "headers_required": s.headers_required,
                "auth_required": s.auth_required,
                "response_shape": s.response_shape,
                "suspected_vuln_types": s.suspected_vuln_types or [],
                "sink_hints": s.sink_hints or [],
                "times_seen": s.times_seen,
                "notes": (s.notes or "")[:500],
                "last_seen_at": str(s.last_seen_at) if s.last_seen_at else None,
            }
            for s in specs
        ],
    }


def _recall_dead_ends(target_host: str, vuln_type: str, endpoint: str) -> dict:
    """특정 host/vuln_type/endpoint 조합에 막힌 패턴 조회. 시도 전 회피용."""
    from api.models import DeadEnd

    host = _host_of(target_host)
    qs = DeadEnd.objects.filter(target_host=host)
    if vuln_type:
        qs = qs.filter(vuln_type=vuln_type)
    if endpoint:
        qs = qs.filter(endpoint=endpoint)
    return {
        "host": host,
        "count": qs.count(),
        "dead_ends": [
            {
                "endpoint": d.endpoint,
                "vuln_type": d.vuln_type,
                "pattern_id": str(d.pattern_id) if d.pattern_id else None,
                "payload_used": d.payload_used,
                "reason": d.reason,
                "times_seen": d.times_seen,
            }
            for d in qs[:20]
        ],
    }


# ─────────────────────────────────────────────────────────────
# MCP 등록
# ─────────────────────────────────────────────────────────────

def register(mcp):

    @mcp.tool()
    async def recall_target(target_host: str) -> str:
        """이 host에 대해 이전 스캔에서 누적된 지식을 회상한다.

        반환: profile (framework/server/WAF/fingerprint) + learned_patterns (이전에 통한 페이로드)
        + dead_ends (막힌 시도). 처음 보는 host면 known=false.

        Planner는 정찰 시작 시 이 도구를 호출하면 LLM이 모르는 host-specific 지식을
        즉시 활용 가능 (Voyager skill library 패턴).
        """
        try:
            result = await sync_to_async(_recall_target, thread_sensitive=True)(
                target_host=target_host
            )
            return json.dumps(result, ensure_ascii=False, default=str)
        except Exception as e:
            return json.dumps({"error": f"recall_target failed: {e}"})

    @mcp.tool()
    async def recall_dead_ends(
        target_host: str,
        vuln_type: str = "",
        endpoint: str = "",
    ) -> str:
        """특정 host/vuln_type/endpoint 조합에 이전 스캔에서 *막힌* 패턴 조회.
        Executor가 페이로드 시도 전에 호출하면 무의미한 반복을 피한다.
        """
        try:
            result = await sync_to_async(_recall_dead_ends, thread_sensitive=True)(
                target_host=target_host, vuln_type=vuln_type, endpoint=endpoint,
            )
            return json.dumps(result, ensure_ascii=False, default=str)
        except Exception as e:
            return json.dumps({"error": f"recall_dead_ends failed: {e}"})

    @mcp.tool()
    async def record_endpoint_spec(
        target_host: str,
        method: str,
        endpoint: str,
        params_schema: str = "",
        headers_required: str = "",
        auth_required: bool = False,
        response_shape: str = "",
        suspected_vuln_types: str = "",
        sink_hints: str = "",
        notes: str = "",
    ) -> str:
        """API endpoint 명세를 KB 에 누적. 같은 host 재방문 시 정찰 단축용.

        EntryPoint sub-agent 가 endpoint 분석 끝에 호출 권장. 같은
        (host, method, endpoint) 가 있으면 갱신 (params/sinks/vuln_types union, times_seen+=1).

        Args:
            target_host: 대상 host (예: "juice-shop:3000")
            method: HTTP method (GET/POST/...)
            endpoint: 경로 (예: "/rest/user/login")
            params_schema: JSON 문자열. 예: '{"email":{"type":"str","in":"body","required":true}}'
            headers_required: JSON list. 예: '["Authorization","X-CSRF"]'
            auth_required: 인증 필요 여부
            response_shape: JSON. 예: '{"status_codes":[200,401], "fields":["id","email"]}'
            suspected_vuln_types: JSON list 또는 문자열. 예: '["sqli","auth_bypass"]'
            sink_hints: JSON list. 예: '["bcrypt_compare","raw_sql_query"]'
            notes: 자유 메모
        """
        try:
            result = await sync_to_async(_record_endpoint_spec, thread_sensitive=True)(
                target_host=target_host, method=method, endpoint=endpoint,
                params_schema=params_schema, headers_required=headers_required,
                auth_required=bool(auth_required), response_shape=response_shape,
                suspected_vuln_types=suspected_vuln_types, sink_hints=sink_hints,
                notes=notes,
            )
            return json.dumps(result, ensure_ascii=False, default=str)
        except Exception as e:
            return json.dumps({"error": f"record_endpoint_spec failed: {e}"})

    @mcp.tool()
    async def recall_endpoint_specs(
        target_host: str,
        vuln_type: str = "",
        limit: int = 30,
    ) -> str:
        """특정 host (선택: vuln_type 매칭) 의 endpoint 명세 목록.

        RouteMap 이 새 scan 시작 시 호출하면 이전 정찰 결과로 endpoint 후보 즉시 확보.
        EntryPoint 도 sink_hints 보고 가설 좁히는 데 활용.
        """
        try:
            result = await sync_to_async(_recall_endpoint_specs, thread_sensitive=True)(
                target_host=target_host, vuln_type=vuln_type,
                limit=int(limit) if limit else 30,
            )
            return json.dumps(result, ensure_ascii=False, default=str)
        except Exception as e:
            return json.dumps({"error": f"recall_endpoint_specs failed: {e}"})

    @mcp.tool()
    async def learn_from_finding(
        finding_id: str,
        target_host: str,
        payload_used: str,
        is_novel: bool,
        novelty_reason: str,
        oracle_signature: str = "",
        pattern_id: str = "",
        notes: str = "",
    ) -> str:
        """confirmed finding을 host-specific learned 패턴 + TargetProfile 갱신.

        ## 핵심 — novelty 판단은 당신(Verifier)의 책임

        is_novel=True 일 때만 KB에 host-specific 패턴으로 저장. False면 TargetProfile
        카운터만 갱신하고 패턴 저장 skip. **commodity 페이로드를 KB에 저장하면 자산 가치 0**
        — sqlmap/dalfox/nuclei가 평생 자동 시도하고, LLM도 이미 학습했으므로 retrieve 가치 없음.

        ### is_novel=True 후보 (이런 것만 KB에 저장)
        - LLM이 explore mode에서 자체 생성한 페이로드 (KB seed에 없던 것)
        - mutate_payload로 만든 변종이 confirmed된 경우
        - WAF/필터 우회를 위한 특이 인코딩/공백/주석 chain
        - framework/lib-specific quirk (예: Flask `?id[]=`, Django `__regex`, Spring SpEL)
        - logic flaw / business logic (IDOR persona swap, race, mass assignment 등)
        - multi-endpoint composition chain (A로 토큰 추출 → B로 권한 상승)
        - 알려진 CVE의 변종이지만 기존 도구 시그니처와 다른 형태

        ### is_novel=False 후보 (이런 것은 저장 skip)
        - sqlmap/dalfox/nuclei가 default로 시도하는 표준 페이로드 (`1' OR '1'='1`, `<script>alert(1)</script>` 등)
        - OWASP / PortSwigger / HackTricks cheat sheet의 1차 페이로드
        - 흔한 traversal (`../../../etc/passwd`), 흔한 SSRF target (`127.0.0.1`, `169.254.169.254`)
        - 단순 인코딩 변형 (URL-encode 한 번 정도)

        애매하면 is_novel=False로. 진짜 새로운 것만 KB로.

        Args:
            finding_id: confirm_finding 반환 id
            target_host: scan target의 host (예: "wargame:5000")
            payload_used: 실제로 통한 페이로드
            is_novel: 위 기준에 따라 당신이 판단
            novelty_reason: is_novel 판정 이유 한 줄. 예: "Flask array param injection,
                기존 sqlmap 시그니처 미적용", "URL encoded NULL byte chain", 등.
                is_novel=False면 commodity 이유 (예: "standard sqlmap default payload").
            oracle_signature: oracle_*가 매치한 시그니처 (예: "/etc/passwd (unix)")
            pattern_id: 사용한 seed PayloadPattern.pattern_id (있으면 parent로 link)
            notes: 자유 메모
        """
        try:
            result = await sync_to_async(_learn_from_finding, thread_sensitive=True)(
                finding_id=finding_id,
                target_host=target_host,
                payload_used=payload_used,
                oracle_signature=oracle_signature,
                pattern_id=pattern_id,
                notes=notes,
                is_novel=bool(is_novel),
                novelty_reason=novelty_reason or "",
            )
            return json.dumps(result, ensure_ascii=False, default=str)
        except Exception as e:
            return json.dumps({"error": f"learn_from_finding failed: {e}"})

    @mcp.tool()
    async def learn_dead_end(
        target_host: str,
        endpoint: str,
        vuln_type: str,
        pattern_id: str = "",
        payload_used: str = "",
        reason: str = "",
    ) -> str:
        """dismiss 또는 oracle 실패한 시도를 dead end로 등록. 다음 스캔 회피용.

        Verifier가 dismiss_candidate 호출 직후, 또는 Executor가 명백히 안 통하는
        시도 직후 호출 권장.
        """
        try:
            result = await sync_to_async(_learn_dead_end, thread_sensitive=True)(
                target_host=target_host,
                endpoint=endpoint,
                vuln_type=vuln_type,
                pattern_id=pattern_id,
                payload_used=payload_used,
                reason=reason,
            )
            return json.dumps(result, ensure_ascii=False, default=str)
        except Exception as e:
            return json.dumps({"error": f"learn_dead_end failed: {e}"})

    @mcp.tool()
    async def update_target_profile(
        target_host: str,
        framework: str = "",
        server: str = "",
        waf: str = "",
        fingerprint_json: str = "",
        notes: str = "",
    ) -> str:
        """정찰 중 발견한 framework/server/WAF/fingerprint를 TargetProfile에 누적.

        Planner가 browser_navigate 또는 wafw00f_scan/whatweb_scan 결과로
        framework 등을 식별하면 이 도구로 저장. 다음 스캔 시 즉시 활용.
        fingerprint_json은 임의 구조 JSON 문자열 ({"react": true, "csp": "..."} 등).
        """
        try:
            result = await sync_to_async(_update_target_profile, thread_sensitive=True)(
                target_host=target_host,
                framework=framework, server=server, waf=waf,
                fingerprint_json=fingerprint_json, notes=notes,
            )
            return json.dumps(result, ensure_ascii=False, default=str)
        except Exception as e:
            return json.dumps({"error": f"update_target_profile failed: {e}"})
