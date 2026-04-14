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
    if existing:
        existing.times_succeeded += 1
        existing.times_used += 1
        if oracle_signature:
            meta = existing.attack_metadata or {}
            sigs = set(meta.get("oracle_signatures") or [])
            sigs.add(oracle_signature)
            meta["oracle_signatures"] = sorted(sigs)
            meta["last_endpoint"] = endpoint
            existing.attack_metadata = meta
        existing.save()
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
            is_active=True,
        )
        created = True

    profile, _ = TargetProfile.objects.get_or_create(host=host)
    profile.confirmed_findings_count += 1
    if created:
        profile.learned_patterns_count += 1
    profile.last_scan_at = timezone.now()
    profile.save()

    return {
        "learned_pattern_id": str(learned.pattern_id),
        "created": created,
        "host": host,
        "vuln_type": vuln_type,
        "endpoint": endpoint,
        "novelty_reason": novelty_reason,
        "profile_findings_count": profile.confirmed_findings_count,
        "profile_learned_count": profile.learned_patterns_count,
    }


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
    obj, created = DeadEnd.objects.get_or_create(
        target_host=host,
        endpoint=endpoint,
        vuln_type=vuln_type,
        pattern_id=pid,
        defaults={"payload_used": payload_used, "reason": reason},
    )
    if not created:
        obj.times_seen += 1
        if reason:
            obj.reason = reason
        obj.save()

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
    """이 host에 대해 이전 스캔에서 누적된 모든 지식 한 방에 반환."""
    from api.models import DeadEnd, PayloadPattern, TargetProfile

    host = _host_of(target_host)
    if not host:
        return {"error": "target_host 필수"}

    try:
        profile = TargetProfile.objects.get(host=host)
    except TargetProfile.DoesNotExist:
        return {
            "host": host,
            "known": False,
            "note": "이 host는 처음 스캔. living KB 비어있음.",
        }

    learned = PayloadPattern.objects.filter(
        target_host=host, source="learned", is_active=True
    ).order_by("-times_succeeded")[:20]

    dead = DeadEnd.objects.filter(target_host=host).order_by("-times_seen")[:20]

    return {
        "host": host,
        "known": True,
        "profile": {
            "framework": profile.framework,
            "server": profile.server,
            "waf": profile.waf,
            "fingerprint": profile.fingerprint,
            "notes": profile.notes,
            "confirmed_findings_count": profile.confirmed_findings_count,
            "learned_patterns_count": profile.learned_patterns_count,
            "dead_ends_count": profile.dead_ends_count,
            "last_scan_at": str(profile.last_scan_at) if profile.last_scan_at else None,
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
