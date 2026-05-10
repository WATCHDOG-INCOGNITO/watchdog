"""외부 ground truth 대조 도구 — 진짜 novelty 판정.

LLM 사전학습 기반 추측이 아니라, 다음 3 채널과 *실제* 대조:
  1. commodity_check_local — 로컬에 내려둔 payloadbox 목록 grep
  2. commodity_check_cve  — NVD REST API description 검색
  3. commodity_check_web  — DuckDuckGo HTML scrape (무료, anti-bot 위험 있음)

매칭 결과를 Verifier에게 반환해, Verifier가 "진짜 novel" 인지 *증거 기반* 으로 판정.
세 채널 모두 매치 0건이면 진짜 novel 강한 신호. 단 하나라도 매치면 commodity 고려.
"""
from __future__ import annotations

import json
import os
import re
from html import unescape
from pathlib import Path

import requests

PAYLOADS_DB = Path(os.environ.get("PAYLOADS_DB_DIR", "/app/payloads_db"))
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DDG_HTML = "https://html.duckduckgo.com/html/"


# ─────────────────────────────────────────────────────────────
# Local payload DB grep
# ─────────────────────────────────────────────────────────────

VULN_TYPE_TO_FILES = {
    "sqli": ["sqli.txt"],
    "xss": ["xss.txt"],
    "cmdi": ["cmdi.txt"],
    "lfi": ["lfi.txt"],
    "ssrf": ["ssrf.txt"],
    # 매핑 없는 경우 모든 파일 검색
}


def _payload_signature(payload: str) -> str:
    """매칭용 정규화 — 공백 압축, 소문자, 양끝 자르기."""
    if not payload:
        return ""
    s = payload.strip().lower()
    s = re.sub(r"\s+", " ", s)
    return s


def _commodity_check_local(payload: str, vuln_type: str, max_matches: int = 5) -> dict:
    if not PAYLOADS_DB.exists():
        return {
            "available": False,
            "reason": f"payload DB 디렉터리 없음 ({PAYLOADS_DB})",
            "matches": [],
        }
    sig = _payload_signature(payload)
    if not sig or len(sig) < 4:
        return {"available": True, "matches": [], "reason": "payload too short"}

    files = VULN_TYPE_TO_FILES.get((vuln_type or "").lower())
    if files:
        targets = [PAYLOADS_DB / f for f in files if (PAYLOADS_DB / f).exists()]
    else:
        targets = list(PAYLOADS_DB.glob("*.txt"))

    matches: list[dict] = []
    for path in targets:
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                for lineno, line in enumerate(f, 1):
                    if len(matches) >= max_matches:
                        break
                    norm = _payload_signature(line)
                    if not norm or len(norm) < 4:
                        continue
                    # 양방향 substring — payload 가 line에 들어있거나, line이 payload에 들어있거나
                    if sig in norm or norm in sig:
                        matches.append({
                            "file": path.name,
                            "lineno": lineno,
                            "line": line.strip()[:200],
                        })
        except Exception:
            continue
        if len(matches) >= max_matches:
            break

    return {
        "available": True,
        "is_commodity_local": bool(matches),
        "matches": matches,
        "files_searched": [t.name for t in targets],
    }


# ─────────────────────────────────────────────────────────────
# NVD CVE search
# ─────────────────────────────────────────────────────────────

def _nvd_request(params: dict, timeout: int = 10) -> tuple[int, dict | str]:
    """NVD API 공통 호출 — apiKey 헤더 자동 추가."""
    headers = {}
    nvd_key = os.environ.get("NVD_API_KEY", "").strip()
    if nvd_key:
        headers["apiKey"] = nvd_key
    try:
        r = requests.get(NVD_API, params=params, headers=headers, timeout=timeout)
        if r.status_code != 200:
            return r.status_code, f"NVD HTTP {r.status_code}: {r.text[:200]}"
        return 200, r.json()
    except Exception as e:
        return 0, f"NVD query failed: {e}"


def _extract_poc_urls(refs: list[dict]) -> list[dict]:
    """NVD references 에서 PoC/exploit 가능성 높은 URL만 골라낸다."""
    out = []
    poc_hosts = ("github.com", "exploit-db.com", "packetstormsecurity",
                 "huntr.dev", "huntress.com", "rapid7.com", "synacktiv",
                 "snyk.io", "sansec.io", "horizon3.ai", "praetorian.com")
    poc_tags = {"exploit", "patch", "third party advisory", "vendor advisory",
                "technical description"}
    for ref in refs:
        url = (ref.get("url") or "").strip()
        tags = {t.lower() for t in (ref.get("tags") or [])}
        if not url:
            continue
        host_match = any(h in url.lower() for h in poc_hosts)
        tag_match = bool(tags & poc_tags)
        if host_match or tag_match:
            out.append({
                "url": url,
                "source": (ref.get("source") or "")[:80],
                "tags": sorted(tags),
            })
    return out[:10]


def _fetch_cve_details(cve_id: str) -> dict:
    """NVD에서 단일 CVE 상세 + references + PoC 후보 URL 반환.

    LLM이 후속으로 references URL(GitHub PoC, security blog 등)을 따라가서 trigger
    코드 분석 → variant 생성 가능. 시드 큐레이션 없이 just-in-time 활용.
    """
    cid = (cve_id or "").strip().upper()
    if not cid.startswith("CVE-"):
        return {"error": "cve_id must start with CVE- (e.g. CVE-2024-34102)"}

    status, body = _nvd_request({"cveId": cid})
    if status != 200:
        return {"error": body if isinstance(body, str) else "NVD lookup failed"}

    items = body.get("vulnerabilities", [])
    if not items:
        return {"cve_id": cid, "found": False}

    cve = items[0].get("cve", {})
    descs = cve.get("descriptions", [])
    desc_en = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
    metrics = cve.get("metrics", {}) or {}
    cvss31 = (metrics.get("cvssMetricV31") or [{}])[0].get("cvssData", {})
    cvss30 = (metrics.get("cvssMetricV30") or [{}])[0].get("cvssData", {})
    cvss = cvss31 or cvss30 or {}
    weaknesses = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value")
            if v:
                weaknesses.append(v)
    refs = cve.get("references", []) or []
    poc_refs = _extract_poc_urls(refs)
    configs = cve.get("configurations", [])
    affected = []
    for cfg in configs:
        for node in cfg.get("nodes", []) or []:
            for cm in node.get("cpeMatch", []) or []:
                cpe = cm.get("criteria")
                if cpe:
                    affected.append(cpe)
    return {
        "cve_id": cid,
        "found": True,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "description": desc_en[:1500],
        "cvss_score": cvss.get("baseScore"),
        "cvss_severity": cvss.get("baseSeverity"),
        "cvss_vector": cvss.get("vectorString"),
        "weaknesses": weaknesses[:10],
        "affected_cpes": affected[:30],
        "all_references": [
            {"url": r.get("url"), "source": r.get("source"), "tags": r.get("tags") or []}
            for r in refs[:30]
        ],
        "poc_candidate_refs": poc_refs,
        "hint": (
            "poc_candidate_refs 의 URL을 http_request로 GET 해 trigger 코드 또는 "
            "exploit description 분석 → variant 작성에 활용."
        ),
    }


def _suggest_cves_for_framework(
    framework: str,
    year_min: int = 0,
    cvss_min: float = 0.0,
    cwe_id: str = "",
    limit: int = 10,
) -> dict:
    """NVD keyword search로 framework 적용 가능 CVE 목록을 CVSS 정렬 반환.

    시드 큐레이션 부담 없이 즉시 framework-specific CVE 후보를 받는다.
    각 항목은 cve_id + 설명 + CVSS + 주요 references — LLM이 fetch_cve_details
    로 더 깊이 보거나 그대로 가설로 활용.
    """
    fw = (framework or "").strip()
    if not fw:
        return {"error": "framework is required"}

    params = {
        "keywordSearch": fw[:200],
        "resultsPerPage": min(max(limit * 3, 10), 50),  # 필터링 여유
    }
    if cwe_id:
        params["cweId"] = cwe_id

    status, body = _nvd_request(params)
    if status != 200:
        return {"error": body if isinstance(body, str) else "NVD lookup failed"}

    items = body.get("vulnerabilities", []) or []
    candidates = []
    for it in items:
        cve = it.get("cve", {}) or {}
        cid = cve.get("id") or ""
        published = cve.get("published") or ""
        try:
            year = int(published[:4]) if published else 0
        except ValueError:
            year = 0
        if year_min and year and year < year_min:
            continue
        descs = cve.get("descriptions", []) or []
        desc_en = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {}) or {}
        cvss31 = (metrics.get("cvssMetricV31") or [{}])[0].get("cvssData", {})
        cvss30 = (metrics.get("cvssMetricV30") or [{}])[0].get("cvssData", {})
        cvss = cvss31 or cvss30 or {}
        score = cvss.get("baseScore") or 0.0
        if cvss_min and score < cvss_min:
            continue
        refs = cve.get("references", []) or []
        candidates.append({
            "cve_id": cid,
            "published": published,
            "year": year,
            "description": desc_en[:300],
            "cvss_score": score,
            "cvss_severity": cvss.get("baseSeverity"),
            "ref_count": len(refs),
            "poc_candidate_refs": _extract_poc_urls(refs)[:5],
        })

    # CVSS score 내림차순 + 최신 우선
    candidates.sort(key=lambda c: (-(c["cvss_score"] or 0.0), -(c["year"] or 0)))
    return {
        "query": {
            "framework": fw, "year_min": year_min, "cvss_min": cvss_min,
            "cwe_id": cwe_id, "limit": limit,
        },
        "total_results": body.get("totalResults", 0),
        "filtered_count": len(candidates),
        "candidates": candidates[:limit],
        "hint": (
            "각 candidate의 poc_candidate_refs 또는 fetch_cve_details(cve_id) 로 "
            "심화 분석. 검증된 핵심 CVE는 techniques/cve/*.md 로 큐레이션 권장."
        ),
    }


def _commodity_check_cve(keywords: str, cwe_id: str = "", limit: int = 5) -> dict:
    """NVD REST API에서 keywords로 CVE 검색.
    keywords는 페이로드 fragment, vuln 클래스명, 특이 함수명 등.
    """
    if not keywords or len(keywords.strip()) < 3:
        return {"available": True, "matches": [], "reason": "keywords too short"}
    params = {
        "keywordSearch": keywords[:200],
        "resultsPerPage": min(limit, 20),
    }
    if cwe_id:
        params["cweId"] = cwe_id

    headers = {}
    nvd_key = os.environ.get("NVD_API_KEY", "").strip()
    if nvd_key:
        headers["apiKey"] = nvd_key
    try:
        r = requests.get(NVD_API, params=params, headers=headers, timeout=10)
        if r.status_code != 200:
            return {
                "available": False,
                "reason": f"NVD HTTP {r.status_code}: {r.text[:200]}",
                "matches": [],
            }
        data = r.json()
        items = data.get("vulnerabilities", [])[:limit]
        matches = []
        for it in items:
            cve = it.get("cve", {})
            descs = cve.get("descriptions", [])
            desc_en = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
            matches.append({
                "cve_id": cve.get("id"),
                "published": cve.get("published"),
                "description": desc_en[:300],
            })
        return {
            "available": True,
            "is_commodity_cve": bool(matches),
            "matches": matches,
            "total_results": data.get("totalResults", 0),
        }
    except Exception as e:
        return {"available": False, "reason": f"NVD query failed: {e}", "matches": []}


# ─────────────────────────────────────────────────────────────
# DuckDuckGo HTML search (free, no API key, scraping)
# ─────────────────────────────────────────────────────────────

def _commodity_check_web(query: str, limit: int = 5) -> dict:
    """DuckDuckGo HTML 결과 페이지에서 결과 갯수 추출.
    무료지만 anti-bot에 막힐 수 있음. 막히면 available=False.
    """
    if not query or len(query.strip()) < 3:
        return {"available": True, "matches": [], "reason": "query too short"}
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
        ),
    }
    try:
        r = requests.post(
            DDG_HTML, data={"q": query[:300]}, headers=headers, timeout=10
        )
        if r.status_code != 200:
            return {
                "available": False,
                "reason": f"DDG HTTP {r.status_code}",
                "matches": [],
            }
        body = r.text
        # 결과 링크 패턴: <a class="result__a" href="..."> title </a>
        results: list[dict] = []
        for m in re.finditer(
            r'<a[^>]*class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"[^>]*>([^<]+)</a>',
            body,
        ):
            results.append({
                "title": unescape(m.group(2)).strip()[:160],
                "url": unescape(m.group(1)).strip()[:300],
            })
            if len(results) >= limit:
                break
        return {
            "available": True,
            "is_commodity_web": bool(results),
            "matches": results,
            "query": query[:200],
        }
    except Exception as e:
        return {"available": False, "reason": f"DDG query failed: {e}", "matches": []}


# ─────────────────────────────────────────────────────────────
# MCP 등록
# ─────────────────────────────────────────────────────────────

def register(mcp):

    @mcp.tool()
    async def commodity_check_local(payload: str, vuln_type: str = "") -> str:
        """로컬에 내려둔 payloadbox 목록(SQLi/XSS/CMDi/LFI/SSRF)에서 substring 매칭.

        payload가 공개 페이로드 list에 이미 있으면 commodity. 매치 0이면 첫 번째 통과.
        Verifier가 is_novel 판단 시 이 결과를 1차 증거로 사용 권장.
        """
        from asgiref.sync import sync_to_async
        try:
            result = await sync_to_async(_commodity_check_local, thread_sensitive=True)(
                payload=payload, vuln_type=vuln_type or "",
            )
            return json.dumps(result, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": f"commodity_check_local failed: {e}"})

    @mcp.tool()
    async def commodity_check_cve(keywords: str, cwe_id: str = "") -> str:
        """NVD REST API에서 키워드로 CVE 검색. 매치 있으면 known variant 가능성 큼.

        keywords는 페이로드의 핵심 fragment 또는 특이 함수명 (예: "Flask render_template",
        "PHP filter base64-encode"). cwe_id 옵션 (예: "CWE-89").
        """
        from asgiref.sync import sync_to_async
        try:
            result = await sync_to_async(_commodity_check_cve, thread_sensitive=True)(
                keywords=keywords, cwe_id=cwe_id or "",
            )
            return json.dumps(result, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": f"commodity_check_cve failed: {e}"})

    @mcp.tool()
    async def fetch_cve_details(cve_id: str) -> str:
        """단일 CVE의 NVD 상세 — description / CVSS / weaknesses / affected CPE / references / PoC 후보 URL.

        시드 큐레이션 없이 just-in-time variant analysis 가능.
        poc_candidate_refs 의 URL을 http_request 로 가져와 trigger 코드 분석 → 자체 변종 작성.

        Args:
            cve_id: 예 "CVE-2024-34102"
        """
        from asgiref.sync import sync_to_async
        try:
            result = await sync_to_async(_fetch_cve_details, thread_sensitive=True)(cve_id=cve_id)
            return json.dumps(result, ensure_ascii=False, default=str)
        except Exception as e:
            return json.dumps({"error": f"fetch_cve_details failed: {e}"})

    @mcp.tool()
    async def suggest_cves_for_framework(
        framework: str,
        year_min: int = 0,
        cvss_min: float = 0.0,
        cwe_id: str = "",
        limit: int = 10,
    ) -> str:
        """framework 키워드 → NVD에서 매칭되는 CVE 목록 (CVSS 정렬).

        framework: 예 "magento", "spring boot", "wordpress", "laravel"
        year_min: 이 연도 이후 CVE만 (예 2022)
        cvss_min: 이 CVSS 이상만 (예 7.0)
        cwe_id: 선택 (예 "CWE-89")

        반환 항목 각각: cve_id + 설명 + CVSS + poc_candidate_refs.
        깊이 분석은 fetch_cve_details(cve_id) 추가 호출.
        """
        from asgiref.sync import sync_to_async
        try:
            result = await sync_to_async(_suggest_cves_for_framework, thread_sensitive=True)(
                framework=framework, year_min=int(year_min) if year_min else 0,
                cvss_min=float(cvss_min) if cvss_min else 0.0,
                cwe_id=cwe_id or "", limit=int(limit) if limit else 10,
            )
            return json.dumps(result, ensure_ascii=False, default=str)
        except Exception as e:
            return json.dumps({"error": f"suggest_cves_for_framework failed: {e}"})

    @mcp.tool()
    async def commodity_check_web(query: str) -> str:
        """DuckDuckGo HTML 검색 — 페이로드/패턴이 인터넷 어딘가에 이미 글로 있나 확인.

        결과 0건이면 진짜 novel 강한 신호. 결과 있으면 query를 인용한 글이 있다는 뜻.
        anti-bot에 막힐 수 있고(available=False), 그 경우 다른 채널로 판단.
        """
        from asgiref.sync import sync_to_async
        try:
            result = await sync_to_async(_commodity_check_web, thread_sensitive=True)(
                query=query,
            )
            return json.dumps(result, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": f"commodity_check_web failed: {e}"})
