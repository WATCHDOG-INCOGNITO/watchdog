"""Knowledge DB 시드 — VulnerabilityEntry + PayloadPattern 기본 세트.

사용:
    python manage.py seed_knowledge              # upsert (기본)
    python manage.py seed_knowledge --reset      # 기존 데이터 삭제 후 재시드
"""
from __future__ import annotations

from django.core.management.base import BaseCommand
from django.db import transaction

from api.embedding_service import (
    EMBEDDING_MODEL,
    embed_documents,
    is_available as embeddings_available,
    pattern_text,
)
from api.models import PayloadPattern, VulnerabilityEntry


# ── 취약점 정의 ────────────────────────────────────────────────

VULN_SEED: list[dict] = [
    {
        "title": "SQL Injection",
        "vuln_type": "sqli",
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021-Injection",
        "severity_default": "high",
        "description": (
            "사용자 입력이 SQL 쿼리에 직접 삽입되어, 데이터 유출/인증 우회/원격 코드 실행으로 이어질 수 있다."
        ),
        "preconditions": "요청 파라미터가 쿼리 컨텍스트(WHERE, ORDER BY 등)에 주입됨. prepared statement 미사용.",
        "impact": "DB 덤프, 인증 우회, 2차 RCE",
        "false_positive_hints": (
            "500 에러가 단순한 SQL 구문 오류일 수 있음. boolean-based/time-based로 확증하고 결과 폭을 비교."
        ),
        "evidence_points": "에러 문구 노출, true/false 응답 길이 차이, SLEEP 응답 지연.",
        "tags": ["injection", "db"],
    },
    {
        "title": "Reflected XSS",
        "vuln_type": "xss",
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021-Injection",
        "severity_default": "medium",
        "description": "사용자 입력이 HTML/JS 컨텍스트에 escape 없이 렌더링된다.",
        "preconditions": "입력이 HTML body, attribute, JS 리터럴, URL 컨텍스트에 반영됨.",
        "impact": "세션 탈취, CSRF 트리거, UI 조작",
        "false_positive_hints": (
            "입력이 반영되어도 `<`, `>`, `\"` 가 엔티티로 인코딩되면 실행 불가. "
            "실제 브라우저 렌더링 또는 CSP 확인 필수."
        ),
        "evidence_points": "페이로드가 원문 그대로 응답에 포함되고, 브라우저에서 JS 실행되는 스샷.",
        "tags": ["xss", "client"],
    },
    {
        "title": "IDOR (Insecure Direct Object Reference)",
        "vuln_type": "idor",
        "cwe_id": "CWE-639",
        "owasp_category": "A01:2021-Broken Access Control",
        "severity_default": "high",
        "description": "식별자(id/uid)를 바꿔 다른 사용자의 리소스에 인가 없이 접근한다.",
        "preconditions": "URL/Body에 수치/UUID 식별자가 있고, 서버가 소유자 체크를 수행하지 않음.",
        "impact": "타 사용자 PII 노출, 권한 상승",
        "false_positive_hints": (
            "동일 테넌트의 공개 리소스는 false positive. 서로 다른 세션(persona_a vs persona_b) "
            "간 응답 차이와 민감 필드 포함 여부로 확증."
        ),
        "evidence_points": "persona_b 토큰으로 persona_a 리소스 200 + 민감 필드 노출.",
        "tags": ["access-control", "authorization"],
    },
    {
        "title": "SSRF (Server-Side Request Forgery)",
        "vuln_type": "ssrf",
        "cwe_id": "CWE-918",
        "owasp_category": "A10:2021-Server-Side Request Forgery",
        "severity_default": "high",
        "description": "사용자가 제공한 URL을 서버가 직접 호출한다. 메타데이터/내부망 접근 가능.",
        "preconditions": "요청이 외부 URL을 파라미터로 받아 서버 측 fetch 수행.",
        "impact": "클라우드 메타데이터 유출, 내부 서비스 스캔, RCE 체이닝",
        "false_positive_hints": (
            "allow-list가 적용되어 내부 주소가 실제로 거부되는지 확인. DNS rebinding 여지도 고려."
        ),
        "evidence_points": "169.254.169.254/internal host 응답 본문 일부가 에코되는 증거.",
        "tags": ["ssrf", "server"],
    },
    {
        "title": "Local File Inclusion",
        "vuln_type": "lfi",
        "cwe_id": "CWE-22",
        "owasp_category": "A01:2021-Broken Access Control",
        "severity_default": "high",
        "description": "파일 경로 파라미터가 검증 없이 파일 시스템에 전달되어 임의 파일을 읽거나 실행한다.",
        "preconditions": "filename 파라미터가 open()/include() 등에 전달. path traversal 차단 미흡.",
        "impact": "소스코드/설정 노출, /etc/passwd 읽기, 때때로 RCE",
        "false_positive_hints": (
            "open_basedir나 chroot로 경로가 제한될 수 있음. 실제 민감 파일 내용이 응답에 포함돼야 확증."
        ),
        "evidence_points": "/etc/passwd 형식 본문, web.config/Procfile 등 내부 파일 노출.",
        "tags": ["path-traversal", "file"],
    },
    {
        "title": "Open Redirect",
        "vuln_type": "open_redirect",
        "cwe_id": "CWE-601",
        "owasp_category": "A01:2021-Broken Access Control",
        "severity_default": "medium",
        "description": "redirect 대상 URL을 사용자가 제어해 피싱/세션 탈취에 이용할 수 있다.",
        "preconditions": "?next=/?returnTo= 등의 파라미터가 외부 URL을 허용.",
        "impact": "피싱, OAuth 코드 탈취",
        "false_positive_hints": "same-origin만 허용되면 악용 불가. 스킴과 호스트 비교.",
        "evidence_points": "Location 헤더 또는 meta refresh 가 공격자 도메인으로 지정됨.",
        "tags": ["redirect"],
    },
    {
        "title": "Command Injection",
        "vuln_type": "cmdi",
        "cwe_id": "CWE-78",
        "owasp_category": "A03:2021-Injection",
        "severity_default": "critical",
        "description": "사용자 입력이 shell 명령에 concat되어 임의 명령 실행이 가능하다.",
        "preconditions": "system(), exec(), subprocess(shell=True) 등에 사용자 입력 전달.",
        "impact": "RCE, 서버 장악",
        "false_positive_hints": (
            "sleep 기반 시간 차이, 독립 아웃바운드 DNS 콜백(OOB)로 확증. 에러만으로 판단 금지."
        ),
        "evidence_points": "OOB DNS 콜백, sleep 기반 응답 지연.",
        "tags": ["injection", "rce"],
    },
]


# ── 페이로드 패턴 ──────────────────────────────────────────────
# 각 항목의 vuln_type은 위 VULN_SEED와 매치되어야 한다.

PATTERN_SEED: list[dict] = [
    # ── SQLi ─────────────────────────────────────────────
    {
        "vuln_type": "sqli",
        "name": "SQLi boolean-based OR 1=1",
        "category": "detection",
        "safety_level": "safe",
        "request_template": "{param}=1' OR '1'='1",
        "matcher": {"type": "response_diff", "compare_to": "baseline", "indicator": "row_count_increase"},
        "safety_notes": "읽기 전용. WHERE 절 조작만 수행.",
        "tags": ["boolean-based"],
    },
    {
        "vuln_type": "sqli",
        "name": "SQLi error-based single-quote",
        "category": "detection",
        "safety_level": "safe",
        "request_template": "{param}=1'",
        "matcher": {"type": "regex", "pattern": "(?i)(sql syntax|sqlite|mysql|psql|ORA-|unclosed quotation)"},
        "safety_notes": "단순 에러 노출 확인용.",
        "tags": ["error-based"],
    },
    {
        "vuln_type": "sqli",
        "name": "SQLi time-based SLEEP",
        "category": "verification",
        "safety_level": "cautious",
        "request_template": "{param}=1 AND SLEEP(3)--",
        "matcher": {"type": "timing", "threshold_ms": 2500},
        "safety_notes": "요청 지연 유발. 서비스 영향 있을 수 있으니 저빈도로만 사용.",
        "tags": ["time-based"],
        "request_cost": 3,
    },
    {
        "vuln_type": "sqli",
        "name": "SQLi UNION SELECT column-probe",
        "category": "exploitation",
        "safety_level": "cautious",
        "request_template": "{param}=1 UNION SELECT NULL,NULL,NULL--",
        "matcher": {"type": "response_diff", "indicator": "column_count_match"},
        "safety_notes": "컬럼 수 탐색. 데이터 변경 없음.",
        "tags": ["union-based"],
    },
    # ── XSS ──────────────────────────────────────────────
    {
        "vuln_type": "xss",
        "name": "XSS reflected script tag",
        "category": "detection",
        "safety_level": "safe",
        "request_template": "{param}=<script>WATCHDOG_XSS()</script>",
        "matcher": {"type": "reflection", "needle": "<script>WATCHDOG_XSS()</script>"},
        "safety_notes": "본문 HTML 원문 반사 확인.",
        "tags": ["reflected"],
    },
    {
        "vuln_type": "xss",
        "name": "XSS attribute-break via onmouseover",
        "category": "detection",
        "safety_level": "safe",
        "request_template": "{param}=\" onmouseover=WATCHDOG_XSS() x=\"",
        "matcher": {"type": "reflection", "needle": "onmouseover=WATCHDOG_XSS()"},
        "safety_notes": "속성 컨텍스트 탈출 여부.",
        "tags": ["attribute"],
    },
    {
        "vuln_type": "xss",
        "name": "XSS img onerror",
        "category": "verification",
        "safety_level": "safe",
        "request_template": "{param}=<img src=x onerror=WATCHDOG_XSS()>",
        "matcher": {"type": "reflection", "needle": "onerror=WATCHDOG_XSS()"},
        "safety_notes": "script 필터 우회 확인.",
        "tags": ["html-injection"],
    },
    # ── IDOR ─────────────────────────────────────────────
    {
        "vuln_type": "idor",
        "name": "IDOR sequential id probe",
        "category": "detection",
        "safety_level": "safe",
        "request_template": "{param}={neighbor_id}",
        "matcher": {"type": "persona_diff", "indicator": "200_with_sensitive_fields"},
        "safety_notes": "보통 1→2→3. 다른 테넌트 접근 여부 확인.",
        "tags": ["access-control"],
    },
    {
        "vuln_type": "idor",
        "name": "IDOR uuid swap between personas",
        "category": "verification",
        "safety_level": "safe",
        "request_template": "{param}={persona_b_uuid}",
        "matcher": {"type": "persona_diff", "indicator": "cross_tenant_success"},
        "safety_notes": "persona_a 토큰으로 persona_b 리소스 획득 여부.",
        "tags": ["access-control"],
    },
    # ── SSRF ─────────────────────────────────────────────
    {
        "vuln_type": "ssrf",
        "name": "SSRF cloud metadata probe",
        "category": "detection",
        "safety_level": "cautious",
        "request_template": "{param}=http://169.254.169.254/latest/meta-data/",
        "matcher": {"type": "regex", "pattern": "(?i)(ami-id|instance-id|iam/security-credentials)"},
        "safety_notes": "AWS 메타데이터 노출 확인. 금지된 호스트 응답을 담지 말 것.",
        "tags": ["cloud-metadata"],
    },
    {
        "vuln_type": "ssrf",
        "name": "SSRF localhost loopback",
        "category": "detection",
        "safety_level": "safe",
        "request_template": "{param}=http://127.0.0.1:80/",
        "matcher": {"type": "response_diff", "indicator": "internal_banner"},
        "safety_notes": "loopback 호출 가능 여부.",
        "tags": ["loopback"],
    },
    {
        "vuln_type": "ssrf",
        "name": "SSRF OOB DNS callback",
        "category": "verification",
        "safety_level": "cautious",
        "request_template": "{param}=http://{oob_domain}/",
        "matcher": {"type": "oob", "channel": "dns"},
        "safety_notes": "interactsh 등 OOB 도메인 필요.",
        "tags": ["oob"],
        "request_cost": 2,
    },
    # ── LFI ──────────────────────────────────────────────
    {
        "vuln_type": "lfi",
        "name": "LFI etc/passwd traversal",
        "category": "detection",
        "safety_level": "safe",
        "request_template": "{param}=../../../../etc/passwd",
        "matcher": {"type": "regex", "pattern": "^root:.*:0:0:"},
        "safety_notes": "unix 시스템 식별.",
        "tags": ["path-traversal"],
    },
    {
        "vuln_type": "lfi",
        "name": "LFI null byte (legacy)",
        "category": "detection",
        "safety_level": "safe",
        "request_template": "{param}=../../../../etc/passwd%00.png",
        "matcher": {"type": "regex", "pattern": "^root:.*:0:0:"},
        "safety_notes": "구버전 PHP/런타임 대상.",
        "tags": ["null-byte"],
    },
    {
        "vuln_type": "lfi",
        "name": "LFI php filter wrapper",
        "category": "exploitation",
        "safety_level": "cautious",
        "request_template": "{param}=php://filter/convert.base64-encode/resource={file}",
        "matcher": {"type": "regex", "pattern": "^[A-Za-z0-9+/=]{40,}$"},
        "safety_notes": "PHP 대상. base64로 소스코드 유출.",
        "tags": ["php-wrapper"],
    },
    # ── Open Redirect ────────────────────────────────────
    {
        "vuln_type": "open_redirect",
        "name": "Open redirect absolute URL",
        "category": "detection",
        "safety_level": "safe",
        "request_template": "{param}=https://watchdog.example/",
        "matcher": {"type": "header", "name": "Location", "needle": "watchdog.example"},
        "safety_notes": "Location 헤더 또는 meta-refresh 검사.",
        "tags": ["redirect"],
    },
    # ── Command Injection ────────────────────────────────
    {
        "vuln_type": "cmdi",
        "name": "CMDi time-based semicolon sleep",
        "category": "verification",
        "safety_level": "cautious",
        "request_template": "{param}=; sleep 3",
        "matcher": {"type": "timing", "threshold_ms": 2500},
        "safety_notes": "sleep 유발. 운영 서비스에 저빈도로만.",
        "tags": ["time-based"],
        "request_cost": 3,
    },
    {
        "vuln_type": "cmdi",
        "name": "CMDi OOB via backtick nslookup",
        "category": "verification",
        "safety_level": "cautious",
        "request_template": "{param}=`nslookup {oob_domain}`",
        "matcher": {"type": "oob", "channel": "dns"},
        "safety_notes": "OOB 도메인 필요.",
        "tags": ["oob"],
    },
]


class Command(BaseCommand):
    help = "Seed Knowledge DB (VulnerabilityEntry + PayloadPattern)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset",
            action="store_true",
            help="기존 시드 데이터(source='seed')를 삭제하고 재시드",
        )
        parser.add_argument(
            "--skip-embeddings",
            action="store_true",
            help="Voyage 임베딩 생성 단계를 건너뜀",
        )

    @transaction.atomic
    def handle(self, *args, **opts):
        if opts.get("reset"):
            deleted_p = PayloadPattern.objects.filter(source="seed").delete()
            deleted_v = VulnerabilityEntry.objects.filter(
                patterns__source="seed"
            ).distinct().delete()
            self.stdout.write(self.style.WARNING(
                f"reset: patterns {deleted_p}, vulnerabilities {deleted_v}"
            ))

        vuln_by_type: dict[str, VulnerabilityEntry] = {}
        for v in VULN_SEED:
            entry, created = VulnerabilityEntry.objects.update_or_create(
                vuln_type=v["vuln_type"],
                title=v["title"],
                defaults={
                    "cwe_id": v.get("cwe_id"),
                    "owasp_category": v.get("owasp_category"),
                    "severity_default": v.get("severity_default", "medium"),
                    "description": v.get("description"),
                    "preconditions": v.get("preconditions"),
                    "impact": v.get("impact"),
                    "false_positive_hints": v.get("false_positive_hints"),
                    "evidence_points": v.get("evidence_points"),
                    "tags": v.get("tags"),
                },
            )
            vuln_by_type[v["vuln_type"]] = entry
            self.stdout.write(
                f"  vuln {'+' if created else '='} {v['vuln_type']:14s} {v['title']}"
            )

        created_cnt = 0
        updated_cnt = 0
        for p in PATTERN_SEED:
            vuln = vuln_by_type.get(p["vuln_type"])
            if vuln is None:
                self.stdout.write(self.style.WARNING(
                    f"skip pattern (no vuln): {p['name']}"
                ))
                continue
            defaults = {
                "vulnerability": vuln,
                "vuln_type": p["vuln_type"],
                "category": p.get("category", "detection"),
                "safety_level": p.get("safety_level", "safe"),
                "request_template": p.get("request_template"),
                "matcher": p.get("matcher"),
                "safety_notes": p.get("safety_notes"),
                "request_cost": p.get("request_cost", 1),
                "tags": p.get("tags"),
                "source": "seed",
                "is_active": True,
            }
            obj, created = PayloadPattern.objects.update_or_create(
                name=p["name"],
                source="seed",
                defaults=defaults,
            )
            if created:
                created_cnt += 1
            else:
                updated_cnt += 1

        self.stdout.write(self.style.SUCCESS(
            f"\npatterns: +{created_cnt} created, ={updated_cnt} updated, "
            f"total vulns={len(VULN_SEED)}, total patterns={len(PATTERN_SEED)}"
        ))

        # ── 임베딩 생성 ────────────────────────────────────────
        if opts.get("skip_embeddings"):
            self.stdout.write("skip-embeddings: 임베딩 생성 건너뜀")
            return
        if not embeddings_available():
            self.stdout.write(self.style.WARNING(
                "Voyage 임베딩 비활성: VOYAGE_API_KEY 미설정 또는 voyageai 미설치 — "
                "search_knowledge 는 동작하지만 retrieve_similar_patterns 는 빈 결과 반환."
            ))
            return

        targets = list(
            PayloadPattern.objects.filter(source="seed").select_related("vulnerability")
        )
        if not targets:
            return

        texts = [pattern_text(p) for p in targets]
        self.stdout.write(f"embedding {len(texts)} patterns via {EMBEDDING_MODEL} ...")
        vectors = embed_documents(texts)
        if not vectors:
            self.stdout.write(self.style.WARNING("임베딩 생성 실패 — 건너뜀"))
            return

        for p, vec in zip(targets, vectors):
            p.embedding = vec
            p.embedding_model = EMBEDDING_MODEL
            p.save(update_fields=["embedding", "embedding_model"])
        self.stdout.write(self.style.SUCCESS(
            f"embeddings saved for {len(vectors)} patterns ({EMBEDDING_MODEL})"
        ))
