---
name: safe_strlen_content_length_desync
vuln_type: http_smuggling
sub_technique: content_length_desync
category: exploitation
safety_level: safe
tags:
- smuggling
- content-length
- desync
- php
- control-char
---

# Safe Strlen Content-Length Desync — Http Request Smuggling Via Control Character Truncation

## When to Apply

A PHP app computes Content-Length using a safe_strlen-style function that returns immediately on ctype_cntrl($c). When the actual body length differs from safe_strlen's result, a second request can be smuggled to the backend.

## Prerequisites

- PHP safe_strlen: for-loop + ctype_cntrl → return $len (early termination on control char)
- PHP forwards requests to backend via curl — keep-alive connection
- Backend (Node.js, etc.) reads body based on actual Content-Length, leaving remaining bytes as next request

## Steps

1. Analyze `safe_strlen` — check if it truncates length at first control char (\x00-\x1f)
2. Construct actual body: `VISIBLE_PART + \r + SMUGGLED_HTTP_REQUEST`
   → safe_strlen returns `len(VISIBLE_PART)`, but actual transmission is the full length
3. PHP sends POST to backend with `Content-Length: safe_strlen(body)` (keep-alive)
4. Backend reads only VISIBLE_PART as the first request body,
   remaining `\r + SMUGGLED_HTTP_REQUEST` is parsed as a new request
5. Insert desired endpoint/header/body into smuggled request for arbitrary actions

## Code Template

```
visible = b'action=healthcheck'
smuggled = (
    b'\r\n'
    b'POST /set/{key}/{value} HTTP/1.1\r\n'
    b'X-Auth: {auth_header}\r\n'
    b'Content-Length: 0\r\n'
    b'\r\n'
)
body = visible + b'\r' + smuggled  # \r triggers safe_strlen cutoff
# PHP sees Content-Length: len(visible), backend gets both requests
```

## Examples

### Example 1

- **safe_strlen_trigger**: \r (0x0d) or any ctype_cntrl char
- **frontend**: PHP curl → Node.js Express
- **smuggled_action**: POST /set/:key/:value

Solvable without smuggling if there's no input sanitization, but CL desync is required when danger()-style filters are present.

### Example 2

- **safe_strlen_trigger**: \r (0x0d)
- **frontend**: PHP curl → Node.js Express
- **smuggled_action**: POST /set/:key/:value — input filter bypass

danger()-style function filters pipe(|)/null/newline, so direct command injection in URL is not possible → bypass via CL desync.
