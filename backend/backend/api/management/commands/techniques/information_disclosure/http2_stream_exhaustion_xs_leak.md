---
name: http2_stream_exhaustion_xs_leak
vuln_type: information_disclosure
sub_technique: xs_leak_http2
category: exploitation
safety_level: safe
---

# Http/2 Stream Multiplexing Exhaustion — Xs-Leak Via Pending Response Oracle

## When to Apply

A web application is served behind an HTTP/2-enabled reverse proxy (nginx with `http2 on`) that has a limited number of concurrent streams per connection (default 128). An endpoint returns a pending/incomplete response for certain inputs (e.g., missing file → NestJS `return;` without `res.sendFile()` when using `@Res()` without passthrough). Another endpoint performs a prefix-based file lookup that returns data for correct prefixes but hangs for wrong ones. The application uses `SameSite=None; Secure` cookies and `frame-ancestors: *` CSP, allowing cross-site iframe embedding with authenticated context. A side-channel view-count mechanism (e.g., POST `/api/memo/:id/view` after rendering) serves as the oracle.

## Prerequisites

- HTTP/2 enabled on reverse proxy with limited concurrent streams (nginx default: 128)
- Endpoint that returns pending/hanging response for invalid inputs (NestJS @Res() without passthrough)
- Admin-only endpoint with prefix-based file matching (file.startsWith(input))
- SameSite=None + Secure cookie → cross-site iframe sends credentials
- CSP frame-ancestors: * → page embeddable in attacker iframe
- View count or similar side-effect that depends on remaining available streams
- Bot that visits attacker-controlled URL while authenticated as admin
- DOMPurify-sanitized HTML allowing <img> tags with same-origin src

## Steps

1. Identify HTTP/2 behind nginx: check `http2 on` in nginx.conf, default 128 streams
2. Find pending response endpoint: `/api/image?filename=nonexistent` hangs (NestJS @Res() bug)
3. Find prefix-match admin endpoint: `/api/image/admin?filename=flag_X` returns image or hangs
4. Confirm SameSite=None cookie + frame-ancestors: * CSP
5. Create N memos (one per candidate char), each containing:
   - 127 `<img src="/api/image?filename=N">` to occupy 127 of 128 streams with pending responses
   - 1 `<img src="/api/image/admin?filename=prefix_GUESS">` as the 128th stream
6. Share each memo and collect sharedKeys
7. Host attacker page that loads each shared memo in sequential iframes
8. Bot visits attacker page → admin cookie sent → iframes load in admin context
9. For correct guess: admin image returns → connection freed → view POST succeeds → views=1
10. For wrong guess: all 128 streams blocked → view POST queued → views=0
11. Check view counts as oracle → extract one character per round
12. Repeat for each hex character of the flag filename

## Code Template

```
// Create 16 memos (0-9a-f), each blocking 127 streams + 1 guess stream\nconst CHARS = '0123456789abcdef';\nconst TEMPLATE = Array.from({length: 127}, (_, i) =>\n    `<img src=\"/api/image?filename=${i+1}\">`\n).join('');\nfor (let c of CHARS) {\n    await createMemo({\n        title: 'test_' + c,\n        content: TEMPLATE + `<img src=\"/api/image/admin?filename=${leaked}${c}\">`,\n    });\n}\n// Share memos, bot visits iframe page, check views==1 for correct char
```

## Examples

### Example 1

- **proxy**: nginx with http2 on, 128 default max concurrent streams
- **pending_endpoint**: /api/image?filename=N (nonexistent → NestJS return; hangs)
- **admin_endpoint**: /api/image/admin with startsWith() prefix file matching
- **cookie**: SameSite=None; Secure; HttpOnly → sent in cross-site iframes
- **csp**: frame-ancestors: * → any origin can iframe the app
- **oracle**: memo view count (POST /api/memo/:id/view) succeeds only if streams available
- **flag_format**: flag_{hex16}.png → 16 hex chars to leak

The key insight is HTTP/2 multiplexing: all requests share one TCP connection with limited streams. By filling 127/128 streams with pending responses, only 1 stream remains. If the guess is correct, the admin image returns and frees the connection, allowing the view-count POST to succeed. If wrong, all 128 streams are blocked. nginx keepalive_requests=2500 ensures no mid-leak connection reset. sec-fetch-site: same-origin check is bypassed because <img> loads within same-origin iframe.
