---
name: dns_rebinding_sw_speculation_rules_prefetch_exfil
vuln_type: xss
sub_technique: dns_rebinding_sw_prefetch
category: exploitation
safety_level: cautious
tags:
- dns-rebinding
- service-worker
- speculation-rules
- prefetch
- sec-fetch
- pna-bypass
- bot
---

# Dns Rebinding → Admin Login + Speculationrules Prefetch + Service Worker Head/Tail Split Exfil

## When to Apply

The target checks sec-fetch-mode/sec-fetch-dest headers: `document` requests return only first 8 chars of flag, other modes return the tail. PNA (Private Network Access) blocks direct JS fetch to 127.0.0.1. DNS rebinding (rbndr.us) is needed to get same-origin JS execution on localhost. Service Worker intercepts navigate requests to exfil tail, while speculationrules prefetch + cache read recovers head.

## Prerequisites

- sec-fetch-dest=document returns partial flag (head)
- Other sec-fetch-dest returns remaining flag (tail)
- PNA blocking direct fetch to 127.0.0.1 from external origins
- DNS rebinding service (rbndr.us or equivalent)
- Chrome with Service Worker and Speculation Rules support
- CSRF token required for login/register

## Steps

1. Register user + get CSRF token + session cookie from target (ex1.py).
2. Set up Flask server (ex2.py) on attacker IP, serving /final and /sw.js.
3. /final HTML: registers Service Worker, sets session cookie, flushes DNS cache (1000 requests to nip.io), logs in as admin via form POST, creates speculationrules for /flag prefetch.
4. /sw.js: intercepts navigate to /flag → exfils tail to listener. On message event, fetches /flag?head=1 with cache: only-if-cached → exfils head.
5. DNS rebinding: initial resolution → attacker IP, subsequent → 127.0.0.1.
   URL: `http://{attacker_hex}.7f000001.rbndr.us:{port}/final`
6. Submit URL to /report. Bot opens it.
7. After DNS rebind, form POST to /login hits localhost → admin session.
8. Speculation rules prefetch /flag?head=1 (cached) and /flag?pre=... (SW intercepts tail).
9. SW message: cache-only fetch for head. Combine head + tail = full flag.

## Code Template

```
# DNS rebinding URL
url = f'http://{attacker_hex}.7f000001.rbndr.us:{port}/final'
# Speculation rules (injected by /final JS)
spec = JSON.stringify({prefetch: [{source: 'list', urls: ['/flag?head=1', '/flag?pre=...']}]})
# SW tail exfil
self.addEventListener('fetch', (event) => {
  if (url.pathname === '/flag' && event.request.mode === 'navigate') {
    event.respondWith(fetch(event.request).then(res => { /* clone + exfil tail */ }))
  }
})
```

## Examples

### Example 1

- **dns_service**: rbndr.us ({attacker_hex}.{target_hex}.rbndr.us)
- **dns_flush**: 1000 requests to nip.io to evict Chrome DNS cache
- **flag_split**: sec-fetch-dest=document → head (8 chars), other → tail

PNA prevents simple fetch to 127.0.0.1 but DNS rebinding bypasses this. The Speculation Rules API enables prefetch without full navigation. Service Worker is essential because the flag endpoint splits output by sec-fetch-dest, requiring both a navigate request (tail) and a cached prefetch (head).
