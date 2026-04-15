---
name: compression_dict_header_injection_dcz_mismatch_dom_xss
vuln_type: xss
sub_technique: compression_dict_mismatch_xss
category: exploitation
safety_level: cautious
tags:
- compression-dictionary
- dcz
- header-injection
- dom-xss
- dictionary-mismatch
- bot
---

# Use-As-Dictionary Header Injection Via Title → Dcz Dictionary Mismatch → Dom Breakout Xss

## When to Apply

A Flask app sets `Use-As-Dictionary` header using user-controlled title without full Structured Header validation. The server does not verify the Available-Dictionary hash from the browser. This allows an attacker to make the browser cache dictionary A but the server compresses with dictionary B, causing dcz decompression mismatch that corrupts HTML and breaks tag boundaries, enabling XSS.

## Prerequisites

- HTTPS proxy (secure context required for Compression Dictionary Transport)
- Server uses user-controlled title in Use-As-Dictionary header
- Server skips Available-Dictionary hash verification
- Bot visits path1 then path2 (dictionary warmup + trigger)
- External request bin (e.g. ptsv3.com) for exfiltration

## Steps

1. Register/login via HTTPS proxy URL.
2. Create TARGET doc v1, visit /doc/{id}/1 to warm dict cache.
3. Create attacker doc with title injecting extra dict id binding:
   `title = 'AA", match="/x", ttl=1, id="dict-{target_id}-TARGET'`
4. Create v1 and v2 with crafted content pairs (c1/c2) designed so that post-mismatch decompression produces executable `<img onerror=...>` tags.
5. Submit to /bot: path1=doc/{atk}/1, path2=doc/{atk}/2.
6. Bot loads path1 (dictionary cached), then path2 (dcz mismatch → DOM XSS).
7. XSS fetches /admin and POSTs body to ptsv3.com.
8. Poll ptsv3 API for flag.

## Code Template

```
inj_title = f'AA", match="/x", ttl=1, id="dict-{target_id}-TARGET'
s.post(f'{base}/upload', data={'title': inj_title, 'content': c1})
s.post(f'{base}/edit/{atk_id}', data={'title': inj_title+'-v2', 'content': c2})
s.post(f'{base}/bot', data={'path1': f'doc/{atk_id}/1', 'path2': f'doc/{atk_id}/2'})
```

## Examples

### Example 1

- **header_injection**: title containing `"` to break Structured Header field
- **dcz_mismatch**: browser dict A vs server dict B → corrupted decompression
- **xss_trigger**: onerror handler in corrupted DOM

Compression Dictionary Transport (CDT) is a relatively new browser feature. The attack exploits the gap between browser-side dictionary and server-side dictionary when hash verification is missing.
