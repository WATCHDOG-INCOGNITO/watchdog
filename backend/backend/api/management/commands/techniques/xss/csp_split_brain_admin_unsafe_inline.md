---
name: csp_split_brain_admin_unsafe_inline
vuln_type: xss
sub_technique: csp_bypass
category: exploitation
safety_level: safe
tags:
- csp
- unsafe-inline
- admin
- xss
- policy-inconsistency
---

# Csp Split-Brain — Unsafe-Inline On Admin Routes Enables Xss Execution

## When to Apply

The web app applies different CSP policies per route, and admin routes have script-src 'unsafe-inline'. XSS is blocked on public pages via nonce-based CSP, but becomes executable when redirected to admin pages.

## Prerequisites

- Admin route: script-src 'self' 'unsafe-inline'
- Public route: script-src 'nonce-...'
- Admin page has a sink that reflects user input (innerHTML, etc.)
- A way to direct users to the admin page (form submit, redirect, etc.)

## Steps

1. Analyze CSP headers: `req.path.startsWith('/admin')` → unsafe-inline
2. Confirm XSS payload is blocked by CSP on public pages
3. Find a sink on admin pages that accepts user input (innerHTML, eval, etc.)
4. Insert form/redirect to admin page in stored content on public pages
5. When victim (bot) visits admin page, XSS executes under unsafe-inline CSP

## Code Template

```
// Express middleware CSP config (vulnerable pattern)
if (req.path.startsWith('/admin')) {
  res.setHeader('CSP', "script-src 'self' 'unsafe-inline'");
} else {
  res.setHeader('CSP', `script-src 'nonce-${nonce}'`);
}
// innerHTML = userInput on admin page → XSS possible
```

## Examples

### Example 1

- **admin_csp**: default-src 'self'; script-src 'self' 'unsafe-inline'; base-uri 'none'
- **public_csp**: default-src 'self'; script-src 'nonce-{random}'; base-uri 'none'
- **admin_sink**: /admin/page → atob(params) → fetch /admin/sanitize → innerHTML
