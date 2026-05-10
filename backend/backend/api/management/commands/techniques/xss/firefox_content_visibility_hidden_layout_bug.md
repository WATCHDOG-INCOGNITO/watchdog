---
name: firefox_content_visibility_hidden_layout_bug
vuln_type: xss
sub_technique: browser_layout_quirk
category: exploitation
safety_level: safe
tags:
- firefox
- content-visibility
- checkVisibility
- css
- browser-bug
- defense-bypass
---

# Firefox Content-Visibility:Hidden Bug — Checkvisibility()=False But Layout Still Works

## When to Apply

The web app implements a defense using JavaScript `element.checkVisibility()` to detect and remove CSS-displayed elements. A Firefox ESR 140.0 bug causes `content-visibility:hidden` to make `checkVisibility()` return false (bypassing the defense), while internal flex/grid layout, font loading, container queries, and background-image loading still work normally, enabling CSS-only attacks.

## Prerequisites

- Firefox ESR 140.0 (or version with this bug)
- JS defense relies on checkVisibility()
- Attacker can set content-visibility:hidden via CSS injection
- Side-channel via internal layout or resource loading required

## Steps

1. Analyze JS defense: `f.checkVisibility()` → if true, `f.remove()`
2. CSS injection: `#page { content-visibility: hidden !important; }`
3. `checkVisibility()` → returns false (defense bypassed)
4. Firefox bug: internal layout still works
5. Execute side-channel via flex layout + font ligature + container query
6. Ref: https://bugzilla.mozilla.org/show_bug.cgi?id=2025174

## Code Template

```
#page {
  content-visibility: hidden !important;
  display: flex !important;
  /* internal layout still works due to Firefox bug */
}
#flag {
  display: block !important;
  /* checkVisibility()=false so JS does not remove it */
}
```

## Examples

### Example 1

- **browser**: Firefox ESR 140.0 (headless)
- **bug_url**: https://bugzilla.mozilla.org/show_bug.cgi?id=2025174
- **defense**: setInterval(check, 50) + MutationObserver — checkVisibility() based
- **bypassed_checks**: `["display !== none", "checkVisibility() === true"]`
