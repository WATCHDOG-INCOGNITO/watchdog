---
name: headless_bot_click_hijack_css_overlay
vuln_type: xss
sub_technique: css_clickjacking
category: exploitation
safety_level: safe
tags:
- clickjacking
- headless-browser
- puppeteer
- css
- bot
- ui-redress
---

# Headless Bot Click Hijacking Via Css Absolute Position Overlay

## When to Apply

A CTF or web app has a headless browser bot (Puppeteer, etc.) that visits a page and clicks a specific element (#delete, etc.). User-controllable HTML/CSS can overlay another element on top of the click target, hijacking the bot's click to perform a different action (form submit, etc.).

## Prerequisites

- Headless browser bot visits a page and clicks a specific element
- User can insert form/button into HTML content
- CSS absolute/fixed positioning is available (theme traversal, inline style, etc.)
- Bot visits with an authenticated session (cookie)

## Steps

1. Analyze bot behavior: `page.$('#delete').click()` etc.
2. Insert `<form action="/target">` + `<button class="slider">` into user content
3. CSS (.slider) covers entire area with position: absolute + width/height: 100%
4. Bot attempts to click #delete → actually clicks .slider submit button
5. Form sends GET request to /target with authenticated session → delivers attacker payload

## Code Template

```
<!-- Post content with clickjack overlay -->
<form action="http://target/admin/test">
    <input type="hidden" name="title" value="{b64_title}">
    <input type="hidden" name="content" value="{b64_xss_payload}">
    <button type="submit" class="slider"></button>
</form>
<!-- theme: ../switch loads CSS with .slider { position: absolute } -->
```

## Examples

### Example 1

- **bot_action**: page.$('#delete').click()
- **overlay_css**: .slider { position: absolute; cursor: pointer; width: 100%; height: 100% }
- **redirect_target**: /admin/page?title=...&content=<b64_xss>
- **bot_cookie**: JWT with sensitive data in claims
