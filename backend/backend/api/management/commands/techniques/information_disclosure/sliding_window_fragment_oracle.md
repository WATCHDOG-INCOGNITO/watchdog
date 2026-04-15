---
name: sliding_window_fragment_oracle
vuln_type: information_disclosure
sub_technique: fragment_oracle
category: exploitation
safety_level: safe
---

# Sliding Window Fragment Oracle — 4-Char Window Index Enables Character-By-Character Secret Extraction

## When to Apply

A server creates a sliding window index of all N-char substrings (default N=4) of a secret string (e.g., flag). An endpoint checks if a query matches any stored fragment and returns a distinguishable response (200 for hit, 404 for miss). The endpoint is protected by one-time visit tokens (wid + rv), and the response can be observed from an attacker page via script onload/onerror events. A bot (admin) visits attacker-controlled pages that trigger these probes with fresh tokens obtained per iteration through the application's workflow.

## Prerequisites

- Secret indexed as all N-char (typically 4) sliding windows in a fragment map
- Endpoint returns distinguishable responses based on fragment existence (200 vs 404)
- One-time visit tokens (rv) consumed per request — each probe needs a fresh token
- Fresh tokens obtainable by triggering application workflow (e.g., new follow-up ticket → admin mail → visit token)
- Bot (Playwright/Puppeteer) visits attacker page and navigates to token-bearing URLs
- Script tag onload/onerror usable as oracle from attacker's page
- Known prefix of the secret (e.g., flag format 'codegate2026{')

## Steps

1. Know the secret's prefix (e.g., `codegate2026{`) and charset (e.g., hex + `}`)
2. For each candidate character:
   a. Take last 3 chars of known prefix + candidate = 4-char window
   b. Trigger application workflow to generate a new visit token (wid, rv)
   c. Bot visits attacker page → attacker page gets wid+rv from URL params
   d. Attacker page creates `<script src='/mail/queue/assets/{wid}/{slot}.js?q={window}&rv={rv}'>`
   e. onload → HIT (character is correct), onerror → MISS
3. Extend known prefix with the correct character
4. Repeat until closing delimiter (e.g., `}`) is found
5. Each probe requires: prepare thread → send follow-up → wait for bot → collect result

## Code Template

```
# Oracle probe via script load\nscript = document.createElement('script')\nscript.onload = () => report('HIT')\nscript.onerror = () => report('MISS')\nscript.src = assetURL(wid, candidate_4char, bucket, rv)\ndocument.head.appendChild(script)
```

## Examples

### Example 1

- **window_size**: 4 characters (archiveWindowSize = 4)
- **secret_format**: codegate2026{hex_chars} — known prefix + hex charset + closing brace
- **oracle_endpoint**: /mail/queue/assets/{resumeRef}/{slot}.js?q={query}&bucket={bucket}&rv={visitToken}
- **token_flow**: follow-up ticket → worker → admin mail → bot opens → iframe postMessage → /mail/open/ → wid+rv
- **response**: 200 + JS body if HasFragment(query)=true, 404 otherwise

The archive stores ALL 4-char windows of the secret, so probing 'ate2' confirms that 'ate2' appears somewhere in the secret. By using the last 3 known chars + 1 candidate, each probe uniquely identifies the next character. The one-time visit token prevents replay but can be obtained repeatedly through the application workflow. The total number of probes is O(|secret| * |charset|), e.g., ~24 chars * 17 candidates ≈ 408 probes.
