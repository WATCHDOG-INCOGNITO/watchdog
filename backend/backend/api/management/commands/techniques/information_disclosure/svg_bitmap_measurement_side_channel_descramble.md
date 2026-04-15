---
name: svg_bitmap_measurement_side_channel_descramble
vuln_type: information_disclosure
sub_technique: svg_side_channel
category: exploitation
safety_level: safe
---

# Svg Bitmap Font Side-Channel — Noisy Measurement Artifacts + Prng Descramble + Majority Voting Recovers Flag

## When to Apply

A multi-origin web application encodes a secret (flag) as a bitmap font rendered into an SVG with `<rect filter=...>` elements (filtered = bit '1', clear = bit '0'). The SVG is only accessible to a staff bot via cookie authentication and protected by X-Frame-Options: DENY and CORP: same-site. However, a bot popup chain (coordinator → preview → export → inspector) measures each cell via a timing-like oracle: filtered cells receive a higher 'boost' value than clear cells in a signal/baseline delta measurement. The resulting deltaRows artifact is scrambled with a seeded Fisher-Yates column permutation and stored server-side. The attacker can poll the completed artifact along with the renderSeed and layoutSeed. By reproducing the xorshift PRNG, the column permutation can be reversed. A known header pattern (generated from layoutSeed) enables threshold calibration. Multiple sessions with majority voting reduce noise to recover the full bit matrix, which is decoded using 5×7 Adafruit GFX bitmap font matching.

## Prerequisites

- Flag encoded as 5×7 bitmap font in SVG <rect filter=...> elements
- Staff-only SVG endpoint with cookie auth + CORP: same-site + X-Frame-Options: DENY
- Bot popup chain that measures filtered/clear cells and produces noisy delta artifacts
- Completed artifact (deltaRows), renderSeed, and layoutSeed exposed via review API
- Fisher-Yates shuffle based on xorshift PRNG with seed derived from renderSeed
- Known header pattern generated from layoutSeed for threshold calibration
- parse5-based HTML validator accepts specific bootstrap config format
- Scan window constraint: scanWidth × scanHeight ≤ 350

## Steps

1. Register/login, create window-v1 config notes for each scan window\n   - Total bitmap: 297×7, window size 50×7 (6 windows)\n   - HTML must pass parse5 validator (section > svg > filter > feComponentTransfer > feFuncR/G/B + p)\n2. Submit for review → bot popup chain runs → noisy artifact generated\n3. Poll `GET /api/review/:sessionId` until `state=completed`\n   - Receive: deltaRows (scrambled), renderSeed, layoutSeed\n4. Descramble: reproduce xorshift PRNG from renderSeed\n   - Fisher-Yates full column permutation → rank-based local permutation for window slice\n   - Apply inverse permutation to deltaRows\n5. Threshold calibration: reproduce xorshift PRNG from layoutSeed\n   - Generate 20×7 known header pattern\n   - threshold = (mean(filtered_deltas) + mean(clear_deltas)) / 2\n6. Repeat 3× sessions per window → majority voting per pixel\n7. Decode: skip header(20) + spacer(2), split into 5×7 symbols\n   - Hamming distance match against Adafruit GFX 5×7 font → flag characters

## Code Template

```
# xorshift PRNG (matching JS implementation)\ndef xorshift(seed):\n    value = seed & 0xFFFFFFFF\n    def _next():\n        nonlocal value\n        value ^= (value << 13) & 0xFFFFFFFF\n        value ^= (value >> 17)\n        value ^= (value << 5) & 0xFFFFFFFF\n        value = value & 0xFFFFFFFF\n        return value / 0xFFFFFFFF\n    return _next\n\n# Fisher-Yates column order from renderSeed\ndef build_column_order(render_seed, width):\n    rng = xorshift(seed_from_hex(render_seed))\n    perm = list(range(width))\n    for i in range(width - 1, 0, -1):\n        j = int(rng() * (i + 1))\n        perm[i], perm[j] = perm[j], perm[i]\n    return perm
```

## Examples

### Example 1

- **origins**: 3-origin: app.pixelpad.local, share.pixelpad.local, account.pixelpad.local
- **bitmap_encoding**: 5×7 Adafruit GFX font → SVG <rect filter=...> for '1' bits, plain <rect> for '0'
- **measurement_oracle**: measureCell(): filtered=1 gets boost ~0.55+, clear=0 gets boost ~0.03+ (noisy)
- **scrambling**: Fisher-Yates shuffle with xorshift PRNG from renderSeed → column permutation
- **header_calibration**: 20-col random header from layoutSeed, known bits → threshold = midpoint of filtered/clear means
- **noise_reduction**: 3× session majority voting per pixel eliminates per-session noise
- **total_bitmap**: 297 columns × 7 rows, 6 scan windows of 50×7

This is a sophisticated multi-stage side-channel attack on a web application that encodes secrets in SVG bitmap data. The key insight is that even though the SVG is protected by strict access controls (staff cookie, CORP, X-Frame-Options), the bot's measurement popup chain leaks information through noisy delta artifacts that are accessible to the attacker. The noise is overcome through statistical analysis: known header bits enable per-session threshold calibration, and multi-session majority voting reduces error rate. The column scrambling is reversible because the renderSeed is exposed in the completed review data.
