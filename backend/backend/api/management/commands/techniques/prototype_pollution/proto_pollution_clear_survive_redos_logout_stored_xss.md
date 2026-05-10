---
name: proto_pollution_clear_survive_redos_logout_stored_xss
vuln_type: prototype_pollution
sub_technique: proto_clear_survive_redos_xss
category: exploitation
safety_level: cautious
tags:
- prototype-pollution
- redos
- stored-xss
- session-race
- dayjs
- bot
---

#   Proto   User Session Survives /Clear → Time Format Pollution + Redos Logout Delay + Stored Xss

## When to Apply

An app stores user data as `accounts[username].content`. Creating a user named `__proto__` and writing to it after /clear (which deletes all accounts but preserves sessions) pollutes Object.prototype via `accounts['__proto__'].content`. dayjs format() has O(n^2) regex behavior on certain inputs, usable to delay the event loop and prevent /logout from completing before stored XSS executes.

## Prerequisites

- accounts['__proto__'].content structure pollutes Object.prototype
- /clear deletes accounts but keeps sessions alive
- dayjs format() with superlinear regex cost
- Bot logs in as admin, visits attacker page, then hits /logout
- Stored XSS (HTML in content rendered without sanitization)

## Steps

1. Create `__proto__` account, login, call /clear → session persists.
2. Write TIME_FORMAT.content = 'YYYY-MM-DD HH:mm:ss' to leak viewtime.
3. Create attacker account (country=content), visit /view to get viewtime.
4. Call /check?day=<viewtime> to set checked=true.
5. Write stored XSS to attacker's content: repeatedly fetch /view?username=admin, then login as attacker and /write flag to own page.
6. Change TIME_FORMAT.content to '[' * 20000 for ReDoS.
7. Trigger bot: /bot?path=/view?username=attacker.
8. Immediately send parallel /view?username=dos requests to delay event loop.
9. Bot's /logout is delayed → XSS runs with admin session → flag saved to attacker's view.

## Code Template

```
# Phase 1: pollution
session.post(f'{BASE}/write', data={'content': 'YYYY-MM-DD HH:mm:ss'})  # as '__proto__' user
# Phase 2: stored XSS
xss = '<script>...fetch /view?username=admin...write flag...</script>'
# Phase 3: ReDoS
session.post(f'{BASE}/write', data={'content': '[' * 20000})  # as '__proto__'
# Phase 4: trigger
session.post(f'{BASE}/bot', data={'path': '/view?username=attacker'})
```

## Examples

### Example 1

- **pollution_path**: accounts['__proto__'].content → Object.prototype.content
- **redos_payload**: '[' * 20000 → dayjs format O(n^2)
- **delay_achieved**: 0.4-0.6s per /view request

The ReDoS is not for denial-of-service but for a precise timing attack: delaying /logout just long enough for the stored XSS to execute with the admin's still-active session.
