---
name: password_reset_challenge_bruteforce_race
vuln_type: race_condition
sub_technique: reset_challenge_concurrent_bruteforce
category: exploitation
safety_level: cautious
tags:
- race-condition
- password-reset
- bruteforce
- concurrent
- session-race
---

# Password Reset Challenge Brute-Force With Concurrent Lock-Breaker Race

## When to Apply

A password reset flow uses a secure-code challenge (pick 2 words from N). The challenge_token is reusable for multiple submit attempts. A 'lock user' technique keeps one valid pass_reset_token alive via concurrent password-change requests, while worker threads brute-force the admin's 2-word challenge.

## Prerequisites

- Password reset with challenge (2 of N words, N=20 → 380 combos)
- No rate limiting on challenge submission
- challenge_token reusable across attempts
- Admin UUID discoverable (e.g. from transfer logs)
- Ability to create a lock user with known secure code

## Steps

1. Sign up base user, login, find admin UUID from /api/cash/krw/log.
2. Create lock user (username=LOCK:{admin_uuid}), save secure code.
3. Get lock user's challenge_token, solve it (known words), get pass_reset_token.
4. Start 16 breaker threads: continuously call change_password(lock_pass_token, ...) to keep the token alive.
5. Get admin's challenge_token, note the 2 required indices.
6. Start 100 worker threads: brute-force 380 word combinations against admin's challenge_token.
7. On match: get admin's pass_reset_token → change admin password → login.
8. Read admin memo containing flag.

## Code Template

```
combos = Queue()
for w1 in WORDS:
    for w2 in WORDS:
        if w1 != w2: combos.put((w1, w2))
# 16 lock-breaker threads + 100 brute-force workers
# On match → change_password(admin_pass_token, new_pw) → login('admin', new_pw)
```

## Examples

### Example 1

- **word_count**: 20
- **combo_space**: 20*19 = 380
- **workers**: 100
- **breaker_threads**: 16

The lock-breaker trick is the key insight: by continuously exercising a valid pass_reset_token, it prevents the challenge_token from being invalidated, allowing unlimited brute-force attempts.
