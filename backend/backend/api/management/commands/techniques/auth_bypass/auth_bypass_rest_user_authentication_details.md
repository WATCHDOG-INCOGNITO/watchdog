---
name: auth_bypass_rest_user_authentication_details
vuln_type: auth_bypass
category: exploitation
safety_level: safe
tags:
- auth_bypass
---

# Auth Bypass /Rest/User/Authentication-Details

## When to Apply

JWT 'none' algorithm bypass on authentication endpoint - critical auth bypass exposing full user database

## Prerequisites

- Target vulnerable to auth_bypass

## Steps

1. Send the following payload:

```
{{JWT_NONE_ALG_EXAMPLE}} 
```

2. Verify with oracle or response analysis.

## Code Template

```
{{JWT_NONE_ALG_EXAMPLE}} 
```

## Examples

### Example 1

- **original_endpoint**: /rest/user/authentication-details
- **oracle_signatures**: `["200 OK with full user data dump including admin accounts and deluxe tokens"]`

Succeeded 1/1 times.
