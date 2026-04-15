---
name: python_sql_escape_type_bypass
vuln_type: sqli
sub_technique: escape_type_bypass
category: exploitation
safety_level: safe
---

# Python Sql Escape Type-Confusion Bypass — Non-String Values Skip Sanitization

## When to Apply

A Python/Flask API uses a custom sql_escape function that only sanitizes string values (isinstance(val, str)) before interpolating into SQL via str.format() or % formatting. If the sanitize helper itself has a calling-convention bug (e.g., missing argument) that crashes on string inputs, ALL string-bearing requests fail with 500, while non-string JSON values (int, bool, dict, list of ints) pass through unescaped. Attackers can submit non-string typed JSON values that get format()-interpolated into raw SQL.

## Prerequisites

- Custom sql_escape iterates JSON body keys and only escapes isinstance(val, str)
- sanitize() function has a calling bug (e.g., sanitize(val) instead of sanitize(conn, val)) causing TypeError on strings
- SQL queries use str.format() or % formatting with the unsanitized values
- express.json() / Flask request.get_json() parses full JSON types (int, bool, dict, null)

## Steps

1. Identify sql_escape: check if it only covers isinstance(val, str) — dicts/ints/bools pass through
2. Confirm sanitize bug: send a request with string values → 500 Internal Server Error
3. Send non-string values (integers, bools) that pass sql_escape without error
4. The value is interpolated into SQL via format() — integer pid works for normal queries
5. For UPDATE statements like `checksum = checksum + {}`, non-string values produce valid SQL
6. Combine with direct DB access if available to achieve full exploitation

## Code Template

```
import requests
# String values crash sql_escape
r = requests.post(f'{url}/endpoint', json={'field': 'string_value'})  # → 500
# Non-string values bypass sql_escape
r = requests.post(f'{url}/endpoint', json={'field': 123})  # → 200, value interpolated raw
# SQL: SELECT * FROM table WHERE field = '123'
```

## Examples

### Example 1

- **sql_escape_bug**: sanitize(val) instead of sanitize(conn, val) → TypeError on strings
- **bypass_type**: integer/bool/dict values skip isinstance(val, str) branch
- **affected_endpoints**: All POST endpoints using json_body() → sql_escape()

The broken sanitize effectively disables ALL string-based SQL escaping. Normal app functionality (join, login) is broken. Exploitation relies on non-string JSON types or direct DB access.
