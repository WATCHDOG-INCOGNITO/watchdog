---
name: js_asi_const_overwrite
vuln_type: xss
sub_technique: js_parser_quirk
category: exploitation
safety_level: safe
tags:
- javascript
- asi
- const
- parser-quirk
- nodejs
---

# Js Automatic Semicolon Insertion — Const Literal Overwrite

## When to Apply

In JavaScript source, `const X = "<value>"` is not followed by a semicolon and the next line starts with `[a, b] = expr`. ASI interprets `[` after a string literal as member-access and does not insert a semicolon → the whole thing is parsed as a single statement `const X = "..."[a,b] = expr`. The comma expression `[a,b]` evaluates to `b` → `"..."[b] = expr` is a string prop assignment (silent fail in sloppy mode), and the assignment expression value = expr. Result: `const X = expr` — const overwritten with attacker-controlled value.

## Prerequisites

- Analyzable JS source (difficult in blackbox, but possible with source leak/writeup)
- Declaration: `const X = "literal"` missing semicolon at end
- Immediately next line: `[var1, var2] = <attacker_controlled_expr>`
- Sloppy mode (strict mode would throw TypeError — must not be strict)
- Subsequent comparison: `X == something` where attacker can make expr value equal to one side

## Steps

1. Search JS source for `const ... = "..."` lines missing a trailing semicolon.
2. If the next line matches `[...] = <expr>` pattern, `X` is overwritten with expr.
3. Check for comparison (`if (X == target)`) — if attacker can make expr result equal to target, the check is bypassed.
4. Exploit JS loose equality (`==`) coercion — e.g.: `["0000"] == false` → array→string `"0000"` → number `0` ↔ `false` → `0` → true.
5. Inject payload into expr source (req.query, req.body, etc.).


## Code Template

```
// vulnerable source pattern:
//   const TARGET = "..."
//   [a, b] = req.query.X !== undefined ? atob(req.query.X).split("|") : [...]
// attacker sends X=<base64> such that after atob+split, compared value == initial false/0/null.
// example: X=MDAwMA== (atob="0000") → TARGET=["0000"] → ["0000"] == false → 0==0 → true

```

## Examples

### Example 1

- **guess**: MDAwMA==
- **atob_decoded**: 0000
- **final_compare**: ["0000"] == false  -> "0000" == 0 -> true
- **overwritten_const**: SecretVariable

const SecretVariable = "[REDACTED]"\n[param1, param2] = req.query.guess !== undefined ? atob(req.query.guess).split("|") : [...] → ASI fails, parsed as one statement. Attacker controls guess → SecretVariable itself is overwritten with an array. Comparison operand is false (initial value), so array→0 coercion matches.
