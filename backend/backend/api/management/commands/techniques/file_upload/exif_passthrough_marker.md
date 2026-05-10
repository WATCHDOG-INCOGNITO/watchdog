---
name: exif_passthrough_marker
vuln_type: file_upload
sub_technique: exif_metadata_injection
category: exploitation
safety_level: safe
tags:
- exif
- image
- passthrough
- marker
---

# Exif Passthrough — Binary Marker + Json Payload

## When to Apply

The server searches uploaded JPEG EXIF data for magic bytes like `b"<MARKER>\x00"` and parses the following bytes as JSON (applies to all metadata-inspection type challenges)

## Prerequisites

- Server processes EXIF via piexif/PIL — only standard EXIF tags are dumped
- Raw bytes append (img.info['exif']) is dropped by PIL save
- MakerNote(0x927C) or UserComment(0x9286) are standard free-form binary tags in Exif IFD

## Steps

1. piexif.load(image_exif) → exif_dict
2. exif_dict['Exif'][piexif.ExifIFD.MakerNote] = b'<MARKER>\x00<JSON>'
   or use piexif.ExifIFD.UserComment (both accept free-form binary)
3. piexif.dump(exif_dict) → exif_bytes
4. img.save(out, format='JPEG', exif=exif_bytes)
5. Server runs exif_data.find(b'<MARKER>\x00') + len → JSON parse succeeds

## Code Template

```
import io, piexif
from PIL import Image
img = Image.new('RGB', (100,100), {color})
buf = io.BytesIO(); img.save(buf, format='JPEG')
exif_dict = piexif.load(buf.getvalue())
exif_dict['Exif'][piexif.ExifIFD.MakerNote] = b'{marker}\x00' + {json_bytes}
out = io.BytesIO()
Image.open(io.BytesIO(buf.getvalue())).save(out, format='JPEG',
                                            exif=piexif.dump(exif_dict))
```

## Examples

### Example 1

- **marker**: CUSTOM_MARKER
- **json_bytes**: b'{}'
- **tag_used**: MakerNote

UserComment / MakerNote both produce the same effect — server verification searches for the marker in the full img.info['exif'] bytes.
