---
name: sqli_union_select_native_crypto_unicorn_emulation
vuln_type: sqli
sub_technique: union_select_encrypted_download
category: exploitation
safety_level: cautious
tags:
- sqli
- union
- android
- native-lib
- unicorn
- aes
- reverse-engineering
---

# Sql Injection Union Select + Encrypted File Download + Unicorn Native Decryption Emulation

## When to Apply

An Android DRM app's API has SQLi in the `id` parameter of `request_book`. The server returns a download token + fileKey. The downloaded file is encrypted by a native library (libnative-lib.runtime.so) with a custom AES-like cipher. Paths, headers, and keys are RC4-obfuscated in APK resources.

## Prerequisites

- APK decompilation to recover hidden API paths and auth headers
- SQL injection in request_book?id= parameter
- Extracted .so from APK's lib/ directory
- Unicorn emulator (or actual Android device) to run native decryption

## Steps

1. Decompile APK, extract RC4-encrypted paths/headers from resources.
2. Send `request_book?id=1 UNION SELECT '/flag'` with recovered UA + Auth headers.
3. Download encrypted blob via `/download/<token>`.
4. Parse fileKey: key16=fileKey[0:16], nonce12=fileKey[16:28], trailer=last 16 bytes.
5. Load libnative-lib.runtime.so into Unicorn (x86_64).
6. Stub libc calls (malloc, calloc, free, memset, memcpy).
7. Hook 0x6B100 to return 0 (force software crypto path).
8. Call: 0x6B200(key_schedule) -> 0x6A8F0(derive_state) -> 0x6ADC0(decrypt_stream).
9. Read plaintext flag from emulator memory.

## Code Template

```
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
emu = Uc(UC_ARCH_X86, UC_MODE_64)
emu.mem_map(M_BASE, 0x500000)
emu.mem_write(M_BASE, Path(LIB_PATH).read_bytes())
# hook libc stubs + force software path
call(0x6B200, [key_ctx+0x10, key_ptr, 16])
call(0x6A8F0, [key_ctx, 16, nonce_ptr, tmp_ptr])
call(0x6ADC0, [tmp_ptr+0x18, nonce_len, trailer_ptr, ct_ptr, ct_len, out_ptr])
```

## Examples

### Example 1

- **sqli_payload**: 1 UNION SELECT '/flag'
- **hidden_headers**: RC4-encrypted UA and Bearer token extracted from APK resources

The APK stores all sensitive strings (paths, headers) encrypted with RC4. The native crypto uses a 3-step initialization that must be called in exact order. Hooking the hardware-detection function to return 0 forces the software fallback path.
