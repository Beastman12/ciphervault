# CipherVault file format — version 1

A vault is a single binary file. All integers are **big-endian**. Strings are length-prefixed with a `uint32` byte count and are UTF-8; they do not include a terminator.

## Layout

```
+-----------------------------------------------------+
| header (42 bytes)                                   |
+-----------------------------------------------------+
| ciphertext (ciphertext_len bytes)                   |
+-----------------------------------------------------+
| GCM tag (16 bytes)                                  |
+-----------------------------------------------------+
```

### Header (42 bytes, authenticated as AAD)

| Offset | Size | Field | Value |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `CVLT` (`43 56 4C 54`) |
| 4 | 1 | format version | `1` |
| 5 | 1 | KDF id | `1` = PBKDF2-HMAC-SHA256 |
| 6 | 4 | iterations | PBKDF2 rounds; 10,000 – 5,000,000; default 210,000 |
| 10 | 16 | salt | random bytes, regenerated on `init` and `passwd` |
| 26 | 12 | nonce | random 96-bit GCM nonce, fresh on every save |
| 38 | 4 | ciphertext length | length of the encrypted payload |
| 42 | — | ciphertext | AES-256-GCM(plaintext, key, nonce, AAD = header[0..42)) |
| 42 + n | 16 | tag | GCM authentication tag |

The 256-bit key is `PBKDF2-HMAC-SHA256(master_password, salt, iterations, 32)`. The header bytes from offset 0 through 41 (including the ciphertext length) are passed as additional authenticated data.

### Encrypted payload

The plaintext is a versioned, length-delimited structure. Because the whole payload is encrypted and authenticated, it leaks only its total size.

| Size | Field | Notes |
|---:|---|---|
| 4 | magic | ASCII `CVPL` |
| 1 | payload version | `1` |
| 4 + n | vault id | 32-character lowercase hex (128 random bits) |
| 8 | created | Unix time, signed 64-bit, seconds |
| 8 | revision | unsigned 64-bit; incremented on every save |
| 4 | entry count | at most 100,000 |
| … | entries | see below |
| 0 | end | trailing bytes are rejected |

### Entry

| Size | Field | Notes |
|---:|---|---|
| 4 + n | id | 32-character hex (128 random bits), unique within the vault |
| 4 + n | title | |
| 4 + n | username | may be empty |
| 4 + n | password | may be empty |
| 4 + n | url | may be empty |
| 4 + n | notes | may contain newlines |
| 2 | tag count | at most 256 |
| 4 + n (× tags) | tags | each tag at most 256 bytes |
| 8 | created | Unix time, signed 64-bit, seconds |
| 8 | modified | Unix time, signed 64-bit, seconds |

A single string may not exceed 1 MiB. A vault file may not exceed 64 MiB.

## Validation rules

On open, the reader enforces all of the following before returning any data:

1. The file is at least 58 bytes (42-byte header + 16-byte tag).
2. The magic is `CVLT` and the format version is `1`.
3. The KDF id is `1` and the iteration count is within the supported range.
4. The declared ciphertext length fits exactly in the file: `42 + length + 16 == file size`.
5. The GCM tag verifies over the header (as AAD) and ciphertext. Failure is reported as authentication failure without distinguishing a wrong password from tampering.
6. The decrypted payload starts with `CVPL`, has payload version `1`, and parses to exactly its declared length.
7. Entry IDs are non-empty, unique, and no field exceeds its size limit.
8. No trailing bytes remain after the entry list.

## Save semantics

1. Serialize the payload with `revision + 1`.
2. Generate a new random 12-byte nonce.
3. Derive the key (the salt and iteration count are unchanged on ordinary saves).
4. Encrypt with AES-256-GCM, using the newly built header as AAD.
5. Write header + ciphertext + tag to a temporary file in the vault directory.
6. Flush, then atomically replace the vault file; keep the previous version as `<vault>.bak`.

`passwd` additionally generates a fresh salt, derives a new key, and removes `<vault>.bak`, since that file would still be decryptable with the old password.

## Compatibility

Version 1 is the initial public format. A reader must reject any other magic, format version, payload version, or KDF id rather than guessing. Future versions are expected to extend the header and bump the format version; the payload carries its own version so it can evolve independently.

## Design notes

- Header-as-AAD binds the KDF parameters, salt, nonce, and ciphertext length to the authentication tag. An attacker cannot weaken the iteration count or swap the salt without detection.
- A fresh nonce per save is mandatory for GCM safety; it is generated from the OS CSPRNG.
- The encrypted payload has a length prefix for every string, which makes parsing unambiguous and avoids delimiter-injection issues.
- Because the payload is compressed neither before nor after encryption, the ciphertext length reveals only an approximate number of entries and their total size.
