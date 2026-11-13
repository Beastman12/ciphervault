# Security model

CipherVault is a local, single-user password manager. This document describes what it protects, how, and where the boundaries are.

## Threat model

### In scope

An attacker who obtains the vault file, or a copy of it, without knowing the master password. This includes:

- a stolen laptop or backup drive;
- cloud-sync or backup services that upload the file;
- an attacker who can read the file but not execute code as the user;
- accidental exposure through source control, email, or a shared folder.

The attacker is assumed to have full knowledge of the format and the source code (Kerckhoffs's principle). Security rests entirely on the master password and the correctness of the cryptography.

### Out of scope

- **A compromised machine.** Malware, a keylogger, a debugger attached to the process, or a malicious shell can capture the master password or decrypted entries. No local password manager can defend against this.
- **Chosen-password guessing.** A weak master password can be brute-forced offline. PBKDF2's 210,000 iterations raise the cost, but they do not make a six-character password safe.
- **Denial of service and rollback.** An attacker with write access can truncate the vault, replace it with an older valid copy, or delete it. Authentication detects modification of a given file, not substitution with a previously valid file. A revision counter is stored and authenticated, but the CLI does not compare it against a separate trusted clock or record.
- **Swap, hibernation, and crash dumps.** Keys and plaintext exist in process memory while the vault is unlocked. The OS may write that memory to disk. `mlock`/`VirtualLock` are not used.
- **Clipboard observation.** Other applications can read the clipboard while a password is on it. The 30-second auto-clear reduces the window but is not a security boundary.
- **Side channels.** The implementation is portable C++ with no explicit constant-time guarantees beyond constant-time tag/password comparison. Cache-timing and power analysis are out of scope for this project.

## Cryptography

| Function | Construction | Parameters |
|---|---|---|
| Key derivation | PBKDF2-HMAC-SHA256 | 210,000 rounds (default), random 16-byte salt, 32-byte output |
| Encryption | AES-256-GCM | 96-bit random nonce per save, 128-bit tag |
| Hash | SHA-256 | FIPS 180-4 |
| MAC | HMAC-SHA-256 | RFC 2104 / FIPS 198-1 |
| Randomness | OS CSPRNG | `BCryptGenRandom` (Windows), `getrandom` (Linux), `arc4random_buf` (macOS/BSD) |

All primitives are implemented in this repository, without OpenSSL or any other crypto library. They are validated against published vectors in `ciphervault selftest` and the unit test suite:

- SHA-256: FIPS 180-4 `abc`, empty string, and the one-million-`a` vector
- HMAC-SHA-256: RFC 4231 test cases
- PBKDF2-HMAC-SHA256: RFC 6070 test vectors
- AES-256: FIPS-197 Appendix C.3
- AES-GCM: NIST CAVP vectors including empty plaintext, AAD, and tag-tampering rejection

> The AES S-box is computed arithmetically from the field inverse rather than stored as a 256-byte table. This removes a well-known cache-timing side channel, at a small performance cost.

## Design decisions

### Authenticate before decrypt

GCM verification happens before plaintext is parsed. A wrong password and a corrupted file produce the same generic error, which avoids giving an attacker an oracle that distinguishes "wrong key" from "valid key, bad data".

### The header is additional authenticated data

The 42-byte header — magic, version, KDF id, iteration count, salt, nonce, and ciphertext length — is passed to GCM as AAD. Changing any of it (for example, lowering the iteration count, swapping the salt, or truncating the payload) invalidates the tag. The decryption key is derived from the salt and iteration count, so those fields are also implicitly bound.

### Fresh nonce every save

A new 96-bit nonce is generated with the OS CSPRNG for every write. Reusing a nonce with the same key is catastrophic for GCM, so nonces are never derived from a counter, time, or file contents. Each save also increments an authenticated revision number.

### Master password changes are real re-keys

`ciphervault passwd` verifies the current password against the in-memory key, generates a new 16-byte salt, derives a new key, and re-encrypts every entry with a fresh nonce. The previous `.bak` file is deleted because it remains decryptable with the old password. Users who need a historical copy must export one deliberately.

### Persistent state is written atomically

Writes go to a temporary file in the same directory, are flushed, and are then atomically replaced (`MoveFileEx` with `MOVEFILE_REPLACE_EXISTING` on Windows, `rename` on POSIX). The previous file is retained as `.bak` for crash recovery. On POSIX the vault and its directory are restricted to the owner (`0700`/`0600`).

### Secrets do not linger

- Derived keys live in fixed-size arrays wiped by `secure_zero`, which uses an optimizer barrier so the wipe is not optimized away.
- Serialized plaintext is wiped after parsing.
- Generated passwords are wiped after being displayed.
- The clipboard helper receives only a SHA-256 digest of the copied value. It clears the clipboard after 30 seconds **only if the clipboard still contains the same value**, so it never destroys something the user copied in the meantime.

### Errors reveal little

Authentication failures share one message. The CLI does not print entry data on failure, and it does not echo passwords typed at the prompt (POSIX `termios` / Windows console mode).

## Operational guidance

1. **Use a long, unique master password.** A multi-word passphrase of 5–6 words is better than a short complex string. The CLI warns below 12 characters and estimates strength, but ultimately trusts the user.
2. **Protect the `.bak` file.** It is encrypted with the same password, but it is still sensitive. Deleting it after a successful save is safe; keeping it helps recover from a crash mid-write.
3. **Delete CSV exports immediately.** `export` writes plaintext by design; it requires typing `EXPORT` interactively and does not add the file to the vault.
4. **Keep the vault off shared or untrusted storage.** Sync is fine if you trust the provider not to serve you a stale copy, but there is no anti-rollback protection.
5. **Rebuild from source** if you want assurance that the binary matches the audited code.

## Known limitations

- No memory locking, no guard pages, no protection against core dumps.
- No hardware-backed key storage (TPM, Secure Enclave) or two-factor unlock.
- No encrypted metadata beyond the whole-file encryption: the file size leaks an approximate entry count.
- No rollback protection using external state.
- Not independently audited. Treat it as an educational and portfolio project, not as a replacement for a mature password manager.
