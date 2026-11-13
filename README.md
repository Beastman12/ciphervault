# CipherVault

**A local-first, encrypted password manager written in C++17 — with its own AES-256-GCM and PBKDF2 implementation.**

No third-party cryptography, no cloud, no telemetry. Your credentials live in a single authenticated-encryption file that only your master password can open.

[![CI](https://github.com/Beastman12/ciphervault/actions/workflows/ci.yml/badge.svg)](https://github.com/Beastman12/ciphervault/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C.svg)](https://isocpp.org/)

---

## Why this project

Most password-manager side projects call a library such as OpenSSL and stop there. CipherVault implements the cryptographic core itself — SHA-256, HMAC-SHA-256, PBKDF2, AES-256, and GCM — and validates every primitive against published test vectors (FIPS-197, RFC 4231, RFC 6070, NIST GCM). The result is a small, readable, dependency-free codebase that demonstrates applied cryptography, binary file-format design, secure memory handling, and a polished CLI.

## Features

| | |
|---|---|
| **Encrypted at rest** | AES-256-GCM authenticated encryption. A wrong password or a single flipped bit is detected before any plaintext is returned. |
| **Hard key derivation** | PBKDF2-HMAC-SHA256 with 210,000 iterations and a random 16-byte salt. Iteration count is stored in the header and can be raised. |
| **Local-first** | One vault file. No server, no account, no sync, no telemetry. |
| **Master-password auth** | The master password is never stored. Changing it re-encrypts the vault with a fresh salt and removes the stale `.bak`. |
| **Password generator** | CSPRNG-backed, configurable length and character classes, guarantees at least one character from each selected class. |
| **Search & retrieve** | Case-insensitive multi-term search over title, username, URL, notes, and tags; lookup by full ID or unique ID prefix. |
| **Clipboard hygiene** | Passwords copied to the clipboard are cleared after 30 seconds by a detached helper — and only if the clipboard still holds the same value. |
| **Vault auditing** | Flags weak, reused, and year-old passwords. |
| **Import / export** | CSV round-trip with a deliberate, hard-to-trigger plaintext-export confirmation. |
| **Crash-safe writes** | Temp file + atomic replace, previous version kept as `.bak`, owner-only permissions on POSIX. |
| **Zero dependencies** | Only the C++17 standard library and the OS CSPRNG (`BCryptGenRandom` / `getrandom` / `arc4random_buf`). |
| **Built-in self-test** | `ciphervault selftest` runs known-answer tests for every primitive in the shipped binary. |

## Quick start

### Build

Requires CMake 3.16+ and a C++17 compiler (MSVC 2019+, GCC 9+, or Clang 10+).

```bash
git clone https://github.com/Beastman12/ciphervault.git
cd ciphervault
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

The executable is `build/ciphervault` (`build/Release/ciphervault.exe` with Visual Studio).

<details>
<summary>Building with zig (no system compiler required)</summary>

Any Clang-compatible driver works. With a Zig toolchain:

```bash
zig c++ -std=c++17 -Iinclude -O2 src/*.cpp -o ciphervault -lbcrypt   # Windows
zig c++ -std=c++17 -Iinclude -O2 src/*.cpp -o ciphervault            # Linux/macOS
```

</details>

### First vault

```console
$ ciphervault init
Creating a vault at C:\Users\you\AppData\Roaming\CipherVault\vault.spm
The master password is never stored. There is no recovery if you lose it.

Choose a master password: ****************
Confirm master password:   ****************

Vault created.
  Encryption: AES-256-GCM
  KDF:        PBKDF2-HMAC-SHA256, 210000 rounds
  Vault id:   0c933bb4a0758dc41ea36eda0c9c9342

$ ciphervault add --title GitHub --username you@example.com --generate
Added GitHub (67a85bb6)
  Password: *Wnt4UEm!_,O2J!KAarb
  Strength: very strong (131 bits)

$ ciphervault list
ID        TITLE            USERNAME          URL                 UPDATED
------------------------------------------------------------------------
67a85bb6  GitHub           you@example.com   https://github.com  just now
  1 credential(s)

$ ciphervault get github --copy
Password copied to the clipboard. It will be cleared in 30 seconds if unchanged.
```

## Commands

```
ciphervault [global options] <command> [options]
```

| Command | What it does |
|---|---|
| `init [--iterations N] [--force]` | Create a vault (or replace one, keeping a `.bak`) |
| `add [--title T] [--username U] [--password P] [--url U] [--notes N] [--tags a,b] [--generate] [--length N]` | Add a credential; missing fields are prompted |
| `list [--sort title\|updated\|created]` | List credentials |
| `search <terms...>` | AND-search across every field |
| `get <id\|terms...> [--show] [--copy] [--stdout] [--field NAME]` | Show, copy, or print one field |
| `edit <id> [options]` | Update fields, optionally generate a new password |
| `rm <id> [--yes]` | Delete a credential |
| `gen [--length N] [--count N] [--copy] [--no-symbols] ...` | Generate random passwords |
| `audit` | Report weak, reused, and stale passwords |
| `passwd` | Change the master password (new salt, full re-encryption) |
| `export <file.csv> [--yes]` | Plaintext CSV export behind an explicit confirmation |
| `import <file.csv>` | Import credentials from CSV |
| `info` | Show vault metadata and KDF parameters |
| `backup [destination]` | Copy the encrypted vault file |
| `selftest` | Run built-in crypto known-answer tests |
| `help [command]` | Per-command help |

Global options: `--vault <path>`, `--no-color`, `-h/--help`, `-V/--version`.

The default vault is `%APPDATA%\CipherVault\vault.spm` on Windows and `~/.local/share/ciphervault/vault.spm` on Linux/macOS, overridable with `--vault` or `CIPHERVAULT_PATH`. The master password can be supplied via `CIPHERVAULT_MASTER` for scripted use (a warning is printed — this is development-only, since environment variables leak to child processes).

## Security design

```
master password
      │
      ├── PBKDF2-HMAC-SHA256 (210,000 rounds, random 16-byte salt)
      ▼
  256-bit key ──► AES-256-GCM ──► CVLT file
                       ▲
             fresh 96-bit nonce per save
             header (incl. ciphertext length) authenticated as AAD
```

- **Authenticated encryption first.** The GCM tag is verified before decryption; tampering or a bad password fails closed with a single generic error.
- **No nonce reuse.** Every save generates a new random 96-bit nonce. Saving also bumps an authenticated revision counter.
- **Header binding.** The full 42-byte header is passed as AAD, so an attacker cannot alter the KDF parameters, salt, nonce, or length without invalidating the tag.
- **Fresh salt on password change.** `passwd` derives a new key from a new salt and discards the old `.bak`, which would otherwise remain decryptable with the old password.
- **Memory hygiene.** Key material is wiped with a compiler-resistant `secure_zero`, plaintext buffers are wiped after parsing, and only a hash of copied clipboard text is passed to the clearing helper.
- **Constant-time comparison** for tags and password checks.
- **Atomic persistence.** Data is written to a temporary file, flushed, then atomically renamed; the previous version becomes `.bak`.

The primitives are implemented in-tree and tested against standard vectors. See [`docs/SECURITY.md`](docs/SECURITY.md) for the threat model and limitations, and [`docs/FORMAT.md`](docs/FORMAT.md) for the byte-level vault format.

> **Scope.** CipherVault is a portfolio-quality engineering project, not an audited product. For real secrets, prefer a mature, independently audited password manager.

## Testing

```bash
ctest --test-dir build --output-on-failure   # 43 unit tests + CLI self-test
./build/ciphervault selftest                 # known-answer tests in the binary
```

The suite covers SHA-256 (including the million-`a` vector), HMAC-SHA-256 (RFC 4231), PBKDF2 (RFC 6070), AES-256 (FIPS-197), GCM (NIST vectors, AAD, tamper detection), CSPRNG range behavior, password strength and generation, CSV quoting/delimiters, and full vault lifecycle: create, reopen, wrong password, tamper, backup, re-key, and import/export round-trips.

## Project layout

```
include/ciphervault/   public headers (crypto, vault, entry, CLI utilities)
src/crypto/            SHA-256, HMAC, PBKDF2, AES-256, GCM, CSPRNG, secure memory
src/                   vault format, CLI, generator, strength, CSV, clipboard
tests/                 lightweight in-tree test framework and 43 tests
docs/                  security model, file format, GitHub Pages site
```

## License

MIT — see [LICENSE](LICENSE).
