# Cipher

An encryption-as-a-service engine for [ShrouDB](https://github.com/shroudb/shroudb).

## What It Does

Cipher manages encryption keys and performs cryptographic operations server-side. Keys never leave the server. Applications send plaintext and receive ciphertext — the application never handles raw key material.

```
KEYRING CREATE payments aes-256-gcm
ENCRYPT payments SGVsbG8gV29ybGQ=
→ { "ciphertext": "k3Xm:...", "key_version": 1 }

DECRYPT payments k3Xm:...
→ { "plaintext": "SGVsbG8gV29ybGQ=" }
```

Cipher supports five algorithms across two operation classes:

| Algorithm | Operations | Use Case |
|-----------|-----------|----------|
| `aes-256-gcm` | Encrypt/Decrypt | General-purpose authenticated encryption |
| `chacha20-poly1305` | Encrypt/Decrypt | Alternative AEAD (no AES-NI required) |
| `hmac-sha256` | Sign/Verify | Symmetric message authentication |
| `ed25519` | Sign/Verify | Asymmetric signatures (EdDSA) |
| `ecdsa-p256` | Sign/Verify | Asymmetric signatures (NIST P-256) |

## Quick Start

```sh
# Build and run (dev mode — ephemeral master key)
cargo run

# Or with a master key for durable storage
export SHROUDB_MASTER_KEY="$(openssl rand -hex 32)"
cargo run
```

Cipher listens on TCP port 6599 (RESP3 wire protocol).

## Wire Protocol (RESP3)

### Keyring Management

```
KEYRING CREATE <name> <algorithm> [ROTATION_DAYS <n>] [DRAIN_DAYS <n>] [CONVERGENT]
KEYRING LIST
```

### Encryption Operations

```
ENCRYPT <keyring> <plaintext_b64> [CONTEXT <aad>] [KEY_VERSION <v>] [CONVERGENT]
DECRYPT <keyring> <ciphertext> [CONTEXT <aad>]
REWRAP <keyring> <ciphertext> [CONTEXT <aad>]
GENERATE_DATA_KEY <keyring> [BITS <128|256|512>]
```

### Signing Operations

```
SIGN <keyring> <data_b64>
VERIFY_SIGNATURE <keyring> <data_b64> <signature_hex>
```

### Key Lifecycle

```
ROTATE <keyring> [FORCE] [DRYRUN]
KEY_INFO <keyring>
```

### Operational

```
HEALTH
AUTH <token>
PING
COMMAND LIST
```

## Configuration

```toml
[server]
tcp_bind = "0.0.0.0:6599"

[store]
mode = "embedded"
data_dir = "./cipher-data"

[engine]
default_rotation_days = 90
default_drain_days = 30

[auth]
method = "token"

[auth.tokens.my-token]
tenant = "tenant-a"
actor = "my-app"
platform = false
grants = [
    { namespace = "cipher.*", scopes = ["read", "write"] },
]

[keyrings.payments]
algorithm = "aes-256-gcm"
rotation_days = 30

[keyrings.signing]
algorithm = "ed25519"
```

## CLI

```sh
# Single command
shroudb-cipher-cli KEYRING CREATE payments aes-256-gcm
shroudb-cipher-cli ENCRYPT payments SGVsbG8=
shroudb-cipher-cli KEY_INFO payments

# Interactive mode
shroudb-cipher-cli
cipher> KEYRING LIST
cipher> ENCRYPT payments SGVsbG8=
cipher> quit
```

## Docker

```sh
docker run -d \
  -p 6599:6599 \
  -v cipher-data:/data \
  -e SHROUDB_MASTER_KEY="$(openssl rand -hex 32)" \
  shroudb/shroudb-cipher
```

## Server-Side vs Client-Side Encryption

Cipher supports two encryption models:

| Model | Crate | Key Holder | Use Case |
|-------|-------|------------|----------|
| **Server-side** | `shroudb-cipher-server` | Cipher server | Centralized key management, key rotation, REWRAP |
| **Client-side** | `shroudb-cipher-blind` | Client application | End-to-end encryption, zero-knowledge workflows |

**Server-side (default):** Applications send plaintext to Cipher, which encrypts with server-managed keys. The server handles rotation, draining, and retirement. Use this when you want centralized key lifecycle management.

**Client-side (blind):** Applications hold their own `ClientKey` and encrypt locally. Cipher server never sees the plaintext. Output is wire-compatible with `CiphertextEnvelope` (shared via `shroudb-cipher-core`). Use this for E2EE workflows where the server must not have access to plaintext.

Both models can coexist. An application might use server-side encryption for operational data (where key rotation matters) and client-side encryption for user-owned secrets (where zero-knowledge matters).

## Architecture

```
shroudb-cipher-core/        — domain types (Keyring, KeyVersion, CiphertextEnvelope)
shroudb-cipher-engine/      — Store-backed keyring management + crypto operations
shroudb-cipher-protocol/    — RESP3 command parsing + dispatch
shroudb-cipher-server/      — TCP server binary
shroudb-cipher-client/      — Rust client SDK
shroudb-cipher-cli/         — CLI tool
shroudb-cipher-blind/       — client-side encryption (E2EE, CiphertextEnvelope-compatible)
```

See [DOCS.md](DOCS.md) for full reference and [ABOUT.md](ABOUT.md) for architecture details.

## License

MIT OR Apache-2.0
