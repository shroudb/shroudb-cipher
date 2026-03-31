# Cipher (formerly Transit) — Agent Instructions

> Encryption-as-a-service engine: key lifecycle management, encrypt/decrypt/rewrap/sign/verify operations with versioned keyrings and automatic rotation.

## Quick Context

- **Role in ecosystem**: Pure crypto primitive — other engines (Veil, Courier, Sigil) call Cipher for encryption; it has no knowledge of data semantics
- **Deployment modes**: embedded | remote (TCP port 6599)
- **Wire protocol**: RESP3
- **Backing store**: ShrouDB Store trait (encrypted at rest)

## Workspace Layout

```
shroudb-cipher-core/      # Domain types: Keyring, KeyVersion, CiphertextEnvelope, KeyState, Policy
shroudb-cipher-engine/    # Store-backed CipherEngine, crypto_ops, KeyringManager, scheduler
shroudb-cipher-protocol/  # RESP3 command parsing + dispatch
shroudb-cipher-server/    # Standalone TCP binary
shroudb-cipher-client/    # Typed Rust SDK
shroudb-cipher-cli/       # CLI tool
```

## RESP3 Commands

### Keyring Management

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `KEYRING CREATE` | `<name> <algorithm> [ROTATION_DAYS <n>] [DRAIN_DAYS <n>] [CONVERGENT]` | `{status, keyring, algorithm, active_version}` | Create keyring with first Active key (Admin) |
| `KEYRING LIST` | — | `["name1", "name2"]` | List all keyring names |

### Encryption

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `ENCRYPT` | `<keyring> <plaintext_b64> [CONTEXT <aad>] [KEY_VERSION <v>] [CONVERGENT]` | `{status, ciphertext, key_version}` | Encrypt with active or specified key |
| `DECRYPT` | `<keyring> <ciphertext> [CONTEXT <aad>]` | `{status, plaintext}` | Decrypt using embedded key version |
| `REWRAP` | `<keyring> <ciphertext> [CONTEXT <aad>]` | `{status, ciphertext, key_version}` | Decrypt with old key, re-encrypt with current active key |
| `GENERATE_DATA_KEY` | `<keyring> [BITS <128\|256\|512>]` | `{status, plaintext_key, wrapped_key, key_version}` | Envelope encryption: generate DEK + wrap it |

### Signing

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `SIGN` | `<keyring> <data_b64>` | `{status, signature, key_version}` | Sign data with active key (hex signature) |
| `VERIFY_SIGNATURE` | `<keyring> <data_b64> <signature_hex>` | `{status, valid}` | Verify against Active + Draining keys |

### Key Lifecycle

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `ROTATE` | `<keyring> [FORCE] [DRYRUN]` | `{status, rotated, key_version, previous_version?}` | Rotate keyring to new key version (Admin) |
| `KEY_INFO` | `<keyring>` | `{keyring, algorithm, active_version, versions}` | Keyring metadata and version history |

### Operational

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `AUTH` | `<token>` | `{status}` | Authenticate connection |
| `HEALTH` | — | `{status}` | Health check |
| `PING` | — | `PONG` | Liveness |
| `COMMAND LIST` | — | `{count, commands}` | List commands |

### Command Examples

```
> KEYRING CREATE payments aes-256-gcm ROTATION_DAYS 90
{"status":"ok","keyring":"payments","algorithm":"aes-256-gcm","active_version":1}

> ENCRYPT payments SGVsbG8gV29ybGQ= CONTEXT user-123
{"status":"ok","ciphertext":"k3Xm:DKxzrL2p8wI=","key_version":1}

> DECRYPT payments k3Xm:DKxzrL2p8wI= CONTEXT user-123
{"status":"ok","plaintext":"SGVsbG8gV29ybGQ="}
```

## Public API (Embedded Mode)

### Core Types

```rust
pub struct Keyring { pub name: String, pub algorithm: KeyringAlgorithm, pub key_versions: Vec<KeyVersion>, /* ... */ }
pub enum KeyringAlgorithm { Aes256Gcm, ChaCha20Poly1305, Ed25519, EcdsaP256, HmacSha256 }
pub enum KeyState { Staged, Active, Draining, Retired }
pub struct CiphertextEnvelope { /* obfuscated_prefix:base64url_payload */ }
```

### Usage Pattern

```rust
use shroudb_cipher_engine::{CipherEngine, CipherConfig};

let config = CipherConfig { default_rotation_days: 90, default_drain_days: 30, scheduler_interval_secs: 3600 };
let engine = CipherEngine::new(store.clone(), config, None).await?;

let result = engine.encrypt("payments", b"hello", Some("user-123"), None, false).await?;
let decrypted = engine.decrypt("payments", &result.ciphertext, Some("user-123")).await?;
```

## Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server.tcp_bind` | `SocketAddr` | `"0.0.0.0:6599"` | TCP listen address |
| `server.log_level` | `Option<String>` | `"info"` | Tracing log level |
| `store.mode` | `String` | `"embedded"` | Storage mode |
| `store.data_dir` | `PathBuf` | `"./cipher-data"` | Data directory |
| `engine.default_rotation_days` | `u32` | `90` | Auto-rotation threshold |
| `engine.default_drain_days` | `u32` | `30` | Grace period before retirement |
| `engine.scheduler_interval_secs` | `u64` | `3600` | Key lifecycle check interval |
| `auth.method` | `Option<String>` | `None` | `"token"` to enable auth |

## Data Model

- **Namespace**: `cipher.keyrings`
- **Key**: Keyring name (UTF-8 bytes)
- **Value**: JSON-serialized `Keyring` (includes all key versions with hex-encoded key material)
- **Cache**: `DashMap<String, Keyring>` — write-through

### Key State Machine

```
Staged → Active → Draining → Retired

Active:   can encrypt + decrypt + sign
Draining: can encrypt + decrypt + sign (grace period after rotation)
Retired:  cannot encrypt/decrypt (requires REWRAP to migrate ciphertext)
```

### Ciphertext Format (Obfuskey Prefix)

```
{obfuscated_prefix}:{base64url_payload}

Prefix encodes: key_version (16 bits) + algorithm_id (4 bits)
Obfuscated via custom BASE62 alphabet (hides version/algo from inspection)

Payload: nonce (12 bytes) || ciphertext || auth_tag (16 bytes)
```

### Convergent Encryption

When `CONVERGENT` flag is set:
- Keyring must have `convergent=true`
- `CONTEXT` is required
- Nonce derived deterministically: `HMAC-SHA256(key, plaintext || aad)[..12]`
- Same plaintext + context + key = same ciphertext (enables deduplication)

## Integration Patterns

Cipher is called by other engines as a pure crypto primitive:

- **Veil** calls `ENCRYPT`/`DECRYPT` via RESP3 PIPELINE to process batches of blind index entries
- **Courier** calls `DECRYPT` just-in-time before delivery to decrypt recipients and message bodies
- **Sigil** calls `ENCRYPT`/`DECRYPT` for PII fields via the `CipherOps` trait

In Moat (embedded mode), these calls go through direct method invocation on `CipherEngine`, not TCP.

## Common Mistakes

- Always pass the same `CONTEXT` for decrypt that was used for encrypt — mismatched AAD causes decryption failure
- `Retired` keys cannot decrypt. If you need to access old ciphertext, the key must still be `Active` or `Draining`. Use `REWRAP` before the drain period expires.
- Convergent encryption requires both the `CONVERGENT` flag on the command AND `convergent=true` on the keyring
- The obfuscated prefix is NOT encryption — it hides version/algo metadata but is reversible. Security comes from the AES-256-GCM payload.

## Related Crates

| Crate | Relationship |
|-------|-------------|
| `shroudb-store` | Provides Store trait for keyring persistence |
| `shroudb-crypto` | AES-256-GCM, ChaCha20-Poly1305, Ed25519, ECDSA primitives |
| `obfuskey` | Prefix obfuscation for ciphertext envelopes |
| `shroudb-veil` | Calls Cipher for decrypt/re-encrypt during encrypted search |
| `shroudb-courier` | Calls Cipher for JIT decryption before notification delivery |
| `shroudb-sigil` | Calls Cipher for PII field encryption via CipherOps trait |
