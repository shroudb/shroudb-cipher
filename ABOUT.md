# Understanding Cipher

## For Everyone: What Cipher Does

Applications that handle encryption face a common problem: managing cryptographic keys is hard to get right. Generating keys safely, rotating them on schedule, keeping old keys available for decryption while preventing new encryptions with retired keys, and ensuring key material never leaks to logs or disk — these are distinct concerns that most teams solve ad hoc.

**Cipher is an encryption-as-a-service engine.** You create keyrings (named containers of versioned keys), and Cipher handles the rest. Applications send plaintext to Cipher and receive ciphertext. The application never sees or handles raw key material.

- **Encrypt/Decrypt** with AES-256-GCM or ChaCha20-Poly1305
- **Sign/Verify** with HMAC-SHA256, Ed25519, or ECDSA-P256
- **Automatic key rotation** with configurable rotation and drain periods
- **Envelope encryption** (GENERATE_DATA_KEY) for large data
- **Convergent encryption** for deterministic ciphertext when needed
- **REWRAP** to migrate ciphertext to new key versions without exposing plaintext

## For Technical Leaders: Architecture and Trade-offs

### The Problem

Applications need encryption but shouldn't manage keys. Key management requires: secure generation from a CSPRNG, encrypted storage with a master key hierarchy, rotation schedules with draining periods, version tracking in ciphertext for correct key selection on decrypt, and memory-safe handling that zeros key material after use. Getting any of these wrong creates a vulnerability. Most teams either hardcode keys, use a cloud KMS (vendor lock-in), or build a fragile custom solution.

### What Cipher Is

Cipher is an **encryption operations server** — not a KMS in the traditional sense. It doesn't store your data; it encrypts and decrypts data you send to it. Keys live inside Cipher, backed by ShrouDB's encrypted store. The ciphertext envelope self-describes which key version was used, so Cipher can always select the right key for decryption.

### Key Architectural Decisions

| Decision | Rationale |
|----------|-----------|
| **Keys never leave the server** | Encrypt and decrypt happen server-side. Applications receive ciphertext, not key material. This eliminates an entire class of key-leak vulnerabilities. |
| **Self-describing ciphertext** | The ciphertext envelope embeds the key version and algorithm via Obfusbit (obfuscated bitpacking). No trial decryption, no external version tracking. |
| **Key state machine** | Staged → Active → Draining → Retired. Only Active keys encrypt. Active and Draining keys decrypt. Retired keys cannot decrypt (forcing REWRAP). This model prevents stale key use. |
| **Convergent encryption is opt-in** | Deterministic encryption (same plaintext = same ciphertext) is useful for deduplication but weakens confidentiality. Requires three conditions: keyring config flag, per-request flag, and mandatory context. Hard to enable by accident. |
| **TCP-only** | Cipher is machine-to-machine. No HTTP, no CORS, no CSRF, no browser interaction. Simpler attack surface, lower overhead. |
| **Store-backed persistence** | Keyrings and key versions are persisted via the ShrouDB Store trait. An in-memory DashMap cache serves all crypto operations at memory speed. Mutations write-through to Store. |

### Key Lifecycle

```
Key Created (Active)
       │
       ▼  rotation_days elapsed
  New Key (Active)  ←──  Old Key (Draining)
       │                      │
       │                      ▼  drain_days elapsed
       │                 Old Key (Retired)
       │                   [material cleared]
       ▼
    REWRAP migrates ciphertext
    from Draining → Active key
```

### Ciphertext Envelope Format

```
{obfuscated_prefix}:{base64url_payload}
```

The prefix encodes key version (16 bits) and algorithm ID (4 bits) via Obfusbit with a custom base62 alphabet. Observers cannot read the version or algorithm from the prefix.

### Operational Model

- **Persistence:** ShrouDB Store trait. Embedded mode (in-process ShrouDB) for standalone deployment or remote mode (planned) for connecting to an existing ShrouDB server.
- **Key material:** Held in `SecretBytes` (zeroized on drop, mlocked on Unix). Serialized as hex in the Store, encrypted at rest by ShrouDB's master key.
- **Auto-rotation:** Background scheduler checks keyrings every hour (configurable). Keys exceeding `rotation_days` are auto-rotated. Draining keys exceeding `drain_days` are auto-retired (material cleared).
- **Authentication:** Token-based via `shroudb-acl`. Disabled by default (dev mode). When enabled, connections must AUTH before protected operations.
- **Security:** Core dumps disabled. Fail-closed on all error paths. No `#[allow]` attributes. Compiler and clippy warnings are errors.

### Ecosystem

Cipher is one engine in the ShrouDB ecosystem:

- **ShrouDB** — encrypted versioned KV store (the foundation)
- **Sigil** — credential envelope (password hashing, JWT, field-level crypto routing)
- **Cipher** — encryption-as-a-service (this engine)
- **Veil** — blind indexing (searchable encryption)
- **Keep** — versioned secret storage
- **Forge** — certificate management
- **Sentry** — authorization policies
- **Courier** — notification queues
- **Chronicle** — audit event streams
- **Moat** — single-binary hub embedding all engines

Cipher is consumed by Sigil (for PII field encryption), Veil (for blind index derivation), and any application that needs server-side encryption without managing keys.

## For Developers: Getting Started

### Rust Client

```rust
use shroudb_cipher_client::CipherClient;

let mut client = CipherClient::connect("127.0.0.1:6599").await?;

// Create a keyring
client.keyring_create("myapp", "aes-256-gcm", None, None, false).await?;

// Encrypt
let enc = client.encrypt("myapp", "SGVsbG8=", None, None, false).await?;
println!("ciphertext: {}", enc.ciphertext);

// Decrypt
let dec = client.decrypt("myapp", &enc.ciphertext, None).await?;
assert_eq!(dec.plaintext, "SGVsbG8=");

// Envelope encryption for large data
let dek = client.generate_data_key("myapp", Some(256)).await?;
// Use dek.plaintext_key locally, store dek.wrapped_key alongside ciphertext
// Later: client.decrypt("myapp", &dek.wrapped_key, None) to recover the DEK
```

### Envelope Encryption Pattern

For data too large to send over the wire:

1. `GENERATE_DATA_KEY myapp BITS 256` — get a plaintext DEK and wrapped DEK
2. Encrypt your data locally with the plaintext DEK
3. Discard the plaintext DEK from memory
4. Store the wrapped DEK alongside your encrypted data
5. To decrypt: `DECRYPT myapp <wrapped_dek>` to recover the plaintext DEK, then decrypt locally

### Convergent Encryption

For deterministic ciphertext (same input = same output):

```
KEYRING CREATE dedup aes-256-gcm CONVERGENT
ENCRYPT dedup SGVsbG8= CONTEXT user-123 CONVERGENT
```

All three conditions must be met:
1. Keyring created with `CONVERGENT` flag
2. `CONVERGENT` flag on each ENCRYPT request
3. `CONTEXT` must be provided (non-empty AAD)

This enables deduplication and equality checks on ciphertext, at the cost of leaking whether two plaintexts are identical within the same context.
