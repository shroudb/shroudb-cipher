# Cipher Reference

Complete reference for the ShrouDB Cipher encryption-as-a-service engine.

## Server

### Binary

```
shroudb-cipher [OPTIONS]
```

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `-c, --config` | `CIPHER_CONFIG` | — | Path to TOML config file |
| `--data-dir` | `CIPHER_DATA_DIR` | `./cipher-data` | Storage directory |
| `--tcp-bind` | `CIPHER_TCP_BIND` | `0.0.0.0:6599` | TCP bind address |
| `--log-level` | `CIPHER_LOG_LEVEL` | `info` | Log level (trace/debug/info/warn/error) |

### Master Key

The master key encrypts all data at rest. Configure via environment:

| Env Var | Description |
|---------|-------------|
| `SHROUDB_MASTER_KEY` | Hex-encoded 32-byte master key |
| `SHROUDB_MASTER_KEY_FILE` | Path to file containing the master key |

If neither is set, Cipher runs in **ephemeral mode** (random key, data lost on restart). Suitable for development only.

### Configuration File

```toml
[server]
tcp_bind = "0.0.0.0:6599"    # TCP bind address
log_level = "info"             # Log level

[store]
mode = "embedded"              # "embedded" (in-process ShrouDB)
data_dir = "./cipher-data"     # Data directory for embedded mode

[engine]
default_rotation_days = 90     # Default key rotation period
default_drain_days = 30        # Default drain period before retirement
scheduler_interval_secs = 3600 # Background scheduler interval

[auth]
method = "token"               # "token" to enable auth, omit to disable

[auth.tokens."my-secret-token"]
tenant = "tenant-a"
actor = "my-app"
platform = false               # true = admin access (bypasses namespace grants)
grants = [
    { namespace = "cipher.payments.*", scopes = ["read", "write"] },
    { namespace = "cipher.signing.*", scopes = ["read"] },
]

# Seed keyrings on startup (created if not already present)
[keyrings.payments]
algorithm = "aes-256-gcm"
rotation_days = 30
drain_days = 14

[keyrings.signing]
algorithm = "ed25519"

[keyrings.dedup]
algorithm = "aes-256-gcm"
convergent = true
```

## Commands

### KEYRING CREATE

Create a new keyring with its first active key.

```
KEYRING CREATE <name> <algorithm> [ROTATION_DAYS <n>] [DRAIN_DAYS <n>] [CONVERGENT]
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `name` | Yes | Keyring name (alphanumeric, hyphens, underscores, max 255 chars) |
| `algorithm` | Yes | One of: `aes-256-gcm`, `chacha20-poly1305`, `hmac-sha256`, `ed25519`, `ecdsa-p256` |
| `ROTATION_DAYS` | No | Auto-rotation period in days (default: 90) |
| `DRAIN_DAYS` | No | Drain period before retirement in days (default: 30) |
| `CONVERGENT` | No | Enable deterministic encryption |

**ACL:** Admin

**Response:**
```json
{"status": "ok", "keyring": "payments", "algorithm": "aes-256-gcm", "active_version": 1}
```

### KEYRING LIST

List all keyring names.

```
KEYRING LIST
```

**ACL:** None (public)

**Response:**
```json
["payments", "signing"]
```

### ENCRYPT

Encrypt plaintext with the active key version.

```
ENCRYPT <keyring> <plaintext_b64> [CONTEXT <aad>] [KEY_VERSION <v>] [CONVERGENT]
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `keyring` | Yes | Target keyring (must support encryption) |
| `plaintext_b64` | Yes | Base64-encoded plaintext |
| `CONTEXT` | No | Additional authenticated data (AAD) — must match on decrypt |
| `KEY_VERSION` | No | Specific key version (default: active) |
| `CONVERGENT` | No | Use deterministic encryption (see convergent requirements) |

**ACL:** Namespace write (`cipher.<keyring>.*`)

**Response:**
```json
{"status": "ok", "ciphertext": "k3Xm:...", "key_version": 1}
```

### DECRYPT

Decrypt ciphertext. The key version is embedded in the ciphertext envelope.

```
DECRYPT <keyring> <ciphertext> [CONTEXT <aad>]
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `keyring` | Yes | Target keyring |
| `ciphertext` | Yes | Ciphertext from ENCRYPT |
| `CONTEXT` | No | AAD used during encryption (must match exactly) |

**ACL:** Namespace read (`cipher.<keyring>.*`)

**Response:**
```json
{"status": "ok", "plaintext": "SGVsbG8="}
```

**Errors:** Key version retired (use REWRAP first), algorithm mismatch, decryption failed (wrong context or tampered ciphertext).

### REWRAP

Re-encrypt ciphertext with the current active key version. Plaintext never leaves the server.

```
REWRAP <keyring> <ciphertext> [CONTEXT <aad>]
```

**ACL:** Namespace write (`cipher.<keyring>.*`)

**Response:**
```json
{"status": "ok", "ciphertext": "f1Lv:...", "key_version": 2}
```

Use REWRAP to migrate ciphertext from a draining key to the active key before the old key is retired.

### GENERATE_DATA_KEY

Generate a data encryption key for envelope encryption.

```
GENERATE_DATA_KEY <keyring> [BITS <128|256|512>]
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `keyring` | Yes | Target keyring (must support encryption) |
| `BITS` | No | Key size: 128, 256, or 512 (default: 256) |

**ACL:** Namespace write (`cipher.<keyring>.*`)

**Response:**
```json
{
  "status": "ok",
  "plaintext_key": "base64-encoded-dek",
  "wrapped_key": "k3Xm:...",
  "key_version": 1
}
```

Use `plaintext_key` for local encryption, then discard it. Store `wrapped_key` alongside your ciphertext. To recover the DEK later, `DECRYPT <keyring> <wrapped_key>`.

### SIGN

Create a detached signature.

```
SIGN <keyring> <data_b64>
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `keyring` | Yes | Target keyring (must support signing) |
| `data_b64` | Yes | Base64-encoded data to sign |

**ACL:** Namespace write (`cipher.<keyring>.*`)

**Response:**
```json
{"status": "ok", "signature": "hex-encoded-sig", "key_version": 1}
```

### VERIFY_SIGNATURE

Verify a detached signature. Checks against all Active and Draining key versions.

```
VERIFY_SIGNATURE <keyring> <data_b64> <signature_hex>
```

**ACL:** Namespace read (`cipher.<keyring>.*`)

**Response:**
```json
{"status": "ok", "valid": true}
```

### ROTATE

Rotate the keyring to a new key version.

```
ROTATE <keyring> [FORCE] [DRYRUN]
```

| Parameter | Required | Description |
|-----------|----------|-------------|
| `keyring` | Yes | Target keyring |
| `FORCE` | No | Rotate regardless of rotation_days age |
| `DRYRUN` | No | Preview rotation without applying |

Without `FORCE`, rotation only occurs if the active key exceeds `rotation_days`. The background scheduler also auto-rotates on this schedule.

**ACL:** Namespace write (`cipher.<keyring>.*`)

**Response:**
```json
{"status": "ok", "rotated": true, "key_version": 2, "previous_version": 1}
```

### KEY_INFO

Get keyring metadata and all key versions.

```
KEY_INFO <keyring>
```

**ACL:** Namespace read (`cipher.<keyring>.*`)

**Response:**
```json
{
  "keyring": "payments",
  "algorithm": "aes-256-gcm",
  "active_version": 2,
  "versions": [
    {"version": 1, "state": "Draining", "created_at": 1711700000, "activated_at": 1711700000, "draining_since": 1711800000},
    {"version": 2, "state": "Active", "created_at": 1711800000, "activated_at": 1711800000}
  ]
}
```

### HEALTH

Health check.

```
HEALTH
```

**ACL:** None (public)

### AUTH

Authenticate the connection.

```
AUTH <token>
```

**ACL:** None

### PING

Connectivity check.

```
PING
```

**ACL:** None

**Response:** `"PONG"`

### COMMAND LIST

List all supported commands.

```
COMMAND LIST
```

**ACL:** None

## Key Lifecycle

### States

| State | Encrypts | Decrypts | Description |
|-------|----------|----------|-------------|
| **Active** | Yes | Yes | Current key for new operations. One per keyring. |
| **Draining** | No | Yes | Old key, still decrypts. REWRAP ciphertext away from this key. |
| **Retired** | No | No | Key material cleared. DECRYPT returns error suggesting REWRAP. |

### Transitions

```
Active → Draining    (on rotation: new key becomes Active)
Draining → Retired   (after drain_days, or manually via scheduler)
```

### Auto-Rotation

The background scheduler runs every `scheduler_interval_secs` (default: 1 hour):

1. For each keyring: if the active key exceeds `rotation_days`, generate a new Active key and demote the old one to Draining.
2. For each keyring: if any Draining key exceeds `drain_days`, retire it (clear key material).

## Authentication

When `[auth] method = "token"` is configured, connections must `AUTH <token>` before issuing protected commands.

### ACL Requirements

| Command | Requirement |
|---------|------------|
| HEALTH, PING, COMMAND LIST, KEYRING LIST | None (public) |
| KEYRING CREATE | Admin (platform token) |
| DECRYPT, VERIFY_SIGNATURE, KEY_INFO | Namespace read |
| ENCRYPT, REWRAP, GENERATE_DATA_KEY, SIGN, ROTATE | Namespace write |

Namespace grants use the pattern `cipher.<keyring>.*`. A grant for `cipher.payments.*` with scope `read` allows DECRYPT and KEY_INFO on the `payments` keyring.

## Convergent Encryption

Convergent (deterministic) encryption produces the same ciphertext for the same plaintext and context. This enables equality checks and deduplication at the cost of leaking plaintext equality.

**All three conditions must be met:**
1. Keyring created with `CONVERGENT` flag
2. `CONVERGENT` flag on the ENCRYPT request
3. Non-empty `CONTEXT` provided (AAD is mandatory)

The nonce is derived from `HMAC-SHA256(key_material, plaintext || context)[:12]` instead of a random CSPRNG nonce. REWRAP always uses a random nonce regardless of convergent settings.

## Algorithms

| Algorithm | Type | Key Size | Operations |
|-----------|------|----------|------------|
| `aes-256-gcm` | Symmetric AEAD | 256 bits | Encrypt, Decrypt, Rewrap, GenerateDataKey |
| `chacha20-poly1305` | Symmetric AEAD | 256 bits | Encrypt, Decrypt, Rewrap, GenerateDataKey |
| `hmac-sha256` | Symmetric MAC | 256 bits | Sign, Verify |
| `ed25519` | Asymmetric EdDSA | 256 bits | Sign, Verify |
| `ecdsa-p256` | Asymmetric ECDSA | 256 bits | Sign, Verify |

Using an encryption operation on a signing keyring (or vice versa) returns an error.

## CLI

```
shroudb-cipher-cli [OPTIONS] [COMMAND...]
```

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--addr` | `CIPHER_ADDR` | `127.0.0.1:6599` | Server address |

Without arguments, starts interactive REPL mode. With arguments, executes a single command and exits.

## Error Codes

| Code | Description |
|------|-------------|
| NOTFOUND | Keyring or key version not found |
| EXISTS | Keyring already exists |
| BADARG | Invalid argument (base64, hex, algorithm, key size) |
| WRONGTYPE | Operation not supported for keyring algorithm |
| DISABLED | Keyring is disabled |
| RETIRED | Key version is retired (use REWRAP) |
| POLICY | Operation denied by keyring policy |
| DENIED | Authentication required or insufficient permissions |
| INTERNAL | Unexpected server error |
