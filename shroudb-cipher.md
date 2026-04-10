# Cipher — ShrouDB Repository Analysis

**Component:** shroudb-cipher  
**Type:** Engine (7-crate workspace: core library, engine, protocol, server binary, client SDK, CLI binary, client-side encryption library)  
**Language:** Rust (Edition 2024, MSRV 1.92)  
**License:** MIT OR Apache-2.0  
**Published:** Private registry (`shroudb`), Docker Hub  
**Analyzed:** /Users/nlucas/dev/shroudb/shroudb-cipher (v1.4.10)

---

## Role in Platform

Cipher is the encryption primitive for the entire ShrouDB platform. It manages keyrings of versioned cryptographic keys and performs encrypt/decrypt/sign/verify operations server-side — keys never leave the server boundary. Without Cipher, no other engine can encrypt data at the field level: Sigil cannot route encryption annotations, Veil cannot derive blind indexes (it calls Cipher for decrypt/re-encrypt), and Keep loses its field-level encryption capability. Cipher is the only component that touches raw key material.

---

## Behavioral Surface

### Public API

**RESP3 Commands (13):**

| Command | ACL | Async | Purpose |
|---------|-----|-------|---------|
| `KEYRING CREATE` | Admin | Yes | Create keyring with algorithm, rotation/drain policy, convergent flag |
| `KEYRING LIST` | None | No | List all keyring names |
| `ENCRYPT` | Write (ns) | Yes | Encrypt base64 plaintext, optional AAD context, optional version targeting, optional convergent mode |
| `DECRYPT` | Read (ns) | Yes | Decrypt ciphertext envelope, optional AAD context |
| `REWRAP` | Write (ns) | No | Re-encrypt ciphertext under current active key version |
| `GENERATE_DATA_KEY` | Write (ns) | No | Generate envelope DEK (128/256/512-bit), return plaintext + wrapped |
| `SIGN` | Write (ns) | Yes | Sign base64 data with Ed25519/ECDSA-P256/HMAC-SHA256 |
| `VERIFY_SIGNATURE` | Read (ns) | No | Verify signature against data |
| `ROTATE` | Write (ns) | Yes | Rotate active key, supports `FORCE` and `DRYRUN` |
| `KEY_INFO` | Read (ns) | No | Return keyring metadata and version states |
| `HEALTH` | None | No | Liveness check |
| `PING` | None | No | Echo |
| `COMMAND LIST` | None | No | Introspection |

**Namespace scoping:** Protected commands use `cipher.{keyring}.*` with Read or Write scope.

**Embedded API (library mode):** `CipherEngine<S: Store>` exposes the same operations as async methods. Constructor accepts optional `PolicyEvaluator`, `ChronicleOps`, and `CourierOps` capability traits for Moat integration.

**Client SDK:** `CipherClient` — async Rust client over TCP/RESP3. Result types: `EncryptResult`, `DecryptResult`, `DataKeyResult`, `SignResult`, `RotateResult`.

**Client-side encryption:** `shroudb-cipher-blind` — `ClientKey` for E2EE workflows. Supports generate, derive (HKDF-SHA256), encrypt, encrypt_convergent, decrypt. Wire-compatible `CiphertextEnvelope` output. WASM feature flag for browser entropy.

**CLI:** `shroudb-cipher-cli` — single-command and interactive modes over TCP.

### Core operations traced

**Encrypt flow:** `CipherClient::encrypt()` → RESP3 `ENCRYPT` → `parse_command()` → `dispatch()` → ACL check via `acl_requirement()` → `CipherEngine::encrypt()` → `KeyringManager::get()` (DashMap cache lookup) → `find_active_key()` or `find_key_version()` → base64 decode plaintext → `crypto_ops::encrypt_with_key()` (ring AEAD seal, random or convergent nonce) → `CiphertextEnvelope::encode()` (obfuskey prefix + base64url payload) → optional Chronicle audit event → `CipherResponse::Ok`.

**Rotate flow:** `CipherEngine::rotate()` → age check (`activated_at` vs `rotation_days`) → `KeyringManager::update()` → demote Active → Draining (set `draining_since`) → `generate_key_material()` → push new Active `KeyVersion` → persist to Store → update DashMap cache → emit Chronicle event → notify via Courier (if configured). Background scheduler calls this automatically every `scheduler_interval_secs` (default 3600s).

**Key retirement flow (scheduler):** `run_cycle()` iterates keyrings → finds Draining keys where `draining_since` age ≥ `drain_days` → transitions to Retired → zeroizes key material (`km.zeroize()`, sets `key_material = None`) → persists. Retired keys cannot decrypt.

### Capability gating

Three optional capability traits gate behavior at the engine level:
- `PolicyEvaluator` (from shroudb-acl) — ABAC policy evaluation; when absent, all operations are permitted
- `ChronicleOps` (from shroudb-chronicle-core) — audit event emission; when absent, no audit trail
- `CourierOps` (from shroudb-courier-core) — notifications on rotation; when absent, silent

These are injected via `CipherEngine::new_with_capabilities()`. The standalone server passes `None` for all three; Moat injects live implementations.

Per-keyring `KeyringPolicy` (allowed/denied operation lists) provides a second authorization layer independent of ACL.

---

## Cryptographic Constructs

**Algorithms:**
- AES-256-GCM (AEAD, 32-byte key, 12-byte nonce, 16-byte tag)
- ChaCha20-Poly1305 (AEAD, 32-byte key, 12-byte nonce, 16-byte tag)
- Ed25519 (signing, 32-byte seed → keypair)
- ECDSA-P256 (signing, PKCS8 keypair)
- HMAC-SHA256 (MAC, 32-byte key)

**Key generation:** All via `ring::rand::SystemRandom`. Symmetric keys: 32 bytes CSPRNG. Ed25519: `Ed25519KeyPair::from_seed_unchecked()`. ECDSA-P256: `EcdsaKeyPair::from_pkcs8()`.

**Nonce modes:**
- `Random`: 12 bytes from CSPRNG (default)
- `Convergent`: HMAC-SHA256(key_material, plaintext || aad)[0..12] — deterministic nonce for deduplication/blind index support. Requires non-empty AAD. Requires keyring `convergent: true` AND command flag.

**Key derivation (client-side):** `ClientKey::derive()` uses HKDF-SHA256 with caller-provided shared secret and info context.

**Envelope format:** `{obfuskey_prefix}:{base64url(nonce || ciphertext || tag)}`. Prefix encodes key version (16-bit) and algorithm ID (4-bit) via Obfuskey with BASE62 alphabet. Self-describing: decryptor extracts version and algorithm from prefix without external metadata.

**Envelope encryption (DEK):** `GENERATE_DATA_KEY` creates random DEK (128/256/512-bit), encrypts it with the keyring's active key, returns both plaintext DEK (for immediate use by caller) and wrapped DEK (for storage). Unwrap via standard `DECRYPT`.

**Key state machine:** Staged → Active → Draining → Retired. One-way transitions only. Draining keys can still decrypt/verify but not encrypt/sign (new operations use Active). Retired keys have material zeroized and cannot perform any operation.

**Zeroization:** `zeroize` crate with derive feature. `SecretBytes` (from shroudb-crypto) wraps key material with zeroize-on-drop. Scheduler explicitly zeroizes key material before setting to `None` on retirement. `Zeroizing<Vec<u8>>` used in cipher-blind `ClientKey`.

**Obfuscation:** Ciphertext prefixes use `obfuskey` to prevent version/algorithm enumeration from wire inspection. Not cryptographic — prevents casual metadata leakage.

---

## Engine Relationships

### Calls out to

| Component | Call pattern |
|-----------|-------------|
| `shroudb-store` | Persistence trait — all keyring/key version CRUD |
| `shroudb-storage` | `EmbeddedStore` concrete impl (encrypted KV, used in standalone server) |
| `shroudb-crypto` | All cryptographic primitives (AES, ChaCha, Ed25519, ECDSA, HMAC, HKDF) |
| `shroudb-acl` | `ServerAuthConfig` for token validation, `AclRequirement`/`Scope` for command authorization, `PolicyEvaluator` trait for ABAC |
| `shroudb-chronicle-core` | `ChronicleOps` trait — audit event emission after mutations |
| `shroudb-courier-core` | `CourierOps` trait — notification delivery on key rotation |
| `shroudb-protocol-wire` | RESP3 frame encoding/decoding |
| `shroudb-server-tcp` | `ServerProtocol` trait impl, TCP connection handling |
| `shroudb-server-bootstrap` | Logging init, storage opening, master key sourcing, shutdown handling |
| `shroudb-client-common` | TCP connection abstraction for client SDK |

### Called by

| Component | Relationship |
|-----------|-------------|
| shroudb-moat | Embeds `CipherEngine` + `CipherProtocol` as one of 9 engines |
| shroudb-sigil | Routes `@encrypt`/`@decrypt` annotations to Cipher via CipherOps capability trait |
| shroudb-veil | Calls Cipher for decrypt/re-encrypt during blind index derivation |
| shroudb-codegen | Reads `protocol.toml` to generate client code |

### Sentry / ACL integration

Cipher uses the **Sentry fallback pattern**: it accepts an optional `PolicyEvaluator` (the Sentry capability trait). When Sentry is available (Moat deployment), full ABAC evaluation occurs. When absent (standalone deployment), Cipher falls back to `shroudb-acl`'s built-in token-based ACL with namespace grants.

Token-based auth: `ServerAuthConfig` from shroudb-acl defines tokens with tenant, actor, platform flag, and namespace grants (e.g., `cipher.payments.*` with read/write scopes). Platform tokens get Admin access; scoped tokens get namespace-level access.

Per-command ACL requirements are defined in `CipherCommand::acl_requirement()`: public commands (Health, Ping, KeyringList) require None; KeyringCreate requires Admin; all keyring operations require namespace-scoped Read or Write.

---

## Store Trait

`CipherEngine<S: Store>` is generic over the Store trait. `KeyringManager<S: Store>` uses the store for:
- Namespace: `cipher.keyrings`
- Operations: `create_namespace`, `list`, `get`, `put`
- Keyrings serialized as JSON, stored by name

**Concrete backend in standalone mode:** `shroudb_storage::EmbeddedStore` — encrypted key-value store backed by the ShrouDB storage engine. Master key sourced from `SHROUDB_MASTER_KEY` env var or `SHROUDB_MASTER_KEY_FILE`.

**Remote store mode:** Declared in config schema (`mode: "remote"`, `uri: "..."`) but explicitly unimplemented (`anyhow::bail!("remote store mode not yet implemented")`).

**In-memory cache:** `DashMap<String, Arc<Keyring>>` for O(1) reads. Write-through: mutations persist to Store first, then update cache. `init()` loads all keyrings from Store into cache at startup.

---

## Licensing Tier

**Tier:** Open core (MIT OR Apache-2.0)

All 7 crates are dual-licensed MIT/Apache-2.0 and published to the private `shroudb` registry. No feature flags or capability traits fence commercial-only behavior within this repository. The commercial boundary is at the platform level — Moat (which embeds Cipher with Sentry, Chronicle, Courier capabilities) and the capability trait implementations live in separate repos. Cipher itself is fully functional standalone under the open license.

The `server-crypto` feature flag in cipher-core and cipher-blind gates `shroudb-crypto/server` (likely the ring-backed implementation vs. a lighter WASM-compatible subset), but this is a platform portability concern, not a licensing fence.

---

## Standalone Extractability

**Extractable as independent product:** Yes, with minimal work.

Cipher already runs as a standalone TCP server binary with its own Docker image, CLI, and client SDK. It has no hard runtime dependency on other ShrouDB engines — Sentry, Chronicle, and Courier are optional capabilities. The Store trait abstraction means storage backends could be swapped (though currently only EmbeddedStore is wired).

**Value lost without sibling engines:** Audit trail (Chronicle), notification delivery (Courier), ABAC policy evaluation (Sentry), schema-driven encryption routing (Sigil). These are operational conveniences, not core functionality. The encryption primitive is fully self-contained.

**What would need to be rebuilt:** The `shroudb-store`, `shroudb-storage`, `shroudb-crypto`, `shroudb-acl`, `shroudb-protocol-wire`, `shroudb-server-tcp`, `shroudb-server-bootstrap`, and `shroudb-client-common` crates are upstream dependencies. Extracting Cipher independently would require either bundling these commons crates or replacing them with standalone equivalents. The crypto layer (ring-based) and store abstraction are the most significant.

### Target persona if standalone

Platform engineering teams and security-conscious SaaS companies that need a self-hosted encryption-as-a-service layer without adopting a full cloud KMS (AWS KMS, GCP KMS, HashiCorp Vault Transit). Teams building multi-tenant applications that need per-tenant keyring isolation. Companies with compliance requirements mandating key rotation and audit trails.

### Pricing model fit if standalone

**Usage-based** on encrypt/decrypt operations, with a free tier for development. Alternatively, **open core + support**: the server is free, paid tiers add managed hosting, HA clustering, compliance reporting, and SLA guarantees. The self-describing ciphertext format and automatic rotation create lock-in that supports a subscription model.

---

## Deployment Profile

**Standalone binary:** `shroudb-cipher` TCP server on port 6599. Docker images for amd64/arm64 (Alpine-based, non-root). Config via TOML file or env vars. Master key via `SHROUDB_MASTER_KEY` or `SHROUDB_MASTER_KEY_FILE`.

**Library crate:** `CipherEngine<S: Store>` embeddable in any Rust application. Used by Moat for in-process engine embedding.

**CLI binary:** `shroudb-cipher-cli` for ad-hoc operations and scripting.

**Client-side library:** `shroudb-cipher-blind` for E2EE workflows. WASM-compatible with feature flag.

**Infrastructure dependencies:** Filesystem for EmbeddedStore data directory. No external databases, no cloud services. Self-hostable without specialized expertise — single binary, single config file, single data directory.

**Remote store mode:** Declared but not implemented. Would enable shared storage across Cipher instances.

---

## Monetization Signals

**Present:**
- Per-keyring policy enforcement (`KeyringPolicy` with allowed/denied operations) — enables feature gating per tenant
- Namespace-scoped ACL with tenant isolation (`cipher.{keyring}.*`) — multi-tenant ready
- Token-based auth with platform/scoped distinction — admin vs. application separation
- Audit event emission via Chronicle capability — compliance readiness
- Notification delivery via Courier capability — operational alerting
- Config-seeded keyrings — declarative provisioning for managed offerings

**Absent:**
- No quota enforcement (no rate limiting, no operation counters, no storage limits)
- No usage metering or billing hooks
- No license key validation
- No tenant-scoped resource limits
- No API key rotation or expiration

---

## Architectural Moat (Component-Level)

**Self-describing ciphertext format.** The `CiphertextEnvelope` with obfuscated prefix encoding key version and algorithm means ciphertext is portable and self-routing — no external metadata store needed to decrypt. This is a subtle but significant design choice that simplifies key rotation, rewrap, and cross-system migration. Reproducing this requires getting the encoding right and maintaining backward compatibility.

**Key lifecycle state machine with automatic rotation/drain/retirement.** The Staged → Active → Draining → Retired model with configurable rotation/drain periods, background scheduler, and material zeroization on retirement is production-grade key management. The drain period (where old keys still decrypt but new operations use the new key) is the operationally critical piece that most DIY implementations get wrong.

**Convergent encryption with safety rails.** Deterministic nonce derivation (HMAC-SHA256 of key + plaintext + AAD) is gated behind three checks: keyring flag, command flag, and non-empty context. This prevents accidental nonce reuse while enabling blind index and deduplication use cases. The triple-gate design is a deliberate security decision.

**Wire-compatible client-side encryption.** `cipher-blind` produces `CiphertextEnvelope`-compatible output, meaning client-encrypted and server-encrypted data can coexist in the same storage layer with identical decoding paths. This is architecturally non-trivial.

The primary moat is platform-level: Cipher's value multiplies when composed with Sigil (annotation-driven routing), Veil (blind indexing), and Chronicle (audit). The component alone is a solid encryption service; the composition is what's hard to replicate.

---

## Gaps and Liabilities

**Remote store mode unimplemented.** Config accepts `mode: "remote"` and `uri` but the server hard-fails with `bail!()`. This blocks HA/clustering without Moat.

**No TLS termination.** The standalone server is plaintext TCP. TLS is expected to be handled by a reverse proxy or network layer, but this is not documented prominently. The protocol.toml declares `shroudb-cipher+tls://` URI scheme but the server doesn't implement it.

**No rate limiting or quota enforcement.** A compromised client token can issue unlimited operations. Needs external rate limiting for production standalone deployment.

**No key export/import.** Keys cannot be exported from or imported into a Cipher instance. Migration between instances requires re-encryption. No disaster recovery path for key material beyond storage-level backup.

**Retired key cannot decrypt.** Once a key version is retired and material zeroized, ciphertext encrypted with that version is permanently unrecoverable from Cipher. The drain period must be carefully tuned — there's no safety net.

**No CHANGELOG.** Version history is tag-based only. No human-readable changelog for adopters.

**No LICENSE file.** License is declared in Cargo.toml metadata but no LICENSE or LICENSE-MIT/LICENSE-APACHE files exist in the repo root.

**PolicyEvaluator not wired in standalone mode.** `CipherEngine::new(store, config, None, None)` — the standalone server passes `None` for policy evaluator. This means per-keyring `KeyringPolicy` is the only authorization beyond token ACL. Fine for single-tenant; insufficient for multi-tenant standalone without Sentry.

**Test coverage is integration-heavy.** 11 source files contain `#[test]`/`#[cfg(test)]` (unit tests in core + engine + protocol). 1 integration test file with 15 TCP end-to-end tests covering encryption, rotation, signing, convergent mode, ACL, and edge cases. No fuzz testing. No property-based testing for crypto operations.

---

## Raw Signals for Evaluator

- **Obfuskey dependency** for ciphertext prefix obfuscation suggests active concern about metadata leakage from wire inspection — defense-in-depth thinking.
- **Edition 2024 + MSRV 1.92** — aggressively modern Rust. Signals active maintenance but limits adopter compatibility.
- **Private registry (`shroudb`)** — crates are not on crates.io. Distribution is controlled. The registry name matches the product, suggesting a purpose-built private registry infrastructure.
- **`shroudb-server-bootstrap`** shared crate handles logging, storage opening, master key sourcing, core dump disabling, and shutdown across all ShrouDB engines — indicates mature operational infrastructure.
- **DashMap for in-memory cache** — lock-free concurrent reads, appropriate for read-heavy crypto workloads.
- **No `unsafe` blocks** observed in any Cipher crate source.
- **Courier integration on rotation** — proactive operational notification, not just audit logging. Signals production deployment experience.
- **WASM feature flag** on cipher-blind with `getrandom` JS entropy — browser/edge deployment path for client-side encryption.
- **`cargo deny`** with explicit advisory justifications (RSA Marvin attack, atomic-polyfill) — active supply chain hygiene.
- **Config-seeded keyrings** (`seed_if_absent`) — idempotent declarative provisioning, GitOps-friendly.
- **The `check_policy()` + `acl_requirement()` dual-layer auth** (keyring policy + namespace ACL) is belt-and-suspenders authorization. Both must pass for an operation to succeed.
- **Release workflow** publishes Docker images for both server and CLI, publishes crates to private registry, and is triggered by version tags — mature release automation.
