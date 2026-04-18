# Cipher Engine DAG

## Overview

Cipher is the ShrouDB encryption-as-a-service engine: an encryption key
lifecycle manager and cryptographic operations server. Applications send
plaintext to Cipher and receive ciphertext; keys never leave the server.
Cipher manages keyrings of versioned keys across five algorithms — AES-256-GCM,
ChaCha20-Poly1305, HMAC-SHA256, Ed25519, and ECDSA-P256 — with a Staged →
Active → Draining → Retired key lifecycle driven by configurable rotation
and drain windows. A background scheduler auto-rotates aging active keys,
auto-retires drained versions (zeroizing their material), and crypto-shreds
retired material. Ciphertext is self-describing: the envelope embeds key
version and algorithm via Obfusbit-obfuscated bitpacking so Cipher can
always select the right key on decrypt. Beyond direct encrypt/decrypt,
Cipher supports REWRAP (migrate ciphertext to new key versions without
exposing plaintext), GENERATE_DATA_KEY for envelope encryption of large
payloads, detached SIGN/VERIFY, opt-in convergent (deterministic)
encryption under strict guardrails, and client-side E2EE via
`shroudb-cipher-blind` producing wire-compatible envelopes.

## Crate Dependency DAG

Internal workspace crates and their direction of dependence.

```
                    +-----------------------+
                    |  shroudb-cipher-core  |  domain types
                    |  (Keyring, KeyVersion,|  (no internal deps)
                    |   CiphertextEnvelope, |
                    |   CipherError, Policy)|
                    +-----------------------+
                         ^        ^        ^
                         |        |        |
          +--------------+        |        +---------------+
          |                       |                        |
          |                       |                        |
+-------------------+   +----------------------+   +----------------------+
| shroudb-cipher-   |   | shroudb-cipher-      |   | shroudb-cipher-      |
|       blind       |   |       engine         |   |       protocol       |
| (client-side E2EE,|   | (Store-backed ops,   |   | (RESP3 parse +       |
|  ClientKey,       |   |  KeyringManager,     |   |  dispatch to engine) |
|  Algorithm)       |   |  scheduler,          |   +----------------------+
+-------------------+   |  crypto_ops)         |              ^
                        +----------------------+              |
                                   ^                          |
                                   |                          |
                                   +--------------+-----------+
                                                  |
                                         +-------------------+
                                         | shroudb-cipher-   |
                                         |      server       |
                                         | (TCP binary;      |
                                         |  pulls core,      |
                                         |  engine, protocol)|
                                         +-------------------+

   +-------------------+          +-------------------+
   | shroudb-cipher-   |          | shroudb-cipher-   |
   |      client       |<---------|        cli        |
   | (Rust SDK;        |          | (clap-driven CLI; |
   |  built on         |          |  uses client only)|
   |  shroudb-client-  |          +-------------------+
   |  common)          |
   +-------------------+
```

Edges (`A -> B` means A depends on B):

- `cipher-core` — leaf of the internal DAG; depends only on commons
  (`shroudb-crypto`, `obfuskey`, `zeroize`).
- `cipher-blind -> cipher-core` (shares `CiphertextEnvelope`,
  `KeyringAlgorithm`).
- `cipher-engine -> cipher-core` (feature `server-crypto`).
- `cipher-protocol -> cipher-engine, cipher-core`.
- `cipher-server -> cipher-protocol, cipher-engine, cipher-core,
  cipher-client` (the last is a dev-dep for integration tests).
- `cipher-client` — independent of the server-side crates; built on
  `shroudb-client-common`.
- `cipher-cli -> cipher-client`.

## Capabilities

Wire commands exposed via RESP3 on TCP port 6599 (confirmed in
`protocol.toml`):

- `KEYRING CREATE <name> <algorithm> [ROTATION_DAYS n] [DRAIN_DAYS n]
  [CONVERGENT]` — create a new keyring with its first active key.
- `KEYRING LIST` — list all keyring names.
- `ENCRYPT <keyring> <base64-plaintext> [CONTEXT s] [KEY_VERSION n]
  [CONVERGENT]` — encrypt with the active (or specified) key version.
- `DECRYPT <keyring> <ciphertext> [CONTEXT s]` — decrypt using the key
  version embedded in the envelope.
- `REWRAP <keyring> <ciphertext> [CONTEXT s]` — re-encrypt existing
  ciphertext under the current active key version without exposing
  plaintext to the caller.
- `GENERATE_DATA_KEY <keyring> [BITS 128|256|512]` — produce a plaintext
  DEK and its wrapped counterpart for envelope-encryption patterns.
- `SIGN <keyring> <base64-data>` — detached signature under the active
  signing key.
- `VERIFY_SIGNATURE <keyring> <base64-data> <hex-signature>` — verify a
  detached signature.
- `ROTATE <keyring> [FORCE] [DRYRUN]` — manual rotation; moves the
  current active key to Draining and provisions a new Active.
- `KEY_INFO <keyring>` — return keyring metadata and per-version state.
- `HEALTH` — liveness probe.
- `AUTH <token>` — authenticate the connection (required when
  `shroudb-acl` auth is enabled).
- `PING` — bare PONG connectivity check.
- `HELLO` — engine identity handshake (name, version, wire protocol,
  command surface, capability tags).
- `COMMAND LIST` — enumerate supported commands.

Background flows running inside `cipher-engine`:

- **Auto-rotation scheduler** (`scheduler.rs`) — wakes on
  `scheduler_interval_secs` (default 3600s), rotates any keyring whose
  active key exceeds `rotation_days`, and retires draining keys past
  `drain_days`, zeroizing their key material.
- **Crypto-shred on retire** — retired key versions have their
  `key_material` field zeroized and cleared before persistence.
- **Policy gates** — two layers. (1) Every op is gated by the keyring's
  own `KeyringPolicy` allowlist (denies raise
  `CipherError::PolicyDenied`). (2) `keyring_create` and `rotate` additionally
  run through the configured ABAC `PolicyEvaluator` (from `shroudb-acl`);
  a Deny decision raises `CipherError::AbacDenied`. Data-plane ops
  (`encrypt`, `decrypt`, `rewrap`, `sign`, `verify_signature`,
  `generate_data_key`, `key_info`) are not ABAC-evaluated today.

Client-side (via `shroudb-cipher-blind`):

- `ClientKey::generate(Algorithm)` — CSPRNG-generated 32-byte key.
- `ClientKey::from_bytes(...)` — import raw 32-byte key material.
- `ClientKey::derive(alg, shared_secret, info, version)` — HKDF-SHA256
  key derivation for E2EE workflows (e.g. post-X25519 exchange).
- `encrypt` / `encrypt_convergent` / `decrypt` — all produce/consume the
  same `CiphertextEnvelope` wire format as the server.

## Engine Dependencies

Cipher pins two other engines' `-core` crates (confirmed in
`shroudb-cipher-engine/Cargo.toml`): `shroudb-chronicle-core` and
`shroudb-courier-core`. Both are optional capability traits at runtime.

### Dependency: Chronicle

- **What breaks without it.** Cipher still encrypts, decrypts, signs,
  verifies, rewraps, rotates, and runs its scheduler. Every call path
  goes through `CipherEngine::emit_audit_event`, which returns `Ok(())`
  immediately when `self.chronicle` is `None` — audit emission is a
  no-op. The data plane is untouched; there is no audit trail.
- **What works with it.** When a `ChronicleOps` implementation is wired
  in (`CipherEngine::new` or `new_with_capabilities`), a subset of
  operations record an `Event` tagged `ChronicleEngine::Cipher` with
  resource type `keyring`, the resource name, `EventResult::Ok`, and
  the actor. Currently instrumented: `keyring_create`, `encrypt`,
  `decrypt`, `sign`, `rotate`. **Not instrumented** (known gap):
  `rewrap`, `generate_data_key`, `verify_signature`. If Chronicle is
  configured but the `record` call fails, Cipher fails-closed on the
  instrumented operations — `emit_audit_event` returns
  `CipherError::Internal("audit failed: …")`, which propagates out of
  the caller (so for example a `keyring_create` with a broken
  Chronicle link returns an error to the client rather than silently
  dropping the audit record). `decrypt` is the one exception: it logs
  an audit attempt but swallows failure (`let _ = self.emit_audit_event
  …`) so a downed Chronicle cannot lock callers out of reading their
  own ciphertext.

### Dependency: Courier

- **What breaks without it.** Cipher's scheduler still auto-rotates and
  auto-retires keys on schedule; only the operator-facing notification
  is skipped. `CipherEngine::courier()` returns `None`, and the
  `if let Some(c) = engine.courier()` guard in `scheduler::run_cycle`
  short-circuits. Rotation events are still written to `tracing` logs
  (and, if Chronicle is up, to the audit stream).
- **What works with it.** On every successful auto-rotation inside the
  scheduler, Cipher calls `CourierOps::notify("ops", "Key rotated",
  "Keyring '<name>' rotated to v<n>")`, dispatching the alert through
  whatever channel the configured Courier implementation routes `ops`
  to. If the notify call errors, the scheduler logs a warning but does
  not fail the rotation — rotation correctness takes precedence over
  notification delivery.

## Reverse Dependencies

Engines and downstream workspaces that pin Cipher crates (grepped from
`Cargo.toml` files under `/Users/nlucas/dev`):

- **Courier** (`shroudb-courier-server`) pins `shroudb-cipher-client` and
  maintains a `cipher_client.rs` module — Courier uses Cipher to encrypt
  notification template bodies at rest.
- **Scroll** (`shroudb-scroll-server`) pins `shroudb-cipher-client` and
  `shroudb-cipher-core`, consuming the same envelope format used by the
  server.
- **Sigil** (`shroudb-sigil-engine`, `shroudb-sigil-server`) pins
  `shroudb-cipher-client` and `shroudb-cipher-blind` — Sigil routes
  field-level PII encryption through Cipher, and uses `cipher-blind`
  for credentials that must never reach the Cipher server in plaintext.
- **Moat** (`shroudb-moat`) has a `cipher` feature that pulls
  `shroudb-cipher-protocol`, `shroudb-cipher-engine`, and
  `shroudb-cipher-core` in-process.
- **Herald SDK** (`herald-sdk-typescript/wasm`) pulls
  `shroudb-cipher-blind` with the `wasm` feature for browser-side
  `crypto.getRandomValues`-backed E2EE.
- **DAL** (`dal-server`) has a `cipher` feature bundling
  `cipher-core`, `cipher-engine`, and `cipher-protocol`.

## Deployment Modes

Cipher supports two deployment shapes driven from the same
`cipher-engine` core.

**Standalone.** The `shroudb-cipher-server` binary (`shroudb-cipher` on
disk) listens on TCP `0.0.0.0:6599` by default (confirmed in
`server/src/config.rs`). It drives the RESP3 protocol via
`shroudb-server-tcp` and `shroudb-protocol-wire`, boots the store in
either `embedded` mode (in-process ShrouDB at `./cipher-data`) or
remote mode (connecting to an existing ShrouDB server via `uri`), and
starts the auto-rotation scheduler. Auth is token-based via
`shroudb-acl`, disabled by default (dev mode). Clients talk to it with
`shroudb-cipher-client` or any code-generated client derived from
`protocol.toml`.

**Embedded in Moat.** Moat's optional `cipher` Cargo feature pulls
`cipher-engine`, `cipher-protocol`, and `cipher-core` directly into the
single-binary hub. In this mode the RESP3 dispatcher is wired against
a shared in-process `CipherEngine` instead of going over the wire, and
Moat is responsible for providing the `Store`, `PolicyEvaluator`,
`ChronicleOps`, and `CourierOps` capabilities — Cipher keeps the same
API surface regardless of how it is hosted.
