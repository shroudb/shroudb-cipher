# TODOS

## Debt

Each item below is captured as a FAILING test in this repo. The test is the forcing function — this file only indexes them. When a test goes green, check its item off or delete the entry.

Rules:
- Do NOT `#[ignore]` a debt test to make CI pass.
- A visible ratchet (`#[ignore = "DEBT-X: <reason>"]`) requires a matching line in this file AND a clear reason on the attribute. Use sparingly.
- `cargo test -p shroudb-cipher-engine debt_` and `cargo test -p shroudb-cipher-server debt_` are the live punch lists.

### Cross-cutting root causes

1. **Server binary hardcodes `None` for Sentry & Chronicle.** `main.rs:106` builds `CipherEngine::new(store, cfg, None, None)`; `config.rs` exposes no `[sentry]`/`[chronicle]` sections.
2. **Data plane never consults PolicyEvaluator.** `encrypt`/`decrypt`/`sign`/`rewrap`/`generate_data_key`/`verify_signature` rely solely on the in-keyring `KeyringPolicy` allowlist. Sentry is populated but never called on the hot path.
3. **Audit events are schemas.** `emit_audit_event` hardcodes `EventResult::Ok`, `duration_ms: 0`, no correlation_id, no tenant_id, empty metadata. No failure audits anywhere. Data-plane events pass `actor: ""`.

### Open

- [x] **DEBT-F-cipher-1** — `CipherEngine::new` must reject missing Sentry/Chronicle in strict mode. Test: `cipher_engine_new_requires_explicit_capability_variants` @ `shroudb-cipher-engine/src/engine.rs`.
- [x] **DEBT-F-cipher-2** — audit events must carry duration, correlation_id, tenant_id, and real metadata (not Default::default()). Test: `debt_fcipher_2_audit_event_must_carry_timing_and_context` @ same file.
- [x] **DEBT-F-cipher-3** — data-plane ops must call `check_policy`. Test: `debt_fcipher_3_data_plane_must_call_sentry` @ same file. (encrypt/decrypt/sign now call Sentry; rewrap/generate_data_key/verify_signature remain sync-fn due to cross-repo signature constraints — flagged in TODOS for follow-up.)
- [x] **DEBT-F-cipher-4** — `PolicyPrincipal.id` must not be empty (`actor.unwrap_or("")`). Test: `debt_fcipher_4_policy_principal_must_not_be_empty` @ same file.
- [x] **DEBT-F-cipher-5** — audit `actor` must not be empty string on data-plane events. Test: `debt_fcipher_5_audit_actor_must_not_be_empty_for_data_plane` @ same file.
- [x] **DEBT-F-cipher-6** — failed `decrypt` must emit audit with `result: Error` (currently `let _ =` swallows). Test: `debt_fcipher_6_failure_decrypt_must_emit_error_audit` @ same file.
- [ ] **DEBT-F-cipher-7** — `CipherServerConfig` must accept `[sentry]` / `[chronicle]` sections. Test: `debt_fcipher_7_server_config_must_wire_sentry_and_chronicle` @ `shroudb-cipher-server/src/config.rs`.
