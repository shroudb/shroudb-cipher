# Changelog

All notable changes to ShrouDB Cipher are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [v1.4.11] - 2026-04-09

### Added

- adapt to chronicle-core 1.3.0 event model

### Fixed

- adapt Event::new to chronicle-core 1.5.0 resource_type field

## [v1.4.10] - 2026-04-04

### Added

- WASM support for cipher-blind via feature-gated shroudb-crypto

### Changed

- use shared ServerAuthConfig from shroudb-acl

### Other

- docs: add shroudb-cipher-blind documentation across all doc files

## [v1.4.9] - 2026-04-03

### Added

- add shroudb-cipher-blind for client-side E2EE encryption

### Other

- remove accidental Cargo.toml.tmp

## [v1.4.8] - 2026-04-02

### Fixed

- use entrypoint script to fix volume mount permissions

### Other

- Use check_dispatch_acl for consistent ACL error formatting

## [v1.4.7] - 2026-04-01

### Other

- Remove local path patch for shroudb-courier-core — fixes CI

## [v1.4.6] - 2026-04-01

### Other

- Wire CourierOps into scheduler for rotation notifications

## [v1.4.5] - 2026-04-01

### Other

- Wire shroudb-server-bootstrap, eliminate startup boilerplate
- Add storage corruption recovery test

## [v1.4.4] - 2026-04-01

### Other

- Zeroize key material on retirement, matching Forge/Sentry pattern
- Migrate client to shroudb-client-common, eliminate ~63 lines of duplication

## [v1.4.3] - 2026-04-01

### Other

- Fail-closed audit for security-critical operations
- Redact key_material in KeyVersion Debug output

## [v1.4.2] - 2026-04-01

### Other

- Migrate TCP handler to shroudb-server-tcp, eliminate ~165 lines of duplication (v1.4.2)

## [v1.4.1] - 2026-03-31

### Other

- Add edge case tests: empty plaintext, max-length encrypt (v1.4.1)

## [v1.4.0] - 2026-03-31

### Other

- Wire ChronicleOps audit events into Cipher engine (v1.4.0)

## [v1.3.3] - 2026-03-31

### Other

- Add ACL unit tests to protocol dispatch (v1.3.3)

## [v1.3.2] - 2026-03-31

### Other

- Arc-wrap keyrings in cache to avoid cloning key material (v1.3.2)

## [v1.3.1] - 2026-03-31

### Other

- Harden server: expect context on unwraps, add concurrency test (v1.3.1)
- Wire actor identity + scheduler graceful shutdown
- Wire optional Sentry ABAC into Cipher (v1.2.0)
- Harden Cipher v1.1.0: SensitiveBytes, dedup, error handling, tests

## [v1.0.0] - 2026-03-29

### Other

- Cipher v1: encryption-as-a-service engine for ShrouDB

