use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use shroudb_acl::AuthContext;
use shroudb_cipher_core::keyring::KeyringAlgorithm;
use shroudb_cipher_engine::engine::CipherEngine;
use shroudb_store::Store;

use crate::commands::CipherCommand;
use crate::response::CipherResponse;

const SUPPORTED_COMMANDS: &[&str] = &[
    "AUTH",
    "KEYRING CREATE",
    "KEYRING LIST",
    "ENCRYPT",
    "DECRYPT",
    "REWRAP",
    "GENERATE_DATA_KEY",
    "SIGN",
    "VERIFY_SIGNATURE",
    "ROTATE",
    "KEY_INFO",
    "HEALTH",
    "PING",
    "COMMAND LIST",
];

/// Dispatch a parsed command to the CipherEngine and produce a response.
///
/// `auth_context` is the authenticated identity for this connection/request.
/// `None` means auth is disabled (dev mode / no auth config).
/// AUTH commands are handled externally by the TCP layer — dispatch never sees them.
pub async fn dispatch<S: Store>(
    engine: &CipherEngine<S>,
    cmd: CipherCommand,
    auth_context: Option<&AuthContext>,
) -> CipherResponse {
    // Check ACL requirement before dispatch
    let requirement = cmd.acl_requirement();
    if let Some(ctx) = auth_context
        && let Err(e) = ctx.check(&requirement)
    {
        return CipherResponse::error(format!("access denied: {e}"));
    }

    match cmd {
        CipherCommand::Auth { .. } => CipherResponse::error("AUTH handled at connection layer"),

        // ── Keyring management ─────────────────────────────────────
        CipherCommand::KeyringCreate {
            name,
            algorithm,
            rotation_days,
            drain_days,
            convergent,
        } => {
            let algo: KeyringAlgorithm = match algorithm.parse() {
                Ok(a) => a,
                Err(e) => return CipherResponse::error(e),
            };
            match engine
                .keyring_create(&name, algo, rotation_days, drain_days, convergent)
                .await
            {
                Ok(info) => CipherResponse::ok(serde_json::json!({
                    "status": "ok",
                    "keyring": info.name,
                    "algorithm": info.algorithm.wire_name(),
                    "active_version": info.active_version,
                })),
                Err(e) => CipherResponse::error(e.to_string()),
            }
        }

        CipherCommand::KeyringList => {
            let names = engine.keyring_list();
            CipherResponse::ok(serde_json::json!(names))
        }

        // ── Encrypt ────────────────────────────────────────────────
        CipherCommand::Encrypt {
            keyring,
            plaintext,
            context,
            key_version,
            convergent,
        } => match engine.encrypt(
            &keyring,
            &plaintext,
            context.as_deref(),
            key_version,
            convergent,
        ) {
            Ok(result) => CipherResponse::ok(serde_json::json!({
                "status": "ok",
                "ciphertext": result.ciphertext,
                "key_version": result.key_version,
            })),
            Err(e) => CipherResponse::error(e.to_string()),
        },

        // ── Decrypt ───────���────────────────────────────���───────────
        CipherCommand::Decrypt {
            keyring,
            ciphertext,
            context,
        } => match engine.decrypt(&keyring, &ciphertext, context.as_deref()) {
            Ok(result) => CipherResponse::ok(serde_json::json!({
                "status": "ok",
                "plaintext": STANDARD.encode(&result.plaintext),
            })),
            Err(e) => CipherResponse::error(e.to_string()),
        },

        // ── Rewrap ──────────────────────��──────────────────────────
        CipherCommand::Rewrap {
            keyring,
            ciphertext,
            context,
        } => match engine.rewrap(&keyring, &ciphertext, context.as_deref()) {
            Ok(result) => CipherResponse::ok(serde_json::json!({
                "status": "ok",
                "ciphertext": result.ciphertext,
                "key_version": result.key_version,
            })),
            Err(e) => CipherResponse::error(e.to_string()),
        },

        // ── Generate data key ──────────────────────────────────────
        CipherCommand::GenerateDataKey { keyring, bits } => {
            match engine.generate_data_key(&keyring, bits) {
                Ok(result) => CipherResponse::ok(serde_json::json!({
                    "status": "ok",
                    "plaintext_key": STANDARD.encode(&result.plaintext_key),
                    "wrapped_key": result.wrapped_key,
                    "key_version": result.key_version,
                })),
                Err(e) => CipherResponse::error(e.to_string()),
            }
        }

        // ── Sign ───────────────────────────────────��───────────────
        CipherCommand::Sign { keyring, data } => match engine.sign(&keyring, &data) {
            Ok(result) => CipherResponse::ok(serde_json::json!({
                "status": "ok",
                "signature": hex::encode(&result.signature),
                "key_version": result.key_version,
            })),
            Err(e) => CipherResponse::error(e.to_string()),
        },

        // ── Verify signature ───────────────────────────────────────
        CipherCommand::VerifySignature {
            keyring,
            data,
            signature,
        } => match engine.verify_signature(&keyring, &data, &signature) {
            Ok(valid) => CipherResponse::ok(serde_json::json!({
                "status": "ok",
                "valid": valid,
            })),
            Err(e) => CipherResponse::error(e.to_string()),
        },

        // ── Rotate ─────────────────────────────────────────────────
        CipherCommand::Rotate {
            keyring,
            force,
            dryrun,
        } => match engine.rotate(&keyring, force, dryrun).await {
            Ok(result) => CipherResponse::ok(serde_json::json!({
                "status": "ok",
                "rotated": result.rotated,
                "key_version": result.key_version,
                "previous_version": result.previous_version,
            })),
            Err(e) => CipherResponse::error(e.to_string()),
        },

        // ── Key info ──────���────────────────────────────────────────
        CipherCommand::KeyInfo { keyring } => match engine.key_info(&keyring) {
            Ok(info) => CipherResponse::ok(serde_json::json!({
                "keyring": info.name,
                "algorithm": info.algorithm.wire_name(),
                "active_version": info.active_version,
                "versions": info.versions,
            })),
            Err(e) => CipherResponse::error(e.to_string()),
        },

        // ── Operational ──────��─────────────────────────────────────
        CipherCommand::Health => CipherResponse::ok(serde_json::json!({
            "status": "ok",
        })),

        CipherCommand::Ping => CipherResponse::ok(serde_json::json!("PONG")),

        CipherCommand::CommandList => CipherResponse::ok(serde_json::json!({
            "count": SUPPORTED_COMMANDS.len(),
            "commands": SUPPORTED_COMMANDS,
        })),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::commands::parse_command;
    use shroudb_cipher_engine::engine::CipherConfig;

    async fn setup() -> CipherEngine<shroudb_storage::EmbeddedStore> {
        let store = create_test_store().await;
        CipherEngine::new(store, CipherConfig::default())
            .await
            .unwrap()
    }

    async fn create_test_store() -> Arc<shroudb_storage::EmbeddedStore> {
        let dir = tempfile::tempdir().unwrap().keep();
        let config = shroudb_storage::StorageEngineConfig {
            data_dir: dir,
            ..Default::default()
        };
        let engine = shroudb_storage::StorageEngine::open(config, &EphemeralKey)
            .await
            .unwrap();
        Arc::new(shroudb_storage::EmbeddedStore::new(
            Arc::new(engine),
            "cipher-test",
        ))
    }

    struct EphemeralKey;
    impl shroudb_storage::MasterKeySource for EphemeralKey {
        fn source_name(&self) -> &str {
            "ephemeral-test"
        }
        fn load<'a>(
            &'a self,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<shroudb_crypto::SecretBytes, shroudb_storage::StorageError>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(shroudb_crypto::SecretBytes::new(vec![0x42u8; 32])) })
        }
    }

    #[tokio::test]
    async fn full_encrypt_decrypt_flow() {
        let engine = setup().await;

        // Create keyring
        let cmd = parse_command(&["KEYRING", "CREATE", "payments", "aes-256-gcm"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "keyring create failed: {resp:?}");

        // Encrypt
        let cmd = parse_command(&["ENCRYPT", "payments", "SGVsbG8gV29ybGQ="]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "encrypt failed: {resp:?}");

        let ciphertext = match &resp {
            CipherResponse::Ok(v) => v["ciphertext"].as_str().unwrap().to_string(),
            _ => panic!("expected ok"),
        };

        // Decrypt
        let cmd = parse_command(&["DECRYPT", "payments", &ciphertext]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok(), "decrypt failed: {resp:?}");

        let plaintext = match &resp {
            CipherResponse::Ok(v) => v["plaintext"].as_str().unwrap().to_string(),
            _ => panic!("expected ok"),
        };
        assert_eq!(plaintext, "SGVsbG8gV29ybGQ=");
    }

    #[tokio::test]
    async fn rotate_and_rewrap_flow() {
        let engine = setup().await;

        let cmd = parse_command(&["KEYRING", "CREATE", "test", "aes-256-gcm"]).unwrap();
        dispatch(&engine, cmd, None).await;

        let cmd = parse_command(&["ENCRYPT", "test", "SGVsbG8="]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        let ct = match &resp {
            CipherResponse::Ok(v) => v["ciphertext"].as_str().unwrap().to_string(),
            _ => panic!("expected ok"),
        };

        // Rotate
        let cmd = parse_command(&["ROTATE", "test", "FORCE"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());

        // Rewrap
        let cmd = parse_command(&["REWRAP", "test", &ct]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn sign_verify_flow() {
        let engine = setup().await;

        let cmd = parse_command(&["KEYRING", "CREATE", "signing", "ed25519"]).unwrap();
        dispatch(&engine, cmd, None).await;

        let cmd = parse_command(&["SIGN", "signing", "SGVsbG8="]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        let sig = match &resp {
            CipherResponse::Ok(v) => v["signature"].as_str().unwrap().to_string(),
            _ => panic!("expected ok"),
        };

        let cmd = parse_command(&["VERIFY_SIGNATURE", "signing", "SGVsbG8=", &sig]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());
        match &resp {
            CipherResponse::Ok(v) => assert!(v["valid"].as_bool().unwrap()),
            _ => panic!("expected ok"),
        }
    }

    #[tokio::test]
    async fn health_and_ping() {
        let engine = setup().await;

        let cmd = parse_command(&["HEALTH"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());

        let cmd = parse_command(&["PING"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn keyring_list_flow() {
        let engine = setup().await;

        let cmd = parse_command(&["KEYRING", "CREATE", "a", "aes-256-gcm"]).unwrap();
        dispatch(&engine, cmd, None).await;
        let cmd = parse_command(&["KEYRING", "CREATE", "b", "ed25519"]).unwrap();
        dispatch(&engine, cmd, None).await;

        let cmd = parse_command(&["KEYRING", "LIST"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn key_info_flow() {
        let engine = setup().await;

        let cmd = parse_command(&["KEYRING", "CREATE", "test", "aes-256-gcm"]).unwrap();
        dispatch(&engine, cmd, None).await;

        let cmd = parse_command(&["KEY_INFO", "test"]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn nonexistent_keyring_returns_error() {
        let engine = setup().await;

        let cmd = parse_command(&["ENCRYPT", "nope", "SGVsbG8="]).unwrap();
        let resp = dispatch(&engine, cmd, None).await;
        assert!(!resp.is_ok());
    }
}
