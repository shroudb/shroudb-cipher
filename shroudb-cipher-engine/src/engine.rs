use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use shroudb_acl::{PolicyEffect, PolicyEvaluator, PolicyPrincipal, PolicyRequest, PolicyResource};
use shroudb_cipher_core::ciphertext::CiphertextEnvelope;
use shroudb_cipher_core::error::CipherError;
use shroudb_cipher_core::key_version::KeyState;
use shroudb_cipher_core::keyring::KeyringAlgorithm;
use shroudb_cipher_core::policy::KeyringOperation;
use shroudb_crypto::{SecretBytes, SensitiveBytes};
use shroudb_store::Store;

use crate::crypto_ops::{self, NonceMode};
use crate::keyring_manager::{
    KeyringCreateOpts, KeyringManager, find_active_key, find_key_version,
};

/// Configuration for the Cipher engine.
pub struct CipherConfig {
    pub default_rotation_days: u32,
    pub default_drain_days: u32,
    pub scheduler_interval_secs: u64,
}

impl Default for CipherConfig {
    fn default() -> Self {
        Self {
            default_rotation_days: 90,
            default_drain_days: 30,
            scheduler_interval_secs: 3600,
        }
    }
}

/// Encrypt operation result.
#[derive(Debug)]
pub struct EncryptResult {
    pub ciphertext: String,
    pub key_version: u32,
}

/// Decrypt operation result.
#[derive(Debug)]
pub struct DecryptResult {
    pub plaintext: SensitiveBytes,
}

/// Data encryption key result (envelope encryption).
#[derive(Debug)]
pub struct DataKeyResult {
    pub plaintext_key: SensitiveBytes,
    pub wrapped_key: String,
    pub key_version: u32,
}

/// Sign operation result.
#[derive(Debug)]
pub struct SignResult {
    pub signature: SensitiveBytes,
    pub key_version: u32,
}

/// Rotate operation result.
#[derive(Debug)]
pub struct RotateResult {
    pub key_version: u32,
    pub previous_version: Option<u32>,
    pub rotated: bool,
}

/// Key info result.
#[derive(Debug)]
pub struct KeyInfoResult {
    pub name: String,
    pub algorithm: KeyringAlgorithm,
    pub active_version: Option<u32>,
    pub versions: serde_json::Value,
}

/// The unified Cipher engine. Single entry point for all operations.
///
/// Generic over `S: Store` — works identically with `EmbeddedStore`
/// (in-process ShrouDB) or `RemoteStore` (TCP to ShrouDB server).
pub struct CipherEngine<S: Store> {
    pub(crate) keyrings: KeyringManager<S>,
    pub(crate) config: CipherConfig,
    policy_evaluator: Option<Arc<dyn PolicyEvaluator>>,
}

impl<S: Store> CipherEngine<S> {
    /// Create a new Cipher engine.
    pub async fn new(
        store: Arc<S>,
        config: CipherConfig,
        policy_evaluator: Option<Arc<dyn PolicyEvaluator>>,
    ) -> Result<Self, CipherError> {
        let keyrings = KeyringManager::new(store);
        keyrings.init().await?;
        Ok(Self {
            keyrings,
            config,
            policy_evaluator,
        })
    }

    async fn check_policy(
        &self,
        resource_id: &str,
        action: &str,
        actor: Option<&str>,
    ) -> Result<(), CipherError> {
        let Some(evaluator) = &self.policy_evaluator else {
            return Ok(());
        };
        let request = PolicyRequest {
            principal: PolicyPrincipal {
                id: actor.unwrap_or("").to_string(),
                roles: vec![],
                claims: Default::default(),
            },
            resource: PolicyResource {
                id: resource_id.to_string(),
                resource_type: "keyring".to_string(),
                attributes: Default::default(),
            },
            action: action.to_string(),
        };
        let decision = evaluator
            .evaluate(&request)
            .await
            .map_err(|e| CipherError::Internal(format!("policy evaluation: {e}")))?;
        if decision.effect == PolicyEffect::Deny {
            return Err(CipherError::AbacDenied {
                action: action.to_string(),
                resource: resource_id.to_string(),
                policy: decision.matched_policy.unwrap_or_default(),
            });
        }
        Ok(())
    }

    // ── Keyring management ─────────────────────────────────────────

    pub async fn keyring_create(
        &self,
        name: &str,
        algorithm: KeyringAlgorithm,
        rotation_days: Option<u32>,
        drain_days: Option<u32>,
        convergent: bool,
        actor: Option<&str>,
    ) -> Result<KeyInfoResult, CipherError> {
        self.check_policy(name, "keyring_create", actor).await?;
        let kr = self
            .keyrings
            .create(
                name,
                algorithm,
                KeyringCreateOpts {
                    rotation_days: rotation_days.unwrap_or(self.config.default_rotation_days),
                    drain_days: drain_days.unwrap_or(self.config.default_drain_days),
                    convergent,
                    ..Default::default()
                },
            )
            .await?;
        Ok(build_key_info(&kr))
    }

    pub fn keyring_list(&self) -> Vec<String> {
        self.keyrings.list()
    }

    // ── Encrypt ────────────────────────────────────────────────────

    pub fn encrypt(
        &self,
        keyring_name: &str,
        plaintext_b64: &str,
        context: Option<&str>,
        key_version: Option<u32>,
        convergent: bool,
    ) -> Result<EncryptResult, CipherError> {
        let keyring = self.keyrings.get(keyring_name)?;
        check_disabled(&keyring)?;
        check_policy(&keyring, KeyringOperation::Encrypt)?;

        if !keyring.algorithm.is_encryption() {
            return Err(CipherError::AlgorithmMismatch {
                expected: keyring.algorithm.wire_name().to_string(),
                required: "encryption algorithm".to_string(),
            });
        }

        let plaintext = STANDARD
            .decode(plaintext_b64)
            .map_err(|e| CipherError::InvalidArgument(format!("invalid base64 plaintext: {e}")))?;

        let kv = match key_version {
            Some(v) => find_key_version(&keyring, v)?,
            None => find_active_key(&keyring)?,
        };

        // Key must be Active or Draining for encryption
        if kv.state == KeyState::Retired {
            return Err(CipherError::KeyVersionRetired {
                keyring: keyring_name.to_string(),
                version: kv.version,
            });
        }

        let key_material = decode_key_material(kv)?;
        let aad = context.unwrap_or("").as_bytes();

        // Convergent encryption guardrails
        let nonce_mode = if convergent {
            if !keyring.convergent {
                return Err(CipherError::ConvergentGuard);
            }
            if context.is_none() || context == Some("") {
                return Err(CipherError::ConvergentGuard);
            }
            NonceMode::Convergent {
                key_material: key_material.as_bytes(),
                plaintext: &plaintext,
                aad,
            }
        } else {
            NonceMode::Random
        };

        let payload = crypto_ops::encrypt_with_key(
            keyring.algorithm,
            key_material.as_bytes(),
            &plaintext,
            aad,
            nonce_mode,
        )?;

        let envelope = CiphertextEnvelope {
            key_version: kv.version,
            algorithm: keyring.algorithm,
            payload,
        };

        Ok(EncryptResult {
            ciphertext: envelope.encode()?,
            key_version: kv.version,
        })
    }

    // ── Decrypt ────────────────────────────────────────────────────

    pub fn decrypt(
        &self,
        keyring_name: &str,
        ciphertext: &str,
        context: Option<&str>,
    ) -> Result<DecryptResult, CipherError> {
        let keyring = self.keyrings.get(keyring_name)?;
        check_disabled(&keyring)?;
        check_policy(&keyring, KeyringOperation::Decrypt)?;

        let envelope = CiphertextEnvelope::decode(ciphertext)?;
        envelope.validate_algorithm(keyring.algorithm)?;

        let kv = find_key_version(&keyring, envelope.key_version)?;

        if kv.state == KeyState::Retired {
            return Err(CipherError::KeyVersionRetired {
                keyring: keyring_name.to_string(),
                version: kv.version,
            });
        }

        let key_material = decode_key_material(kv)?;
        let aad = context.unwrap_or("").as_bytes();

        let plaintext = crypto_ops::decrypt_with_key(
            keyring.algorithm,
            key_material.as_bytes(),
            &envelope.payload,
            aad,
        )?;

        Ok(DecryptResult {
            plaintext: plaintext.into(),
        })
    }

    // ── Rewrap ─────────────────────────────────────────────────────

    pub fn rewrap(
        &self,
        keyring_name: &str,
        ciphertext: &str,
        context: Option<&str>,
    ) -> Result<EncryptResult, CipherError> {
        let keyring = self.keyrings.get(keyring_name)?;
        check_disabled(&keyring)?;
        check_policy(&keyring, KeyringOperation::Rewrap)?;

        let envelope = CiphertextEnvelope::decode(ciphertext)?;
        envelope.validate_algorithm(keyring.algorithm)?;

        // Decrypt with the old key
        let old_kv = find_key_version(&keyring, envelope.key_version)?;
        if old_kv.state == KeyState::Retired {
            return Err(CipherError::KeyVersionRetired {
                keyring: keyring_name.to_string(),
                version: old_kv.version,
            });
        }

        let old_key = decode_key_material(old_kv)?;
        let aad = context.unwrap_or("").as_bytes();

        let plaintext = crypto_ops::decrypt_with_key(
            keyring.algorithm,
            old_key.as_bytes(),
            &envelope.payload,
            aad,
        )?;

        // Re-encrypt with the active key (always random nonce)
        let active_kv = find_active_key(&keyring)?;
        let active_key = decode_key_material(active_kv)?;

        let new_payload = crypto_ops::encrypt_with_key(
            keyring.algorithm,
            active_key.as_bytes(),
            &plaintext,
            aad,
            NonceMode::Random,
        )?;

        let new_envelope = CiphertextEnvelope {
            key_version: active_kv.version,
            algorithm: keyring.algorithm,
            payload: new_payload,
        };

        Ok(EncryptResult {
            ciphertext: new_envelope.encode()?,
            key_version: active_kv.version,
        })
    }

    // ── Generate data key ──────────────────────────────────────────

    pub fn generate_data_key(
        &self,
        keyring_name: &str,
        bits: Option<u32>,
    ) -> Result<DataKeyResult, CipherError> {
        let keyring = self.keyrings.get(keyring_name)?;
        check_disabled(&keyring)?;
        check_policy(&keyring, KeyringOperation::GenerateDataKey)?;

        if !keyring.algorithm.is_encryption() {
            return Err(CipherError::AlgorithmMismatch {
                expected: keyring.algorithm.wire_name().to_string(),
                required: "encryption algorithm".to_string(),
            });
        }

        let key_size = match bits.unwrap_or(256) {
            128 => 16,
            256 => 32,
            512 => 64,
            other => {
                return Err(CipherError::InvalidArgument(format!(
                    "invalid key size: {other} bits (must be 128, 256, or 512)"
                )));
            }
        };

        // Generate random data key
        let rng = ring::rand::SystemRandom::new();
        let mut dek = vec![0u8; key_size];
        ring::rand::SecureRandom::fill(&rng, &mut dek)
            .map_err(|_| CipherError::Internal("CSPRNG failed".into()))?;

        // Wrap DEK with active key
        let active_kv = find_active_key(&keyring)?;
        let active_key = decode_key_material(active_kv)?;

        let wrapped_payload = crypto_ops::encrypt_with_key(
            keyring.algorithm,
            active_key.as_bytes(),
            &dek,
            b"",
            NonceMode::Random,
        )?;

        let wrapped_envelope = CiphertextEnvelope {
            key_version: active_kv.version,
            algorithm: keyring.algorithm,
            payload: wrapped_payload,
        };

        Ok(DataKeyResult {
            plaintext_key: dek.into(),
            wrapped_key: wrapped_envelope.encode()?,
            key_version: active_kv.version,
        })
    }

    // ── Sign ───────────────────────────────────────────────────────

    pub fn sign(&self, keyring_name: &str, data_b64: &str) -> Result<SignResult, CipherError> {
        let keyring = self.keyrings.get(keyring_name)?;
        check_disabled(&keyring)?;
        check_policy(&keyring, KeyringOperation::Sign)?;

        if !keyring.algorithm.is_signing() {
            return Err(CipherError::AlgorithmMismatch {
                expected: keyring.algorithm.wire_name().to_string(),
                required: "signing algorithm".to_string(),
            });
        }

        let data = STANDARD
            .decode(data_b64)
            .map_err(|e| CipherError::InvalidArgument(format!("invalid base64 data: {e}")))?;

        let active_kv = find_active_key(&keyring)?;
        let key_material = decode_key_material(active_kv)?;

        let signature =
            crypto_ops::sign_with_key(keyring.algorithm, key_material.as_bytes(), &data)?;

        Ok(SignResult {
            signature: signature.into(),
            key_version: active_kv.version,
        })
    }

    // ── Verify signature ───────────────────────────────────────────

    pub fn verify_signature(
        &self,
        keyring_name: &str,
        data_b64: &str,
        signature_hex: &str,
    ) -> Result<bool, CipherError> {
        let keyring = self.keyrings.get(keyring_name)?;
        check_disabled(&keyring)?;
        check_policy(&keyring, KeyringOperation::VerifySignature)?;

        if !keyring.algorithm.is_signing() {
            return Err(CipherError::AlgorithmMismatch {
                expected: keyring.algorithm.wire_name().to_string(),
                required: "signing algorithm".to_string(),
            });
        }

        let data = STANDARD
            .decode(data_b64)
            .map_err(|e| CipherError::InvalidArgument(format!("invalid base64 data: {e}")))?;

        let signature = hex::decode(signature_hex)
            .map_err(|e| CipherError::InvalidArgument(format!("invalid hex signature: {e}")))?;

        // Try Active and Draining key versions
        for kv in &keyring.key_versions {
            if kv.state != KeyState::Active && kv.state != KeyState::Draining {
                continue;
            }

            let key_material = match decode_key_material(kv) {
                Ok(km) => km,
                Err(e) => {
                    tracing::warn!(
                        keyring = keyring_name,
                        version = kv.version,
                        error = %e,
                        "corrupt key material during signature verification"
                    );
                    continue;
                }
            };

            let public_key = kv.public_key.as_ref().and_then(|pk| hex::decode(pk).ok());

            match crypto_ops::verify_with_key(
                keyring.algorithm,
                key_material.as_bytes(),
                public_key.as_deref(),
                &data,
                &signature,
            ) {
                Ok(true) => return Ok(true),
                Ok(false) => continue,
                Err(e) => {
                    tracing::debug!(
                        keyring = keyring_name,
                        version = kv.version,
                        error = %e,
                        "signature verification error for key version"
                    );
                    continue;
                }
            }
        }

        Ok(false)
    }

    // ── Rotate ─────────────────────────────────────────────────────

    pub async fn rotate(
        &self,
        keyring_name: &str,
        force: bool,
        dryrun: bool,
        actor: Option<&str>,
    ) -> Result<RotateResult, CipherError> {
        self.check_policy(keyring_name, "rotate", actor).await?;
        let keyring = self.keyrings.get(keyring_name)?;
        check_disabled(&keyring)?;
        check_policy(&keyring, KeyringOperation::Rotate)?;

        let active_kv = find_active_key(&keyring)?;
        let now = unix_now();

        // Check if rotation is due (unless forced)
        if !force {
            let age_days = active_kv
                .activated_at
                .map(|at| (now.saturating_sub(at)) / 86400)
                .unwrap_or(0);
            if age_days < keyring.rotation_days as u64 {
                return Ok(RotateResult {
                    key_version: active_kv.version,
                    previous_version: None,
                    rotated: false,
                });
            }
        }

        if dryrun {
            return Ok(RotateResult {
                key_version: active_kv.version + 1,
                previous_version: Some(active_kv.version),
                rotated: true,
            });
        }

        let algorithm = keyring.algorithm;
        let prev_version = active_kv.version;

        let keyring = self
            .keyrings
            .update(keyring_name, |kr| {
                // Demote current Active → Draining
                for kv in &mut kr.key_versions {
                    if kv.state == KeyState::Active {
                        kv.state = KeyState::Draining;
                        kv.draining_since = Some(now);
                    }
                }

                // Generate new Active key
                let gkm = crypto_ops::generate_key_material(algorithm)?;
                let new_version = kr
                    .key_versions
                    .iter()
                    .map(|kv| kv.version)
                    .max()
                    .unwrap_or(0)
                    + 1;

                kr.key_versions.push(KeyVersion {
                    version: new_version,
                    state: KeyState::Active,
                    key_material: Some(hex::encode(gkm.private_key.as_bytes())),
                    public_key: gkm.public_key.map(hex::encode),
                    created_at: now,
                    activated_at: Some(now),
                    draining_since: None,
                    retired_at: None,
                });

                Ok(())
            })
            .await?;

        let new_active = find_active_key(&keyring)?;

        tracing::info!(
            keyring = keyring_name,
            new_version = new_active.version,
            previous_version = prev_version,
            "keyring rotated"
        );

        Ok(RotateResult {
            key_version: new_active.version,
            previous_version: Some(prev_version),
            rotated: true,
        })
    }

    // ── Key info ───────────────────────────────────────────────────

    pub fn key_info(&self, keyring_name: &str) -> Result<KeyInfoResult, CipherError> {
        let keyring = self.keyrings.get(keyring_name)?;
        check_policy(&keyring, KeyringOperation::KeyInfo)?;
        Ok(build_key_info(&keyring))
    }

    // ── Scheduler access ───────────────────────────────────────────

    pub fn keyring_manager(&self) -> &KeyringManager<S> {
        &self.keyrings
    }
}

fn check_disabled(keyring: &shroudb_cipher_core::keyring::Keyring) -> Result<(), CipherError> {
    if keyring.disabled {
        return Err(CipherError::Disabled(keyring.name.clone()));
    }
    Ok(())
}

fn check_policy(
    keyring: &shroudb_cipher_core::keyring::Keyring,
    op: KeyringOperation,
) -> Result<(), CipherError> {
    if !keyring.policy.allows(op) {
        return Err(CipherError::PolicyDenied {
            keyring: keyring.name.clone(),
            operation: op,
        });
    }
    Ok(())
}

fn decode_key_material(
    kv: &shroudb_cipher_core::key_version::KeyVersion,
) -> Result<SecretBytes, CipherError> {
    let hex_str = kv
        .key_material
        .as_ref()
        .ok_or_else(|| CipherError::Internal("key version has no key material".into()))?;
    let bytes = hex::decode(hex_str)
        .map_err(|e| CipherError::Internal(format!("corrupt key material hex: {e}")))?;
    Ok(SecretBytes::new(bytes))
}

fn build_key_info(keyring: &shroudb_cipher_core::keyring::Keyring) -> KeyInfoResult {
    let active_version = keyring
        .key_versions
        .iter()
        .find(|kv| kv.state == KeyState::Active)
        .map(|kv| kv.version);

    let versions: Vec<serde_json::Value> = keyring
        .key_versions
        .iter()
        .map(|kv| {
            serde_json::json!({
                "version": kv.version,
                "state": format!("{:?}", kv.state),
                "created_at": kv.created_at,
                "activated_at": kv.activated_at,
                "draining_since": kv.draining_since,
                "retired_at": kv.retired_at,
            })
        })
        .collect();

    KeyInfoResult {
        name: keyring.name.clone(),
        algorithm: keyring.algorithm,
        active_version,
        versions: serde_json::json!(versions),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

use shroudb_cipher_core::key_version::KeyVersion;

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup() -> CipherEngine<shroudb_storage::EmbeddedStore> {
        let store = shroudb_storage::test_util::create_test_store("cipher-test").await;
        CipherEngine::new(store, CipherConfig::default(), None)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn encrypt_decrypt_roundtrip() {
        let engine = setup().await;
        engine
            .keyring_create("test", KeyringAlgorithm::Aes256Gcm, None, None, false, None)
            .await
            .unwrap();

        let plaintext = STANDARD.encode(b"hello world");
        let enc = engine
            .encrypt("test", &plaintext, None, None, false)
            .unwrap();
        let dec = engine.decrypt("test", &enc.ciphertext, None).unwrap();
        assert_eq!(dec.plaintext.as_bytes(), b"hello world");
    }

    #[tokio::test]
    async fn encrypt_decrypt_with_context() {
        let engine = setup().await;
        engine
            .keyring_create("test", KeyringAlgorithm::Aes256Gcm, None, None, false, None)
            .await
            .unwrap();

        let plaintext = STANDARD.encode(b"secret");
        let enc = engine
            .encrypt("test", &plaintext, Some("user-123"), None, false)
            .unwrap();

        // Correct context
        let dec = engine
            .decrypt("test", &enc.ciphertext, Some("user-123"))
            .unwrap();
        assert_eq!(dec.plaintext.as_bytes(), b"secret");

        // Wrong context fails
        assert!(
            engine
                .decrypt("test", &enc.ciphertext, Some("user-456"))
                .is_err()
        );
    }

    #[tokio::test]
    async fn convergent_encryption() {
        let engine = setup().await;
        engine
            .keyring_create("test", KeyringAlgorithm::Aes256Gcm, None, None, true, None)
            .await
            .unwrap();

        let plaintext = STANDARD.encode(b"deterministic");
        let enc1 = engine
            .encrypt("test", &plaintext, Some("ctx"), None, true)
            .unwrap();
        let enc2 = engine
            .encrypt("test", &plaintext, Some("ctx"), None, true)
            .unwrap();

        assert_eq!(enc1.ciphertext, enc2.ciphertext);
    }

    #[tokio::test]
    async fn convergent_guard_no_context() {
        let engine = setup().await;
        engine
            .keyring_create("test", KeyringAlgorithm::Aes256Gcm, None, None, true, None)
            .await
            .unwrap();

        let plaintext = STANDARD.encode(b"data");
        let err = engine
            .encrypt("test", &plaintext, None, None, true)
            .unwrap_err();
        assert!(matches!(err, CipherError::ConvergentGuard));
    }

    #[tokio::test]
    async fn convergent_guard_keyring_not_convergent() {
        let engine = setup().await;
        engine
            .keyring_create("test", KeyringAlgorithm::Aes256Gcm, None, None, false, None)
            .await
            .unwrap();

        let plaintext = STANDARD.encode(b"data");
        let err = engine
            .encrypt("test", &plaintext, Some("ctx"), None, true)
            .unwrap_err();
        assert!(matches!(err, CipherError::ConvergentGuard));
    }

    #[tokio::test]
    async fn rewrap_changes_version() {
        let engine = setup().await;
        engine
            .keyring_create("test", KeyringAlgorithm::Aes256Gcm, None, None, false, None)
            .await
            .unwrap();

        let plaintext = STANDARD.encode(b"rewrap me");
        let enc = engine
            .encrypt("test", &plaintext, None, None, false)
            .unwrap();
        assert_eq!(enc.key_version, 1);

        // Rotate
        engine.rotate("test", true, false, None).await.unwrap();

        // Rewrap
        let rewrapped = engine.rewrap("test", &enc.ciphertext, None).unwrap();
        assert_eq!(rewrapped.key_version, 2);

        // Decrypt the rewrapped ciphertext
        let dec = engine.decrypt("test", &rewrapped.ciphertext, None).unwrap();
        assert_eq!(dec.plaintext.as_bytes(), b"rewrap me");
    }

    #[tokio::test]
    async fn generate_data_key_works() {
        let engine = setup().await;
        engine
            .keyring_create("test", KeyringAlgorithm::Aes256Gcm, None, None, false, None)
            .await
            .unwrap();

        let result = engine.generate_data_key("test", Some(256)).unwrap();
        assert_eq!(result.plaintext_key.len(), 32);
        assert!(!result.wrapped_key.is_empty());

        // Unwrap the key via decrypt
        let dec = engine.decrypt("test", &result.wrapped_key, None).unwrap();
        assert_eq!(dec.plaintext.as_bytes(), result.plaintext_key.as_bytes());
    }

    #[tokio::test]
    async fn sign_verify_roundtrip() {
        let engine = setup().await;
        engine
            .keyring_create(
                "signing",
                KeyringAlgorithm::Ed25519,
                None,
                None,
                false,
                None,
            )
            .await
            .unwrap();

        let data = STANDARD.encode(b"sign this");
        let sig = engine.sign("signing", &data).unwrap();
        let valid = engine
            .verify_signature("signing", &data, &hex::encode(sig.signature.as_bytes()))
            .unwrap();
        assert!(valid);
    }

    #[tokio::test]
    async fn rotate_creates_new_version() {
        let engine = setup().await;
        engine
            .keyring_create("test", KeyringAlgorithm::Aes256Gcm, None, None, false, None)
            .await
            .unwrap();

        let result = engine.rotate("test", true, false, None).await.unwrap();
        assert!(result.rotated);
        assert_eq!(result.key_version, 2);
        assert_eq!(result.previous_version, Some(1));

        let info = engine.key_info("test").unwrap();
        assert_eq!(info.active_version, Some(2));
    }

    #[tokio::test]
    async fn rotate_not_due() {
        let engine = setup().await;
        engine
            .keyring_create("test", KeyringAlgorithm::Aes256Gcm, None, None, false, None)
            .await
            .unwrap();

        let result = engine.rotate("test", false, false, None).await.unwrap();
        assert!(!result.rotated);
    }

    #[tokio::test]
    async fn key_info_returns_versions() {
        let engine = setup().await;
        engine
            .keyring_create("test", KeyringAlgorithm::Aes256Gcm, None, None, false, None)
            .await
            .unwrap();
        engine.rotate("test", true, false, None).await.unwrap();

        let info = engine.key_info("test").unwrap();
        assert_eq!(info.name, "test");
        assert_eq!(info.algorithm, KeyringAlgorithm::Aes256Gcm);
        assert_eq!(info.active_version, Some(2));
        assert_eq!(info.versions.as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn disabled_keyring_rejects_operations() {
        let engine = setup().await;
        engine
            .keyring_create("test", KeyringAlgorithm::Aes256Gcm, None, None, false, None)
            .await
            .unwrap();

        // Disable keyring
        engine
            .keyrings
            .update("test", |kr| {
                kr.disabled = true;
                Ok(())
            })
            .await
            .unwrap();

        let plaintext = STANDARD.encode(b"data");
        let err = engine
            .encrypt("test", &plaintext, None, None, false)
            .unwrap_err();
        assert!(matches!(err, CipherError::Disabled(_)));
    }

    #[tokio::test]
    async fn chacha20_encrypt_decrypt() {
        let engine = setup().await;
        engine
            .keyring_create(
                "cc",
                KeyringAlgorithm::ChaCha20Poly1305,
                None,
                None,
                false,
                None,
            )
            .await
            .unwrap();

        let plaintext = STANDARD.encode(b"chacha data");
        let enc = engine.encrypt("cc", &plaintext, None, None, false).unwrap();
        let dec = engine.decrypt("cc", &enc.ciphertext, None).unwrap();
        assert_eq!(dec.plaintext.as_bytes(), b"chacha data");
    }

    #[tokio::test]
    async fn hmac_sign_verify() {
        let engine = setup().await;
        engine
            .keyring_create(
                "hmac",
                KeyringAlgorithm::HmacSha256,
                None,
                None,
                false,
                None,
            )
            .await
            .unwrap();

        let data = STANDARD.encode(b"hmac data");
        let sig = engine.sign("hmac", &data).unwrap();
        let valid = engine
            .verify_signature("hmac", &data, &hex::encode(sig.signature.as_bytes()))
            .unwrap();
        assert!(valid);
    }

    #[tokio::test]
    async fn decrypt_with_retired_key_rejected() {
        let engine = setup().await;
        engine
            .keyring_create("test", KeyringAlgorithm::Aes256Gcm, None, None, false, None)
            .await
            .unwrap();

        let plaintext = STANDARD.encode(b"data");
        let enc = engine
            .encrypt("test", &plaintext, None, None, false)
            .unwrap();
        let original_version = enc.key_version;

        // Rotate twice to push v1 from Active → Draining → Retired
        engine.rotate("test", true, false, None).await.unwrap();
        engine.rotate("test", true, false, None).await.unwrap();

        // Manually retire v1 by running the scheduler cycle
        engine
            .keyrings
            .update("test", |kr| {
                for kv in &mut kr.key_versions {
                    if kv.version == original_version {
                        kv.state = KeyState::Retired;
                    }
                }
                Ok(())
            })
            .await
            .unwrap();

        // Attempt to decrypt with retired key version
        let err = engine.decrypt("test", &enc.ciphertext, None).unwrap_err();
        assert!(
            matches!(err, CipherError::KeyVersionRetired { .. }),
            "expected KeyVersionRetired, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn double_rotation_creates_two_draining() {
        let engine = setup().await;
        engine
            .keyring_create("test", KeyringAlgorithm::Aes256Gcm, None, None, false, None)
            .await
            .unwrap();

        // First rotation: v1 Active → Draining, v2 Active
        let r1 = engine.rotate("test", true, false, None).await.unwrap();
        assert!(r1.rotated);
        assert_eq!(r1.key_version, 2);

        // Second rotation: v2 Active → Draining, v3 Active
        let r2 = engine.rotate("test", true, false, None).await.unwrap();
        assert!(r2.rotated);
        assert_eq!(r2.key_version, 3);

        // Verify key states
        let info = engine.key_info("test").unwrap();
        let versions = info.versions.as_array().unwrap();
        assert_eq!(versions.len(), 3);

        // v1 and v2 should be Draining, v3 should be Active
        assert_eq!(versions[0]["state"].as_str().unwrap(), "Draining");
        assert_eq!(versions[1]["state"].as_str().unwrap(), "Draining");
        assert_eq!(versions[2]["state"].as_str().unwrap(), "Active");

        // Data encrypted with v1 should still decrypt (v1 is Draining, not Retired)
        let plaintext = STANDARD.encode(b"old data");
        let enc = engine
            .encrypt("test", &plaintext, None, Some(1), false)
            .unwrap();
        let dec = engine.decrypt("test", &enc.ciphertext, None).unwrap();
        assert_eq!(dec.plaintext.as_bytes(), b"old data");
    }

    #[tokio::test]
    async fn concurrent_encrypt_during_rotation() {
        let engine = Arc::new(setup().await);
        engine
            .keyring_create("test", KeyringAlgorithm::Aes256Gcm, None, None, false, None)
            .await
            .unwrap();

        let mut handles = Vec::new();

        // Spawn 10 tasks that each encrypt 5 values
        for task_id in 0..10u32 {
            let eng = Arc::clone(&engine);
            handles.push(tokio::spawn(async move {
                let mut results = Vec::new();
                for i in 0..5u32 {
                    let plaintext = STANDARD.encode(format!("task-{task_id}-item-{i}").as_bytes());
                    let enc = eng.encrypt("test", &plaintext, None, None, false).unwrap();
                    results.push((format!("task-{task_id}-item-{i}"), enc));
                }
                results
            }));
        }

        // Rotate while encrypts are in flight
        engine.rotate("test", true, false, None).await.unwrap();

        // Collect all results — no task should have panicked
        let mut all_results = Vec::new();
        for handle in handles {
            let results = handle.await.unwrap();
            all_results.extend(results);
        }

        assert_eq!(all_results.len(), 50);

        // Every ciphertext must be decryptable
        for (original, enc) in &all_results {
            let dec = engine.decrypt("test", &enc.ciphertext, None).unwrap();
            assert_eq!(
                dec.plaintext.as_bytes(),
                original.as_bytes(),
                "decryption mismatch for {original}"
            );
            // Key version should be 1 (original) or 2 (post-rotation)
            assert!(
                enc.key_version == 1 || enc.key_version == 2,
                "unexpected key version {}",
                enc.key_version
            );
        }
    }

    #[tokio::test]
    async fn sensitive_bytes_debug_is_redacted() {
        let engine = setup().await;
        engine
            .keyring_create("test", KeyringAlgorithm::Aes256Gcm, None, None, false, None)
            .await
            .unwrap();

        let plaintext = STANDARD.encode(b"secret data");
        let result = engine
            .encrypt("test", &plaintext, None, None, false)
            .unwrap();
        let dec = engine.decrypt("test", &result.ciphertext, None).unwrap();

        // Debug output must not contain the plaintext
        let debug = format!("{dec:?}");
        assert!(!debug.contains("secret data"));
        assert!(debug.contains("REDACTED"));
    }
}
