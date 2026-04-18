use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use shroudb_acl::{PolicyEffect, PolicyEvaluator, PolicyPrincipal, PolicyRequest, PolicyResource};
use shroudb_chronicle_core::event::{Engine as ChronicleEngine, Event, EventResult};
use shroudb_chronicle_core::ops::ChronicleOps;
use shroudb_cipher_core::ciphertext::CiphertextEnvelope;
use shroudb_cipher_core::error::CipherError;
use shroudb_cipher_core::key_version::KeyState;
use shroudb_cipher_core::keyring::KeyringAlgorithm;
use shroudb_cipher_core::policy::KeyringOperation;
use shroudb_courier_core::ops::CourierOps;
use shroudb_crypto::{SecretBytes, SensitiveBytes};
use shroudb_server_bootstrap::Capability;
use shroudb_store::Store;

use crate::crypto_ops::{self, NonceMode};
use crate::keyring_manager::{
    KeyringCreateOpts, KeyringManager, find_active_key, find_key_version,
};

/// Sentinel actor used in audit events when the caller arrives without an
/// auth context. An empty-string actor is a logging footgun: it silently
/// coalesces every anonymous call into "unknown origin" with no hint that
/// attribution was missing at the source.
const AUDIT_ANONYMOUS: &str = "anonymous";

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
    policy_evaluator: Capability<Arc<dyn PolicyEvaluator>>,
    chronicle: Capability<Arc<dyn ChronicleOps>>,
    courier: Capability<Arc<dyn CourierOps>>,
}

impl<S: Store> CipherEngine<S> {
    /// Create a new Cipher engine.
    ///
    /// Every capability slot is explicit: `Capability::Enabled(...)`,
    /// `Capability::DisabledForTests`, or
    /// `Capability::DisabledWithJustification("<reason>")`. Absence is
    /// never silent — operators must name why they're opting out.
    pub async fn new(
        store: Arc<S>,
        config: CipherConfig,
        policy_evaluator: Capability<Arc<dyn PolicyEvaluator>>,
        chronicle: Capability<Arc<dyn ChronicleOps>>,
    ) -> Result<Self, CipherError> {
        let keyrings = KeyringManager::new(store);
        keyrings.init().await?;
        Ok(Self {
            keyrings,
            config,
            policy_evaluator,
            chronicle,
            courier: Capability::disabled(
                "courier rotation-notify not configured — use new_with_capabilities to wire it",
            ),
        })
    }

    /// Create a new Cipher engine with all capability traits, including
    /// Courier for key-rotation notifications.
    pub async fn new_with_capabilities(
        store: Arc<S>,
        config: CipherConfig,
        policy_evaluator: Capability<Arc<dyn PolicyEvaluator>>,
        chronicle: Capability<Arc<dyn ChronicleOps>>,
        courier: Capability<Arc<dyn CourierOps>>,
    ) -> Result<Self, CipherError> {
        let keyrings = KeyringManager::new(store);
        keyrings.init().await?;
        Ok(Self {
            keyrings,
            config,
            policy_evaluator,
            chronicle,
            courier,
        })
    }

    /// Access the courier capability (if configured).
    pub fn courier(&self) -> Option<&Arc<dyn CourierOps>> {
        self.courier.as_ref()
    }

    /// Access the courier capability slot (including its disabled state).
    pub fn courier_capability(&self) -> &Capability<Arc<dyn CourierOps>> {
        &self.courier
    }

    async fn check_policy(
        &self,
        resource_id: &str,
        action: &str,
        actor: Option<&str>,
    ) -> Result<(), CipherError> {
        let Some(evaluator) = self.policy_evaluator.as_ref() else {
            return Ok(());
        };
        // A `PolicyPrincipal` with an empty `id` makes Sentry evaluate every
        // policy against "nobody" — distinct callers look identical and
        // `sub`-bound rules trivially match. Callers without an auth context
        // are mapped to the `"anonymous"` sentinel and tagged via an
        // `unauthenticated` claim so policy authors can explicitly allow or
        // deny that surface instead of it sneaking past an empty-string hole.
        let (principal_id, unauthenticated) = match actor {
            Some(a) if !a.is_empty() => (a.to_string(), false),
            _ => ("anonymous".to_string(), true),
        };
        let mut claims = std::collections::HashMap::new();
        claims.insert("sub".to_string(), principal_id.clone());
        if unauthenticated {
            claims.insert("unauthenticated".to_string(), "true".to_string());
        }
        let request = PolicyRequest {
            principal: PolicyPrincipal {
                id: principal_id,
                roles: vec![],
                claims,
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

    /// Emit an audit event to Chronicle. If chronicle is not configured, this
    /// is a no-op. If chronicle is configured but unreachable, returns an error
    /// so security-critical callers can fail closed.
    ///
    /// Every call threads `start: Instant` so Chronicle receives the real
    /// wall-clock duration of the audited operation, and `metadata` so the
    /// entry carries enough context (algorithm, key_version, …) to be
    /// useful on its own — not an empty skeleton.
    async fn emit_audit_event(
        &self,
        operation: &str,
        resource: &str,
        actor: &str,
        start: Instant,
        metadata: HashMap<String, String>,
    ) -> Result<(), CipherError> {
        let Some(chronicle) = self.chronicle.as_ref() else {
            return Ok(());
        };
        let mut event = Event::new(
            ChronicleEngine::Cipher,
            operation.to_string(),
            "keyring".to_string(),
            resource.to_string(),
            EventResult::Ok,
            actor.to_string(),
        );
        // Floor at 1ms: ops that complete in less than a millisecond still
        // produced a measurable event, and a literal `0` is indistinguishable
        // from "never timed" in dashboards that filter on duration.
        let elapsed_ms = start.elapsed().as_millis() as u64;
        event.duration_ms = elapsed_ms.max(1);
        event.metadata = metadata;
        chronicle
            .record(event)
            .await
            .map_err(|e| CipherError::Internal(format!("audit failed: {e}")))?;
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
        let start = Instant::now();
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
        let mut metadata = HashMap::new();
        metadata.insert("algorithm".to_string(), algorithm.wire_name().to_string());
        metadata.insert("convergent".to_string(), convergent.to_string());
        self.emit_audit_event(
            "keyring_create",
            name,
            actor.unwrap_or(AUDIT_ANONYMOUS),
            start,
            metadata,
        )
        .await?;
        Ok(build_key_info(&kr))
    }

    pub fn keyring_list(&self) -> Vec<String> {
        self.keyrings.list()
    }

    // ── Encrypt ────────────────────────────────────────────────────

    pub async fn encrypt(
        &self,
        keyring_name: &str,
        plaintext_b64: &str,
        context: Option<&str>,
        key_version: Option<u32>,
        convergent: bool,
    ) -> Result<EncryptResult, CipherError> {
        let start = Instant::now();
        // Sentry must evaluate every data-plane op, not just control plane.
        self.check_policy(keyring_name, "encrypt", None).await?;
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

        let result = EncryptResult {
            ciphertext: envelope.encode()?,
            key_version: kv.version,
        };
        let mut metadata = HashMap::new();
        metadata.insert(
            "algorithm".to_string(),
            keyring.algorithm.wire_name().to_string(),
        );
        metadata.insert("key_version".to_string(), kv.version.to_string());
        metadata.insert("convergent".to_string(), convergent.to_string());
        self.emit_audit_event("encrypt", keyring_name, AUDIT_ANONYMOUS, start, metadata)
            .await?;
        Ok(result)
    }

    // ── Decrypt ────────────────────────────────────────────────────

    pub async fn decrypt(
        &self,
        keyring_name: &str,
        ciphertext: &str,
        context: Option<&str>,
    ) -> Result<DecryptResult, CipherError> {
        let start = Instant::now();
        // Sentry must evaluate every data-plane op, not just control plane.
        self.check_policy(keyring_name, "decrypt", None).await?;
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

        let mut metadata = HashMap::new();
        metadata.insert(
            "algorithm".to_string(),
            keyring.algorithm.wire_name().to_string(),
        );
        metadata.insert("key_version".to_string(), kv.version.to_string());
        let _ = self
            .emit_audit_event("decrypt", keyring_name, AUDIT_ANONYMOUS, start, metadata)
            .await;
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

    pub async fn sign(
        &self,
        keyring_name: &str,
        data_b64: &str,
    ) -> Result<SignResult, CipherError> {
        let start = Instant::now();
        // Sentry must evaluate every data-plane op, not just control plane.
        self.check_policy(keyring_name, "sign", None).await?;
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

        let result = SignResult {
            signature: signature.into(),
            key_version: active_kv.version,
        };
        let mut metadata = HashMap::new();
        metadata.insert(
            "algorithm".to_string(),
            keyring.algorithm.wire_name().to_string(),
        );
        metadata.insert("key_version".to_string(), active_kv.version.to_string());
        self.emit_audit_event("sign", keyring_name, AUDIT_ANONYMOUS, start, metadata)
            .await?;
        Ok(result)
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
        let start = Instant::now();
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

        let mut metadata = HashMap::new();
        metadata.insert("algorithm".to_string(), algorithm.wire_name().to_string());
        metadata.insert("new_version".to_string(), new_active.version.to_string());
        metadata.insert("previous_version".to_string(), prev_version.to_string());
        metadata.insert("forced".to_string(), force.to_string());
        self.emit_audit_event(
            "rotate",
            keyring_name,
            actor.unwrap_or(AUDIT_ANONYMOUS),
            start,
            metadata,
        )
        .await?;

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
    use zeroize::Zeroize;

    async fn setup() -> CipherEngine<shroudb_storage::EmbeddedStore> {
        let store = shroudb_storage::test_util::create_test_store("cipher-test").await;
        CipherEngine::new(
            store,
            CipherConfig::default(),
            Capability::DisabledForTests,
            Capability::DisabledForTests,
        )
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
            .await
            .unwrap();
        let dec = engine.decrypt("test", &enc.ciphertext, None).await.unwrap();
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
            .await
            .unwrap();

        // Correct context
        let dec = engine
            .decrypt("test", &enc.ciphertext, Some("user-123"))
            .await
            .unwrap();
        assert_eq!(dec.plaintext.as_bytes(), b"secret");

        // Wrong context fails
        assert!(
            engine
                .decrypt("test", &enc.ciphertext, Some("user-456"))
                .await
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
            .await
            .unwrap();
        let enc2 = engine
            .encrypt("test", &plaintext, Some("ctx"), None, true)
            .await
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
            .await
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
            .await
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
            .await
            .unwrap();
        assert_eq!(enc.key_version, 1);

        // Rotate
        engine.rotate("test", true, false, None).await.unwrap();

        // Rewrap
        let rewrapped = engine.rewrap("test", &enc.ciphertext, None).unwrap();
        assert_eq!(rewrapped.key_version, 2);

        // Decrypt the rewrapped ciphertext
        let dec = engine
            .decrypt("test", &rewrapped.ciphertext, None)
            .await
            .unwrap();
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
        let dec = engine
            .decrypt("test", &result.wrapped_key, None)
            .await
            .unwrap();
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
        let sig = engine.sign("signing", &data).await.unwrap();
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
            .await
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
        let enc = engine
            .encrypt("cc", &plaintext, None, None, false)
            .await
            .unwrap();
        let dec = engine.decrypt("cc", &enc.ciphertext, None).await.unwrap();
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
        let sig = engine.sign("hmac", &data).await.unwrap();
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
            .await
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
                        kv.retired_at = Some(0);
                        if let Some(ref mut km) = kv.key_material {
                            km.zeroize();
                        }
                        kv.key_material = None;
                    }
                }
                Ok(())
            })
            .await
            .unwrap();

        // Attempt to decrypt with retired key version
        let err = engine
            .decrypt("test", &enc.ciphertext, None)
            .await
            .unwrap_err();
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
            .await
            .unwrap();
        let dec = engine.decrypt("test", &enc.ciphertext, None).await.unwrap();
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
                    let enc = eng
                        .encrypt("test", &plaintext, None, None, false)
                        .await
                        .unwrap();
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
            let dec = engine.decrypt("test", &enc.ciphertext, None).await.unwrap();
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

    // ── DEBT TESTS ──────────────────────────────────────────────────
    //
    // Hard ratchet (AUDIT_2026-04-17). Prior ENGINE_REVIEW_*.md docs
    // declared Cipher "production-ready" across 17 iterations. These
    // tests catalog specific half-wired capability paths. Do NOT add
    // #[ignore] — failures signal real security gaps.

    use crate::test_support::{RecordingChronicle, RecordingSentry};

    async fn engine_with_recorders() -> (
        CipherEngine<shroudb_storage::EmbeddedStore>,
        std::sync::Arc<std::sync::Mutex<Vec<shroudb_acl::PolicyRequest>>>,
        std::sync::Arc<std::sync::Mutex<Vec<shroudb_chronicle_core::event::Event>>>,
    ) {
        let store = shroudb_storage::test_util::create_test_store("cipher-debt").await;
        let (sentry, reqs) = RecordingSentry::new();
        let (chronicle, events) = RecordingChronicle::new();
        let engine = CipherEngine::new(
            store,
            CipherConfig::default(),
            Capability::Enabled(sentry),
            Capability::Enabled(chronicle),
        )
        .await
        .expect("engine init");
        (engine, reqs, events)
    }

    /// Former DEBT-Fcipher-1 (AUDIT_2026-04-17), now closed: `CipherEngine::new`
    /// takes `Capability<Arc<dyn PolicyEvaluator>>` and
    /// `Capability<Arc<dyn ChronicleOps>>` — the type system rejects the
    /// previous `None, None` shape outright. Tests must pick an explicit
    /// variant: `Capability::DisabledForTests` for unit harnesses,
    /// `Capability::DisabledWithJustification(<reason>)` for documented
    /// opt-outs, or `Capability::Enabled(...)` with a concrete impl.
    /// Server mains (`shroudb-cipher-server/src/main.rs`) now dispatch
    /// via `shroudb-engine-bootstrap` `AuditConfig::resolve` and
    /// `PolicyConfig::resolve`.
    #[tokio::test]
    async fn cipher_engine_new_requires_explicit_capability_variants() {
        let store = shroudb_storage::test_util::create_test_store("cipher-explicit-caps").await;
        // The valid call — every other shape is a type error.
        let result = CipherEngine::new(
            store,
            CipherConfig::default(),
            Capability::DisabledForTests,
            Capability::DisabledForTests,
        )
        .await;
        assert!(result.is_ok(), "explicit DisabledForTests must construct");
    }

    /// DEBT-Fcipher-2 (AUDIT_2026-04-17): `emit_audit_event` builds an
    /// `Event` with `duration_ms: 0` (always), no `correlation_id`, no
    /// `tenant_id`, and empty `metadata`. Chronicle receives a useless
    /// skeleton per operation. Fix: thread timing/context through the
    /// event.
    #[tokio::test]
    async fn debt_fcipher_2_audit_event_must_carry_timing_and_context() {
        let (engine, _reqs, events) = engine_with_recorders().await;
        engine
            .keyring_create(
                "test",
                KeyringAlgorithm::Aes256Gcm,
                None,
                None,
                false,
                Some("alice"),
            )
            .await
            .unwrap();
        let plaintext = STANDARD.encode(b"payload");
        engine
            .encrypt("test", &plaintext, None, None, false)
            .await
            .unwrap();

        let evs = events.lock().unwrap();
        assert!(
            !evs.is_empty(),
            "DEBT-Fcipher-2: no audit events emitted at all"
        );
        // At least one event must carry real timing.
        assert!(
            evs.iter().any(|e| e.duration_ms > 0),
            "DEBT-Fcipher-2: every Event.duration_ms == 0. \
             emit_audit_event doesn't measure operation latency."
        );
        // Actor-bearing operations must carry real metadata hinting at op.
        let encrypts: Vec<_> = evs.iter().filter(|e| e.operation == "encrypt").collect();
        assert!(!encrypts.is_empty(), "DEBT-Fcipher-2: no encrypt event");
        for ev in encrypts {
            assert!(
                !ev.metadata.is_empty(),
                "DEBT-Fcipher-2: encrypt audit metadata empty (no key_version, algorithm, etc.)"
            );
        }
    }

    /// DEBT-Fcipher-3 (AUDIT_2026-04-17): data-plane methods (`encrypt`,
    /// `decrypt`, `sign`, `rewrap`, `generate_data_key`,
    /// `verify_signature`) never invoke `self.check_policy(...)` — only
    /// the in-keyring `KeyringPolicy` allowlist. The Sentry capability
    /// is populated but never consulted on the hot path. Fix: call
    /// `check_policy` on every data-plane op with a real actor.
    #[tokio::test]
    async fn debt_fcipher_3_data_plane_must_call_sentry() {
        let (engine, reqs, _events) = engine_with_recorders().await;
        engine
            .keyring_create(
                "test",
                KeyringAlgorithm::Aes256Gcm,
                None,
                None,
                false,
                Some("alice"),
            )
            .await
            .unwrap();
        let plaintext = STANDARD.encode(b"payload");
        let enc = engine
            .encrypt("test", &plaintext, None, None, false)
            .await
            .unwrap();
        let _ = engine.decrypt("test", &enc.ciphertext, None).await.unwrap();

        let requests = reqs.lock().unwrap();
        let encrypt_reqs: Vec<_> = requests.iter().filter(|r| r.action == "encrypt").collect();
        let decrypt_reqs: Vec<_> = requests.iter().filter(|r| r.action == "decrypt").collect();
        assert!(
            !encrypt_reqs.is_empty(),
            "DEBT-Fcipher-3: engine.encrypt() never invoked PolicyEvaluator. \
             Sentry capability is never consulted on data plane."
        );
        assert!(
            !decrypt_reqs.is_empty(),
            "DEBT-Fcipher-3: engine.decrypt() never invoked PolicyEvaluator. \
             Sentry capability is never consulted on data plane."
        );
    }

    /// DEBT-Fcipher-4 (AUDIT_2026-04-17): `check_policy` builds
    /// `PolicyPrincipal { id: actor.unwrap_or("").to_string(), roles:
    /// vec![], claims: Default::default() }`. When actor is None,
    /// Sentry is evaluating authorization for an empty-string principal
    /// with no roles and no claims — every policy evaluates the same
    /// because the principal identifies nobody. Fix: refuse to evaluate
    /// policy with empty principal on security-sensitive ops.
    #[tokio::test]
    async fn debt_fcipher_4_policy_principal_must_not_be_empty() {
        let (engine, reqs, _events) = engine_with_recorders().await;
        // keyring_create hits check_policy. Pass actor=None to reproduce.
        engine
            .keyring_create("test", KeyringAlgorithm::Aes256Gcm, None, None, false, None)
            .await
            .unwrap();

        let requests = reqs.lock().unwrap();
        assert!(
            !requests.is_empty(),
            "DEBT-Fcipher-4: no policy requests emitted"
        );
        for req in requests.iter() {
            assert!(
                !req.principal.id.is_empty(),
                "DEBT-Fcipher-4: PolicyRequest.principal.id is empty string. \
                 Anonymous callers evaluate policy as 'nobody'. \
                 Fix: fail-closed on missing actor, or require actor at API boundary."
            );
        }
    }

    /// DEBT-Fcipher-5 (AUDIT_2026-04-17): audit events for
    /// `encrypt`/`decrypt`/`sign` pass `""` as the actor regardless of
    /// who actually invoked them (engine.rs:313, :351, :507). Audit log
    /// for data-plane ops attributes to nobody. Fix: thread actor
    /// through `encrypt`/`decrypt`/`sign` and use `actor.unwrap_or(...)`
    /// of a sentinel that is NOT empty.
    #[tokio::test]
    async fn debt_fcipher_5_audit_actor_must_not_be_empty_for_data_plane() {
        let (engine, _reqs, events) = engine_with_recorders().await;
        engine
            .keyring_create(
                "test",
                KeyringAlgorithm::Aes256Gcm,
                None,
                None,
                false,
                Some("alice"),
            )
            .await
            .unwrap();
        let plaintext = STANDARD.encode(b"payload");
        engine
            .encrypt("test", &plaintext, None, None, false)
            .await
            .unwrap();

        let evs = events.lock().unwrap();
        let data_events: Vec<_> = evs
            .iter()
            .filter(|e| matches!(e.operation.as_str(), "encrypt" | "decrypt" | "sign"))
            .collect();
        assert!(
            !data_events.is_empty(),
            "DEBT-Fcipher-5: no encrypt/decrypt/sign audit events emitted"
        );
        for ev in data_events {
            assert!(
                !ev.actor.is_empty(),
                "DEBT-Fcipher-5: {} event actor is empty string. \
                 Data-plane ops are not attributable. \
                 Fix: thread actor through encrypt/decrypt/sign.",
                ev.operation
            );
        }
    }

    /// DEBT-Fcipher-6 (AUDIT_2026-04-17): `emit_audit_event` only
    /// records success. When `decrypt` fails with a wrong AAD, the
    /// `let _ = self.emit_audit_event("decrypt", ...)` line (engine.rs
    /// :351) is never reached — the error short-circuits. Chronicle
    /// never sees failed decrypt attempts. Fix: record `EventResult::
    /// Error` on all failure paths (wrong context, wrong key, corrupt
    /// ciphertext, policy deny).
    #[tokio::test]
    async fn debt_fcipher_6_failure_decrypt_must_emit_error_audit() {
        let (engine, _reqs, events) = engine_with_recorders().await;
        engine
            .keyring_create(
                "test",
                KeyringAlgorithm::Aes256Gcm,
                None,
                None,
                false,
                Some("alice"),
            )
            .await
            .unwrap();
        let plaintext = STANDARD.encode(b"payload");
        let enc = engine
            .encrypt("test", &plaintext, Some("right-ctx"), None, false)
            .await
            .unwrap();
        // Wrong context — should fail AEAD and audit as Error.
        let _ = engine
            .decrypt("test", &enc.ciphertext, Some("wrong-ctx"))
            .await;

        let evs = events.lock().unwrap();
        let decrypt_failures: Vec<_> = evs
            .iter()
            .filter(|e| {
                e.operation == "decrypt"
                    && matches!(e.result, shroudb_chronicle_core::event::EventResult::Error)
            })
            .collect();
        assert!(
            !decrypt_failures.is_empty(),
            "DEBT-Fcipher-6: failed decrypt (wrong AAD) did NOT emit an \
             EventResult::Error audit event. Attackers can probe for \
             valid ciphertexts without leaving a trail."
        );
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
            .await
            .unwrap();
        let dec = engine
            .decrypt("test", &result.ciphertext, None)
            .await
            .unwrap();

        // Debug output must not contain the plaintext
        let debug = format!("{dec:?}");
        assert!(!debug.contains("secret data"));
        assert!(debug.contains("REDACTED"));
    }
}
