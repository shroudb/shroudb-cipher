//! Cryptographic operations — shared encrypt/decrypt/sign/verify primitives.
//!
//! These functions operate on raw key material and are reused by all handlers
//! (encrypt, decrypt, rewrap, generate_data_key, sign, verify_signature).

use shroudb_cipher_core::error::CipherError;
use shroudb_cipher_core::keyring::KeyringAlgorithm;
use shroudb_crypto::SecretBytes;

/// Result of key material generation.
pub struct GeneratedKeyMaterial {
    pub private_key: SecretBytes,
    pub public_key: Option<Vec<u8>>,
}

/// Generate fresh key material for the given algorithm.
pub fn generate_key_material(
    algorithm: KeyringAlgorithm,
) -> Result<GeneratedKeyMaterial, CipherError> {
    match algorithm {
        KeyringAlgorithm::Aes256Gcm
        | KeyringAlgorithm::ChaCha20Poly1305
        | KeyringAlgorithm::HmacSha256 => {
            let rng = ring::rand::SystemRandom::new();
            let mut bytes = vec![0u8; 32];
            ring::rand::SecureRandom::fill(&rng, &mut bytes)
                .map_err(|_| CipherError::Internal("CSPRNG failed".into()))?;
            Ok(GeneratedKeyMaterial {
                private_key: SecretBytes::new(bytes),
                public_key: None,
            })
        }
        KeyringAlgorithm::Ed25519 => {
            let kp = shroudb_crypto::ed25519_generate_keypair()?;
            Ok(GeneratedKeyMaterial {
                private_key: kp.private_key,
                public_key: Some(kp.public_key),
            })
        }
        KeyringAlgorithm::EcdsaP256 => {
            let kp = shroudb_crypto::ecdsa_p256_generate_keypair()?;
            Ok(GeneratedKeyMaterial {
                private_key: kp.private_key,
                public_key: Some(kp.public_key),
            })
        }
    }
}

/// Nonce mode for encryption.
pub enum NonceMode<'a> {
    /// Random nonce from CSPRNG.
    Random,
    /// Deterministic nonce derived from HMAC(key, plaintext || aad).
    Convergent {
        key_material: &'a [u8],
        plaintext: &'a [u8],
        aad: &'a [u8],
    },
}

/// Encrypt plaintext with the given key material.
///
/// Returns the raw payload: `nonce || ciphertext || tag`.
pub fn encrypt_with_key(
    algorithm: KeyringAlgorithm,
    key_material: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    nonce_mode: NonceMode<'_>,
) -> Result<Vec<u8>, CipherError> {
    if !algorithm.is_encryption() {
        return Err(CipherError::AlgorithmMismatch {
            expected: algorithm.wire_name().to_string(),
            required: "encryption algorithm (aes-256-gcm or chacha20-poly1305)".to_string(),
        });
    }

    match nonce_mode {
        NonceMode::Random => match algorithm {
            KeyringAlgorithm::Aes256Gcm => {
                shroudb_crypto::aes_gcm_encrypt(key_material, plaintext, aad)
                    .map_err(CipherError::from)
            }
            KeyringAlgorithm::ChaCha20Poly1305 => {
                shroudb_crypto::chacha20_poly1305_encrypt(key_material, plaintext, aad)
                    .map_err(CipherError::from)
            }
            other => Err(CipherError::AlgorithmMismatch {
                expected: other.wire_name().to_string(),
                required: "supported algorithm for this operation".to_string(),
            }),
        },
        NonceMode::Convergent {
            key_material: km,
            plaintext: pt,
            aad: ad,
        } => {
            let nonce = derive_convergent_nonce(km, pt, ad)?;
            match algorithm {
                KeyringAlgorithm::Aes256Gcm => {
                    shroudb_crypto::aes_gcm_encrypt_with_nonce(key_material, &nonce, plaintext, aad)
                        .map_err(CipherError::from)
                }
                KeyringAlgorithm::ChaCha20Poly1305 => {
                    shroudb_crypto::chacha20_poly1305_encrypt_with_nonce(
                        key_material,
                        &nonce,
                        plaintext,
                        aad,
                    )
                    .map_err(CipherError::from)
                }
                other => Err(CipherError::AlgorithmMismatch {
                    expected: other.wire_name().to_string(),
                    required: "supported algorithm for this operation".to_string(),
                }),
            }
        }
    }
}

/// Decrypt payload (nonce || ciphertext || tag) with the given key material.
pub fn decrypt_with_key(
    algorithm: KeyringAlgorithm,
    key_material: &[u8],
    payload: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CipherError> {
    if !algorithm.is_encryption() {
        return Err(CipherError::AlgorithmMismatch {
            expected: algorithm.wire_name().to_string(),
            required: "encryption algorithm".to_string(),
        });
    }

    match algorithm {
        KeyringAlgorithm::Aes256Gcm => shroudb_crypto::aes_gcm_decrypt(key_material, payload, aad)
            .map_err(|e| {
                CipherError::DecryptionFailed(format!("AES-256-GCM decryption failed: {e}"))
            }),
        KeyringAlgorithm::ChaCha20Poly1305 => {
            shroudb_crypto::chacha20_poly1305_decrypt(key_material, payload, aad).map_err(|e| {
                CipherError::DecryptionFailed(format!("ChaCha20-Poly1305 decryption failed: {e}"))
            })
        }
        other => Err(CipherError::AlgorithmMismatch {
            expected: other.wire_name().to_string(),
            required: "supported encryption algorithm for this operation".to_string(),
        }),
    }
}

/// Sign data with the given key material.
pub fn sign_with_key(
    algorithm: KeyringAlgorithm,
    key_material: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, CipherError> {
    if !algorithm.is_signing() {
        return Err(CipherError::AlgorithmMismatch {
            expected: algorithm.wire_name().to_string(),
            required: "signing algorithm (hmac-sha256, ed25519, or ecdsa-p256)".to_string(),
        });
    }

    match algorithm {
        KeyringAlgorithm::HmacSha256 => {
            shroudb_crypto::hmac_sign(shroudb_crypto::HmacAlgorithm::Sha256, key_material, data)
                .map_err(CipherError::from)
        }
        KeyringAlgorithm::Ed25519 => {
            shroudb_crypto::ed25519_sign(key_material, data).map_err(CipherError::from)
        }
        KeyringAlgorithm::EcdsaP256 => {
            shroudb_crypto::ecdsa_p256_sign(key_material, data).map_err(CipherError::from)
        }
        other => Err(CipherError::AlgorithmMismatch {
            expected: other.wire_name().to_string(),
            required: "supported signing algorithm for this operation".to_string(),
        }),
    }
}

/// Verify a signature against data using the given key material.
pub fn verify_with_key(
    algorithm: KeyringAlgorithm,
    key_material: &[u8],
    public_key: Option<&[u8]>,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, CipherError> {
    if !algorithm.is_signing() {
        return Err(CipherError::AlgorithmMismatch {
            expected: algorithm.wire_name().to_string(),
            required: "signing algorithm".to_string(),
        });
    }

    match algorithm {
        KeyringAlgorithm::HmacSha256 => shroudb_crypto::hmac_verify(
            shroudb_crypto::HmacAlgorithm::Sha256,
            key_material,
            data,
            signature,
        )
        .map_err(CipherError::from),
        KeyringAlgorithm::Ed25519 => {
            let pk = public_key.ok_or_else(|| {
                CipherError::Internal("Ed25519 verification requires public key".into())
            })?;
            shroudb_crypto::ed25519_verify(pk, data, signature).map_err(CipherError::from)
        }
        KeyringAlgorithm::EcdsaP256 => {
            let pk = public_key.ok_or_else(|| {
                CipherError::Internal("ECDSA-P256 verification requires public key".into())
            })?;
            shroudb_crypto::ecdsa_p256_verify(pk, data, signature).map_err(CipherError::from)
        }
        other => Err(CipherError::AlgorithmMismatch {
            expected: other.wire_name().to_string(),
            required: "supported signing algorithm for this operation".to_string(),
        }),
    }
}

/// Derive a deterministic 12-byte nonce for convergent encryption.
///
/// Uses HMAC-SHA256(key_material, plaintext || aad) truncated to 12 bytes.
fn derive_convergent_nonce(
    key_material: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<[u8; 12], CipherError> {
    let mut input = Vec::with_capacity(plaintext.len() + aad.len());
    input.extend_from_slice(plaintext);
    input.extend_from_slice(aad);

    let hmac =
        shroudb_crypto::hmac_sign(shroudb_crypto::HmacAlgorithm::Sha256, key_material, &input)?;

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&hmac[..12]);
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_symmetric_key() {
        let gkm = generate_key_material(KeyringAlgorithm::Aes256Gcm).unwrap();
        assert_eq!(gkm.private_key.as_bytes().len(), 32);
        assert!(gkm.public_key.is_none());
    }

    #[test]
    fn generate_ed25519_key() {
        let gkm = generate_key_material(KeyringAlgorithm::Ed25519).unwrap();
        assert!(!gkm.private_key.as_bytes().is_empty());
        assert!(gkm.public_key.is_some());
    }

    #[test]
    fn generate_ecdsa_key() {
        let gkm = generate_key_material(KeyringAlgorithm::EcdsaP256).unwrap();
        assert!(!gkm.private_key.as_bytes().is_empty());
        assert!(gkm.public_key.is_some());
    }

    #[test]
    fn encrypt_decrypt_aes_roundtrip() {
        let gkm = generate_key_material(KeyringAlgorithm::Aes256Gcm).unwrap();
        let plaintext = b"hello cipher";
        let aad = b"context";

        let payload = encrypt_with_key(
            KeyringAlgorithm::Aes256Gcm,
            gkm.private_key.as_bytes(),
            plaintext,
            aad,
            NonceMode::Random,
        )
        .unwrap();

        let decrypted = decrypt_with_key(
            KeyringAlgorithm::Aes256Gcm,
            gkm.private_key.as_bytes(),
            &payload,
            aad,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_chacha_roundtrip() {
        let gkm = generate_key_material(KeyringAlgorithm::ChaCha20Poly1305).unwrap();
        let plaintext = b"hello chacha";
        let aad = b"";

        let payload = encrypt_with_key(
            KeyringAlgorithm::ChaCha20Poly1305,
            gkm.private_key.as_bytes(),
            plaintext,
            aad,
            NonceMode::Random,
        )
        .unwrap();

        let decrypted = decrypt_with_key(
            KeyringAlgorithm::ChaCha20Poly1305,
            gkm.private_key.as_bytes(),
            &payload,
            aad,
        )
        .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn convergent_produces_same_ciphertext() {
        let gkm = generate_key_material(KeyringAlgorithm::Aes256Gcm).unwrap();
        let key = gkm.private_key.as_bytes();
        let plaintext = b"deterministic";
        let aad = b"context";

        let p1 = encrypt_with_key(
            KeyringAlgorithm::Aes256Gcm,
            key,
            plaintext,
            aad,
            NonceMode::Convergent {
                key_material: key,
                plaintext,
                aad,
            },
        )
        .unwrap();

        let p2 = encrypt_with_key(
            KeyringAlgorithm::Aes256Gcm,
            key,
            plaintext,
            aad,
            NonceMode::Convergent {
                key_material: key,
                plaintext,
                aad,
            },
        )
        .unwrap();

        assert_eq!(p1, p2);
    }

    #[test]
    fn sign_verify_hmac() {
        let gkm = generate_key_material(KeyringAlgorithm::HmacSha256).unwrap();
        let data = b"sign this";

        let sig = sign_with_key(
            KeyringAlgorithm::HmacSha256,
            gkm.private_key.as_bytes(),
            data,
        )
        .unwrap();

        let valid = verify_with_key(
            KeyringAlgorithm::HmacSha256,
            gkm.private_key.as_bytes(),
            None,
            data,
            &sig,
        )
        .unwrap();

        assert!(valid);
    }

    #[test]
    fn sign_verify_ed25519() {
        let gkm = generate_key_material(KeyringAlgorithm::Ed25519).unwrap();
        let data = b"sign this ed25519";

        let sig =
            sign_with_key(KeyringAlgorithm::Ed25519, gkm.private_key.as_bytes(), data).unwrap();

        let valid = verify_with_key(
            KeyringAlgorithm::Ed25519,
            gkm.private_key.as_bytes(),
            gkm.public_key.as_deref(),
            data,
            &sig,
        )
        .unwrap();

        assert!(valid);
    }

    #[test]
    fn sign_verify_ecdsa() {
        let gkm = generate_key_material(KeyringAlgorithm::EcdsaP256).unwrap();
        let data = b"sign this ecdsa";

        let sig = sign_with_key(
            KeyringAlgorithm::EcdsaP256,
            gkm.private_key.as_bytes(),
            data,
        )
        .unwrap();

        let valid = verify_with_key(
            KeyringAlgorithm::EcdsaP256,
            gkm.private_key.as_bytes(),
            gkm.public_key.as_deref(),
            data,
            &sig,
        )
        .unwrap();

        assert!(valid);
    }

    #[test]
    fn encrypt_rejects_signing_algorithm() {
        let gkm = generate_key_material(KeyringAlgorithm::Ed25519).unwrap();
        let err = encrypt_with_key(
            KeyringAlgorithm::Ed25519,
            gkm.private_key.as_bytes(),
            b"hello",
            b"",
            NonceMode::Random,
        )
        .unwrap_err();
        assert!(matches!(err, CipherError::AlgorithmMismatch { .. }));
    }

    #[test]
    fn sign_rejects_encryption_algorithm() {
        let gkm = generate_key_material(KeyringAlgorithm::Aes256Gcm).unwrap();
        let err = sign_with_key(
            KeyringAlgorithm::Aes256Gcm,
            gkm.private_key.as_bytes(),
            b"hello",
        )
        .unwrap_err();
        assert!(matches!(err, CipherError::AlgorithmMismatch { .. }));
    }
}
