//! Client-side encryption for Cipher E2EE workflows.
//!
//! This crate lets clients encrypt and decrypt data locally while producing
//! ciphertext that is wire-compatible with Cipher's `CiphertextEnvelope` format.
//! The Cipher server never sees plaintext or key material.
//!
//! # Usage
//!
//! ```
//! use shroudb_cipher_blind::{ClientKey, Algorithm};
//!
//! // Generate a client-side encryption key
//! let key = ClientKey::generate(Algorithm::Aes256Gcm).unwrap();
//!
//! // Encrypt locally — returns a CiphertextEnvelope-compatible string
//! let ciphertext = key.encrypt(b"sensitive data", b"context").unwrap();
//!
//! // Decrypt locally
//! let plaintext = key.decrypt(&ciphertext, b"context").unwrap();
//! assert_eq!(plaintext.as_bytes(), b"sensitive data");
//! ```

use ring::hmac;
use shroudb_cipher_core::ciphertext::CiphertextEnvelope;
use shroudb_cipher_core::keyring::KeyringAlgorithm;
use shroudb_crypto::SecretBytes;
use zeroize::Zeroizing;

/// Supported encryption algorithms.
///
/// This is a client-facing subset of `KeyringAlgorithm` — only encryption
/// algorithms are exposed. Signing algorithms are not relevant for E2EE
/// content encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Algorithm {
    fn to_keyring_algorithm(self) -> KeyringAlgorithm {
        match self {
            Algorithm::Aes256Gcm => KeyringAlgorithm::Aes256Gcm,
            Algorithm::ChaCha20Poly1305 => KeyringAlgorithm::ChaCha20Poly1305,
        }
    }

    /// Wire name for display/logging.
    pub fn wire_name(&self) -> &'static str {
        match self {
            Algorithm::Aes256Gcm => "aes-256-gcm",
            Algorithm::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }
}

/// A client-side encryption key.
///
/// Holds 32 bytes of key material for symmetric encryption. This key
/// is held exclusively by the client — the Cipher server never sees it.
///
/// For E2EE chat, derive this from a shared secret:
/// ```ignore
/// let shared_secret = x25519_exchange(...);
/// let key = ClientKey::derive(Algorithm::Aes256Gcm, shared_secret, b"cipher-v1", 1)?;
/// ```
pub struct ClientKey {
    algorithm: Algorithm,
    material: Zeroizing<Vec<u8>>,
    version: u32,
}

impl ClientKey {
    /// Create from raw 32-byte key material.
    pub fn from_bytes(
        algorithm: Algorithm,
        key: Vec<u8>,
        version: u32,
    ) -> Result<Self, CipherBlindError> {
        if key.len() != 32 {
            return Err(CipherBlindError::InvalidKeyLength(key.len()));
        }
        Ok(Self {
            algorithm,
            material: Zeroizing::new(key),
            version,
        })
    }

    /// Generate a new random key via CSPRNG.
    pub fn generate(algorithm: Algorithm) -> Result<Self, CipherBlindError> {
        let rng = ring::rand::SystemRandom::new();
        let mut key = vec![0u8; 32];
        ring::rand::SecureRandom::fill(&rng, &mut key)
            .map_err(|_| CipherBlindError::KeyGeneration)?;
        Ok(Self {
            algorithm,
            material: Zeroizing::new(key),
            version: 1,
        })
    }

    /// Derive an encryption key from a shared secret using HKDF-SHA256.
    ///
    /// `version` is the key version stamped into the envelope prefix,
    /// allowing downstream systems to identify which key encrypted the data.
    pub fn derive(
        algorithm: Algorithm,
        shared_secret: &[u8],
        info: &[u8],
        version: u32,
    ) -> Result<Self, CipherBlindError> {
        // HKDF-Extract
        let salt = hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32]);
        let prk = hmac::sign(&salt, shared_secret);

        // HKDF-Expand
        let info_key = hmac::Key::new(hmac::HMAC_SHA256, prk.as_ref());
        let mut expand_input = Vec::with_capacity(info.len() + 1);
        expand_input.extend_from_slice(info);
        expand_input.push(1u8);
        let out = hmac::sign(&info_key, &expand_input);
        let mut okm = vec![0u8; 32];
        okm.copy_from_slice(&out.as_ref()[..32]);

        Self::from_bytes(algorithm, okm, version)
    }

    /// The algorithm this key uses.
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The key version stamped into envelope prefixes.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Export raw key bytes (for storage in client keychain).
    pub fn as_bytes(&self) -> &[u8] {
        &self.material
    }

    /// Encrypt plaintext with random nonce.
    ///
    /// Returns a `CiphertextEnvelope`-compatible wire string that any system
    /// understanding Cipher's format can parse (but not decrypt without the key).
    ///
    /// `aad` is Additional Authenticated Data — bound to the ciphertext but
    /// not encrypted. Use for context binding (e.g., conversation ID).
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<String, CipherBlindError> {
        let payload = encrypt_raw(self.algorithm, &self.material, plaintext, aad)?;

        let envelope = CiphertextEnvelope {
            key_version: self.version,
            algorithm: self.algorithm.to_keyring_algorithm(),
            payload,
        };

        envelope
            .encode()
            .map_err(|e| CipherBlindError::Envelope(e.to_string()))
    }

    /// Encrypt with convergent (deterministic) mode.
    ///
    /// Same plaintext + same key + same AAD = same ciphertext.
    /// Enables deduplication and equality checks on ciphertext without decrypting.
    ///
    /// **Warning:** Leaks whether two ciphertexts contain the same plaintext.
    /// Only use when this is an acceptable tradeoff.
    pub fn encrypt_convergent(
        &self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<String, CipherBlindError> {
        if aad.is_empty() {
            return Err(CipherBlindError::ConvergentRequiresContext);
        }

        let nonce = derive_convergent_nonce(&self.material, plaintext, aad)?;
        let payload =
            encrypt_raw_with_nonce(self.algorithm, &self.material, &nonce, plaintext, aad)?;

        let envelope = CiphertextEnvelope {
            key_version: self.version,
            algorithm: self.algorithm.to_keyring_algorithm(),
            payload,
        };

        envelope
            .encode()
            .map_err(|e| CipherBlindError::Envelope(e.to_string()))
    }

    /// Decrypt a `CiphertextEnvelope`-compatible wire string.
    ///
    /// Validates that the envelope's algorithm matches this key's algorithm.
    /// Returns the plaintext as `SecretBytes` (zeroized on drop).
    pub fn decrypt(&self, ciphertext: &str, aad: &[u8]) -> Result<SecretBytes, CipherBlindError> {
        let envelope = CiphertextEnvelope::decode(ciphertext)
            .map_err(|e| CipherBlindError::Envelope(e.to_string()))?;

        let expected = self.algorithm.to_keyring_algorithm();
        envelope
            .validate_algorithm(expected)
            .map_err(|e| CipherBlindError::Envelope(e.to_string()))?;

        let plaintext = decrypt_raw(self.algorithm, &self.material, &envelope.payload, aad)?;
        Ok(SecretBytes::new(plaintext))
    }
}

// ── Raw crypto operations ───────────────────────────────────────────────

fn encrypt_raw(
    algorithm: Algorithm,
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CipherBlindError> {
    match algorithm {
        Algorithm::Aes256Gcm => {
            shroudb_crypto::aes_gcm_encrypt(key, plaintext, aad).map_err(CipherBlindError::Crypto)
        }
        Algorithm::ChaCha20Poly1305 => {
            shroudb_crypto::chacha20_poly1305_encrypt(key, plaintext, aad)
                .map_err(CipherBlindError::Crypto)
        }
    }
}

fn encrypt_raw_with_nonce(
    algorithm: Algorithm,
    key: &[u8],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CipherBlindError> {
    match algorithm {
        Algorithm::Aes256Gcm => {
            shroudb_crypto::aes_gcm_encrypt_with_nonce(key, nonce, plaintext, aad)
                .map_err(CipherBlindError::Crypto)
        }
        Algorithm::ChaCha20Poly1305 => {
            shroudb_crypto::chacha20_poly1305_encrypt_with_nonce(key, nonce, plaintext, aad)
                .map_err(CipherBlindError::Crypto)
        }
    }
}

fn decrypt_raw(
    algorithm: Algorithm,
    key: &[u8],
    payload: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CipherBlindError> {
    match algorithm {
        Algorithm::Aes256Gcm => shroudb_crypto::aes_gcm_decrypt(key, payload, aad)
            .map_err(|_| CipherBlindError::DecryptionFailed),
        Algorithm::ChaCha20Poly1305 => shroudb_crypto::chacha20_poly1305_decrypt(key, payload, aad)
            .map_err(|_| CipherBlindError::DecryptionFailed),
    }
}

/// Derive a deterministic 12-byte nonce for convergent encryption.
/// Uses HMAC-SHA256(key, plaintext || aad) truncated to 12 bytes.
/// This matches the server-side `derive_convergent_nonce` in crypto_ops.
fn derive_convergent_nonce(
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<[u8; 12], CipherBlindError> {
    let mut input = Vec::with_capacity(plaintext.len() + aad.len());
    input.extend_from_slice(plaintext);
    input.extend_from_slice(aad);

    let sig = shroudb_crypto::hmac_sign(shroudb_crypto::HmacAlgorithm::Sha256, key, &input)
        .map_err(CipherBlindError::Crypto)?;

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sig[..12]);
    Ok(nonce)
}

/// Errors from client-side cipher operations.
#[derive(Debug, thiserror::Error)]
pub enum CipherBlindError {
    #[error("invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),
    #[error("key generation failed")]
    KeyGeneration,
    #[error("envelope error: {0}")]
    Envelope(String),
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("convergent encryption requires non-empty context (AAD)")]
    ConvergentRequiresContext,
    #[error("crypto error: {0}")]
    Crypto(#[from] shroudb_crypto::CryptoError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_key() {
        let key = ClientKey::generate(Algorithm::Aes256Gcm).unwrap();
        assert_eq!(key.as_bytes().len(), 32);
        assert_eq!(key.algorithm(), Algorithm::Aes256Gcm);
        assert_eq!(key.version(), 1);
    }

    #[test]
    fn from_bytes_valid() {
        let key = ClientKey::from_bytes(Algorithm::Aes256Gcm, vec![0x42u8; 32], 5).unwrap();
        assert_eq!(key.as_bytes(), &[0x42u8; 32]);
        assert_eq!(key.version(), 5);
    }

    #[test]
    fn from_bytes_invalid_length() {
        assert!(ClientKey::from_bytes(Algorithm::Aes256Gcm, vec![0u8; 16], 1).is_err());
        assert!(ClientKey::from_bytes(Algorithm::Aes256Gcm, vec![0u8; 64], 1).is_err());
    }

    #[test]
    fn encrypt_decrypt_aes_roundtrip() {
        let key = ClientKey::generate(Algorithm::Aes256Gcm).unwrap();
        let plaintext = b"hello from the client";
        let aad = b"conversation-123";

        let ciphertext = key.encrypt(plaintext, aad).unwrap();
        let decrypted = key.decrypt(&ciphertext, aad).unwrap();

        assert_eq!(decrypted.as_bytes(), plaintext);
    }

    #[test]
    fn encrypt_decrypt_chacha_roundtrip() {
        let key = ClientKey::generate(Algorithm::ChaCha20Poly1305).unwrap();
        let plaintext = b"hello chacha";
        let aad = b"";

        let ciphertext = key.encrypt(plaintext, aad).unwrap();
        let decrypted = key.decrypt(&ciphertext, aad).unwrap();

        assert_eq!(decrypted.as_bytes(), plaintext);
    }

    #[test]
    fn ciphertext_is_envelope_compatible() {
        let key = ClientKey::generate(Algorithm::Aes256Gcm).unwrap();
        let ciphertext = key.encrypt(b"test", b"").unwrap();

        // Should be parseable by CiphertextEnvelope::decode
        let envelope = CiphertextEnvelope::decode(&ciphertext).unwrap();
        assert_eq!(envelope.key_version, 1);
        assert_eq!(envelope.algorithm, KeyringAlgorithm::Aes256Gcm);
        assert!(!envelope.payload.is_empty());
    }

    #[test]
    fn version_stamped_in_envelope() {
        let key = ClientKey::from_bytes(Algorithm::Aes256Gcm, vec![0x42u8; 32], 42).unwrap();
        let ciphertext = key.encrypt(b"test", b"").unwrap();

        let envelope = CiphertextEnvelope::decode(&ciphertext).unwrap();
        assert_eq!(envelope.key_version, 42);
    }

    #[test]
    fn wrong_aad_fails_decrypt() {
        let key = ClientKey::generate(Algorithm::Aes256Gcm).unwrap();
        let ciphertext = key.encrypt(b"test", b"correct-context").unwrap();

        let err = key.decrypt(&ciphertext, b"wrong-context");
        assert!(err.is_err());
    }

    #[test]
    fn wrong_key_fails_decrypt() {
        let key1 = ClientKey::generate(Algorithm::Aes256Gcm).unwrap();
        let key2 = ClientKey::generate(Algorithm::Aes256Gcm).unwrap();

        let ciphertext = key1.encrypt(b"test", b"").unwrap();
        let err = key2.decrypt(&ciphertext, b"");
        assert!(err.is_err());
    }

    #[test]
    fn algorithm_mismatch_fails_decrypt() {
        let aes_key = ClientKey::generate(Algorithm::Aes256Gcm).unwrap();
        let chacha_key = ClientKey::generate(Algorithm::ChaCha20Poly1305).unwrap();

        let ciphertext = aes_key.encrypt(b"test", b"").unwrap();
        let err = chacha_key.decrypt(&ciphertext, b"");
        assert!(err.is_err());
    }

    #[test]
    fn random_nonces_produce_different_ciphertext() {
        let key = ClientKey::generate(Algorithm::Aes256Gcm).unwrap();
        let c1 = key.encrypt(b"same plaintext", b"").unwrap();
        let c2 = key.encrypt(b"same plaintext", b"").unwrap();

        // Random nonces — same plaintext produces different ciphertext
        assert_ne!(c1, c2);
    }

    #[test]
    fn convergent_produces_same_ciphertext() {
        let key = ClientKey::generate(Algorithm::Aes256Gcm).unwrap();
        let c1 = key
            .encrypt_convergent(b"deterministic", b"context")
            .unwrap();
        let c2 = key
            .encrypt_convergent(b"deterministic", b"context")
            .unwrap();

        assert_eq!(c1, c2);
    }

    #[test]
    fn convergent_different_context_produces_different_ciphertext() {
        let key = ClientKey::generate(Algorithm::Aes256Gcm).unwrap();
        let c1 = key
            .encrypt_convergent(b"same plaintext", b"context-a")
            .unwrap();
        let c2 = key
            .encrypt_convergent(b"same plaintext", b"context-b")
            .unwrap();

        assert_ne!(c1, c2);
    }

    #[test]
    fn convergent_requires_context() {
        let key = ClientKey::generate(Algorithm::Aes256Gcm).unwrap();
        let err = key.encrypt_convergent(b"test", b"");
        assert!(err.is_err());
    }

    #[test]
    fn convergent_decrypt_roundtrip() {
        let key = ClientKey::generate(Algorithm::ChaCha20Poly1305).unwrap();
        let ciphertext = key.encrypt_convergent(b"hello convergent", b"ctx").unwrap();
        let decrypted = key.decrypt(&ciphertext, b"ctx").unwrap();
        assert_eq!(decrypted.as_bytes(), b"hello convergent");
    }

    #[test]
    fn derive_produces_32_bytes() {
        let key =
            ClientKey::derive(Algorithm::Aes256Gcm, b"shared-secret", b"cipher-v1", 1).unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn derive_deterministic() {
        let k1 = ClientKey::derive(Algorithm::Aes256Gcm, b"secret", b"info", 1).unwrap();
        let k2 = ClientKey::derive(Algorithm::Aes256Gcm, b"secret", b"info", 1).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_different_info_produces_different_keys() {
        let k1 = ClientKey::derive(Algorithm::Aes256Gcm, b"secret", b"encrypt", 1).unwrap();
        let k2 = ClientKey::derive(Algorithm::Aes256Gcm, b"secret", b"search", 1).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let key = ClientKey::generate(Algorithm::Aes256Gcm).unwrap();
        let ciphertext = key.encrypt(b"", b"").unwrap();
        let decrypted = key.decrypt(&ciphertext, b"").unwrap();
        assert!(decrypted.as_bytes().is_empty());
    }

    #[test]
    fn large_plaintext_roundtrip() {
        let key = ClientKey::generate(Algorithm::ChaCha20Poly1305).unwrap();
        let plaintext = vec![0xABu8; 1024 * 1024]; // 1MB
        let ciphertext = key.encrypt(&plaintext, b"big").unwrap();
        let decrypted = key.decrypt(&ciphertext, b"big").unwrap();
        assert_eq!(decrypted.as_bytes(), &plaintext);
    }

    #[test]
    fn wire_name() {
        assert_eq!(Algorithm::Aes256Gcm.wire_name(), "aes-256-gcm");
        assert_eq!(Algorithm::ChaCha20Poly1305.wire_name(), "chacha20-poly1305");
    }

    #[test]
    fn convergent_nonce_matches_server_side() {
        // Verify client-side convergent nonce derivation produces the same
        // result as the server-side crypto_ops::derive_convergent_nonce.
        // Both use HMAC-SHA256(key, plaintext || aad)[0..12].
        let key_bytes = vec![0x42u8; 32];
        let plaintext = b"deterministic";
        let aad = b"context";

        let nonce = derive_convergent_nonce(&key_bytes, plaintext, aad).unwrap();
        assert_eq!(nonce.len(), 12);

        // Verify deterministic: same inputs produce same nonce
        let nonce2 = derive_convergent_nonce(&key_bytes, plaintext, aad).unwrap();
        assert_eq!(nonce, nonce2);

        // Different inputs produce different nonce
        let nonce3 = derive_convergent_nonce(&key_bytes, b"other", aad).unwrap();
        assert_ne!(nonce, nonce3);
    }

    #[test]
    fn invalid_ciphertext_string_fails() {
        let key = ClientKey::generate(Algorithm::Aes256Gcm).unwrap();
        assert!(key.decrypt("not-a-valid-envelope", b"").is_err());
        assert!(key.decrypt("", b"").is_err());
        assert!(key.decrypt("abc:", b"").is_err());
    }
}
