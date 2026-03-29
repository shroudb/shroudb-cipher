use std::collections::HashMap;
use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use obfuskey::{FieldSchema, Obfusbit, Obfuskey};

use crate::error::CipherError;
use crate::keyring::KeyringAlgorithm;

// ---------------------------------------------------------------------------
// Algorithm ID map
// ---------------------------------------------------------------------------

/// Numeric IDs for each algorithm. These are packed into the obfuscated prefix.
/// The mapping is fixed — never reorder or reuse IDs.
const ALGO_AES_256_GCM: u64 = 0;
const ALGO_CHACHA20_POLY1305: u64 = 1;
const ALGO_HMAC_SHA256: u64 = 2;
const ALGO_ED25519: u64 = 3;
const ALGO_ECDSA_P256: u64 = 4;

fn algorithm_to_id(algo: KeyringAlgorithm) -> u64 {
    match algo {
        KeyringAlgorithm::Aes256Gcm => ALGO_AES_256_GCM,
        KeyringAlgorithm::ChaCha20Poly1305 => ALGO_CHACHA20_POLY1305,
        KeyringAlgorithm::HmacSha256 => ALGO_HMAC_SHA256,
        KeyringAlgorithm::Ed25519 => ALGO_ED25519,
        KeyringAlgorithm::EcdsaP256 => ALGO_ECDSA_P256,
    }
}

fn id_to_algorithm(id: u64) -> Result<KeyringAlgorithm, CipherError> {
    match id {
        ALGO_AES_256_GCM => Ok(KeyringAlgorithm::Aes256Gcm),
        ALGO_CHACHA20_POLY1305 => Ok(KeyringAlgorithm::ChaCha20Poly1305),
        ALGO_HMAC_SHA256 => Ok(KeyringAlgorithm::HmacSha256),
        ALGO_ED25519 => Ok(KeyringAlgorithm::Ed25519),
        ALGO_ECDSA_P256 => Ok(KeyringAlgorithm::EcdsaP256),
        _ => Err(CipherError::InvalidCiphertext(format!(
            "unknown algorithm id: {id}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Obfusbit schema: version (16 bits) + algorithm_id (4 bits) = 20 bits
// ---------------------------------------------------------------------------

const VERSION_BITS: u32 = 16;
const ALGORITHM_BITS: u32 = 4;

/// Custom alphabet for envelope prefixes. Using BASE62 characters in a
/// shuffled order so the prefix doesn't look like standard base62.
const ENVELOPE_ALPHABET: &str = "k3Xm7RqYf1LvNj9GpDw0ZhTs5CxAe4Uo8KiHb2WaSrBn6EcFdJlMgPtQyVuIzO";

fn build_obfusbit() -> Obfusbit {
    let schema = vec![
        FieldSchema {
            name: "version".to_string(),
            bits: VERSION_BITS,
        },
        FieldSchema {
            name: "algorithm_id".to_string(),
            bits: ALGORITHM_BITS,
        },
    ];

    let total_bits = VERSION_BITS + ALGORITHM_BITS;
    let base = ENVELOPE_ALPHABET.chars().count() as f64;
    let key_length = (total_bits as f64 / base.log2()).ceil() as u32;

    let obfuskey =
        Obfuskey::new(ENVELOPE_ALPHABET, Some(key_length), None).expect("valid obfuskey config");
    Obfusbit::new(schema, Some(obfuskey)).expect("valid obfusbit schema")
}

static OBFUSBIT: LazyLock<std::sync::Mutex<Obfusbit>> =
    LazyLock::new(|| std::sync::Mutex::new(build_obfusbit()));

// ---------------------------------------------------------------------------
// CiphertextEnvelope
// ---------------------------------------------------------------------------

/// Ciphertext envelope with an obfuscated prefix.
///
/// Wire format: `{obfuscated_prefix}:{base64url(nonce || ciphertext || tag)}`
///
/// The prefix encodes the key version and algorithm ID via Obfusbit,
/// making them opaque to observers while remaining reversible by Cipher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphertextEnvelope {
    pub key_version: u32,
    pub algorithm: KeyringAlgorithm,
    pub payload: Vec<u8>,
}

impl CiphertextEnvelope {
    /// Encode the envelope to its wire format.
    pub fn encode(&self) -> Result<String, CipherError> {
        let mut values = HashMap::new();
        values.insert("version".to_string(), self.key_version as u64);
        values.insert("algorithm_id".to_string(), algorithm_to_id(self.algorithm));

        let mut obb = OBFUSBIT
            .lock()
            .map_err(|e| CipherError::Internal(format!("obfusbit lock poisoned: {e}")))?;
        let packed = obb
            .pack_u64(&values, true)
            .map_err(|e| CipherError::Internal(format!("envelope pack failed: {e}")))?;
        let prefix = match packed {
            obfuskey::PackedU64::Key(k) => k,
            obfuskey::PackedU64::Int(i) => {
                return Err(CipherError::Internal(format!(
                    "expected obfuscated key, got integer {i}"
                )));
            }
        };

        let encoded_payload = URL_SAFE_NO_PAD.encode(&self.payload);
        Ok(format!("{prefix}:{encoded_payload}"))
    }

    /// Decode an envelope from its wire format.
    pub fn decode(s: &str) -> Result<Self, CipherError> {
        let colon = s
            .find(':')
            .ok_or_else(|| CipherError::InvalidCiphertext("missing ':' separator".into()))?;

        let prefix = &s[..colon];
        let payload_str = &s[colon + 1..];

        if prefix.is_empty() {
            return Err(CipherError::InvalidCiphertext("empty prefix".into()));
        }

        let mut obb = OBFUSBIT
            .lock()
            .map_err(|e| CipherError::Internal(format!("obfusbit lock poisoned: {e}")))?;
        let fields = obb
            .unpack_u64(obfuskey::UnpackDataU64::Key(prefix), true)
            .map_err(|e| CipherError::InvalidCiphertext(format!("invalid prefix: {e}")))?;

        let version = *fields
            .get("version")
            .ok_or_else(|| CipherError::InvalidCiphertext("missing version".into()))?;
        let algorithm_id = *fields
            .get("algorithm_id")
            .ok_or_else(|| CipherError::InvalidCiphertext("missing algorithm_id".into()))?;

        let algorithm = id_to_algorithm(algorithm_id)?;

        let payload = URL_SAFE_NO_PAD
            .decode(payload_str)
            .map_err(|e| CipherError::InvalidCiphertext(format!("invalid base64url: {e}")))?;

        Ok(Self {
            key_version: version as u32,
            algorithm,
            payload,
        })
    }

    /// Validate that the envelope's algorithm matches the expected algorithm.
    pub fn validate_algorithm(&self, expected: KeyringAlgorithm) -> Result<(), CipherError> {
        if self.algorithm != expected {
            return Err(CipherError::AlgorithmMismatch {
                expected: expected.envelope_tag().to_string(),
                required: format!(
                    "ciphertext was encrypted with '{}', keyring expects '{}'",
                    self.algorithm.envelope_tag(),
                    expected.envelope_tag()
                ),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let envelope = CiphertextEnvelope {
            key_version: 3,
            algorithm: KeyringAlgorithm::Aes256Gcm,
            payload: vec![0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD],
        };
        let encoded = envelope.encode().unwrap();
        assert_eq!(encoded.matches(':').count(), 1);

        let decoded = CiphertextEnvelope::decode(&encoded).unwrap();
        assert_eq!(decoded.key_version, 3);
        assert_eq!(decoded.algorithm, KeyringAlgorithm::Aes256Gcm);
        assert_eq!(decoded.payload, envelope.payload);
    }

    #[test]
    fn prefix_is_opaque() {
        let envelope = CiphertextEnvelope {
            key_version: 1,
            algorithm: KeyringAlgorithm::Aes256Gcm,
            payload: b"hello".to_vec(),
        };
        let encoded = envelope.encode().unwrap();
        let prefix = encoded.split(':').next().unwrap();
        assert!(!prefix.contains('v'));
        assert!(!prefix.starts_with("v1"));
        assert!(!prefix.contains("gcm"));
    }

    #[test]
    fn different_versions_produce_different_prefixes() {
        let e1 = CiphertextEnvelope {
            key_version: 1,
            algorithm: KeyringAlgorithm::Aes256Gcm,
            payload: vec![],
        }
        .encode()
        .unwrap();
        let e2 = CiphertextEnvelope {
            key_version: 2,
            algorithm: KeyringAlgorithm::Aes256Gcm,
            payload: vec![],
        }
        .encode()
        .unwrap();

        let p1 = e1.split(':').next().unwrap();
        let p2 = e2.split(':').next().unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn all_algorithms_roundtrip() {
        let algos = [
            KeyringAlgorithm::Aes256Gcm,
            KeyringAlgorithm::ChaCha20Poly1305,
            KeyringAlgorithm::HmacSha256,
            KeyringAlgorithm::Ed25519,
            KeyringAlgorithm::EcdsaP256,
        ];

        for algo in algos {
            let envelope = CiphertextEnvelope {
                key_version: 42,
                algorithm: algo,
                payload: vec![1, 2, 3],
            };
            let decoded = CiphertextEnvelope::decode(&envelope.encode().unwrap()).unwrap();
            assert_eq!(decoded.algorithm, algo, "roundtrip failed for {algo:?}");
            assert_eq!(decoded.key_version, 42);
        }
    }

    #[test]
    fn large_version_roundtrip() {
        let envelope = CiphertextEnvelope {
            key_version: 65535,
            algorithm: KeyringAlgorithm::Aes256Gcm,
            payload: vec![42; 64],
        };
        let decoded = CiphertextEnvelope::decode(&envelope.encode().unwrap()).unwrap();
        assert_eq!(decoded.key_version, 65535);
    }

    #[test]
    fn decode_missing_separator() {
        let err = CiphertextEnvelope::decode("noseparator").unwrap_err();
        assert!(matches!(err, CipherError::InvalidCiphertext(_)));
    }

    #[test]
    fn decode_empty_prefix() {
        let err = CiphertextEnvelope::decode(":aGVsbG8").unwrap_err();
        assert!(matches!(err, CipherError::InvalidCiphertext(_)));
    }

    #[test]
    fn validate_algorithm_match() {
        let envelope = CiphertextEnvelope {
            key_version: 1,
            algorithm: KeyringAlgorithm::Aes256Gcm,
            payload: vec![],
        };
        assert!(
            envelope
                .validate_algorithm(KeyringAlgorithm::Aes256Gcm)
                .is_ok()
        );
    }

    #[test]
    fn validate_algorithm_mismatch() {
        let envelope = CiphertextEnvelope {
            key_version: 1,
            algorithm: KeyringAlgorithm::Aes256Gcm,
            payload: vec![],
        };
        assert!(
            envelope
                .validate_algorithm(KeyringAlgorithm::ChaCha20Poly1305)
                .is_err()
        );
    }

    #[test]
    fn prefix_length_is_consistent() {
        let lengths: Vec<usize> = (0..100)
            .map(|v| {
                let e = CiphertextEnvelope {
                    key_version: v,
                    algorithm: KeyringAlgorithm::Aes256Gcm,
                    payload: vec![],
                };
                e.encode().unwrap().split(':').next().unwrap().len()
            })
            .collect();
        assert!(lengths.windows(2).all(|w| w[0] == w[1]));
    }
}
