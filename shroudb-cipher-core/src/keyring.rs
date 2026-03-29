use serde::{Deserialize, Serialize};

use crate::key_version::KeyVersion;
use crate::policy::KeyringPolicy;

/// A keyring holds versioned encryption keys for a single purpose.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keyring {
    pub name: String,
    pub algorithm: KeyringAlgorithm,
    pub rotation_days: u32,
    pub drain_days: u32,
    pub convergent: bool,
    pub created_at: u64,
    pub disabled: bool,
    pub policy: KeyringPolicy,
    pub key_versions: Vec<KeyVersion>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyringAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
    Ed25519,
    EcdsaP256,
    HmacSha256,
}

impl std::fmt::Display for KeyringAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.wire_name())
    }
}

impl std::str::FromStr for KeyringAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().replace('_', "-").as_str() {
            "aes-256-gcm" | "aes256gcm" => Ok(Self::Aes256Gcm),
            "chacha20-poly1305" | "chacha20poly1305" => Ok(Self::ChaCha20Poly1305),
            "ed25519" => Ok(Self::Ed25519),
            "ecdsa-p256" | "ecdsap256" => Ok(Self::EcdsaP256),
            "hmac-sha256" | "hmacsha256" => Ok(Self::HmacSha256),
            other => Err(format!("unknown algorithm: {other}")),
        }
    }
}

impl KeyringAlgorithm {
    /// Canonical wire name for serialization.
    pub fn wire_name(&self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
            Self::Ed25519 => "ed25519",
            Self::EcdsaP256 => "ecdsa-p256",
            Self::HmacSha256 => "hmac-sha256",
        }
    }

    /// Returns true if this algorithm uses symmetric keys.
    pub fn is_symmetric(&self) -> bool {
        matches!(
            self,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 | Self::HmacSha256
        )
    }

    /// Returns true if this algorithm supports signing operations.
    pub fn is_signing(&self) -> bool {
        matches!(self, Self::Ed25519 | Self::EcdsaP256 | Self::HmacSha256)
    }

    /// Returns true if this algorithm supports encrypt/decrypt operations.
    pub fn is_encryption(&self) -> bool {
        matches!(self, Self::Aes256Gcm | Self::ChaCha20Poly1305)
    }

    /// Short tag for use in the ciphertext envelope format.
    pub fn envelope_tag(&self) -> &'static str {
        match self {
            Self::Aes256Gcm => "gcm",
            Self::ChaCha20Poly1305 => "cc20",
            Self::HmacSha256 => "hmac",
            Self::Ed25519 => "ed25519",
            Self::EcdsaP256 => "p256",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_classification_symmetric() {
        assert!(KeyringAlgorithm::Aes256Gcm.is_symmetric());
        assert!(KeyringAlgorithm::ChaCha20Poly1305.is_symmetric());
        assert!(KeyringAlgorithm::HmacSha256.is_symmetric());
        assert!(!KeyringAlgorithm::Ed25519.is_symmetric());
        assert!(!KeyringAlgorithm::EcdsaP256.is_symmetric());
    }

    #[test]
    fn algorithm_classification_signing() {
        assert!(KeyringAlgorithm::Ed25519.is_signing());
        assert!(KeyringAlgorithm::EcdsaP256.is_signing());
        assert!(KeyringAlgorithm::HmacSha256.is_signing());
        assert!(!KeyringAlgorithm::Aes256Gcm.is_signing());
        assert!(!KeyringAlgorithm::ChaCha20Poly1305.is_signing());
    }

    #[test]
    fn algorithm_classification_encryption() {
        assert!(KeyringAlgorithm::Aes256Gcm.is_encryption());
        assert!(KeyringAlgorithm::ChaCha20Poly1305.is_encryption());
        assert!(!KeyringAlgorithm::Ed25519.is_encryption());
        assert!(!KeyringAlgorithm::EcdsaP256.is_encryption());
        assert!(!KeyringAlgorithm::HmacSha256.is_encryption());
    }

    #[test]
    fn algorithm_from_str_roundtrip() {
        for alg in [
            KeyringAlgorithm::Aes256Gcm,
            KeyringAlgorithm::ChaCha20Poly1305,
            KeyringAlgorithm::Ed25519,
            KeyringAlgorithm::EcdsaP256,
            KeyringAlgorithm::HmacSha256,
        ] {
            let s = alg.to_string();
            let parsed: KeyringAlgorithm = s.parse().unwrap();
            assert_eq!(parsed, alg);
        }
    }

    #[test]
    fn algorithm_from_str_underscore_variants() {
        assert_eq!(
            "aes_256_gcm".parse::<KeyringAlgorithm>().unwrap(),
            KeyringAlgorithm::Aes256Gcm
        );
        assert_eq!(
            "chacha20_poly1305".parse::<KeyringAlgorithm>().unwrap(),
            KeyringAlgorithm::ChaCha20Poly1305
        );
        assert_eq!(
            "ecdsa_p256".parse::<KeyringAlgorithm>().unwrap(),
            KeyringAlgorithm::EcdsaP256
        );
        assert_eq!(
            "hmac_sha256".parse::<KeyringAlgorithm>().unwrap(),
            KeyringAlgorithm::HmacSha256
        );
    }

    #[test]
    fn hmac_is_both_symmetric_and_signing() {
        let algo = KeyringAlgorithm::HmacSha256;
        assert!(algo.is_symmetric());
        assert!(algo.is_signing());
        assert!(!algo.is_encryption());
    }
}
