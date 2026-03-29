//! Per-keyring operation policies.
//!
//! Policies restrict which operations can be performed on a keyring.
//! For example, a keyring might be configured as encrypt-only (no decrypt
//! allowed) or sign-only (no encrypt/decrypt).

use serde::{Deserialize, Serialize};

/// Operations that can be allowed or denied on a keyring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyringOperation {
    Encrypt,
    Decrypt,
    Rewrap,
    GenerateDataKey,
    Sign,
    VerifySignature,
    Rotate,
    KeyInfo,
}

impl KeyringOperation {
    /// Parse an operation name from a command verb string.
    pub fn from_verb(verb: &str) -> Option<Self> {
        match verb.to_ascii_uppercase().as_str() {
            "ENCRYPT" => Some(Self::Encrypt),
            "DECRYPT" => Some(Self::Decrypt),
            "REWRAP" => Some(Self::Rewrap),
            "GENERATE_DATA_KEY" => Some(Self::GenerateDataKey),
            "SIGN" => Some(Self::Sign),
            "VERIFY_SIGNATURE" => Some(Self::VerifySignature),
            "ROTATE" => Some(Self::Rotate),
            "KEY_INFO" => Some(Self::KeyInfo),
            _ => None,
        }
    }
}

/// Policy controlling which operations are allowed on a keyring.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyringPolicy {
    /// Allowed operations. If empty, all operations are allowed.
    #[serde(default)]
    pub allowed_operations: Vec<KeyringOperation>,
    /// Denied operations. Checked after allowed_operations.
    #[serde(default)]
    pub denied_operations: Vec<KeyringOperation>,
}

impl KeyringPolicy {
    /// Check if an operation is allowed by this policy.
    pub fn allows(&self, op: KeyringOperation) -> bool {
        if self.denied_operations.contains(&op) {
            return false;
        }
        if self.allowed_operations.is_empty() {
            return true;
        }
        self.allowed_operations.contains(&op)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_allows_all() {
        let policy = KeyringPolicy::default();
        assert!(policy.allows(KeyringOperation::Encrypt));
        assert!(policy.allows(KeyringOperation::Decrypt));
        assert!(policy.allows(KeyringOperation::Sign));
    }

    #[test]
    fn allowed_list_restricts() {
        let policy = KeyringPolicy {
            allowed_operations: vec![KeyringOperation::Encrypt, KeyringOperation::Decrypt],
            denied_operations: Vec::new(),
        };
        assert!(policy.allows(KeyringOperation::Encrypt));
        assert!(policy.allows(KeyringOperation::Decrypt));
        assert!(!policy.allows(KeyringOperation::Sign));
        assert!(!policy.allows(KeyringOperation::Rotate));
    }

    #[test]
    fn denied_list_overrides() {
        let policy = KeyringPolicy {
            allowed_operations: Vec::new(),
            denied_operations: vec![KeyringOperation::Decrypt],
        };
        assert!(policy.allows(KeyringOperation::Encrypt));
        assert!(!policy.allows(KeyringOperation::Decrypt));
    }

    #[test]
    fn denied_overrides_allowed() {
        let policy = KeyringPolicy {
            allowed_operations: vec![KeyringOperation::Encrypt, KeyringOperation::Decrypt],
            denied_operations: vec![KeyringOperation::Decrypt],
        };
        assert!(policy.allows(KeyringOperation::Encrypt));
        assert!(!policy.allows(KeyringOperation::Decrypt));
    }

    #[test]
    fn from_verb_parsing() {
        assert_eq!(
            KeyringOperation::from_verb("ENCRYPT"),
            Some(KeyringOperation::Encrypt)
        );
        assert_eq!(
            KeyringOperation::from_verb("decrypt"),
            Some(KeyringOperation::Decrypt)
        );
        assert_eq!(KeyringOperation::from_verb("HEALTH"), None);
        assert_eq!(KeyringOperation::from_verb("AUTH"), None);
    }
}
