use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::CipherError;

/// A single version of a key within a keyring.
///
/// Key material is stored as hex-encoded bytes in serialized form.
/// In memory, it is held as `SecretBytes` (zeroized on drop).
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyVersion {
    pub version: u32,
    pub state: KeyState,
    /// Hex-encoded key material. In memory, convert to `SecretBytes` for crypto ops.
    pub key_material: Option<String>,
    /// Hex-encoded public key bytes for asymmetric algorithms (Ed25519, ECDSA-P256).
    /// `None` for symmetric algorithms.
    pub public_key: Option<String>,
    pub created_at: u64,
    pub activated_at: Option<u64>,
    pub draining_since: Option<u64>,
    pub retired_at: Option<u64>,
}

impl fmt::Debug for KeyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyVersion")
            .field("version", &self.version)
            .field("state", &self.state)
            .field(
                "key_material",
                &match &self.key_material {
                    Some(_) => "[REDACTED]",
                    None => "None",
                },
            )
            .field("public_key", &self.public_key)
            .field("created_at", &self.created_at)
            .field("activated_at", &self.activated_at)
            .field("draining_since", &self.draining_since)
            .field("retired_at", &self.retired_at)
            .finish()
    }
}

/// Key lifecycle state machine: Staged -> Active -> Draining -> Retired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    Staged,
    Active,
    Draining,
    Retired,
}

impl KeyState {
    /// Returns whether this state can transition to the target state.
    pub fn can_transition_to(self, target: KeyState) -> bool {
        matches!(
            (self, target),
            (KeyState::Staged, KeyState::Active)
                | (KeyState::Active, KeyState::Draining)
                | (KeyState::Draining, KeyState::Retired)
        )
    }

    /// Attempt to transition to the target state.
    pub fn transition_to(self, target: KeyState) -> Result<KeyState, CipherError> {
        if self.can_transition_to(target) {
            Ok(target)
        } else {
            Err(CipherError::InvalidStateTransition {
                from: self,
                to: target,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_transitions() {
        assert!(KeyState::Staged.can_transition_to(KeyState::Active));
        assert!(KeyState::Active.can_transition_to(KeyState::Draining));
        assert!(KeyState::Draining.can_transition_to(KeyState::Retired));
    }

    #[test]
    fn invalid_transitions() {
        assert!(!KeyState::Staged.can_transition_to(KeyState::Draining));
        assert!(!KeyState::Staged.can_transition_to(KeyState::Retired));
        assert!(!KeyState::Active.can_transition_to(KeyState::Retired));
        assert!(!KeyState::Active.can_transition_to(KeyState::Staged));
        assert!(!KeyState::Draining.can_transition_to(KeyState::Active));
        assert!(!KeyState::Retired.can_transition_to(KeyState::Draining));
        assert!(!KeyState::Active.can_transition_to(KeyState::Active));
    }

    #[test]
    fn transition_to_ok() {
        let state = KeyState::Staged.transition_to(KeyState::Active).unwrap();
        assert_eq!(state, KeyState::Active);
    }

    #[test]
    fn transition_to_err() {
        let err = KeyState::Staged
            .transition_to(KeyState::Retired)
            .unwrap_err();
        assert!(matches!(
            err,
            CipherError::InvalidStateTransition {
                from: KeyState::Staged,
                to: KeyState::Retired,
            }
        ));
    }

    #[test]
    fn debug_redacts_key_material() {
        let kv = KeyVersion {
            version: 1,
            state: KeyState::Active,
            key_material: Some("secret".into()),
            public_key: Some("pub".into()),
            created_at: 100,
            activated_at: Some(100),
            draining_since: None,
            retired_at: None,
        };
        let debug = format!("{:?}", kv);
        assert!(
            debug.contains("[REDACTED]"),
            "expected [REDACTED] in: {debug}"
        );
        assert!(!debug.contains("secret"), "key material leaked in: {debug}");
    }
}
