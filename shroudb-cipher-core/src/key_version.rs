use serde::{Deserialize, Serialize};

use crate::error::CipherError;

/// A single version of a key within a keyring.
///
/// Key material is stored as hex-encoded bytes in serialized form.
/// In memory, it is held as `SecretBytes` (zeroized on drop).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}
