use crate::key_version::KeyState;

#[derive(Debug, thiserror::Error)]
pub enum CipherError {
    #[error("invalid state transition: {from:?} -> {to:?}")]
    InvalidStateTransition { from: KeyState, to: KeyState },

    #[error("keyring not found: {0}")]
    KeyringNotFound(String),

    #[error("keyring already exists: {0}")]
    KeyringExists(String),

    #[error("key version not found: {keyring} v{version}")]
    KeyVersionNotFound { keyring: String, version: u32 },

    #[error("key version retired: {keyring} v{version} — use REWRAP")]
    KeyVersionRetired { keyring: String, version: u32 },

    #[error("no active key in keyring: {0}")]
    NoActiveKey(String),

    #[error("invalid ciphertext format: {0}")]
    InvalidCiphertext(String),

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("algorithm mismatch: keyring is {expected}, operation requires {required}")]
    AlgorithmMismatch { expected: String, required: String },

    #[error("keyring disabled: {0}")]
    Disabled(String),

    #[error("operation denied by policy: {operation:?} on keyring {keyring}")]
    PolicyDenied {
        keyring: String,
        operation: crate::policy::KeyringOperation,
    },

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("convergent encryption requires CONVERGENT flag, keyring convergent=true, and CONTEXT")]
    ConvergentGuard,

    #[error("crypto error: {0}")]
    Crypto(#[from] shroudb_crypto::CryptoError),

    #[error("store error: {0}")]
    Store(String),

    #[error("internal error: {0}")]
    Internal(String),
}
