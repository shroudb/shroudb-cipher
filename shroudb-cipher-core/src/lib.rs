//! Core types for ShrouDB Cipher.
//!
//! Keyring, key version lifecycle, ciphertext envelope format, and error types.

pub mod ciphertext;
pub mod error;
pub mod key_version;
pub mod keyring;
pub mod policy;

pub use ciphertext::CiphertextEnvelope;
pub use error::CipherError;
pub use key_version::{KeyState, KeyVersion};
pub use keyring::{Keyring, KeyringAlgorithm};
pub use policy::{KeyringOperation, KeyringPolicy};
