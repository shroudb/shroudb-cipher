//! Store-backed encryption-as-a-service engine.
//!
//! This is the core Cipher engine — keyring lifecycle management, cryptographic
//! operations (encrypt, decrypt, sign, verify), and automatic key rotation.
//! Consumes the ShrouDB Store trait for persistence.

pub mod crypto_ops;
pub mod engine;
pub mod keyring_manager;
pub mod scheduler;

#[cfg(test)]
mod test_support;
