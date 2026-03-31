//! Typed Rust client library for Cipher.
//!
//! Provides a high-level async API for interacting with a Cipher server
//! over TCP (RESP3 wire protocol).

mod connection;
mod error;

pub use error::ClientError;

use connection::Connection;

/// Result from an encrypt or rewrap operation.
#[derive(Debug, Clone)]
pub struct EncryptResult {
    pub ciphertext: String,
    pub key_version: u32,
}

/// Result from a decrypt operation.
#[derive(Debug, Clone)]
pub struct DecryptResult {
    pub plaintext: String,
}

/// Result from a generate data key operation.
#[derive(Debug, Clone)]
pub struct DataKeyResult {
    pub plaintext_key: String,
    pub wrapped_key: String,
    pub key_version: u32,
}

/// Result from a sign operation.
#[derive(Debug, Clone)]
pub struct SignResult {
    pub signature: String,
    pub key_version: u32,
}

/// Result from a rotate operation.
#[derive(Debug, Clone)]
pub struct RotateResult {
    pub key_version: u32,
    pub previous_version: Option<u32>,
    pub rotated: bool,
}

/// A Cipher client connected via TCP.
pub struct CipherClient {
    conn: Connection,
}

impl CipherClient {
    /// Connect to a Cipher server.
    pub async fn connect(addr: &str) -> Result<Self, ClientError> {
        let conn = Connection::connect(addr).await?;
        Ok(Self { conn })
    }

    /// Authenticate this connection.
    pub async fn auth(&mut self, token: &str) -> Result<(), ClientError> {
        let resp = self.command(&["AUTH", token]).await?;
        check_status(&resp)
    }

    /// Health check.
    pub async fn health(&mut self) -> Result<(), ClientError> {
        let resp = self.command(&["HEALTH"]).await?;
        check_status(&resp)
    }

    // ── Keyring management ─────────────────────────────────────────

    /// Create a keyring.
    pub async fn keyring_create(
        &mut self,
        name: &str,
        algorithm: &str,
        rotation_days: Option<u32>,
        drain_days: Option<u32>,
        convergent: bool,
    ) -> Result<serde_json::Value, ClientError> {
        let mut args = vec!["KEYRING", "CREATE", name, algorithm];
        let rot_str;
        if let Some(rd) = rotation_days {
            rot_str = rd.to_string();
            args.push("ROTATION_DAYS");
            args.push(&rot_str);
        }
        let drain_str;
        if let Some(dd) = drain_days {
            drain_str = dd.to_string();
            args.push("DRAIN_DAYS");
            args.push(&drain_str);
        }
        if convergent {
            args.push("CONVERGENT");
        }
        let resp = self.command(&args).await?;
        check_status(&resp)?;
        Ok(resp)
    }

    /// List all keyring names.
    pub async fn keyring_list(&mut self) -> Result<Vec<String>, ClientError> {
        let resp = self.command(&["KEYRING", "LIST"]).await?;
        resp.as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .ok_or_else(|| ClientError::ResponseFormat("expected array".into()))
    }

    // ── Encryption operations ──────────────────────────────────────

    /// Encrypt plaintext.
    pub async fn encrypt(
        &mut self,
        keyring: &str,
        plaintext_b64: &str,
        context: Option<&str>,
        key_version: Option<u32>,
        convergent: bool,
    ) -> Result<EncryptResult, ClientError> {
        let mut args = vec!["ENCRYPT", keyring, plaintext_b64];
        let ctx_owned;
        if let Some(ctx) = context {
            ctx_owned = ctx.to_string();
            args.push("CONTEXT");
            args.push(&ctx_owned);
        }
        let kv_str;
        if let Some(kv) = key_version {
            kv_str = kv.to_string();
            args.push("KEY_VERSION");
            args.push(&kv_str);
        }
        if convergent {
            args.push("CONVERGENT");
        }
        let resp = self.command(&args).await?;
        check_status(&resp)?;
        Ok(EncryptResult {
            ciphertext: resp["ciphertext"]
                .as_str()
                .ok_or_else(|| ClientError::ResponseFormat("missing ciphertext".into()))?
                .to_string(),
            key_version: resp["key_version"]
                .as_u64()
                .ok_or_else(|| ClientError::ResponseFormat("missing key_version".into()))?
                as u32,
        })
    }

    /// Decrypt ciphertext.
    pub async fn decrypt(
        &mut self,
        keyring: &str,
        ciphertext: &str,
        context: Option<&str>,
    ) -> Result<DecryptResult, ClientError> {
        let mut args = vec!["DECRYPT", keyring, ciphertext];
        let ctx_owned;
        if let Some(ctx) = context {
            ctx_owned = ctx.to_string();
            args.push("CONTEXT");
            args.push(&ctx_owned);
        }
        let resp = self.command(&args).await?;
        check_status(&resp)?;
        Ok(DecryptResult {
            plaintext: resp["plaintext"]
                .as_str()
                .ok_or_else(|| ClientError::ResponseFormat("missing plaintext".into()))?
                .to_string(),
        })
    }

    /// Rewrap ciphertext under the current active key.
    pub async fn rewrap(
        &mut self,
        keyring: &str,
        ciphertext: &str,
        context: Option<&str>,
    ) -> Result<EncryptResult, ClientError> {
        let mut args = vec!["REWRAP", keyring, ciphertext];
        let ctx_owned;
        if let Some(ctx) = context {
            ctx_owned = ctx.to_string();
            args.push("CONTEXT");
            args.push(&ctx_owned);
        }
        let resp = self.command(&args).await?;
        check_status(&resp)?;
        Ok(EncryptResult {
            ciphertext: resp["ciphertext"]
                .as_str()
                .ok_or_else(|| ClientError::ResponseFormat("missing ciphertext".into()))?
                .to_string(),
            key_version: resp["key_version"]
                .as_u64()
                .ok_or_else(|| ClientError::ResponseFormat("missing key_version".into()))?
                as u32,
        })
    }

    /// Generate a data encryption key (envelope encryption).
    pub async fn generate_data_key(
        &mut self,
        keyring: &str,
        bits: Option<u32>,
    ) -> Result<DataKeyResult, ClientError> {
        let mut args = vec!["GENERATE_DATA_KEY", keyring];
        let bits_str;
        if let Some(b) = bits {
            bits_str = b.to_string();
            args.push("BITS");
            args.push(&bits_str);
        }
        let resp = self.command(&args).await?;
        check_status(&resp)?;
        Ok(DataKeyResult {
            plaintext_key: resp["plaintext_key"]
                .as_str()
                .ok_or_else(|| ClientError::ResponseFormat("missing plaintext_key".into()))?
                .to_string(),
            wrapped_key: resp["wrapped_key"]
                .as_str()
                .ok_or_else(|| ClientError::ResponseFormat("missing wrapped_key".into()))?
                .to_string(),
            key_version: resp["key_version"]
                .as_u64()
                .ok_or_else(|| ClientError::ResponseFormat("missing key_version".into()))?
                as u32,
        })
    }

    /// Sign data.
    pub async fn sign(&mut self, keyring: &str, data_b64: &str) -> Result<SignResult, ClientError> {
        let resp = self.command(&["SIGN", keyring, data_b64]).await?;
        check_status(&resp)?;
        Ok(SignResult {
            signature: resp["signature"]
                .as_str()
                .ok_or_else(|| ClientError::ResponseFormat("missing signature".into()))?
                .to_string(),
            key_version: resp["key_version"]
                .as_u64()
                .ok_or_else(|| ClientError::ResponseFormat("missing key_version".into()))?
                as u32,
        })
    }

    /// Verify a signature.
    pub async fn verify_signature(
        &mut self,
        keyring: &str,
        data_b64: &str,
        signature_hex: &str,
    ) -> Result<bool, ClientError> {
        let resp = self
            .command(&["VERIFY_SIGNATURE", keyring, data_b64, signature_hex])
            .await?;
        check_status(&resp)?;
        resp["valid"]
            .as_bool()
            .ok_or_else(|| ClientError::ResponseFormat("missing valid field".into()))
    }

    /// Rotate a keyring.
    pub async fn rotate(
        &mut self,
        keyring: &str,
        force: bool,
    ) -> Result<RotateResult, ClientError> {
        let mut args = vec!["ROTATE", keyring];
        if force {
            args.push("FORCE");
        }
        let resp = self.command(&args).await?;
        check_status(&resp)?;
        Ok(RotateResult {
            key_version: resp["key_version"]
                .as_u64()
                .ok_or_else(|| ClientError::ResponseFormat("missing key_version".into()))?
                as u32,
            previous_version: resp["previous_version"].as_u64().map(|v| v as u32),
            rotated: resp["rotated"]
                .as_bool()
                .ok_or_else(|| ClientError::ResponseFormat("missing rotated field".into()))?,
        })
    }

    /// Get keyring info.
    pub async fn key_info(&mut self, keyring: &str) -> Result<serde_json::Value, ClientError> {
        self.command(&["KEY_INFO", keyring]).await
    }

    // ── Internal ────────────────────────────────────────────────────

    async fn command(&mut self, args: &[&str]) -> Result<serde_json::Value, ClientError> {
        self.conn.send_command(args).await
    }
}

fn check_status(resp: &serde_json::Value) -> Result<(), ClientError> {
    if let Some(status) = resp.get("status").and_then(|s| s.as_str())
        && status == "ok"
    {
        return Ok(());
    }
    if resp.is_array() || resp.is_object() {
        return Ok(());
    }
    Err(ClientError::ResponseFormat("unexpected response".into()))
}
