use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;
use shroudb_acl::ServerAuthConfig;
use shroudb_engine_bootstrap::{AuditConfig, PolicyConfig};

#[derive(Debug, Deserialize, Default)]
pub struct CipherServerConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub engine: EngineConfig,
    #[serde(default)]
    pub auth: ServerAuthConfig,
    #[serde(default)]
    pub keyrings: HashMap<String, KeyringConfig>,
    /// Audit (Chronicle) capability slot. Absent = defaults to embedded
    /// (engine-bootstrap default) — an in-process Chronicle on the
    /// shared storage. Operators opt out explicitly via
    /// `[audit] mode = "disabled" justification = "..."`.
    #[serde(default)]
    pub audit: Option<AuditConfig>,
    /// Policy (Sentry) capability slot. Absent = defaults to embedded
    /// (engine-bootstrap default) — an in-process Sentry on the shared
    /// storage. Same explicit-disable contract as `audit`.
    #[serde(default)]
    pub policy: Option<PolicyConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_tcp_bind")]
    pub tcp_bind: SocketAddr,
    #[serde(default)]
    pub log_level: Option<String>,
    #[serde(default)]
    pub tls: Option<shroudb_server_tcp::TlsConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            tcp_bind: default_tcp_bind(),
            log_level: None,
            tls: None,
        }
    }
}

fn default_tcp_bind() -> SocketAddr {
    "0.0.0.0:6599".parse().expect("valid hardcoded address")
}

#[derive(Debug, Deserialize)]
pub struct StoreConfig {
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default)]
    pub uri: Option<String>,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            data_dir: default_data_dir(),
            uri: None,
        }
    }
}

fn default_mode() -> String {
    "embedded".to_string()
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./cipher-data")
}

#[derive(Debug, Deserialize)]
pub struct EngineConfig {
    #[serde(default = "default_rotation_days")]
    pub default_rotation_days: u32,
    #[serde(default = "default_drain_days")]
    pub default_drain_days: u32,
    #[serde(default = "default_scheduler_interval")]
    pub scheduler_interval_secs: u64,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            default_rotation_days: default_rotation_days(),
            default_drain_days: default_drain_days(),
            scheduler_interval_secs: default_scheduler_interval(),
        }
    }
}

fn default_rotation_days() -> u32 {
    90
}

fn default_drain_days() -> u32 {
    30
}

fn default_scheduler_interval() -> u64 {
    3600
}

/// Config-defined keyring to seed on startup.
#[derive(Debug, Clone, Deserialize)]
pub struct KeyringConfig {
    pub algorithm: String,
    #[serde(default)]
    pub rotation_days: Option<u32>,
    #[serde(default)]
    pub drain_days: Option<u32>,
    #[serde(default)]
    pub convergent: bool,
}

/// Load config from a TOML file, or return defaults.
pub fn load_config(path: Option<&str>) -> anyhow::Result<CipherServerConfig> {
    match path {
        Some(p) => {
            let raw = std::fs::read_to_string(p)
                .map_err(|e| anyhow::anyhow!("failed to read config: {e}"))?;
            let config: CipherServerConfig =
                toml::from_str(&raw).map_err(|e| anyhow::anyhow!("failed to parse config: {e}"))?;
            Ok(config)
        }
        None => Ok(CipherServerConfig::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_to_embedded_mode() {
        let cfg = CipherServerConfig::default();
        assert_eq!(cfg.store.mode, "embedded");
        assert!(cfg.store.uri.is_none());
    }

    #[test]
    fn config_parses_remote_mode_with_uri() {
        let toml = r#"
[store]
mode = "remote"
uri = "shroudb://token@127.0.0.1:6399"
"#;
        let cfg: CipherServerConfig = toml::from_str(toml).expect("parse failed");
        assert_eq!(cfg.store.mode, "remote");
        assert_eq!(
            cfg.store.uri.as_deref(),
            Some("shroudb://token@127.0.0.1:6399")
        );
    }

    /// Former DEBT-Fcipher-7 (AUDIT_2026-04-17), now closed: the server
    /// config carries `[audit]` and `[policy]` sections dispatched via
    /// `shroudb-engine-bootstrap`. Running `shroudb-cipher` standalone
    /// requires an explicit audit+policy choice at startup (no silent
    /// `None` hardcode remains in `main.rs`).
    #[test]
    fn cipher_server_config_wires_audit_and_policy_sections() {
        let toml = r#"
[audit]
mode = "remote"
addr = "127.0.0.1:6899"
auth_token = "test"

[policy]
mode = "remote"
addr = "127.0.0.1:6499"
auth_token = "test"
"#;
        let cfg: CipherServerConfig = toml::from_str(toml).expect("config parse");
        let audit = cfg.audit.expect("[audit] must deserialize");
        assert_eq!(audit.mode, "remote");
        assert_eq!(audit.addr.as_deref(), Some("127.0.0.1:6899"));
        let policy = cfg.policy.expect("[policy] must deserialize");
        assert_eq!(policy.mode, "remote");
        assert_eq!(policy.addr.as_deref(), Some("127.0.0.1:6499"));
    }

    #[test]
    fn cipher_server_config_accepts_embedded_audit_and_policy() {
        let toml = r#"
[audit]
mode = "embedded"

[policy]
mode = "embedded"
"#;
        let cfg: CipherServerConfig = toml::from_str(toml).expect("config parse");
        assert_eq!(cfg.audit.unwrap().mode, "embedded");
        assert_eq!(cfg.policy.unwrap().mode, "embedded");
    }

    /// When `[audit]` and `[policy]` are omitted, the server falls
    /// through to engine-bootstrap's embedded default. We verify this
    /// here at the config layer: the bare `Option<…>` is `None`, and
    /// `unwrap_or_default()` (what `main.rs` does) yields a config with
    /// `mode = "embedded"`.
    #[test]
    fn cipher_server_config_absent_audit_and_policy_default_to_embedded() {
        let toml = r#"
[store]
mode = "embedded"
"#;
        let cfg: CipherServerConfig = toml::from_str(toml).expect("config parse");
        assert!(
            cfg.audit.is_none(),
            "omitted [audit] must deserialize as None"
        );
        assert!(
            cfg.policy.is_none(),
            "omitted [policy] must deserialize as None"
        );
        // The server collapses None into the engine-bootstrap default,
        // which is mode = "embedded" per `AuditConfig`/`PolicyConfig`.
        let audit = cfg.audit.clone().unwrap_or_default();
        let policy = cfg.policy.clone().unwrap_or_default();
        assert_eq!(audit.mode, "embedded");
        assert_eq!(policy.mode, "embedded");
    }

    #[test]
    fn cipher_server_config_accepts_disabled_with_justification() {
        let toml = r#"
[audit]
mode = "disabled"
justification = "air-gapped deployment"

[policy]
mode = "disabled"
justification = "ABAC enforced upstream at LB layer"
"#;
        let cfg: CipherServerConfig = toml::from_str(toml).expect("config parse");
        let audit = cfg.audit.unwrap();
        assert_eq!(audit.mode, "disabled");
        assert!(audit.justification.unwrap().contains("air-gapped"));
        let policy = cfg.policy.unwrap();
        assert_eq!(policy.mode, "disabled");
        assert!(policy.justification.unwrap().contains("ABAC"));
    }

    #[test]
    fn config_parses_remote_mode_tls_uri() {
        let toml = r#"
[store]
mode = "remote"
uri = "shroudb+tls://token@store.example.com:6399"
"#;
        let cfg: CipherServerConfig = toml::from_str(toml).expect("parse failed");
        assert_eq!(cfg.store.mode, "remote");
        assert_eq!(
            cfg.store.uri.as_deref(),
            Some("shroudb+tls://token@store.example.com:6399")
        );
    }
}
