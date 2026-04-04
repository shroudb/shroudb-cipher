use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;
use shroudb_acl::ServerAuthConfig;

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
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_tcp_bind")]
    pub tcp_bind: SocketAddr,
    #[serde(default)]
    pub log_level: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            tcp_bind: default_tcp_bind(),
            log_level: None,
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
