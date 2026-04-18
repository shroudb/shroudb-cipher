use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("ephemeral port addr")
        .port()
}

fn find_binary() -> Option<PathBuf> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let candidates = [
        PathBuf::from(manifest_dir).join("../target/debug/shroudb-cipher"),
        PathBuf::from(manifest_dir).join("target/debug/shroudb-cipher"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

/// Test server configuration.
#[derive(Default)]
pub struct TestServerConfig {
    /// Auth tokens. Empty = auth disabled.
    pub tokens: Vec<TestToken>,
    /// Keyrings to seed on startup.
    pub keyrings: Vec<TestKeyring>,
}

pub struct TestToken {
    pub raw: String,
    pub tenant: String,
    pub actor: String,
    pub platform: bool,
    pub grants: Vec<TestGrant>,
}

pub struct TestGrant {
    pub namespace: String,
    pub scopes: Vec<String>,
}

pub struct TestKeyring {
    pub name: String,
    pub algorithm: String,
}

/// A running test server. Killed on drop.
pub struct TestServer {
    child: Child,
    pub tcp_addr: String,
    _data_dir: tempfile::TempDir,
    _config_dir: tempfile::TempDir,
}

impl TestServer {
    pub async fn start() -> Option<Self> {
        Self::start_with_config(TestServerConfig::default()).await
    }

    /// Start a cipher server in remote store mode, pointing to the given ShrouDB URI.
    pub async fn start_remote(remote_uri: &str) -> Option<Self> {
        let binary = find_binary()?;
        let tcp_port = free_port();
        let tcp_addr = format!("127.0.0.1:{tcp_port}");
        let data_dir = tempfile::tempdir().ok()?;
        let config_dir = tempfile::tempdir().ok()?;

        let config_path = config_dir.path().join("config.toml");
        let toml = generate_remote_config(&tcp_addr, remote_uri);
        std::fs::write(&config_path, toml).ok()?;

        let child = Command::new(&binary)
            .arg("--config")
            .arg(&config_path)
            .arg("--log-level")
            .arg("warn")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .ok()?;

        let mut server = Self {
            child,
            tcp_addr: tcp_addr.clone(),
            _data_dir: data_dir,
            _config_dir: config_dir,
        };

        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if tokio::time::Instant::now() > deadline {
                eprintln!("cipher remote server failed to start within 10s");
                return None;
            }
            if let Some(status) = server.child.try_wait().ok().flatten() {
                eprintln!("cipher remote server exited during startup: {status}");
                return None;
            }
            if let Ok(mut client) = shroudb_cipher_client::CipherClient::connect(&tcp_addr).await
                && client.health().await.is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Some(server)
    }

    pub async fn start_with_config(config: TestServerConfig) -> Option<Self> {
        let binary = find_binary()?;
        let tcp_port = free_port();
        let tcp_addr = format!("127.0.0.1:{tcp_port}");
        let data_dir = tempfile::tempdir().ok()?;
        let config_dir = tempfile::tempdir().ok()?;

        let config_path = config_dir.path().join("config.toml");
        let toml = generate_config(&tcp_addr, &config);
        std::fs::write(&config_path, toml).ok()?;

        let child = Command::new(&binary)
            .arg("--config")
            .arg(&config_path)
            .arg("--data-dir")
            .arg(data_dir.path())
            .arg("--log-level")
            .arg("warn")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .ok()?;

        let mut server = Self {
            child,
            tcp_addr: tcp_addr.clone(),
            _data_dir: data_dir,
            _config_dir: config_dir,
        };

        // Wait for the server to be ready by polling TCP health
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if tokio::time::Instant::now() > deadline {
                eprintln!("cipher server failed to start within 10s");
                return None;
            }
            if let Some(status) = server.child.try_wait().ok().flatten() {
                eprintln!("cipher server exited during startup: {status}");
                return None;
            }
            if let Ok(mut client) = shroudb_cipher_client::CipherClient::connect(&tcp_addr).await
                && client.health().await.is_ok()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Some(server)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A ShrouDB core server used as a remote store backend.
pub struct ShrouDBServer {
    child: Child,
    pub tcp_addr: String,
    _data_dir: tempfile::TempDir,
    _config_dir: tempfile::TempDir,
}

impl ShrouDBServer {
    pub async fn start() -> Option<Self> {
        let binary = find_shroudb_binary()?;
        let tcp_port = free_port();
        let tcp_addr = format!("127.0.0.1:{tcp_port}");
        let data_dir = tempfile::tempdir().ok()?;
        let config_dir = tempfile::tempdir().ok()?;

        let config_path = config_dir.path().join("config.toml");
        let toml = format!(
            r#"[server]
bind = "{tcp_addr}"

[storage]
data_dir = "{data_dir}"
"#,
            data_dir = data_dir.path().display()
        );
        std::fs::write(&config_path, toml).ok()?;

        let child = Command::new(&binary)
            .arg("--config")
            .arg(&config_path)
            .arg("--log-level")
            .arg("warn")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .ok()?;

        let mut server = Self {
            child,
            tcp_addr: tcp_addr.clone(),
            _data_dir: data_dir,
            _config_dir: config_dir,
        };

        // Wait for health
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if tokio::time::Instant::now() > deadline {
                eprintln!("shroudb server failed to start within 10s");
                return None;
            }
            if let Some(status) = server.child.try_wait().ok().flatten() {
                eprintln!("shroudb server exited during startup: {status}");
                return None;
            }
            if let Ok(mut client) = shroudb_cipher_client::CipherClient::connect(&tcp_addr).await {
                // Use raw PING via health-like check
                if client.health().await.is_ok() {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Some(server)
    }

    pub fn uri(&self) -> String {
        format!("shroudb://{}", self.tcp_addr)
    }
}

impl Drop for ShrouDBServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn find_shroudb_binary() -> Option<PathBuf> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    // Look in the shroudb core repo's target directory
    let candidates = [
        PathBuf::from(manifest_dir).join("../../shroudb/target/debug/shroudb"),
        PathBuf::from(manifest_dir).join("../../shroudb/target/release/shroudb"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

fn generate_remote_config(tcp_bind: &str, remote_uri: &str) -> String {
    format!(
        r#"[server]
tcp_bind = "{tcp_bind}"

[store]
mode = "remote"
uri = "{remote_uri}"

[audit]
mode = "disabled"
justification = "integration tests do not run a Chronicle process"

[policy]
mode = "disabled"
justification = "integration tests cover the cipher surface, not Sentry policy"
"#,
    )
}

fn generate_config(tcp_bind: &str, config: &TestServerConfig) -> String {
    let mut toml = format!(
        r#"[server]
tcp_bind = "{tcp_bind}"

[store]
mode = "embedded"

[audit]
mode = "disabled"
justification = "integration tests do not run a Chronicle process"

[policy]
mode = "disabled"
justification = "integration tests cover the cipher surface, not Sentry policy"
"#
    );

    if !config.tokens.is_empty() {
        toml.push_str("\n[auth]\nmethod = \"token\"\n\n");
        for token in &config.tokens {
            toml.push_str(&format!(
                "[auth.tokens.\"{}\"]\ntenant = \"{}\"\nactor = \"{}\"\nplatform = {}\n",
                token.raw, token.tenant, token.actor, token.platform
            ));
            if !token.grants.is_empty() {
                toml.push_str("grants = [\n");
                for grant in &token.grants {
                    let scopes: Vec<String> =
                        grant.scopes.iter().map(|s| format!("\"{s}\"")).collect();
                    toml.push_str(&format!(
                        "  {{ namespace = \"{}\", scopes = [{}] }},\n",
                        grant.namespace,
                        scopes.join(", ")
                    ));
                }
                toml.push_str("]\n");
            }
            toml.push('\n');
        }
    }

    for kr in &config.keyrings {
        toml.push_str(&format!(
            "\n[keyrings.{}]\nalgorithm = \"{}\"\n",
            kr.name, kr.algorithm
        ));
    }

    toml
}
