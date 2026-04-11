mod config;
mod tcp;

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use shroudb_cipher_core::keyring::KeyringAlgorithm;
use shroudb_cipher_engine::engine::{CipherConfig, CipherEngine};
use shroudb_cipher_engine::keyring_manager::KeyringCreateOpts;
use shroudb_cipher_engine::scheduler;
use shroudb_store::Store;

use crate::config::{CipherServerConfig, load_config};

#[derive(Parser)]
#[command(
    name = "shroudb-cipher",
    about = "Cipher encryption-as-a-service engine"
)]
struct Cli {
    /// Path to config file.
    #[arg(short, long, env = "CIPHER_CONFIG")]
    config: Option<String>,

    /// Data directory (overrides config).
    #[arg(long, env = "CIPHER_DATA_DIR")]
    data_dir: Option<String>,

    /// TCP bind address (overrides config).
    #[arg(long, env = "CIPHER_TCP_BIND")]
    tcp_bind: Option<String>,

    /// Log level.
    #[arg(long, env = "CIPHER_LOG_LEVEL", default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load config
    let mut cfg = load_config(cli.config.as_deref())?;

    // Resolve log level
    let log_level = if cli.log_level != "info" {
        cli.log_level.clone()
    } else {
        cfg.server
            .log_level
            .take()
            .unwrap_or_else(|| "info".to_string())
    };

    // Bootstrap: logging + core dumps + key source
    let key_source = shroudb_server_bootstrap::bootstrap(&log_level);

    // CLI overrides
    if let Some(ref dir) = cli.data_dir {
        cfg.store.data_dir = dir.into();
    }
    if let Some(ref bind) = cli.tcp_bind {
        cfg.server.tcp_bind = bind.parse().context("invalid TCP bind address")?;
    }

    // Store: embedded or remote
    match cfg.store.mode.as_str() {
        "embedded" => {
            let storage =
                shroudb_server_bootstrap::open_storage(&cfg.store.data_dir, key_source.as_ref())
                    .await
                    .context("failed to open storage engine")?;
            let store = Arc::new(shroudb_storage::EmbeddedStore::new(storage, "cipher"));
            run_server(cfg, store).await
        }
        "remote" => {
            let uri = cfg
                .store
                .uri
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("remote mode requires store.uri"))?;
            tracing::info!(uri, "connecting to remote store");
            let store = Arc::new(
                shroudb_client::RemoteStore::connect(uri)
                    .await
                    .context("failed to connect to remote store")?,
            );
            run_server(cfg, store).await
        }
        other => anyhow::bail!("unknown store mode: {other}"),
    }
}

async fn run_server<S: Store + 'static>(
    cfg: CipherServerConfig,
    store: Arc<S>,
) -> anyhow::Result<()> {
    // Cipher engine
    let cipher_config = CipherConfig {
        default_rotation_days: cfg.engine.default_rotation_days,
        default_drain_days: cfg.engine.default_drain_days,
        scheduler_interval_secs: cfg.engine.scheduler_interval_secs,
    };
    let engine = Arc::new(
        CipherEngine::new(store, cipher_config, None, None)
            .await
            .context("failed to initialize cipher engine")?,
    );

    // Seed keyrings from config
    for (name, kr_cfg) in &cfg.keyrings {
        let algorithm: KeyringAlgorithm = kr_cfg
            .algorithm
            .parse()
            .map_err(|e: String| anyhow::anyhow!("keyring '{name}': {e}"))?;
        engine
            .keyring_manager()
            .seed_if_absent(
                name,
                algorithm,
                KeyringCreateOpts {
                    rotation_days: kr_cfg
                        .rotation_days
                        .unwrap_or(cfg.engine.default_rotation_days),
                    drain_days: kr_cfg.drain_days.unwrap_or(cfg.engine.default_drain_days),
                    convergent: kr_cfg.convergent,
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("failed to seed keyring '{name}'"))?;
    }

    // Shutdown signal
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Start scheduler
    let _scheduler_handle = scheduler::start_scheduler(
        engine.clone(),
        cfg.engine.scheduler_interval_secs,
        shutdown_rx.clone(),
    );

    // Auth
    let token_validator = cfg.auth.build_validator();
    if token_validator.is_some() {
        tracing::info!(tokens = cfg.auth.tokens.len(), "token-based auth enabled");
    }

    // TCP server
    let tcp_listener = tokio::net::TcpListener::bind(cfg.server.tcp_bind)
        .await
        .context("failed to bind TCP")?;

    let tls_acceptor = cfg
        .server
        .tls
        .as_ref()
        .map(shroudb_server_tcp::build_tls_acceptor)
        .transpose()
        .context("failed to build TLS acceptor")?;

    let tcp_engine = engine.clone();
    let tcp_validator = token_validator.clone();
    let tcp_shutdown = shutdown_rx.clone();
    let tcp_handle = tokio::spawn(async move {
        tcp::run_tcp(
            tcp_listener,
            tcp_engine,
            tcp_validator,
            tcp_shutdown,
            tls_acceptor,
        )
        .await;
    });

    // Banner
    shroudb_server_bootstrap::print_banner(
        "Cipher",
        env!("CARGO_PKG_VERSION"),
        &cfg.server.tcp_bind.to_string(),
        &cfg.store.data_dir,
    );

    // Wait for shutdown
    shroudb_server_bootstrap::wait_for_shutdown(shutdown_tx).await?;
    let _ = tcp_handle.await;

    Ok(())
}
