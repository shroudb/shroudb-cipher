//! Background scheduler for automatic key rotation and retirement.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use shroudb_cipher_core::key_version::KeyState;
use shroudb_store::Store;
use tokio::sync::watch;
use zeroize::Zeroize;

use crate::engine::CipherEngine;
use crate::keyring_manager::find_active_key;

/// Start the background scheduler that auto-rotates and auto-retires keys.
pub fn start_scheduler<S: Store + 'static>(
    engine: Arc<CipherEngine<S>>,
    interval_secs: u64,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(interval_secs)) => {
                    if let Err(e) = run_cycle(&engine).await {
                        tracing::warn!(error = %e, "scheduler cycle failed");
                    }
                }
                _ = shutdown.changed() => {
                    tracing::info!("cipher scheduler shutting down");
                    break;
                }
            }
        }
    })
}

async fn run_cycle<S: Store>(engine: &CipherEngine<S>) -> Result<(), String> {
    let names = engine.keyring_list();
    let now = unix_now();

    for name in names {
        let keyring = match engine.keyring_manager().get(&name) {
            Ok(kr) => kr,
            Err(e) => {
                tracing::warn!(keyring = name, error = %e, "failed to load keyring in scheduler");
                continue;
            }
        };

        if keyring.disabled {
            continue;
        }

        // Auto-rotate: if active key exceeds rotation_days
        if let Ok(active) = find_active_key(&keyring) {
            let age_days = active
                .activated_at
                .map(|at| now.saturating_sub(at) / 86400)
                .unwrap_or(0);

            if age_days >= keyring.rotation_days as u64 {
                match engine.rotate(&name, true, false, None).await {
                    Ok(result) => {
                        tracing::info!(
                            keyring = name,
                            new_version = result.key_version,
                            "auto-rotated key"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(keyring = name, error = %e, "auto-rotation failed");
                    }
                }
            }
        }

        // Auto-retire: if any draining key exceeds drain_days
        let should_retire: Vec<u32> = keyring
            .key_versions
            .iter()
            .filter(|kv| kv.state == KeyState::Draining)
            .filter(|kv| {
                kv.draining_since
                    .map(|ds| (now.saturating_sub(ds)) / 86400 >= keyring.drain_days as u64)
                    .unwrap_or(false)
            })
            .map(|kv| kv.version)
            .collect();

        if !should_retire.is_empty() {
            let result = engine
                .keyring_manager()
                .update(&name, |kr| {
                    for kv in &mut kr.key_versions {
                        if should_retire.contains(&kv.version) && kv.state == KeyState::Draining {
                            kv.state = KeyState::Retired;
                            kv.retired_at = Some(now);
                            // Zeroize key material before dropping
                            if let Some(ref mut km) = kv.key_material {
                                km.zeroize();
                            }
                            kv.key_material = None;
                            tracing::info!(
                                keyring = kr.name,
                                version = kv.version,
                                "auto-retired key version"
                            );
                        }
                    }
                    Ok(())
                })
                .await;

            if let Err(e) = result {
                tracing::warn!(keyring = name, error = %e, "auto-retirement failed");
            }
        }
    }

    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}
