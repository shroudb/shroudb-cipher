//! Store-backed keyring management with in-memory cache.
//!
//! All crypto operations read from the in-memory DashMap cache.
//! Mutations write-through to the Store, then update the cache.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use shroudb_cipher_core::error::CipherError;
use shroudb_cipher_core::key_version::{KeyState, KeyVersion};
use shroudb_cipher_core::keyring::{Keyring, KeyringAlgorithm};
use shroudb_cipher_core::policy::KeyringPolicy;
use shroudb_store::Store;

use crate::crypto_ops;

const KEYRINGS_NAMESPACE: &str = "cipher.keyrings";

/// Options for creating a new keyring.
pub struct KeyringCreateOpts {
    pub rotation_days: u32,
    pub drain_days: u32,
    pub convergent: bool,
    pub policy: KeyringPolicy,
}

impl Default for KeyringCreateOpts {
    fn default() -> Self {
        Self {
            rotation_days: 90,
            drain_days: 30,
            convergent: false,
            policy: KeyringPolicy::default(),
        }
    }
}

/// Manages keyrings with a Store-backed persistence layer and in-memory cache.
pub struct KeyringManager<S: Store> {
    store: Arc<S>,
    cache: DashMap<String, Keyring>,
}

impl<S: Store> KeyringManager<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            cache: DashMap::new(),
        }
    }

    /// Initialize: create namespace and load all keyrings into cache.
    pub async fn init(&self) -> Result<(), CipherError> {
        // Create namespace if it doesn't exist
        match self
            .store
            .namespace_create(
                KEYRINGS_NAMESPACE,
                shroudb_store::NamespaceConfig::default(),
            )
            .await
        {
            Ok(()) => {}
            Err(shroudb_store::StoreError::NamespaceExists(_)) => {}
            Err(e) => return Err(CipherError::Store(e.to_string())),
        }

        // Load all keyrings into cache
        let mut cursor = None;
        loop {
            let page = self
                .store
                .list(KEYRINGS_NAMESPACE, None, cursor.as_deref(), 100)
                .await
                .map_err(|e| CipherError::Store(e.to_string()))?;

            for key in &page.keys {
                let entry = self
                    .store
                    .get(KEYRINGS_NAMESPACE, key, None)
                    .await
                    .map_err(|e| CipherError::Store(e.to_string()))?;
                let keyring: Keyring = serde_json::from_slice(&entry.value)
                    .map_err(|e| CipherError::Internal(format!("corrupt keyring data: {e}")))?;
                self.cache.insert(keyring.name.clone(), keyring);
            }

            if page.cursor.is_none() {
                break;
            }
            cursor = page.cursor;
        }

        let count = self.cache.len();
        if count > 0 {
            tracing::info!(count, "loaded keyrings from store");
        }

        Ok(())
    }

    /// Create a new keyring with the first Active key version.
    pub async fn create(
        &self,
        name: &str,
        algorithm: KeyringAlgorithm,
        opts: KeyringCreateOpts,
    ) -> Result<Keyring, CipherError> {
        validate_keyring_name(name)?;

        if self.cache.contains_key(name) {
            return Err(CipherError::KeyringExists(name.to_string()));
        }

        let now = unix_now();

        // Generate initial Active key
        let gkm = crypto_ops::generate_key_material(algorithm)?;
        let first_key = KeyVersion {
            version: 1,
            state: KeyState::Active,
            key_material: Some(hex::encode(gkm.private_key.as_bytes())),
            public_key: gkm.public_key.map(hex::encode),
            created_at: now,
            activated_at: Some(now),
            draining_since: None,
            retired_at: None,
        };

        let keyring = Keyring {
            name: name.to_string(),
            algorithm,
            rotation_days: opts.rotation_days,
            drain_days: opts.drain_days,
            convergent: opts.convergent,
            created_at: now,
            disabled: false,
            policy: opts.policy,
            key_versions: vec![first_key],
        };

        self.save(&keyring).await?;
        self.cache.insert(name.to_string(), keyring.clone());

        tracing::info!(
            keyring = name,
            algorithm = algorithm.wire_name(),
            "keyring created"
        );

        Ok(keyring)
    }

    /// Get a keyring by name from cache.
    pub fn get(&self, name: &str) -> Result<Keyring, CipherError> {
        self.cache
            .get(name)
            .map(|r| r.value().clone())
            .ok_or_else(|| CipherError::KeyringNotFound(name.to_string()))
    }

    /// List all keyring names from cache.
    pub fn list(&self) -> Vec<String> {
        self.cache.iter().map(|r| r.key().clone()).collect()
    }

    /// Update a keyring: applies a mutation function, saves to Store, updates cache.
    pub async fn update(
        &self,
        name: &str,
        f: impl FnOnce(&mut Keyring) -> Result<(), CipherError>,
    ) -> Result<Keyring, CipherError> {
        let mut keyring = self.get(name)?;
        f(&mut keyring)?;
        self.save(&keyring).await?;
        self.cache.insert(name.to_string(), keyring.clone());
        Ok(keyring)
    }

    /// Persist a keyring to the Store.
    async fn save(&self, keyring: &Keyring) -> Result<(), CipherError> {
        let value = serde_json::to_vec(keyring)
            .map_err(|e| CipherError::Internal(format!("serialization failed: {e}")))?;
        self.store
            .put(KEYRINGS_NAMESPACE, keyring.name.as_bytes(), &value, None)
            .await
            .map_err(|e| CipherError::Store(e.to_string()))?;
        Ok(())
    }

    /// Seed a keyring from config if it doesn't already exist.
    pub async fn seed_if_absent(
        &self,
        name: &str,
        algorithm: KeyringAlgorithm,
        opts: KeyringCreateOpts,
    ) -> Result<(), CipherError> {
        if self.cache.contains_key(name) {
            tracing::debug!(keyring = name, "keyring already exists, skipping seed");
            return Ok(());
        }
        self.create(name, algorithm, opts).await?;
        Ok(())
    }
}

fn validate_keyring_name(name: &str) -> Result<(), CipherError> {
    if name.is_empty() {
        return Err(CipherError::InvalidArgument(
            "keyring name cannot be empty".into(),
        ));
    }
    if name.len() > 255 {
        return Err(CipherError::InvalidArgument(
            "keyring name exceeds 255 characters".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(CipherError::InvalidArgument(
            "keyring name must contain only alphanumeric characters, hyphens, and underscores"
                .into(),
        ));
    }
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}

/// Find the active key version in a keyring.
pub fn find_active_key(keyring: &Keyring) -> Result<&KeyVersion, CipherError> {
    keyring
        .key_versions
        .iter()
        .find(|kv| kv.state == KeyState::Active)
        .ok_or_else(|| CipherError::NoActiveKey(keyring.name.clone()))
}

/// Find a specific key version in a keyring.
pub fn find_key_version(keyring: &Keyring, version: u32) -> Result<&KeyVersion, CipherError> {
    keyring
        .key_versions
        .iter()
        .find(|kv| kv.version == version)
        .ok_or_else(|| CipherError::KeyVersionNotFound {
            keyring: keyring.name.clone(),
            version,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_and_get_keyring() {
        let store = shroudb_storage::test_util::create_test_store("cipher-test").await;
        let mgr = KeyringManager::new(store);
        mgr.init().await.unwrap();

        let kr = mgr
            .create(
                "payments",
                KeyringAlgorithm::Aes256Gcm,
                KeyringCreateOpts::default(),
            )
            .await
            .unwrap();

        assert_eq!(kr.name, "payments");
        assert_eq!(kr.algorithm, KeyringAlgorithm::Aes256Gcm);
        assert_eq!(kr.key_versions.len(), 1);
        assert_eq!(kr.key_versions[0].state, KeyState::Active);
        assert_eq!(kr.key_versions[0].version, 1);

        let fetched = mgr.get("payments").unwrap();
        assert_eq!(fetched.name, "payments");
    }

    #[tokio::test]
    async fn create_duplicate_keyring_fails() {
        let store = shroudb_storage::test_util::create_test_store("cipher-test").await;
        let mgr = KeyringManager::new(store);
        mgr.init().await.unwrap();

        mgr.create(
            "payments",
            KeyringAlgorithm::Aes256Gcm,
            KeyringCreateOpts::default(),
        )
        .await
        .unwrap();
        let err = mgr
            .create(
                "payments",
                KeyringAlgorithm::Aes256Gcm,
                KeyringCreateOpts::default(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, CipherError::KeyringExists(_)));
    }

    #[tokio::test]
    async fn list_keyrings() {
        let store = shroudb_storage::test_util::create_test_store("cipher-test").await;
        let mgr = KeyringManager::new(store);
        mgr.init().await.unwrap();

        mgr.create(
            "a",
            KeyringAlgorithm::Aes256Gcm,
            KeyringCreateOpts::default(),
        )
        .await
        .unwrap();
        mgr.create("b", KeyringAlgorithm::Ed25519, KeyringCreateOpts::default())
            .await
            .unwrap();

        let mut names = mgr.list();
        names.sort();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn persistence_survives_reload() {
        let store = shroudb_storage::test_util::create_test_store("cipher-test").await;

        // Create keyring with first manager
        let mgr1 = KeyringManager::new(store.clone());
        mgr1.init().await.unwrap();
        mgr1.create(
            "payments",
            KeyringAlgorithm::Aes256Gcm,
            KeyringCreateOpts::default(),
        )
        .await
        .unwrap();

        // Create second manager — should load from Store
        let mgr2 = KeyringManager::new(store);
        mgr2.init().await.unwrap();
        let kr = mgr2.get("payments").unwrap();
        assert_eq!(kr.name, "payments");
        assert_eq!(kr.algorithm, KeyringAlgorithm::Aes256Gcm);
    }

    #[tokio::test]
    async fn seed_if_absent_creates_new() {
        let store = shroudb_storage::test_util::create_test_store("cipher-test").await;
        let mgr = KeyringManager::new(store);
        mgr.init().await.unwrap();

        mgr.seed_if_absent(
            "payments",
            KeyringAlgorithm::Aes256Gcm,
            KeyringCreateOpts::default(),
        )
        .await
        .unwrap();
        assert!(mgr.get("payments").is_ok());

        // Second call is a no-op
        mgr.seed_if_absent(
            "payments",
            KeyringAlgorithm::Aes256Gcm,
            KeyringCreateOpts::default(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn find_active_and_versioned_keys() {
        let store = shroudb_storage::test_util::create_test_store("cipher-test").await;
        let mgr = KeyringManager::new(store);
        mgr.init().await.unwrap();

        let kr = mgr
            .create(
                "test",
                KeyringAlgorithm::Aes256Gcm,
                KeyringCreateOpts::default(),
            )
            .await
            .unwrap();

        let active = find_active_key(&kr).unwrap();
        assert_eq!(active.version, 1);

        let v1 = find_key_version(&kr, 1).unwrap();
        assert_eq!(v1.state, KeyState::Active);

        assert!(find_key_version(&kr, 99).is_err());
    }
}
