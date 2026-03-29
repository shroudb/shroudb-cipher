mod common;

use common::*;

// ═══════════════════════════════════════════════════════════════════════
// TCP: Full encryption lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_full_encrypt_decrypt_lifecycle() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_cipher_client::CipherClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    // Health
    client.health().await.expect("health check failed");

    // Create keyring
    client
        .keyring_create("payments", "aes-256-gcm", None, None, false)
        .await
        .expect("keyring create failed");

    // List keyrings
    let names = client.keyring_list().await.expect("keyring list failed");
    assert!(names.contains(&"payments".to_string()));

    // Encrypt
    let enc = client
        .encrypt("payments", "SGVsbG8gV29ybGQ=", None, None, false)
        .await
        .expect("encrypt failed");
    assert!(!enc.ciphertext.is_empty());
    assert_eq!(enc.key_version, 1);

    // Decrypt
    let dec = client
        .decrypt("payments", &enc.ciphertext, None)
        .await
        .expect("decrypt failed");
    assert_eq!(dec.plaintext, "SGVsbG8gV29ybGQ=");

    // Encrypt with context (AAD)
    let enc_ctx = client
        .encrypt("payments", "c2VjcmV0", Some("user-123"), None, false)
        .await
        .expect("encrypt with context failed");

    // Decrypt with correct context
    let dec_ctx = client
        .decrypt("payments", &enc_ctx.ciphertext, Some("user-123"))
        .await
        .expect("decrypt with context failed");
    assert_eq!(dec_ctx.plaintext, "c2VjcmV0");

    // Decrypt with wrong context fails
    let bad_ctx = client
        .decrypt("payments", &enc_ctx.ciphertext, Some("wrong"))
        .await;
    assert!(bad_ctx.is_err(), "wrong context should fail");

    // Key info
    let info = client.key_info("payments").await.expect("key info failed");
    assert_eq!(info["keyring"], "payments");
    assert_eq!(info["algorithm"], "aes-256-gcm");
    assert_eq!(info["active_version"], 1);
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Key rotation + rewrap
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_rotation_and_rewrap() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_cipher_client::CipherClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .keyring_create("rottest", "aes-256-gcm", None, None, false)
        .await
        .unwrap();

    // Encrypt with v1
    let enc = client
        .encrypt("rottest", "SGVsbG8=", None, None, false)
        .await
        .unwrap();
    assert_eq!(enc.key_version, 1);

    // Rotate (not due — should not rotate)
    let rot = client.rotate("rottest", false).await.unwrap();
    assert!(
        !rot.rotated,
        "key was just created, rotation should not be due"
    );

    // Force rotate
    let rot = client.rotate("rottest", true).await.unwrap();
    assert!(rot.rotated);
    assert_eq!(rot.key_version, 2);
    assert_eq!(rot.previous_version, Some(1));

    // Old ciphertext still decryptable (v1 key is now Draining)
    let dec = client
        .decrypt("rottest", &enc.ciphertext, None)
        .await
        .unwrap();
    assert_eq!(dec.plaintext, "SGVsbG8=");

    // Rewrap to v2
    let rewrapped = client
        .rewrap("rottest", &enc.ciphertext, None)
        .await
        .unwrap();
    assert_eq!(rewrapped.key_version, 2);

    // Rewrapped ciphertext decrypts to same plaintext
    let dec2 = client
        .decrypt("rottest", &rewrapped.ciphertext, None)
        .await
        .unwrap();
    assert_eq!(dec2.plaintext, "SGVsbG8=");

    // New encryption uses v2
    let enc2 = client
        .encrypt("rottest", "bmV3", None, None, false)
        .await
        .unwrap();
    assert_eq!(enc2.key_version, 2);
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Signing operations
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_sign_verify_ed25519() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_cipher_client::CipherClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .keyring_create("signing", "ed25519", None, None, false)
        .await
        .unwrap();

    let data = "SGVsbG8gV29ybGQ=";

    // Sign
    let sig = client.sign("signing", data).await.unwrap();
    assert!(!sig.signature.is_empty());
    assert_eq!(sig.key_version, 1);

    // Verify
    let valid = client
        .verify_signature("signing", data, &sig.signature)
        .await
        .unwrap();
    assert!(valid);

    // Verify with wrong data
    let invalid = client
        .verify_signature("signing", "d3Jvbmc=", &sig.signature)
        .await
        .unwrap();
    assert!(!invalid);

    // Verify with corrupted signature
    let invalid = client
        .verify_signature("signing", data, "deadbeef")
        .await
        .unwrap();
    assert!(!invalid);
}

#[tokio::test]
async fn tcp_sign_verify_hmac() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_cipher_client::CipherClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .keyring_create("hmac-key", "hmac-sha256", None, None, false)
        .await
        .unwrap();

    let data = "bWVzc2FnZQ==";
    let sig = client.sign("hmac-key", data).await.unwrap();
    let valid = client
        .verify_signature("hmac-key", data, &sig.signature)
        .await
        .unwrap();
    assert!(valid);
}

#[tokio::test]
async fn tcp_sign_verify_ecdsa() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_cipher_client::CipherClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .keyring_create("ecdsa-key", "ecdsa-p256", None, None, false)
        .await
        .unwrap();

    let data = "dGVzdA==";
    let sig = client.sign("ecdsa-key", data).await.unwrap();
    let valid = client
        .verify_signature("ecdsa-key", data, &sig.signature)
        .await
        .unwrap();
    assert!(valid);
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Envelope encryption (generate data key)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_generate_data_key() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_cipher_client::CipherClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .keyring_create("dek-test", "aes-256-gcm", None, None, false)
        .await
        .unwrap();

    let dek = client
        .generate_data_key("dek-test", Some(256))
        .await
        .unwrap();
    assert!(!dek.plaintext_key.is_empty());
    assert!(!dek.wrapped_key.is_empty());
    assert_eq!(dek.key_version, 1);

    // Unwrap the key via decrypt
    let unwrapped = client
        .decrypt("dek-test", &dek.wrapped_key, None)
        .await
        .unwrap();
    assert_eq!(unwrapped.plaintext, dek.plaintext_key);
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: ChaCha20-Poly1305
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_chacha20_encrypt_decrypt() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_cipher_client::CipherClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .keyring_create("cc-test", "chacha20-poly1305", None, None, false)
        .await
        .unwrap();

    let enc = client
        .encrypt("cc-test", "Y2hhY2hh", None, None, false)
        .await
        .unwrap();
    let dec = client
        .decrypt("cc-test", &enc.ciphertext, None)
        .await
        .unwrap();
    assert_eq!(dec.plaintext, "Y2hhY2hh");
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Convergent encryption
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_convergent_encryption() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_cipher_client::CipherClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .keyring_create("conv-test", "aes-256-gcm", None, None, true)
        .await
        .unwrap();

    // Same plaintext + context → same ciphertext
    let enc1 = client
        .encrypt("conv-test", "c2FtZQ==", Some("ctx"), None, true)
        .await
        .unwrap();
    let enc2 = client
        .encrypt("conv-test", "c2FtZQ==", Some("ctx"), None, true)
        .await
        .unwrap();
    assert_eq!(enc1.ciphertext, enc2.ciphertext);

    // Different context → different ciphertext
    let enc3 = client
        .encrypt("conv-test", "c2FtZQ==", Some("other"), None, true)
        .await
        .unwrap();
    assert_ne!(enc1.ciphertext, enc3.ciphertext);

    // Convergent without context should fail
    let err = client
        .encrypt("conv-test", "c2FtZQ==", None, None, true)
        .await;
    assert!(err.is_err(), "convergent without context should fail");
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Config-seeded keyrings
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_config_seeded_keyrings() {
    let config = TestServerConfig {
        keyrings: vec![
            TestKeyring {
                name: "pre-seeded".to_string(),
                algorithm: "aes-256-gcm".to_string(),
            },
            TestKeyring {
                name: "pre-signing".to_string(),
                algorithm: "ed25519".to_string(),
            },
        ],
        ..Default::default()
    };

    let server = TestServer::start_with_config(config)
        .await
        .expect("server failed to start");
    let mut client = shroudb_cipher_client::CipherClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    // Seeded keyrings should be usable immediately
    let enc = client
        .encrypt("pre-seeded", "dGVzdA==", None, None, false)
        .await
        .expect("encrypt on seeded keyring failed");
    let dec = client
        .decrypt("pre-seeded", &enc.ciphertext, None)
        .await
        .expect("decrypt on seeded keyring failed");
    assert_eq!(dec.plaintext, "dGVzdA==");

    let sig = client
        .sign("pre-signing", "dGVzdA==")
        .await
        .expect("sign on seeded keyring failed");
    let valid = client
        .verify_signature("pre-signing", "dGVzdA==", &sig.signature)
        .await
        .expect("verify on seeded keyring failed");
    assert!(valid);
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Error handling
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_error_responses() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_cipher_client::CipherClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    // Nonexistent keyring
    let err = client.encrypt("nope", "SGVsbG8=", None, None, false).await;
    assert!(err.is_err(), "nonexistent keyring should error");

    // Duplicate keyring
    client
        .keyring_create("dup", "aes-256-gcm", None, None, false)
        .await
        .unwrap();
    let err = client
        .keyring_create("dup", "aes-256-gcm", None, None, false)
        .await;
    assert!(err.is_err(), "duplicate keyring should error");

    // Wrong operation type (encrypt on signing keyring)
    client
        .keyring_create("signonly", "ed25519", None, None, false)
        .await
        .unwrap();
    let err = client
        .encrypt("signonly", "SGVsbG8=", None, None, false)
        .await;
    assert!(err.is_err(), "encrypt on signing keyring should error");

    // Sign on encryption keyring
    client
        .keyring_create("enconly", "aes-256-gcm", None, None, false)
        .await
        .unwrap();
    let err = client.sign("enconly", "SGVsbG8=").await;
    assert!(err.is_err(), "sign on encryption keyring should error");

    // Invalid base64
    let err = client
        .encrypt("enconly", "!!!invalid!!!", None, None, false)
        .await;
    assert!(err.is_err(), "invalid base64 should error");

    // Invalid ciphertext format
    let err = client
        .decrypt("enconly", "totally-not-ciphertext", None)
        .await;
    assert!(err.is_err(), "invalid ciphertext should error");
}

// ═══════════════════════════════════════════════════════════════════════
// TCP: Signature verification after rotation
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn tcp_verify_signature_after_rotation() {
    let server = TestServer::start().await.expect("server failed to start");
    let mut client = shroudb_cipher_client::CipherClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client
        .keyring_create("rotsig", "ed25519", None, None, false)
        .await
        .unwrap();

    // Sign with v1
    let sig = client.sign("rotsig", "ZGF0YQ==").await.unwrap();
    assert_eq!(sig.key_version, 1);

    // Rotate
    client.rotate("rotsig", true).await.unwrap();

    // Old signature should still verify (v1 is now Draining)
    let valid = client
        .verify_signature("rotsig", "ZGF0YQ==", &sig.signature)
        .await
        .unwrap();
    assert!(valid, "signature from draining key should still verify");

    // New signature uses v2
    let sig2 = client.sign("rotsig", "ZGF0YQ==").await.unwrap();
    assert_eq!(sig2.key_version, 2);
}

// ═══════════════════════════════════════════════════════════════════════
// ACL: Token-based auth
// ═══════════════════════════════════════════════════════════════════════

fn auth_server_config() -> TestServerConfig {
    TestServerConfig {
        tokens: vec![
            TestToken {
                raw: "admin-token".to_string(),
                tenant: "tenant-a".to_string(),
                actor: "admin".to_string(),
                platform: true,
                grants: vec![],
            },
            TestToken {
                raw: "app-token".to_string(),
                tenant: "tenant-a".to_string(),
                actor: "my-app".to_string(),
                platform: false,
                grants: vec![TestGrant {
                    namespace: "cipher.payments.*".to_string(),
                    scopes: vec!["read".to_string(), "write".to_string()],
                }],
            },
            TestToken {
                raw: "readonly-token".to_string(),
                tenant: "tenant-a".to_string(),
                actor: "reader".to_string(),
                platform: false,
                grants: vec![TestGrant {
                    namespace: "cipher.payments.*".to_string(),
                    scopes: vec!["read".to_string()],
                }],
            },
        ],
        keyrings: vec![],
    }
}

#[tokio::test]
async fn acl_unauthenticated_rejected_for_protected_commands() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("server failed to start");
    let mut client = shroudb_cipher_client::CipherClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    // Health is public — should work without auth
    client.health().await.expect("health should be public");

    // Keyring list is public
    let _ = client
        .keyring_list()
        .await
        .expect("keyring list should be public");

    // Keyring create requires Admin — should fail without auth
    let err = client
        .keyring_create("test", "aes-256-gcm", None, None, false)
        .await;
    assert!(err.is_err(), "unauthenticated keyring create should fail");

    // Encrypt requires Write — should fail without auth
    let err = client
        .encrypt("payments", "SGVsbG8=", None, None, false)
        .await;
    assert!(err.is_err(), "unauthenticated encrypt should fail");
}

#[tokio::test]
async fn acl_admin_token_full_access() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("server failed to start");
    let mut client = shroudb_cipher_client::CipherClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    // Authenticate as admin
    client.auth("admin-token").await.expect("admin auth failed");

    // Admin can create keyrings
    client
        .keyring_create("payments", "aes-256-gcm", None, None, false)
        .await
        .expect("admin should create keyrings");

    // Admin can encrypt/decrypt
    let enc = client
        .encrypt("payments", "SGVsbG8=", None, None, false)
        .await
        .expect("admin should encrypt");
    client
        .decrypt("payments", &enc.ciphertext, None)
        .await
        .expect("admin should decrypt");
}

#[tokio::test]
async fn acl_wrong_token_rejected() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("server failed to start");
    let mut client = shroudb_cipher_client::CipherClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    let err = client.auth("totally-wrong-token").await;
    assert!(err.is_err(), "wrong token should be rejected");
}

#[tokio::test]
async fn acl_non_admin_cannot_create_keyring() {
    let server = TestServer::start_with_config(auth_server_config())
        .await
        .expect("server failed to start");
    let mut client = shroudb_cipher_client::CipherClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.auth("app-token").await.expect("app auth failed");

    // Non-admin cannot create keyrings
    let err = client
        .keyring_create("test", "aes-256-gcm", None, None, false)
        .await;
    assert!(err.is_err(), "non-admin should not create keyrings");
}

#[tokio::test]
async fn acl_scoped_token_can_operate_on_granted_keyring() {
    let mut config = auth_server_config();
    config.keyrings.push(TestKeyring {
        name: "payments".to_string(),
        algorithm: "aes-256-gcm".to_string(),
    });

    let server = TestServer::start_with_config(config)
        .await
        .expect("server failed to start");
    let mut client = shroudb_cipher_client::CipherClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");

    client.auth("app-token").await.expect("app auth failed");

    // App token has cipher.payments.* with read+write — should work
    let enc = client
        .encrypt("payments", "SGVsbG8=", None, None, false)
        .await
        .expect("scoped token should encrypt on granted keyring");
    client
        .decrypt("payments", &enc.ciphertext, None)
        .await
        .expect("scoped token should decrypt on granted keyring");
}

#[tokio::test]
async fn acl_readonly_token_cannot_encrypt() {
    let mut config = auth_server_config();
    config.keyrings.push(TestKeyring {
        name: "payments".to_string(),
        algorithm: "aes-256-gcm".to_string(),
    });

    let server = TestServer::start_with_config(config)
        .await
        .expect("server failed to start");

    // First encrypt something as admin so we can test readonly decrypt
    let mut admin = shroudb_cipher_client::CipherClient::connect(&server.tcp_addr)
        .await
        .unwrap();
    admin.auth("admin-token").await.unwrap();
    let enc = admin
        .encrypt("payments", "SGVsbG8=", None, None, false)
        .await
        .unwrap();

    // Now connect as readonly
    let mut client = shroudb_cipher_client::CipherClient::connect(&server.tcp_addr)
        .await
        .expect("connect failed");
    client
        .auth("readonly-token")
        .await
        .expect("readonly auth failed");

    // Read-only can decrypt (Read scope)
    client
        .decrypt("payments", &enc.ciphertext, None)
        .await
        .expect("readonly should decrypt");

    // Read-only can get key info (Read scope)
    client
        .key_info("payments")
        .await
        .expect("readonly should get key info");

    // Read-only CANNOT encrypt (Write scope required)
    let err = client
        .encrypt("payments", "SGVsbG8=", None, None, false)
        .await;
    assert!(err.is_err(), "readonly should not encrypt");

    // Read-only CANNOT rotate (Write scope required)
    let err = client.rotate("payments", true).await;
    assert!(err.is_err(), "readonly should not rotate");
}
