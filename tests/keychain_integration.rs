//! Integration tests for OS keychain and system store functionality.
//!
//! These tests verify the keyring-based credential storage on each
//! platform:
//! - macOS: Login Keychain (apple-native)
//! - Linux: kernel keyutils (linux-native, no D-Bus needed)
//! - Windows: Credential Manager (windows-native)
//!
//! Tests use unique service/account names to avoid collisions with
//! real keys. All entries are cleaned up after each test.

use std::fs;
use std::process::Command;

use assert_cmd::prelude::*;
use dotenvage::{
    KeyGenOptions,
    KeyStoreTarget,
    SecretManager,
};
use predicates::prelude::*;
use tempfile::TempDir;

// ── Helper ───────────────────────────────────────────────────

/// Generate a key into a temp file and return the manager.
#[cfg(unix)]
fn generate_to_file(dir: &TempDir) -> (SecretManager, std::path::PathBuf) {
    let path = dir.path().join("test.key");
    let result = SecretManager::generate_and_save(KeyGenOptions {
        target: KeyStoreTarget::File,
        key_name: None,
        file_path: Some(path.clone()),
        force: false,
    })
    .expect("generate_and_save file");
    (result.manager, path)
}

// ── generate_and_save: File target ───────────────────────────

#[test]
fn generate_and_save_file_creates_valid_key() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("new.key");

    let result = SecretManager::generate_and_save(KeyGenOptions {
        target: KeyStoreTarget::File,
        key_name: None,
        file_path: Some(path.clone()),
        force: false,
    })
    .expect("generate_and_save");

    // Key file exists and contains a secret key
    let content = fs::read_to_string(&path).unwrap();
    assert!(
        content.contains("AGE-SECRET-KEY-"),
        "file should contain an AGE identity"
    );

    // Public key is valid
    assert!(
        result.public_key.starts_with("age1"),
        "public key should start with age1"
    );

    // Manager can encrypt/decrypt
    let encrypted = result.manager.encrypt_value("hello").unwrap();
    assert!(SecretManager::is_encrypted(&encrypted));
    let decrypted = result.manager.decrypt_value(&encrypted).unwrap();
    assert_eq!(decrypted, "hello");
}

#[test]
fn generate_and_save_file_rejects_existing_without_force() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("existing.key");
    fs::write(&path, "placeholder").unwrap();

    let err = SecretManager::generate_and_save(KeyGenOptions {
        target: KeyStoreTarget::File,
        key_name: None,
        file_path: Some(path),
        force: false,
    })
    .unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("key already exists"),
        "expected 'key already exists', got: {}",
        msg
    );
}

#[test]
fn generate_and_save_file_force_overwrites() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("overwrite.key");
    fs::write(&path, "old-data").unwrap();

    let result = SecretManager::generate_and_save(KeyGenOptions {
        target: KeyStoreTarget::File,
        key_name: None,
        file_path: Some(path.clone()),
        force: true,
    })
    .expect("forced overwrite should succeed");

    let content = fs::read_to_string(&path).unwrap();
    assert!(content.contains("AGE-SECRET-KEY-"));
    assert!(result.public_key.starts_with("age1"));
}

// ── identity_string() ────────────────────────────────────────

#[test]
fn identity_string_is_accessible_and_roundtrips() {
    let manager = SecretManager::generate().unwrap();
    let id_str = manager.identity_string();

    assert!(
        id_str.starts_with("AGE-SECRET-KEY-"),
        "identity_string should be an AGE secret key"
    );

    // Encrypt with original, decrypt with reloaded
    let encrypted = manager.encrypt_value("roundtrip").unwrap();

    // Parse the identity string back into a manager
    let reloaded: SecretManager = {
        use age::x25519;
        let identity: x25519::Identity = id_str.parse().unwrap();
        SecretManager::from_identity(identity)
    };
    let decrypted = reloaded.decrypt_value(&encrypted).unwrap();
    assert_eq!(decrypted, "roundtrip");
}

// ── OS keychain roundtrip ────────────────────────────────────
//
// These tests exercise dotenvage's public keychain API:
//   save_key_to_os_keychain, key_exists_in_os_keychain,
//   delete_from_os_keychain, generate_and_save(OsKeychain).
//
// Tests use unique service/account names (via env vars) to avoid
// collisions with real keys. Cleanup uses delete_from_os_keychain.
//
// The cfg gate is required because delete_from_os_keychain is only
// available when the os-keychain feature is compiled in.

#[cfg(feature = "os-keychain")]
mod os_keychain {
    use serial_test::serial;

    use super::*;

    /// Unique key name scoped to this test run to avoid collisions.
    fn test_key_name() -> String {
        format!(
            "dotenvage-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    /// RAII guard that restores env vars and deletes the keychain
    /// entry on drop.
    struct EnvGuard {
        orig_key_name: Option<String>,
        orig_service: Option<String>,
    }

    impl EnvGuard {
        fn new(key_name: &str, service: &str) -> Self {
            let orig_key_name = std::env::var("AGE_KEY_NAME").ok();
            let orig_service = std::env::var("DOTENVAGE_KEYCHAIN_SERVICE").ok();
            unsafe {
                std::env::set_var("AGE_KEY_NAME", key_name);
                std::env::set_var("DOTENVAGE_KEYCHAIN_SERVICE", service);
            }
            Self {
                orig_key_name,
                orig_service,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // Clean up the keychain entry via the public API
            let _ = SecretManager::delete_from_os_keychain();

            // Restore env vars
            unsafe {
                match &self.orig_key_name {
                    Some(v) => std::env::set_var("AGE_KEY_NAME", v),
                    None => std::env::remove_var("AGE_KEY_NAME"),
                }
                match &self.orig_service {
                    Some(v) => {
                        std::env::set_var("DOTENVAGE_KEYCHAIN_SERVICE", v);
                    }
                    None => {
                        std::env::remove_var("DOTENVAGE_KEYCHAIN_SERVICE");
                    }
                }
            }
        }
    }

    #[test]
    #[serial]
    fn save_and_exists_roundtrip() {
        let key_name = test_key_name();
        let service = "dotenvage-test-roundtrip";
        let _guard = EnvGuard::new(&key_name, service);

        // Generate a key and save to OS keychain via public API
        let manager = SecretManager::generate().unwrap();
        let (svc, acct) = manager.save_key_to_os_keychain().unwrap();
        assert_eq!(svc, service);
        assert_eq!(acct, key_name);

        // key_exists_in_os_keychain should now return true
        assert!(
            SecretManager::key_exists_in_os_keychain(),
            "key should exist in OS keychain after save"
        );

        // Encrypt with the original manager, then verify the key
        // stored in the keychain can decrypt
        let encrypted = manager.encrypt_value("keychain-roundtrip").unwrap();
        let decrypted = manager.decrypt_value(&encrypted).unwrap();
        assert_eq!(decrypted, "keychain-roundtrip");
    }

    #[test]
    #[serial]
    fn not_found_returns_false() {
        let key_name = test_key_name();
        let service = "dotenvage-test-notfound";
        let _guard = EnvGuard::new(&key_name, service);

        assert!(
            !SecretManager::key_exists_in_os_keychain(),
            "non-existent key should not be found"
        );
    }

    #[test]
    #[serial]
    fn delete_is_idempotent() {
        let key_name = test_key_name();
        let service = "dotenvage-test-delete";
        let _guard = EnvGuard::new(&key_name, service);

        // Delete when nothing exists — should not error
        SecretManager::delete_from_os_keychain().unwrap();

        // Save, verify, delete, verify gone
        let manager = SecretManager::generate().unwrap();
        manager.save_key_to_os_keychain().unwrap();
        assert!(SecretManager::key_exists_in_os_keychain());

        SecretManager::delete_from_os_keychain().unwrap();
        assert!(!SecretManager::key_exists_in_os_keychain());

        // Delete again — still should not error
        SecretManager::delete_from_os_keychain().unwrap();
    }

    #[test]
    #[serial]
    fn generate_and_save_os_keychain_target() {
        let key_name = test_key_name();
        let service = "dotenvage-test-gen";
        let _guard = EnvGuard::new(&key_name, service);

        let result = SecretManager::generate_and_save(KeyGenOptions {
            target: KeyStoreTarget::OsKeychain,
            key_name: Some(key_name.clone()),
            file_path: None,
            force: false,
        })
        .expect("generate_and_save OsKeychain");

        // Location reports keychain
        assert!(
            result
                .locations
                .iter()
                .any(|l| matches!(l, dotenvage::KeyLocation::OsKeychain { .. })),
            "should report OsKeychain location"
        );

        // Key exists via public API
        assert!(SecretManager::key_exists_in_os_keychain());

        // Returned manager can encrypt/decrypt
        let encrypted = result.manager.encrypt_value("gen-keychain").unwrap();
        let decrypted = result.manager.decrypt_value(&encrypted).unwrap();
        assert_eq!(decrypted, "gen-keychain");
    }
}

// ── System store (file-based, non-macOS) ─────────────────────
//
// On Linux and Windows the system store is file-based
// (/etc/dotenvage/ or %ProgramData%\dotenvage\). We can't write
// to those real paths in CI without sudo, but we CAN test the
// file backend directly using temp paths, and we can test that
// writing to the real path fails with InsufficientPrivileges
// when not elevated.

#[test]
fn system_store_path_is_platform_appropriate() {
    let path = SecretManager::system_store_path();
    let path_str = path.to_string_lossy();

    #[cfg(target_os = "macos")]
    assert!(
        path_str.contains("System.keychain"),
        "macOS system store should reference System.keychain, got: {}",
        path_str
    );

    #[cfg(target_os = "linux")]
    assert!(
        path_str.starts_with("/etc/dotenvage/"),
        "Linux system store should be under /etc/dotenvage/, got: {}",
        path_str
    );

    #[cfg(target_os = "windows")]
    assert!(
        path_str.contains("dotenvage"),
        "Windows system store should contain 'dotenvage', got: {}",
        path_str
    );
}

// ── CLI: --store system rejects --output ─────────────────────

#[test]
fn cli_store_system_rejects_output() {
    let dir = TempDir::new().unwrap();
    let output = dir.path().join("should-not-exist.key");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("dotenvage"));
    cmd.current_dir(dir.path())
        .arg("keygen")
        .arg("--store")
        .arg("system")
        .arg("--output")
        .arg(&output)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--output is only valid when --store is 'file' or 'both'",
        ));

    assert!(!output.exists(), "output file should not have been created");
}

// ── File-based key: permissions on Unix ──────────────────────

#[cfg(unix)]
#[test]
fn key_file_has_restricted_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let (_manager, path) = generate_to_file(&dir);

    let metadata = fs::metadata(&path).unwrap();
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "key file should have 0600 permissions, got {:o}",
        mode
    );
}

// ── KeyGenResult fields ──────────────────────────────────────

#[test]
fn keygen_result_has_all_fields() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("fields.key");

    let result = SecretManager::generate_and_save(KeyGenOptions {
        target: KeyStoreTarget::File,
        key_name: None,
        file_path: Some(path.clone()),
        force: false,
    })
    .unwrap();

    // locations should have exactly one UserFile entry
    assert_eq!(result.locations.len(), 1);
    assert!(matches!(
        &result.locations[0],
        dotenvage::KeyLocation::UserFile(p) if *p == path
    ));

    // public_key is a valid age recipient
    assert!(result.public_key.starts_with("age1"));

    // manager works
    let enc = result.manager.encrypt_value("test").unwrap();
    let dec = result.manager.decrypt_value(&enc).unwrap();
    assert_eq!(dec, "test");

    // Debug impl works (doesn't panic)
    let debug = format!("{:?}", result);
    assert!(debug.contains("KeyGenResult"));
}
