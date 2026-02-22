//! Integration tests for EnvLoader write APIs.

use std::fs;

use dotenvage::{
    EnvLoader,
    SecretManager,
};
use tempfile::TempDir;

#[test]
fn set_var_in_file_encrypts_sensitive_keys() {
    let temp_dir = TempDir::new().unwrap();
    let env_path = temp_dir.path().join(".env.local");

    let manager = SecretManager::generate().unwrap();
    let loader = EnvLoader::with_manager(manager.clone());

    loader
        .set_var_in_file("WWKG_PASSPHRASE", "super-secret", &env_path)
        .unwrap();

    let raw = fs::read_to_string(&env_path).unwrap();
    assert!(
        raw.contains("WWKG_PASSPHRASE=ENC[AGE:b64:"),
        "expected encrypted value in file, got: {}",
        raw
    );

    let decrypted = loader.load_env_file(&env_path).unwrap();
    assert_eq!(
        decrypted.get("WWKG_PASSPHRASE"),
        Some(&"super-secret".to_string())
    );
}

#[test]
fn set_var_in_file_keeps_non_sensitive_keys_plain() {
    let temp_dir = TempDir::new().unwrap();
    let env_path = temp_dir.path().join(".env.local");

    let manager = SecretManager::generate().unwrap();
    let loader = EnvLoader::with_manager(manager);

    loader
        .set_var_in_file("WWKG_ACTIVE_WORKSPACE", "alpha", &env_path)
        .unwrap();

    let raw = fs::read_to_string(&env_path).unwrap();
    assert!(raw.contains("WWKG_ACTIVE_WORKSPACE=alpha"));
    assert!(!raw.contains("ENC[AGE:b64:"));
}

#[test]
fn set_var_in_file_keeps_age_key_config_plain() {
    let temp_dir = TempDir::new().unwrap();
    let env_path = temp_dir.path().join(".env.local");

    let manager = SecretManager::generate().unwrap();
    let loader = EnvLoader::with_manager(manager);

    loader
        .set_var_in_file("AGE_KEY_NAME", "myapp/prod", &env_path)
        .unwrap();

    let raw = fs::read_to_string(&env_path).unwrap();
    assert!(raw.contains("AGE_KEY_NAME=myapp/prod"));
    assert!(!raw.contains("ENC[AGE:b64:"));
}

#[test]
fn set_var_in_dir_writes_env_local_and_preserves_existing_vars() {
    let temp_dir = TempDir::new().unwrap();
    let env_path = temp_dir.path().join(".env.local");
    fs::write(&env_path, "FOO=bar\n").unwrap();

    let manager = SecretManager::generate().unwrap();
    let loader = EnvLoader::with_manager(manager);

    let written_path = loader
        .set_var_in_dir("HELLO", "world", temp_dir.path())
        .unwrap();
    assert_eq!(written_path, env_path);

    let raw = fs::read_to_string(&env_path).unwrap();
    assert!(raw.contains("FOO=bar"));
    assert!(raw.contains("HELLO=world"));
}
