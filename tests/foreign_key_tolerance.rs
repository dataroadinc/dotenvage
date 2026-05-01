//! Verifies that values encrypted with a foreign age key are silently
//! dropped from the loaded variables instead of aborting the whole load.
//!
//! Rationale: the parent process may already have a value set for the
//! affected key; in that case we want the parent value to prevail,
//! not be clobbered or wiped by a partial-failure error.

use std::fs;

use dotenvage::{
    EnvLoader,
    SecretManager,
};
use tempfile::TempDir;

#[test]
fn foreign_key_value_is_dropped_other_values_load() {
    let temp_dir = TempDir::new().unwrap();
    let env_path = temp_dir.path().join(".env.local");

    let mine = SecretManager::generate().unwrap();
    let stranger = SecretManager::generate().unwrap();

    let mine_value = mine.encrypt_value("mine-secret").unwrap();
    let stranger_value = stranger.encrypt_value("stranger-secret").unwrap();

    let contents = format!(
        "WWKG_PASSPHRASE={mine_value}\n\
         FOREIGN_TOKEN={stranger_value}\n\
         PLAIN_VALUE=hello\n"
    );
    fs::write(&env_path, contents).unwrap();

    let loader = EnvLoader::with_manager(mine);
    let loaded = loader.load_env_file(&env_path).unwrap();

    assert_eq!(
        loaded.get("WWKG_PASSPHRASE"),
        Some(&"mine-secret".to_string()),
        "values encrypted with our key must decrypt"
    );
    assert_eq!(
        loaded.get("PLAIN_VALUE"),
        Some(&"hello".to_string()),
        "plain values must load"
    );
    assert!(
        !loaded.contains_key("FOREIGN_TOKEN"),
        "values encrypted with a foreign key must be dropped, got: {:?}",
        loaded.get("FOREIGN_TOKEN")
    );
}

#[test]
fn foreign_key_does_not_overwrite_parent_env() {
    let temp_dir = TempDir::new().unwrap();
    let env_path = temp_dir.path().join(".env");

    let mine = SecretManager::generate().unwrap();
    let stranger = SecretManager::generate().unwrap();
    let stranger_value = stranger.encrypt_value("from-file").unwrap();

    fs::write(
        &env_path,
        format!("DOTENVAGE_PARENT_WINS={stranger_value}\n"),
    )
    .unwrap();

    let key = "DOTENVAGE_PARENT_WINS";
    // SAFETY: test runs serially via the variable name being unique to
    // this test; we set, load, then remove.
    unsafe {
        std::env::set_var(key, "parent-value");
    }

    let loader = EnvLoader::with_manager(mine);
    let loaded = loader.load_from_dir(temp_dir.path()).unwrap();
    assert!(
        !loaded.is_empty(),
        "load should report files even if every value was foreign"
    );

    let observed = std::env::var(key).ok();
    unsafe {
        std::env::remove_var(key);
    }

    assert_eq!(
        observed.as_deref(),
        Some("parent-value"),
        "foreign-key value must not overwrite the parent process env var"
    );
}
