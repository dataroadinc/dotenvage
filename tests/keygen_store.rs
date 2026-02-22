//! CLI tests for keygen --store behavior.

use std::fs;
use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn keygen_store_os_rejects_output() {
    let temp_dir = TempDir::new().unwrap();
    let output = temp_dir.path().join("custom.key");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("dotenvage"));
    cmd.current_dir(temp_dir.path())
        .arg("keygen")
        .arg("--store")
        .arg("os")
        .arg("--output")
        .arg(&output)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "--output is only valid when --store is 'file' or 'both'",
        ));
}

#[test]
fn keygen_store_file_writes_to_output() {
    let temp_dir = TempDir::new().unwrap();
    let output = temp_dir.path().join("custom.key");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("dotenvage"));
    cmd.current_dir(temp_dir.path())
        .arg("keygen")
        .arg("--store")
        .arg("file")
        .arg("--output")
        .arg(&output)
        .assert()
        .success();

    let content = fs::read_to_string(&output).unwrap();
    assert!(
        content.contains("AGE-SECRET-KEY-"),
        "generated key file should contain an AGE identity"
    );
}

#[test]
fn keygen_store_file_force_required_for_existing_output() {
    let temp_dir = TempDir::new().unwrap();
    let output = temp_dir.path().join("existing.key");
    fs::write(&output, "existing").unwrap();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("dotenvage"));
    cmd.current_dir(temp_dir.path())
        .arg("keygen")
        .arg("--store")
        .arg("file")
        .arg("--output")
        .arg(&output)
        .assert()
        .failure()
        .stderr(predicate::str::contains("Key file already exists"));

    let mut force_cmd = Command::new(assert_cmd::cargo::cargo_bin!("dotenvage"));
    force_cmd
        .current_dir(temp_dir.path())
        .arg("keygen")
        .arg("--store")
        .arg("file")
        .arg("--force")
        .arg("--output")
        .arg(&output)
        .assert()
        .success();

    let content = fs::read_to_string(&output).unwrap();
    assert!(
        content.contains("AGE-SECRET-KEY-"),
        "forced overwrite should write a valid AGE identity"
    );
}
