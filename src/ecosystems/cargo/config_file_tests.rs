//! Cargo reads `.cargo/config.toml` in every directory above where it runs, not
//! only inside the scanned directory.

use super::*;
use crate::parsers::test_utils::{cleanup, empty_test_dir};

const EVIL_REPLACEMENT: &str = "[source.crates-io]\nreplace-with = \"evil\"\n[source.evil]\nregistry = \"sparse+https://evil.example.com/index/\"\n";

fn write(path: &std::path::Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

/// `root/proj` with a crates.io dependency; returns the project directory.
fn project(root: &std::path::Path) -> std::path::PathBuf {
    let proj = root.join("proj");
    write(
        &proj.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nitoa = \"1.0.11\"\n",
    );
    write(&proj.join("Cargo.lock"), "version = 4\n");
    proj
}

fn rewrites_for(
    proj: &std::path::Path,
    config: &config::SloppyJoeConfig,
    home: &std::path::Path,
) -> Result<(CargoConfigRewrites, Vec<Issue>)> {
    load_effective_cargo_config_rewrites_for_test(
        proj,
        &proj.join("Cargo.toml"),
        config,
        Some(home.join(".cargo")),
    )
}

#[test]
fn repo_config_above_the_scanned_directory_is_read() {
    let repo = empty_test_dir("cargo-config-above");
    let home = empty_test_dir("cargo-config-above-home");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    write(&repo.join(".cargo/config.toml"), EVIL_REPLACEMENT);
    let proj = project(&repo);

    let (rewrites, _) = rewrites_for(&proj, &config::SloppyJoeConfig::default(), &home).unwrap();
    assert_eq!(
        rewrites
            .source_replace_with
            .get("crates-io")
            .map(String::as_str),
        Some("evil"),
        "the repository's own Cargo config applies to the subdirectory"
    );
    cleanup(&repo);
    cleanup(&home);
}

#[test]
fn config_above_the_repository_is_host_local_and_blocked_by_default() {
    let outer = empty_test_dir("cargo-config-outer");
    let home = empty_test_dir("cargo-config-outer-home");
    write(&outer.join(".cargo/config.toml"), EVIL_REPLACEMENT);
    let repo = outer.join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    let proj = project(&repo);

    let err = rewrites_for(&proj, &config::SloppyJoeConfig::default(), &home)
        .map(|_| ())
        .expect_err("Cargo config above the repository must not be ignored");
    assert!(err.to_string().contains("host-local Cargo config"), "{err}");

    let allowed = config::SloppyJoeConfig {
        allow_host_local_cargo_config: true,
        ..Default::default()
    };
    let (rewrites, warnings) = rewrites_for(&proj, &allowed, &home).unwrap();
    assert_eq!(
        rewrites
            .source_replace_with
            .get("crates-io")
            .map(String::as_str),
        Some("evil")
    );
    assert!(!warnings.is_empty());
    cleanup(&outer);
    cleanup(&home);
}

#[test]
fn without_a_checkout_config_above_the_scan_root_is_host_local() {
    let outer = empty_test_dir("cargo-config-nogit");
    let home = empty_test_dir("cargo-config-nogit-home");
    write(&outer.join(".cargo/config"), EVIL_REPLACEMENT);
    let proj = project(&outer);

    assert!(rewrites_for(&proj, &config::SloppyJoeConfig::default(), &home).is_err());
    cleanup(&outer);
    cleanup(&home);
}
