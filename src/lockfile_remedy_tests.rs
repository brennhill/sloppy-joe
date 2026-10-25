//! Message step of docs/specs/fix-lockfile.md: every blocking lockfile-format or staleness error
//! names the exact manual command and the minimum tool version, points at
//! `sloppy-joe fix-lockfile`, and carries its remedy so `fix-lockfile` can classify it.
use super::*;
use crate::remedy::{self, Remedy};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn project(files: &[(&str, &str)]) -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-remedy-{}-{}", std::process::id(), id));
    let _ = std::fs::remove_dir_all(&dir);
    for (name, content) in files {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }
    dir
}

fn assert_remedy(files: &[(&str, &str)], project_type: &str, expected: &'static Remedy) {
    let dir = project(files);
    let err = preflight_scan_inputs(&dir, Some(project_type))
        .expect_err("the lockfile problem must block");
    let msg = err.to_string();
    assert_eq!(
        remedy::find(&err).map(|remedy| remedy.id),
        Some(expected.id),
        "{msg}"
    );
    assert!(msg.contains(expected.command), "{msg}");
    assert!(msg.contains(expected.min_version), "{msg}");
    assert!(msg.contains("sloppy-joe fix-lockfile"), "{msg}");
    let _ = std::fs::remove_dir_all(&dir);
}

const PACKAGE_JSON: &str =
    r#"{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#;

#[test]
fn missing_npm_lockfile_names_the_lockfile_only_install() {
    assert_remedy(
        &[("package.json", PACKAGE_JSON)],
        "npm",
        &remedy::NPM_LOCKFILE,
    );
}

#[test]
fn legacy_npm_lockfile_names_the_upgrade() {
    let lock = r#"{"name":"app","version":"1.0.0","lockfileVersion":1,"requires":true,"dependencies":{"left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz","integrity":"sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQEgmQkFbyPgDYDTiNU1AmoMo9fEZknKCdQ4IGGqqSdqrMhqA=="}}}"#;
    assert_remedy(
        &[("package.json", PACKAGE_JSON), ("package-lock.json", lock)],
        "npm",
        &remedy::NPM_LOCKFILE_UPGRADE,
    );
}

#[test]
fn old_pnpm_lockfile_names_pnpm_9() {
    let lock = "lockfileVersion: '6.0'\n\ndependencies:\n  left-pad:\n    specifier: 1.3.0\n    version: 1.3.0\n\npackages:\n\n  /left-pad@1.3.0:\n    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQEgmQkFbyPgDYDTiNU1AmoMo9fEZknKCdQ4IGGqqSdqrMhqA==}\n    dev: false\n";
    assert_remedy(
        &[("package.json", PACKAGE_JSON), ("pnpm-lock.yaml", lock)],
        "npm",
        &remedy::PNPM_LOCKFILE,
    );
}

#[test]
fn missing_cargo_lockfile_names_generate_lockfile() {
    let manifest = "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nitoa = \"=1.0.10\"\n";
    assert_remedy(
        &[("Cargo.toml", manifest)],
        "cargo",
        &remedy::CARGO_GENERATE_LOCKFILE,
    );
}

#[test]
fn incomplete_go_sum_names_go_mod_download_all() {
    let go_mod = "module example.com/app\n\ngo 1.22\n\nrequire github.com/google/uuid v1.6.0\n";
    let go_sum =
        "github.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=\n";
    assert_remedy(
        &[("go.mod", go_mod), ("go.sum", go_sum)],
        "go",
        &remedy::GO_SUM,
    );
}

#[test]
fn missing_composer_lockfile_names_composer_update() {
    let manifest = r#"{"name":"acme/app","require":{"monolog/monolog":"3.5.0"}}"#;
    assert_remedy(
        &[("composer.json", manifest)],
        "php",
        &remedy::COMPOSER_LOCK_MISSING,
    );
}

#[test]
fn missing_gemfile_lock_names_bundle_lock() {
    assert_remedy(
        &[(
            "Gemfile",
            "source 'https://rubygems.org'\ngem 'rake', '13.0.6'\n",
        )],
        "ruby",
        &remedy::BUNDLE_LOCK,
    );
}

#[test]
fn npm_overrides_are_a_decision_not_a_command() {
    let manifest = r#"{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"},"overrides":{"left-pad":"1.3.0"}}"#;
    let lock = r#"{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}},"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz","integrity":"sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQEgmQkFbyPgDYDTiNU1AmoMo9fEZknKCdQ4IGGqqSdqrMhqA=="}}}"#;
    assert_remedy(
        &[("package.json", manifest), ("package-lock.json", lock)],
        "npm",
        &remedy::JS_DEPENDENCY_REWRITE,
    );
}
