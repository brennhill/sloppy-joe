//! A ranged crates.io requirement is trusted from `Cargo.lock` when the lock
//! holds exactly one registry version that satisfies the requirement, which is
//! the version Cargo installs. A lock that contradicts the manifest is out of
//! sync, and several satisfying versions stay ambiguous.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

const REGISTRY: &str = "registry+https://github.com/rust-lang/crates.io-index";

fn resolve(requirement: &str, locked: &[&str]) -> (Option<String>, Vec<String>) {
    let dir = std::env::temp_dir().join(format!(
        "sj-cargo-range-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        format!("[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"{requirement}\"\n"),
    )
    .unwrap();
    let mut lock = String::from("version = 4\n");
    for version in locked {
        lock.push_str(&format!(
            "\n[[package]]\nname = \"serde\"\nversion = \"{version}\"\nsource = \"{REGISTRY}\"\n"
        ));
    }
    std::fs::write(dir.join("Cargo.lock"), lock).unwrap();
    let deps = crate::parsers::cargo_toml::parse(&dir).unwrap();
    let data = LockfileData::parse(&dir, &deps).unwrap();
    let version = data.resolution.exact_version(&deps[0]).map(str::to_string);
    let checks = data
        .resolution
        .issues
        .iter()
        .map(|issue| issue.check.clone())
        .collect();
    let _ = std::fs::remove_dir_all(&dir);
    (version, checks)
}

#[test]
fn a_locked_version_that_satisfies_the_requirement_is_trusted() {
    for requirement in ["1.0", "^1", "~1.0", ">=1.0, <2", "1.0.*", "1"] {
        let (version, issues) = resolve(requirement, &["1.0.228"]);
        assert_eq!(version.as_deref(), Some("1.0.228"), "{requirement}");
        assert!(issues.is_empty(), "{requirement}: {issues:?}");
    }
}

#[test]
fn a_locked_version_that_contradicts_the_requirement_is_out_of_sync() {
    for requirement in ["2.0", "~1.1", "<1.0", ">=1.1"] {
        let (version, issues) = resolve(requirement, &["1.0.228"]);
        assert_eq!(version, None, "{requirement}");
        assert_eq!(issues, ["resolution/lockfile-out-of-sync"], "{requirement}");
    }
}

#[test]
fn prereleases_only_match_requirements_that_name_one() {
    let (version, issues) = resolve("1.0", &["1.0.0-rc.1"]);
    assert_eq!(version, None);
    assert_eq!(issues, ["resolution/lockfile-out-of-sync"]);
    let (version, _) = resolve(">=1.0.0-rc.1", &["1.0.0-rc.1"]);
    assert_eq!(version.as_deref(), Some("1.0.0-rc.1"));
}

#[test]
fn only_one_satisfying_candidate_among_several_is_chosen() {
    let (version, issues) = resolve("1.0", &["0.9.1", "1.0.228"]);
    assert_eq!(version.as_deref(), Some("1.0.228"));
    assert!(issues.is_empty(), "{issues:?}");
}

#[test]
fn several_satisfying_candidates_stay_ambiguous() {
    let (version, issues) = resolve(">=0.9", &["0.9.1", "1.0.228"]);
    assert_eq!(version, None);
    assert_eq!(issues, ["resolution/ambiguous"]);
}

#[test]
fn candidates_that_all_miss_the_requirement_are_out_of_sync() {
    let (version, issues) = resolve("3.0", &["0.9.1", "1.0.228"]);
    assert_eq!(version, None);
    assert_eq!(issues, ["resolution/lockfile-out-of-sync"]);
}

#[test]
fn unparseable_requirements_keep_the_sync_block() {
    let (version, issues) = resolve("not-a-version", &["1.0.228"]);
    assert_eq!(version, None);
    assert_eq!(issues, ["resolution/no-trusted-lockfile-sync"]);
}
