//! poetry.lock keeps one entry per Python-version split (`python-versions`
//! differs), so a root dependency can resolve to several locked versions. Which
//! one is installed depends on the interpreter, so every candidate must be
//! scanned instead of the whole project being rejected as ambiguous.

use super::python::{parse_all_from_value_for_roots, reachable_package_identities};
use crate::{Dependency, Ecosystem};

fn lock() -> toml::Value {
    toml::from_str(
        r#"
[[package]]
name = "platformdirs"
version = "4.12.4"
python-versions = ">=3.10,<3.11"

[[package]]
name = "platformdirs"
version = "4.13.0"
python-versions = ">=3.11"

[[package]]
name = "requests"
version = "2.32.3"
python-versions = ">=3.8"

[package.dependencies]
idna = ">=2.5,<4"

[[package]]
name = "idna"
version = "3.10"
python-versions = ">=3.6"

[metadata]
lock-version = "2.1"
"#,
    )
    .unwrap()
}

fn dep(name: &str, version: Option<&str>) -> Dependency {
    Dependency {
        name: name.to_string(),
        version: version.map(str::to_string),
        ecosystem: Ecosystem::PyPI,
        actual_name: None,
    }
}

#[test]
fn every_locked_version_of_a_split_root_dependency_is_reachable() {
    let direct = vec![dep("platformdirs", Some(">=3.0.0,<5"))];
    let reachable = reachable_package_identities(&lock(), &direct, None)
        .expect("split resolutions must not be rejected as ambiguous");
    let mut versions: Vec<&str> = reachable
        .iter()
        .filter(|identity| identity.normalized_name == "platformdirs")
        .map(|identity| identity.version.as_str())
        .collect();
    versions.sort();
    assert_eq!(versions, vec!["4.12.4", "4.13.0"]);
}

#[test]
fn every_locked_version_of_a_split_root_dependency_is_scanned() {
    let direct = vec![
        dep("platformdirs", Some(">=3.0.0,<5")),
        dep("requests", Some(">=2")),
    ];
    let scanned = parse_all_from_value_for_roots(&lock(), &direct, None)
        .expect("split resolutions must not be rejected as ambiguous");
    let mut platformdirs: Vec<&str> = scanned
        .iter()
        .filter(|dependency| dependency.name == "platformdirs")
        .filter_map(|dependency| dependency.version.as_deref())
        .collect();
    platformdirs.sort();
    assert_eq!(platformdirs, vec!["4.12.4", "4.13.0"]);
    assert!(
        scanned.iter().any(|dependency| dependency.name == "idna"),
        "ordinary transitives are still scanned"
    );
}

#[test]
fn an_exactly_pinned_root_dependency_still_resolves_to_its_pin() {
    let direct = vec![dep("platformdirs", Some("==4.13.0"))];
    let reachable = reachable_package_identities(&lock(), &direct, None).unwrap();
    let versions: Vec<&str> = reachable
        .iter()
        .filter(|identity| identity.normalized_name == "platformdirs")
        .map(|identity| identity.version.as_str())
        .collect();
    assert_eq!(versions, vec!["4.13.0"]);
}

#[test]
fn a_split_with_a_non_default_source_candidate_still_fails_closed() {
    // Leaving the version open would let the lock's own `evil` source authorize
    // itself for the root, so this must keep failing closed.
    let lock: toml::Value = toml::from_str(
        r#"
[[package]]
name = "widget"
version = "1.1.0"
python-versions = ">=3.8"

[[package]]
name = "widget"
version = "2.0.0"
python-versions = ">=3.8"

[package.source]
type = "explicit"
url = "https://evil.example/simple"
reference = "evil"

[metadata]
lock-version = "2.1"
"#,
    )
    .unwrap();
    let direct = vec![dep("widget", Some("^1.0.0"))];
    let err = reachable_package_identities(&lock, &direct, None)
        .expect_err("a non-default source among the candidates must fail closed");
    assert!(err.to_string().contains("ambiguous"), "{err}");
}
