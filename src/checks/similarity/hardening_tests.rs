//! Regression tests for red-team findings against similarity detection.

use super::*;
use crate::registry::{PackageMetadata, RegistryExistence, RegistryMetadata};
use async_trait::async_trait;
use std::sync::Mutex;

/// FakeRegistry that records every `exists` query.
struct FakeRegistry {
    existing: HashSet<String>,
    queried: Mutex<Vec<String>>,
}

impl FakeRegistry {
    fn with(names: &[&str]) -> Self {
        FakeRegistry {
            existing: names.iter().map(|s| s.to_string()).collect(),
            queried: Mutex::new(Vec::new()),
        }
    }

    fn was_queried(&self, name: &str) -> bool {
        self.queried.lock().unwrap().iter().any(|q| q == name)
    }
}

#[async_trait]
impl RegistryExistence for FakeRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.queried.lock().unwrap().push(package_name.to_string());
        Ok(self.existing.contains(package_name))
    }

    fn ecosystem(&self) -> &str {
        "npm"
    }
}

#[async_trait]
impl RegistryMetadata for FakeRegistry {
    async fn metadata(
        &self,
        package_name: &str,
        _version: Option<&str>,
    ) -> Result<Option<PackageMetadata>> {
        Ok(self
            .existing
            .contains(package_name)
            .then(|| PackageMetadata {
                downloads: Some(5),
                ..Default::default()
            }))
    }
}

fn dep(name: &str, ecosystem: Ecosystem) -> Dependency {
    Dependency {
        name: name.into(),
        version: None,
        ecosystem,
        actual_name: None,
    }
}

const DAY: u64 = 24 * 3600;

fn read_raw_cache(path: &Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

// ── Finding 1: similarity negative cache must expire per entry ──

#[tokio::test]
async fn stale_negative_entry_is_requeried_even_when_file_was_recently_rewritten() {
    let dir = crate::parsers::test_utils::empty_test_dir("sim-cache-entry-ttl");
    let cp = cache_path_for(Ecosystem::Npm, Some(&dir));
    let now = cache::now_epoch();
    // File was rewritten a minute ago (another scan), but the 'express'
    // negative entry was recorded 8 days ago -- beyond the 7-day TTL.
    let raw = serde_json::json!({
        "timestamp": now - 60,
        "entries": {
            "express": {"exists": false, "checked_at": now - 8 * DAY}
        }
    });
    cache::atomic_write_json(&cp, &raw);

    let registry = FakeRegistry::with(&["express"]);
    let deps = vec![dep("expresss", Ecosystem::Npm)];
    let issues = check_similarity_with_cache(
        &registry,
        &deps,
        Ecosystem::Npm,
        Some(&dir),
        false,
        false,
        None,
    )
    .await
    .unwrap();

    assert!(
        registry.was_queried("express"),
        "expired entry must be re-queried"
    );
    assert!(
        issues.iter().any(|i| i.package == "expresss"),
        "typosquat of newly-registered target must be detected: {:?}",
        issues
    );
    crate::parsers::test_utils::cleanup(&dir);
}

#[tokio::test]
async fn writing_new_results_preserves_age_of_existing_entries() {
    let dir = crate::parsers::test_utils::empty_test_dir("sim-cache-preserve-age");
    let cp = cache_path_for(Ecosystem::Npm, Some(&dir));
    let old_ts = cache::now_epoch() - 6 * DAY;
    // Legacy-format cache file (bool entries, single file timestamp).
    let raw = serde_json::json!({
        "timestamp": old_ts,
        "entries": {"express": false}
    });
    cache::atomic_write_json(&cp, &raw);

    let registry = FakeRegistry::with(&["express"]);
    let deps = vec![
        dep("expresss", Ecosystem::Npm),
        dep("lodashh", Ecosystem::Npm),
    ];
    check_similarity_with_cache(
        &registry,
        &deps,
        Ecosystem::Npm,
        Some(&dir),
        false,
        false,
        None,
    )
    .await
    .unwrap();

    // Legacy entry is still within TTL, so it is served from cache this run...
    assert!(!registry.was_queried("express"));
    // ...but its age must not be renewed by the write of unrelated results.
    let saved = read_raw_cache(&cp);
    let entry = &saved["entries"]["express"];
    assert_eq!(entry["exists"], serde_json::json!(false), "saved: {saved}");
    assert_eq!(
        entry["checked_at"],
        serde_json::json!(old_ts),
        "saved: {saved}"
    );

    // A day later (simulated by aging the saved entry) it must be re-queried.
    let mut aged = saved.clone();
    aged["entries"]["express"]["checked_at"] = serde_json::json!(old_ts - 2 * DAY);
    cache::atomic_write_json(&cp, &aged);
    let registry = FakeRegistry::with(&["express"]);
    let issues = check_similarity_with_cache(
        &registry,
        &deps,
        Ecosystem::Npm,
        Some(&dir),
        false,
        false,
        None,
    )
    .await
    .unwrap();
    assert!(registry.was_queried("express"));
    assert!(issues.iter().any(|i| i.package == "expresss"));
    crate::parsers::test_utils::cleanup(&dir);
}

#[tokio::test]
async fn fresh_per_entry_cache_is_still_served() {
    let dir = crate::parsers::test_utils::empty_test_dir("sim-cache-fresh-entry");
    let cp = cache_path_for(Ecosystem::Npm, Some(&dir));
    let now = cache::now_epoch();
    let raw = serde_json::json!({
        "timestamp": now,
        "entries": {"express": {"exists": true, "checked_at": now - DAY}}
    });
    cache::atomic_write_json(&cp, &raw);
    let registry = FakeRegistry::with(&[]);
    let deps = vec![dep("expresss", Ecosystem::Npm)];
    let issues = check_similarity_with_cache(
        &registry,
        &deps,
        Ecosystem::Npm,
        Some(&dir),
        false,
        false,
        None,
    )
    .await
    .unwrap();
    assert!(!registry.was_queried("express"));
    assert!(issues.iter().any(|i| i.package == "expresss"));
    crate::parsers::test_utils::cleanup(&dir);
}

// ── Finding 2: missing-separator typosquats ──

#[tokio::test]
async fn missing_separator_typosquats_are_detected() {
    // 2017 npm attack names: crossenv (cross-env), babelcli (babel-cli).
    let registry = FakeRegistry::with(&["cross-env", "babel-cli", "react-dom", "python-dateutil"]);
    for (eco, name, target) in [
        (Ecosystem::Npm, "crossenv", "cross-env"),
        (Ecosystem::Npm, "babelcli", "babel-cli"),
        (Ecosystem::Npm, "reactdom", "react-dom"),
        (Ecosystem::PyPI, "pythondateutil", "python-dateutil"),
    ] {
        let issues = check_similarity(&registry, &[dep(name, eco)], eco)
            .await
            .unwrap();
        assert!(
            issues
                .iter()
                .any(|i| i.package == name && i.suggestion.as_deref() == Some(target)),
            "{name} should be flagged as a squat of {target}: {issues:?}"
        );
    }
}

#[test]
fn separator_insertion_covers_every_interior_boundary() {
    let m = generate_mutations("crossenv", Ecosystem::Npm);
    for candidate in ["c-rossenv", "cross-env", "crossen-v"] {
        assert_eq!(m.get(candidate), Some(&"separator-swap"), "{candidate}");
    }
    // Scoped npm names: only the package part gets separators.
    let m = generate_mutations("@babel/presetenv", Ecosystem::Npm);
    assert!(m.contains_key("@babel/preset-env"));
    assert!(!m.keys().any(|k| k.starts_with("@ba-bel")));
}

#[test]
fn separator_insertion_matches_multi_separator_popular_names() {
    let m = generate_mutations("reactrouterdom", Ecosystem::Npm);
    assert!(
        m.contains_key("react-router-dom"),
        "{:?}",
        m.keys().collect::<Vec<_>>()
    );
}

#[test]
fn pypi_separator_insertion_never_targets_the_same_normalized_name() {
    let m = generate_mutations("python_dateutil", Ecosystem::PyPI);
    assert!(!m.contains_key("python-dateutil"));
}

#[test]
fn separator_insertion_is_bounded() {
    let long = "a".repeat(200);
    let insertions = generators::separator_insertions(&long, Ecosystem::Npm);
    assert!(insertions.len() <= generators::MAX_SEPARATOR_INSERTIONS);
}
