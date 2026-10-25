//! Regression tests for typosquats that drop one character from a known name
//! (red-team finding RT7: `expres`, `typescipt`, `date-fn`, `body-parse`).

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

    fn query_count(&self) -> usize {
        self.queried.lock().unwrap().len()
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
            .then(PackageMetadata::default))
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

async fn missing_char_issue(
    registry: &FakeRegistry,
    name: &str,
    ecosystem: Ecosystem,
    config: &crate::config::SloppyJoeConfig,
) -> Option<Issue> {
    run_uncached(registry, &[dep(name, ecosystem)], ecosystem, config)
        .await
        .into_iter()
        .find(|issue| issue.check == crate::names::SIMILARITY_MISSING_CHAR)
}

/// Similarity with the disk cache off, so results from other tests cannot leak in.
async fn run_uncached(
    registry: &FakeRegistry,
    deps: &[Dependency],
    ecosystem: Ecosystem,
    config: &crate::config::SloppyJoeConfig,
) -> Vec<Issue> {
    check_similarity_with_options(
        registry,
        deps,
        ecosystem,
        SimilarityRunOptions {
            cache_dir: None,
            no_cache: true,
            paranoid: false,
            dep_metadata: None,
            config,
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn dropped_character_typosquats_of_popular_packages_are_detected() {
    let config = crate::config::SloppyJoeConfig::default();
    let cases = [
        ("expres", "express", Ecosystem::Npm),
        ("typescipt", "typescript", Ecosystem::Npm),
        ("date-fn", "date-fns", Ecosystem::Npm),
        ("body-parse", "body-parser", Ecosystem::Npm),
        ("reqests", "requests", Ecosystem::PyPI),
        ("sere", "serde", Ecosystem::Cargo),
    ];
    for (squat, real, ecosystem) in cases {
        let registry = FakeRegistry::with(&[real, squat]);
        let issue = missing_char_issue(&registry, squat, ecosystem, &config)
            .await
            .unwrap_or_else(|| panic!("'{squat}' must be flagged as missing a character of '{real}'"));
        assert_eq!(issue.suggestion.as_deref(), Some(real));
        assert_eq!(issue.severity, Severity::Error);
        assert!(issue.message.contains(real), "{}", issue.message);
    }
}

#[tokio::test]
async fn pypi_missing_character_ignores_separator_spelling() {
    let config = crate::config::SloppyJoeConfig::default();
    let registry = FakeRegistry::with(&["scikit-learn"]);
    let issue = missing_char_issue(&registry, "scikit_lern", Ecosystem::PyPI, &config)
        .await
        .expect("PyPI separator spelling must not hide a dropped character");
    assert_eq!(issue.suggestion.as_deref(), Some("scikit-learn"));
}

#[tokio::test]
async fn dropped_character_of_a_configured_root_is_detected() {
    let config = crate::config::SloppyJoeConfig {
        allowed: HashMap::from([("npm".to_string(), vec!["acme-widgets".to_string()])]),
        ..Default::default()
    };
    let registry = FakeRegistry::with(&["acme-widgets"]);
    let issue = missing_char_issue(&registry, "acme-widget", Ecosystem::Npm, &config)
        .await
        .expect("a dropped character of a configured package must be flagged");
    assert_eq!(issue.suggestion.as_deref(), Some("acme-widgets"));
}

#[test]
fn popular_dependency_is_never_a_missing_character_squat() {
    for ecosystem in [Ecosystem::Npm, Ecosystem::PyPI, Ecosystem::Cargo] {
        for popular in popular::top_packages(ecosystem) {
            assert!(
                generators::missing_char_targets(popular, ecosystem, &[]).is_empty(),
                "popular package '{popular}' must not be reported as missing a character"
            );
        }
    }
}

#[test]
fn very_short_names_are_not_matched_by_missing_character() {
    // "uid", "jet", "nxt" are three characters; one deletion from a four-letter
    // popular name lands on too many unrelated real packages.
    for short in ["uid", "jet", "nxt", "cor"] {
        assert!(
            generators::missing_char_targets(short, Ecosystem::Npm, &[]).is_empty(),
            "'{short}' is too short for missing-character matching"
        );
    }
}

#[test]
fn missing_character_targets_are_exact_single_insertions() {
    assert_eq!(
        generators::missing_char_targets("expres", Ecosystem::Npm, &[]),
        vec!["express".to_string()]
    );
    assert!(generators::missing_char_targets("zzzzzz", Ecosystem::Npm, &[]).is_empty());
    // Two characters missing is not a single deletion.
    assert!(generators::missing_char_targets("expe", Ecosystem::Npm, &[]).is_empty());
    // A dropped separator is reported by separator-swap, not here.
    assert!(generators::missing_char_targets("crossenv", Ecosystem::Npm, &[]).is_empty());
    // Same length (substitution) is not a deletion.
    assert!(generators::missing_char_targets("exprezs", Ecosystem::Npm, &[]).is_empty());
}

#[tokio::test]
async fn missing_character_detection_adds_at_most_one_probe_per_matching_target() {
    let config = crate::config::SloppyJoeConfig::default();
    let generators = default_generators();
    let baseline: HashSet<String> = generators
        .iter()
        .filter(|g| g.name() != "missing-char")
        .flat_map(|g| g.generate("expres", Ecosystem::Npm))
        .collect();
    let registry = FakeRegistry::with(&["express"]);
    let _ = run_uncached(&registry, &[dep("expres", Ecosystem::Npm)], Ecosystem::Npm, &config).await;
    // Every non-missing-char candidate plus the one popular target ("express"),
    // never an n x alphabet insertion fan-out.
    assert!(
        registry.query_count() <= baseline.len() + 1,
        "missing-char added {} probes beyond the other generators",
        registry.query_count().saturating_sub(baseline.len())
    );
}
