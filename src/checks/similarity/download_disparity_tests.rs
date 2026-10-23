//! Download-disparity evidence direction.
//!
//! The scanner flags dependency D (in the user's manifest) as a possible
//! typosquat of candidate C (an existing lookalike name). Typosquat evidence is
//! D being obscure while C is popular. D popular and C obscure points the
//! other way (C is more likely the imitation) and must never be reported as a
//! high-confidence squat of D.

use super::*;
use crate::checks::metadata::MetadataLookup;
use crate::registry::{PackageMetadata, RegistryExistence, RegistryMetadata};
use async_trait::async_trait;

/// Registry where every listed package exists with a fixed download count
/// (`None` = downloads unknown).
struct DownloadsRegistry {
    packages: HashMap<String, Option<u64>>,
}

impl DownloadsRegistry {
    fn with(packages: &[(&str, Option<u64>)]) -> Self {
        Self {
            packages: packages
                .iter()
                .map(|(name, downloads)| (name.to_string(), *downloads))
                .collect(),
        }
    }
}

#[async_trait]
impl RegistryExistence for DownloadsRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        Ok(self.packages.contains_key(package_name))
    }

    fn ecosystem(&self) -> &str {
        "npm"
    }
}

#[async_trait]
impl RegistryMetadata for DownloadsRegistry {
    async fn metadata(
        &self,
        package_name: &str,
        _version: Option<&str>,
    ) -> Result<Option<PackageMetadata>> {
        Ok(self
            .packages
            .get(package_name)
            .map(|downloads| PackageMetadata {
                downloads: *downloads,
                ..Default::default()
            }))
    }
}

fn lookup(package: &str, downloads: Option<u64>) -> MetadataLookup {
    MetadataLookup {
        package: package.to_string(),
        ecosystem: Ecosystem::Npm,
        version: None,
        resolved_version: None,
        unresolved_version: false,
        exists: true,
        metadata: Some(PackageMetadata {
            downloads,
            ..Default::default()
        }),
    }
}

async fn scan(
    dep_name: &str,
    dep_downloads: Option<u64>,
    candidate: &str,
    candidate_downloads: Option<u64>,
) -> Vec<Issue> {
    let registry = DownloadsRegistry::with(&[(candidate, candidate_downloads)]);
    let deps = vec![crate::test_helpers::npm_dep(dep_name)];
    let lookups = vec![lookup(dep_name, dep_downloads)];
    let issues = check_similarity_with_cache(
        &registry,
        &deps,
        Ecosystem::Npm,
        None,
        true,
        false,
        Some(&lookups),
    )
    .await
    .unwrap();
    assert_eq!(issues.len(), 1, "{issues:?}");
    issues
}

#[tokio::test]
async fn obscure_dependency_resembling_popular_package_is_high_confidence() {
    let issues = scan("expresss", Some(12), "express", Some(50_000_000)).await;
    let message = &issues[0].message;
    assert!(message.contains("HIGH CONFIDENCE"), "{message}");
    assert!(
        message.contains("'expresss' has 12 downloads vs 50000000 for 'express'"),
        "{message}"
    );
    assert_eq!(issues[0].severity, Severity::Error);
}

#[tokio::test]
async fn popular_dependency_resembling_obscure_package_is_not_high_confidence() {
    let issues = scan("expresss", Some(50_000_000), "express", Some(500)).await;
    let message = &issues[0].message;
    assert!(!message.contains("HIGH CONFIDENCE"), "{message}");
    // The reverse disparity is surfaced as evidence against, not silently
    // dropped. Severity is unchanged: download counts can be inflated, so they
    // never clear a finding on their own.
    assert!(message.contains("LOW CONFIDENCE"), "{message}");
    assert!(
        message.contains("'expresss' has 50000000 downloads vs 500 for 'express'"),
        "{message}"
    );
    assert_eq!(issues[0].severity, Severity::Error);
}

#[tokio::test]
async fn missing_download_data_makes_no_confidence_claim() {
    for (dep_downloads, candidate_downloads) in
        [(None, Some(50_000_000)), (Some(12), None), (None, None)]
    {
        let issues = scan("expresss", dep_downloads, "express", candidate_downloads).await;
        let message = &issues[0].message;
        assert!(!message.contains("CONFIDENCE"), "{message}");
    }
}

#[tokio::test]
async fn missing_dependency_lookup_makes_no_confidence_claim() {
    let registry = DownloadsRegistry::with(&[("express", Some(50_000_000))]);
    let deps = vec![crate::test_helpers::npm_dep("expresss")];
    let issues =
        check_similarity_with_cache(&registry, &deps, Ecosystem::Npm, None, true, false, None)
            .await
            .unwrap();
    assert_eq!(issues.len(), 1);
    assert!(
        !issues[0].message.contains("CONFIDENCE"),
        "{}",
        issues[0].message
    );
}

#[tokio::test]
async fn comparable_download_counts_make_no_confidence_claim() {
    let issues = scan("expresss", Some(40_000), "express", Some(50_000)).await;
    assert!(
        !issues[0].message.contains("CONFIDENCE"),
        "{}",
        issues[0].message
    );
}

#[test]
fn disparity_note_direction() {
    assert!(
        download_disparity_note("d", Some(10), "c", Some(1_000_000))
            .unwrap()
            .starts_with("HIGH CONFIDENCE")
    );
    assert!(
        download_disparity_note("d", Some(1_000_000), "c", Some(10))
            .unwrap()
            .starts_with("LOW CONFIDENCE")
    );
    assert_eq!(download_disparity_note("d", Some(10), "c", None), None);
    assert_eq!(download_disparity_note("d", None, "c", Some(10)), None);
    assert_eq!(
        download_disparity_note("d", Some(5_000), "c", Some(5_000)),
        None
    );
}
