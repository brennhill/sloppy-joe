//! Regression tests for red-team findings against pipeline data flow.

use super::*;
use crate::registry::{PackageMetadata, RegistryExistence, RegistryMetadata};
use async_trait::async_trait;
use std::sync::Mutex;

/// FakeRegistry: popular `express`, low-download squat `expresss`.
struct FakeRegistry {
    metadata_calls: Mutex<Vec<String>>,
}

#[async_trait]
impl RegistryExistence for FakeRegistry {
    async fn exists(&self, name: &str) -> Result<bool> {
        Ok(name == "express" || name == "expresss")
    }
    fn ecosystem(&self) -> &str {
        "npm"
    }
}

#[async_trait]
impl RegistryMetadata for FakeRegistry {
    async fn metadata(&self, name: &str, _v: Option<&str>) -> Result<Option<PackageMetadata>> {
        self.metadata_calls.lock().unwrap().push(name.to_string());
        Ok(match name {
            "express" => Some(PackageMetadata {
                downloads: Some(50_000_000),
                created: Some("2010-01-01T00:00:00Z".into()),
                latest_version_date: Some("2020-01-01T00:00:00Z".into()),
                repository_url: Some("https://github.com/expressjs/express".into()),
                ..Default::default()
            }),
            "expresss" => Some(PackageMetadata {
                downloads: Some(12),
                created: Some("2010-01-01T00:00:00Z".into()),
                latest_version_date: Some("2020-01-01T00:00:00Z".into()),
                repository_url: Some("https://github.com/x/y".into()),
                ..Default::default()
            }),
            _ => None,
        })
    }
}

struct NoOsv;
#[async_trait]
impl super::super::malicious::OsvClient for NoOsv {
    async fn query(&self, _: &str, _: &str, _: Option<&str>) -> Result<Vec<String>> {
        Ok(vec![])
    }
}

#[tokio::test]
async fn download_disparity_evidence_reaches_similarity_in_default_pipeline() {
    // The dependency in the manifest has almost no downloads; the near-name
    // candidate on the registry is the popular package it imitates.
    let deps = vec![crate::Dependency {
        name: "expresss".into(),
        version: Some("1.0.0".into()),
        ecosystem: crate::Ecosystem::Npm,
        actual_name: None,
    }];
    let config = crate::config::SloppyJoeConfig::default();
    let resolution = crate::lockfiles::ResolutionResult::default();
    let opts = crate::ScanOptions {
        no_cache: true,
        disable_osv_disk_cache: true,
        ..Default::default()
    };
    let registry = FakeRegistry {
        metadata_calls: Mutex::new(Vec::new()),
    };
    let ctx = CheckContext {
        checkable_deps: &deps,
        non_internal_deps: &deps,
        config: &config,
        registry: &registry,
        osv_client: &NoOsv,
        resolution: &resolution,
        ecosystem: crate::Ecosystem::Npm,
        opts: &opts,
    };
    let mut acc = ScanAccumulator::new();
    for check in default_pipeline() {
        check.run(&ctx, &mut acc).await.unwrap();
    }
    let sim = acc
        .issues
        .iter()
        .find(|i| i.check.starts_with("similarity/"))
        .expect("similarity issue");
    assert!(sim.message.contains("HIGH CONFIDENCE"), "{}", sim.message);

    // Metadata for the dependency is fetched once, not again by MetadataCheck.
    let calls = registry.metadata_calls.lock().unwrap();
    assert_eq!(
        calls.iter().filter(|n| *n == "expresss").count(),
        1,
        "{calls:?}"
    );
}
