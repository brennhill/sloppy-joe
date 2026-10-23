//! The per-scan tarball download cap comes from config and overflow is
//! visible: every selected version past the cap blocks, with the count.

use super::*;
use crate::registry::npm_tarball::NpmManifestFacts;
use crate::registry::{RegistryExistence, RegistryMetadata};
use crate::report::Severity;
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Mutex;

#[derive(Default)]
struct CleanTarballs {
    calls: Mutex<usize>,
}

#[async_trait]
impl RegistryExistence for CleanTarballs {
    async fn exists(&self, _: &str) -> Result<bool> {
        Ok(true)
    }
    fn ecosystem(&self) -> &str {
        "npm"
    }
}

#[async_trait]
impl RegistryMetadata for CleanTarballs {
    async fn verify_npm_tarball(
        &self,
        _package_name: &str,
        _tarball: &NpmTarballRef,
    ) -> Result<Option<NpmManifestFacts>> {
        *self.calls.lock().unwrap() += 1;
        Ok(Some(NpmManifestFacts::default()))
    }
}

/// Published moments ago, so always selected for verification.
fn recent_lookup(package: &str) -> MetadataLookup {
    MetadataLookup {
        package: package.into(),
        ecosystem: Ecosystem::Npm,
        version: Some("1.0.0".into()),
        resolved_version: Some("1.0.0".into()),
        unresolved_version: false,
        exists: true,
        metadata: Some(PackageMetadata {
            latest_version_date: Some(cache::now_iso8601()),
            npm_tarball: Some(NpmTarballRef {
                version: "1.0.0".into(),
                tarball: Some(format!(
                    "https://registry.npmjs.org/{package}/-/{package}-1.0.0.tgz"
                )),
                integrity: Some(format!("sha512-{package}")),
                shasum: None,
                declared: NpmManifestFacts::default(),
            }),
            ..Default::default()
        }),
    }
}

#[test]
fn scan_options_take_the_cap_from_config() {
    let config = SloppyJoeConfig {
        max_npm_tarball_verifications: 7,
        ..Default::default()
    };
    let opts = crate::ScanOptions::default();
    assert_eq!(
        TarballVerificationOptions::from_scan(&opts, &config).max_fetches,
        7
    );
    assert_eq!(
        TarballVerificationOptions::from_scan(&opts, &SloppyJoeConfig::default()).max_fetches,
        DEFAULT_MAX_TARBALL_FETCHES
    );
}

#[tokio::test]
async fn every_version_past_the_cap_blocks_and_reports_the_count() {
    let registry = CleanTarballs::default();
    let mut lookups: Vec<_> = ["a", "b", "c", "d", "e"]
        .into_iter()
        .map(recent_lookup)
        .collect();
    let config = SloppyJoeConfig {
        min_version_age_hours: 0,
        max_npm_tarball_verifications: 2,
        ..Default::default()
    };
    let options = TarballVerificationOptions {
        cache_dir: None,
        no_cache: true,
        verify_all: false,
        max_fetches: config.max_npm_tarball_verifications,
    };
    let issues =
        verify_npm_tarballs(&registry, &mut lookups, &config, &HashSet::new(), &options).await;
    assert_eq!(*registry.calls.lock().unwrap(), 2);
    let unverified: Vec<_> = issues
        .iter()
        .filter(|i| i.check == names::METADATA_TARBALL_UNVERIFIED)
        .collect();
    assert_eq!(unverified.len(), 3, "{issues:?}");
    for issue in unverified {
        assert_eq!(issue.severity, Severity::Error);
        assert!(
            issue.message.contains("limit (2)")
                && issue.message.contains("3 of 5 selected npm versions"),
            "{}",
            issue.message
        );
        assert!(
            issue.fix.contains("max_npm_tarball_verifications"),
            "{}",
            issue.fix
        );
    }
}
