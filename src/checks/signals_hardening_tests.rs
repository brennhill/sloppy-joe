//! Regression tests for red-team findings against metadata signals.

use super::*;
use crate::Ecosystem;
use crate::names;
use std::collections::HashSet;

fn lookup(meta: PackageMetadata) -> MetadataLookup {
    MetadataLookup {
        package: "pkg".into(),
        ecosystem: Ecosystem::Npm,
        version: Some("1.0.2".into()),
        resolved_version: Some("1.0.2".into()),
        unresolved_version: false,
        exists: true,
        metadata: Some(meta),
    }
}

fn mature_meta() -> PackageMetadata {
    PackageMetadata {
        created: Some("2015-01-01T00:00:00Z".into()),
        latest_version_date: Some("2016-01-01T00:00:00Z".into()),
        downloads: Some(5_000_000),
        repository_url: Some("https://github.com/a/b".into()),
        ..Default::default()
    }
}

fn issues_for(meta: PackageMetadata) -> Vec<Issue> {
    let config = crate::config::SloppyJoeConfig::default();
    crate::checks::metadata::issues_from_lookups(&[lookup(meta)], &config, &HashSet::new())
}

// ── Finding 5: downloads unavailable ──

#[test]
fn downloads_unavailable_emits_visible_warning() {
    let meta = PackageMetadata {
        downloads: None,
        downloads_unavailable: Some("HTTP 429".into()),
        ..mature_meta()
    };
    let issues = issues_for(meta);
    let issue = issues
        .iter()
        .find(|i| i.check == names::METADATA_DOWNLOADS_UNAVAILABLE)
        .expect("downloads-unavailable warning");
    assert_eq!(issue.severity, Severity::Warning);
    assert!(issue.message.contains("HTTP 429"));
}

#[test]
fn available_downloads_emit_no_warning() {
    let issues = issues_for(mature_meta());
    assert!(
        !issues
            .iter()
            .any(|i| i.check == names::METADATA_DOWNLOADS_UNAVAILABLE)
    );
}

// ── Finding 3: manifest inconsistency is blocking ──

#[test]
fn manifest_inconsistency_is_blocking() {
    let meta = PackageMetadata {
        has_install_scripts: true,
        manifest_inconsistency: Some("registry reports an install script".into()),
        ..mature_meta()
    };
    let issues = issues_for(meta);
    let issue = issues
        .iter()
        .find(|i| i.check == names::METADATA_MANIFEST_INCONSISTENCY)
        .expect("manifest-inconsistency error");
    assert_eq!(issue.severity, Severity::Error);
}

// ── Finding 4: removed previous version ──

#[test]
fn removed_previous_version_emits_signal() {
    let meta = PackageMetadata {
        current_publisher: Some("mallory".into()),
        previous_publisher: Some("mallory".into()),
        removed_previous_version: Some("1.0.1".into()),
        ..mature_meta()
    };
    let issues = issues_for(meta);
    let issue = issues
        .iter()
        .find(|i| i.check == names::METADATA_REMOVED_PREVIOUS_VERSION)
        .expect("removed-previous-version signal");
    assert!(issue.message.contains("1.0.1"));
}

#[test]
fn removed_previous_version_with_unknown_previous_publisher_is_blocking() {
    let meta = PackageMetadata {
        current_publisher: Some("mallory".into()),
        previous_publisher: None,
        removed_previous_version: Some("1.0.0".into()),
        ..mature_meta()
    };
    let issues = issues_for(meta);
    let issue = issues
        .iter()
        .find(|i| i.check == names::METADATA_REMOVED_PREVIOUS_VERSION)
        .expect("removed-previous-version signal");
    assert_eq!(issue.severity, Severity::Error);
}
