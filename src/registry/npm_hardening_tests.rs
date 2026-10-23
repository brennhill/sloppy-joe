//! Regression tests for red-team findings against npm metadata parsing.

use super::*;
use serde_json::json;

fn body_with_versions(time: serde_json::Value, versions: serde_json::Value) -> serde_json::Value {
    json!({
        "time": time,
        "dist-tags": {"latest": "1.0.2"},
        "versions": versions,
    })
}

// ── Finding 9: fully unpublished packages do not exist ──

fn unpublished_body() -> serde_json::Value {
    // Shape served by registry.npmjs.org (HTTP 200) after a full unpublish.
    json!({
        "_id": "gone-pkg",
        "name": "gone-pkg",
        "time": {
            "created": "2020-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "unpublished": {"time": "2024-01-01T00:00:00Z", "versions": ["1.0.0"]}
        }
    })
}

#[test]
fn unpublished_packument_is_not_installable() {
    assert!(is_unpublished_packument(&unpublished_body()));
    let mut empty_versions = unpublished_body();
    empty_versions["versions"] = json!({});
    assert!(is_unpublished_packument(&empty_versions));
    assert!(!is_unpublished_packument(&json!({
        "versions": {"1.0.0": {}}, "time": {"1.0.0": "2020-01-01T00:00:00Z"}
    })));
}

#[test]
fn unpublished_packument_yields_no_metadata() {
    assert!(metadata_from_body(&unpublished_body(), Some("1.0.0")).is_none());
    assert!(metadata_from_body(&unpublished_body(), None).is_none());
}

// ── Finding 4: removed intermediate versions ──

#[test]
fn removed_intermediate_version_does_not_blank_previous_publisher() {
    // npm keeps time[] entries for removed versions.
    let body = body_with_versions(
        json!({"created":"2020-01-01T00:00:00Z","modified":"2024-02-01T00:00:00Z",
               "1.0.0":"2020-01-02T00:00:00Z","1.0.1":"2024-01-01T00:00:00Z","1.0.2":"2024-02-01T00:00:00Z"}),
        json!({
            "1.0.0": {"scripts":{}, "dependencies":{}, "_npmUser":{"name":"alice"}},
            "1.0.2": {"scripts":{}, "dependencies":{"a":"1","b":"1"}, "_npmUser":{"name":"mallory"}}
        }),
    );
    let m = metadata_from_body(&body, Some("1.0.2")).unwrap();
    assert_eq!(m.current_publisher.as_deref(), Some("mallory"));
    assert_eq!(m.previous_publisher.as_deref(), Some("alice"));
    assert_eq!(m.previous_dependency_count, Some(0));
    assert_eq!(m.removed_previous_version.as_deref(), Some("1.0.1"));

    let lookup = crate::checks::metadata::MetadataLookup {
        package: "pkg".into(),
        ecosystem: crate::Ecosystem::Npm,
        version: Some("1.0.2".into()),
        resolved_version: Some("1.0.2".into()),
        unresolved_version: false,
        exists: true,
        metadata: Some(m.clone()),
    };
    assert!(crate::checks::signals::check_maintainer_change(&lookup, &m).is_some());
}

#[test]
fn removed_versions_older_than_previous_existing_version_are_not_reported() {
    let body = body_with_versions(
        json!({"created":"2020-01-01T00:00:00Z","modified":"2024-02-01T00:00:00Z",
               "0.9.0":"2019-12-01T00:00:00Z",
               "1.0.0":"2020-01-02T00:00:00Z","1.0.2":"2024-02-01T00:00:00Z"}),
        json!({
            "1.0.0": {"_npmUser":{"name":"alice"}},
            "1.0.2": {"_npmUser":{"name":"alice"}}
        }),
    );
    let m = metadata_from_body(&body, Some("1.0.2")).unwrap();
    assert_eq!(m.previous_publisher.as_deref(), Some("alice"));
    assert_eq!(m.removed_previous_version, None);
}

#[test]
fn all_earlier_versions_removed_reports_removed_version() {
    let body = body_with_versions(
        json!({"created":"2020-01-01T00:00:00Z","modified":"2024-02-01T00:00:00Z",
               "1.0.0":"2020-01-02T00:00:00Z","1.0.2":"2024-02-01T00:00:00Z"}),
        json!({"1.0.2": {"_npmUser":{"name":"mallory"}}}),
    );
    let m = metadata_from_body(&body, Some("1.0.2")).unwrap();
    assert_eq!(m.previous_publisher, None);
    assert_eq!(m.removed_previous_version.as_deref(), Some("1.0.0"));
}

// ── Finding 3: packument/tarball manifest confusion mitigations ──

fn single_version(version_obj: serde_json::Value) -> serde_json::Value {
    json!({
        "time": {"created":"2020-01-01T00:00:00Z","1.0.0":"2020-01-02T00:00:00Z"},
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": version_obj},
    })
}

#[test]
fn registry_install_flag_without_declared_scripts_is_inconsistent() {
    for version_obj in [
        json!({"hasInstallScript": true, "scripts": {}}),
        json!({"hasInstallScript": true}),
        json!({"hasInstallScript": true, "scripts": {"test": "jest"}}),
    ] {
        let m = metadata_from_body(&single_version(version_obj.clone()), Some("1.0.0")).unwrap();
        assert!(m.has_install_scripts, "{version_obj}");
        assert!(m.manifest_inconsistency.is_some(), "{version_obj}");
    }
}

#[test]
fn declared_lifecycle_scripts_with_negative_registry_flag_are_inconsistent() {
    let m = metadata_from_body(
        &single_version(json!({"hasInstallScript": false, "scripts": {"postinstall": "node x"}})),
        Some("1.0.0"),
    )
    .unwrap();
    assert!(m.has_install_scripts);
    assert!(m.manifest_inconsistency.is_some());
}

#[test]
fn gypfile_implies_install_script() {
    let m = metadata_from_body(
        &single_version(json!({"gypfile": true, "hasInstallScript": true, "scripts": {}})),
        Some("1.0.0"),
    )
    .unwrap();
    assert!(m.has_install_scripts);
    assert_eq!(m.manifest_inconsistency, None);
}

#[test]
fn consistent_manifests_report_no_inconsistency() {
    for version_obj in [
        json!({"hasInstallScript": true, "scripts": {"install": "node-gyp rebuild"}}),
        json!({"scripts": {"postinstall": "node x"}}),
        json!({"scripts": {"test": "jest"}}),
        json!({"hasInstallScript": false, "scripts": {"prepare": "tsc"}}),
    ] {
        let m = metadata_from_body(&single_version(version_obj.clone()), Some("1.0.0")).unwrap();
        assert_eq!(m.manifest_inconsistency, None, "{version_obj}");
    }
}

#[test]
fn version_history_uses_registry_install_flag() {
    let body = json!({
        "time": {"created":"2020-01-01T00:00:00Z", "1.0.0": crate::cache::now_iso8601()},
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {"hasInstallScript": true, "_npmUser": {"name": "a"}}},
    });
    let m = metadata_from_body(&body, Some("1.0.0")).unwrap();
    assert!(m.version_history.iter().all(|r| r.has_install_scripts));
    assert!(!m.version_history.is_empty());
}

// ── Finding 5: downloads API failures must be visible ──

#[test]
fn downloads_non_success_status_is_unavailable() {
    let result = downloads_from_response(reqwest::StatusCode::TOO_MANY_REQUESTS, &json!({}));
    assert!(result.is_err());
}

#[test]
fn downloads_missing_count_is_unavailable() {
    let result = downloads_from_response(reqwest::StatusCode::OK, &json!({"error": "x"}));
    assert!(result.is_err());
}

#[test]
fn downloads_success_returns_count() {
    let result = downloads_from_response(reqwest::StatusCode::OK, &json!({"downloads": 1234}));
    assert_eq!(result.unwrap(), 1234);
}

#[test]
fn failed_downloads_lookup_marks_metadata() {
    let mut meta = crate::registry::PackageMetadata::default();
    apply_downloads(&mut meta, Err(anyhow::anyhow!("connection reset")));
    assert_eq!(meta.downloads, None);
    assert!(meta.downloads_unavailable.is_some());

    let mut meta = crate::registry::PackageMetadata::default();
    apply_downloads(&mut meta, Ok(42));
    assert_eq!(meta.downloads, Some(42));
    assert_eq!(meta.downloads_unavailable, None);
}
