//! Lockfile integrity vs registry packument hashes.

use super::*;
use crate::lockfiles::integrity::{LockedSource, NpmLockfileIntegrity};
use crate::lockfiles::{ResolutionKey, ResolutionSource, ResolvedVersion};
use crate::names;
use crate::registry::PackageMetadata;
use crate::registry::npm_tarball::NpmTarballRef;
use crate::report::Severity;
use std::sync::Arc;

const SHA1_HEX: &str = "4dd7a8ee69d7ca1ebe2f7c3e18c71b3f2d1b6a8c";
const SHA1_SRI: &str = "sha1-Tdeo7mnXyh6+L3w+GMcbPy0baow=";
const OTHER_SHA1_HEX: &str = "0000000000000000000000000000000000000000";

// -- compare ---------------------------------------------------------------

#[test]
fn equal_sha512_matches() {
    assert_eq!(
        compare(Some("sha512-AAAA"), None, Some("sha512-AAAA"), None),
        Comparison::Match("sha512")
    );
}

#[test]
fn different_sha512_mismatches() {
    assert!(matches!(
        compare(Some("sha512-AAAA"), None, Some("sha512-BBBB"), None),
        Comparison::Mismatch {
            algorithm: "sha512",
            ..
        }
    ));
}

#[test]
fn lockfile_sha1_is_compared_with_registry_shasum() {
    assert_eq!(
        compare(Some(SHA1_SRI), None, Some("sha512-AAAA"), Some(SHA1_HEX)),
        Comparison::Match("sha1")
    );
    assert!(matches!(
        compare(
            Some(SHA1_SRI),
            None,
            Some("sha512-AAAA"),
            Some(OTHER_SHA1_HEX)
        ),
        Comparison::Mismatch {
            algorithm: "sha1",
            ..
        }
    ));
}

#[test]
fn uppercase_registry_shasum_is_normalized() {
    assert_eq!(
        compare(
            Some(SHA1_SRI),
            None,
            None,
            Some(&SHA1_HEX.to_ascii_uppercase())
        ),
        Comparison::Match("sha1")
    );
}

#[test]
fn different_algorithms_never_pass() {
    assert!(matches!(
        compare(Some("sha512-AAAA"), None, None, Some(SHA1_HEX)),
        Comparison::NoCommonAlgorithm { .. }
    ));
    assert!(matches!(
        compare(Some(SHA1_SRI), None, Some("sha512-AAAA"), None),
        Comparison::NoCommonAlgorithm { .. }
    ));
    assert!(matches!(
        compare(Some("md5-AAAA"), None, Some("md5-AAAA"), None),
        Comparison::NoCommonAlgorithm { .. }
    ));
    assert!(matches!(
        compare(None, None, Some("sha512-AAAA"), Some(SHA1_HEX)),
        Comparison::NoCommonAlgorithm { .. }
    ));
}

#[test]
fn malformed_registry_shasum_is_not_a_sha1() {
    assert!(matches!(
        compare(Some(SHA1_SRI), None, None, Some("not-hex")),
        Comparison::NoCommonAlgorithm { .. }
    ));
}

#[test]
fn every_shared_algorithm_must_agree() {
    // sha512 agrees but the Yarn resolved-URL SHA-1 does not.
    assert!(matches!(
        compare(
            Some("sha512-AAAA"),
            Some(OTHER_SHA1_HEX),
            Some("sha512-AAAA"),
            Some(SHA1_HEX)
        ),
        Comparison::Mismatch {
            algorithm: "sha1",
            ..
        }
    ));
    assert_eq!(
        compare(
            Some("sha512-AAAA"),
            Some(SHA1_HEX),
            Some("sha512-AAAA"),
            Some(SHA1_HEX)
        ),
        Comparison::Match("sha512")
    );
}

#[test]
fn yarn_resolved_sha1_alone_is_compared_with_shasum() {
    assert_eq!(
        compare(None, Some(SHA1_HEX), Some("sha512-AAAA"), Some(SHA1_HEX)),
        Comparison::Match("sha1")
    );
}

#[test]
fn multi_hash_sri_matches_any_listed_digest() {
    assert_eq!(
        compare(
            Some("sha512-AAAA sha512-CCCC"),
            None,
            Some("sha512-CCCC?opt"),
            None
        ),
        Comparison::Match("sha512")
    );
}

// -- check_lockfile_integrity -----------------------------------------------

fn meta(integrity: Option<&str>, shasum: Option<&str>) -> PackageMetadata {
    PackageMetadata {
        npm_tarball: Some(NpmTarballRef {
            version: "1.0.0".into(),
            tarball: Some("https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz".into()),
            integrity: integrity.map(str::to_string),
            shasum: shasum.map(str::to_string),
            declared: Default::default(),
        }),
        ..Default::default()
    }
}

fn lookup(package: &str, metadata: PackageMetadata) -> MetadataLookup {
    MetadataLookup {
        package: package.into(),
        ecosystem: Ecosystem::Npm,
        version: Some("^1.0.0".into()),
        resolved_version: Some("1.0.0".into()),
        unresolved_version: false,
        exists: true,
        metadata: Some(metadata),
    }
}

fn dep(name: &str) -> Dependency {
    Dependency {
        name: name.into(),
        version: Some("^1.0.0".into()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }
}

fn resolution(
    deps: &[Dependency],
    source: ResolutionSource,
    entries: Vec<(&str, LockedSource)>,
) -> ResolutionResult {
    let mut result = ResolutionResult::default();
    for dep in deps {
        result.exact_versions.insert(
            ResolutionKey::from(dep),
            ResolvedVersion {
                version: "1.0.0".into(),
                source: source.clone(),
            },
        );
    }
    let mut integrity = NpmLockfileIntegrity::new("package-lock.json");
    for (name, locked) in entries {
        integrity.insert(name, "1.0.0", &format!("node_modules/{name}"), locked);
    }
    result.npm_integrity = Some(Arc::new(integrity));
    result
}

fn locked(integrity: &str) -> LockedSource {
    LockedSource::Registry {
        integrity: Some(integrity.into()),
        sha1_hex: None,
    }
}

fn checks(issues: &[Issue]) -> Vec<(&str, &str, Severity)> {
    issues
        .iter()
        .map(|i| (i.package.as_str(), i.check.as_str(), i.severity))
        .collect()
}

#[test]
fn mismatched_lockfile_integrity_blocks() {
    let deps = vec![dep("pkg")];
    let res = resolution(
        &deps,
        ResolutionSource::Lockfile,
        vec![("pkg", locked("sha512-EVIL"))],
    );
    let issues = check_lockfile_integrity(
        &[lookup("pkg", meta(Some("sha512-GOOD"), None))],
        &deps,
        &res,
    );
    assert_eq!(
        checks(&issues),
        vec![(
            "pkg",
            names::METADATA_LOCKFILE_INTEGRITY_MISMATCH,
            Severity::Error
        )]
    );
    let message = &issues[0].message;
    assert!(message.contains("package-lock.json"), "{message}");
    assert!(message.contains("pkg@1.0.0"), "{message}");
    assert!(message.contains("sha512-EVIL"), "{message}");
    assert!(message.contains("sha512-GOOD"), "{message}");
}

#[test]
fn matching_lockfile_integrity_passes() {
    let deps = vec![dep("pkg")];
    let res = resolution(
        &deps,
        ResolutionSource::Lockfile,
        vec![("pkg", locked("sha512-GOOD"))],
    );
    let issues = check_lockfile_integrity(
        &[lookup("pkg", meta(Some("sha512-GOOD"), Some(SHA1_HEX)))],
        &deps,
        &res,
    );
    assert!(issues.is_empty(), "{issues:?}");
}

#[test]
fn any_mismatching_duplicate_entry_blocks() {
    let deps = vec![dep("pkg")];
    let res = resolution(
        &deps,
        ResolutionSource::Lockfile,
        vec![
            ("pkg", locked("sha512-GOOD")),
            ("pkg", locked("sha512-EVIL")),
        ],
    );
    let issues = check_lockfile_integrity(
        &[lookup("pkg", meta(Some("sha512-GOOD"), None))],
        &deps,
        &res,
    );
    assert_eq!(
        checks(&issues),
        vec![(
            "pkg",
            names::METADATA_LOCKFILE_INTEGRITY_MISMATCH,
            Severity::Error
        )]
    );
}

#[test]
fn registry_entry_without_integrity_blocks() {
    let deps = vec![dep("pkg")];
    let res = resolution(
        &deps,
        ResolutionSource::Lockfile,
        vec![(
            "pkg",
            LockedSource::Registry {
                integrity: None,
                sha1_hex: None,
            },
        )],
    );
    let issues = check_lockfile_integrity(
        &[lookup("pkg", meta(Some("sha512-GOOD"), None))],
        &deps,
        &res,
    );
    assert_eq!(
        checks(&issues),
        vec![(
            "pkg",
            names::METADATA_LOCKFILE_INTEGRITY_UNVERIFIED,
            Severity::Error
        )]
    );
}

#[test]
fn no_shared_algorithm_blocks_as_unverified() {
    let deps = vec![dep("pkg")];
    let res = resolution(
        &deps,
        ResolutionSource::Lockfile,
        vec![("pkg", locked("sha512-GOOD"))],
    );
    let issues =
        check_lockfile_integrity(&[lookup("pkg", meta(None, Some(SHA1_HEX)))], &deps, &res);
    assert_eq!(
        checks(&issues),
        vec![(
            "pkg",
            names::METADATA_LOCKFILE_INTEGRITY_UNVERIFIED,
            Severity::Error
        )]
    );
    assert!(
        issues[0].message.contains("sha512"),
        "{}",
        issues[0].message
    );
    assert!(issues[0].message.contains("sha1"), "{}", issues[0].message);
}

#[test]
fn lockfile_resolved_version_without_entry_blocks() {
    let deps = vec![dep("pkg")];
    let res = resolution(&deps, ResolutionSource::Lockfile, vec![]);
    let issues = check_lockfile_integrity(
        &[lookup("pkg", meta(Some("sha512-GOOD"), None))],
        &deps,
        &res,
    );
    assert_eq!(
        checks(&issues),
        vec![(
            "pkg",
            names::METADATA_LOCKFILE_INTEGRITY_UNVERIFIED,
            Severity::Error
        )]
    );
}

#[test]
fn manifest_exact_version_without_entry_is_not_reported_here() {
    let deps = vec![dep("pkg")];
    let res = resolution(&deps, ResolutionSource::ManifestExact, vec![]);
    let issues = check_lockfile_integrity(
        &[lookup("pkg", meta(Some("sha512-GOOD"), None))],
        &deps,
        &res,
    );
    assert!(issues.is_empty(), "{issues:?}");
}

#[test]
fn non_registry_entries_are_not_compared() {
    let deps = vec![dep("pkg")];
    let res = resolution(
        &deps,
        ResolutionSource::Lockfile,
        vec![("pkg", LockedSource::NotRegistry)],
    );
    let issues = check_lockfile_integrity(
        &[lookup("pkg", meta(Some("sha512-GOOD"), None))],
        &deps,
        &res,
    );
    assert!(issues.is_empty(), "{issues:?}");
}

#[test]
fn without_npm_lockfile_integrity_nothing_is_compared() {
    let deps = vec![dep("pkg")];
    let mut res = resolution(&deps, ResolutionSource::Lockfile, vec![]);
    res.npm_integrity = None;
    let issues = check_lockfile_integrity(
        &[lookup("pkg", meta(Some("sha512-GOOD"), None))],
        &deps,
        &res,
    );
    assert!(issues.is_empty(), "{issues:?}");
}

#[test]
fn packument_for_a_different_version_is_not_compared() {
    let deps = vec![dep("pkg")];
    let res = resolution(
        &deps,
        ResolutionSource::Lockfile,
        vec![("pkg", locked("sha512-EVIL"))],
    );
    let mut lookup = lookup("pkg", meta(Some("sha512-GOOD"), None));
    lookup.resolved_version = Some("2.0.0".into());
    let issues = check_lockfile_integrity(&[lookup], &deps, &res);
    assert!(issues.is_empty(), "{issues:?}");
}

#[test]
fn duplicate_lookups_report_once() {
    let deps = vec![dep("pkg")];
    let res = resolution(
        &deps,
        ResolutionSource::Lockfile,
        vec![("pkg", locked("sha512-EVIL"))],
    );
    let issues = check_lockfile_integrity(
        &[
            lookup("pkg", meta(Some("sha512-GOOD"), None)),
            lookup("pkg", meta(Some("sha512-GOOD"), None)),
        ],
        &deps,
        &res,
    );
    assert_eq!(issues.len(), 1, "{issues:?}");
}

#[test]
fn non_npm_lookups_are_ignored() {
    let deps = vec![dep("pkg")];
    let res = resolution(
        &deps,
        ResolutionSource::Lockfile,
        vec![("pkg", locked("sha512-EVIL"))],
    );
    let mut lookup = lookup("pkg", meta(Some("sha512-GOOD"), None));
    lookup.ecosystem = Ecosystem::Cargo;
    assert!(check_lockfile_integrity(&[lookup], &deps, &res).is_empty());
}
