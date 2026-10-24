//! Python lockfile hashes vs PyPI's published digests.

use super::*;
use crate::lockfiles::python_hashes::PythonLockfileHashes;
use crate::lockfiles::{ResolutionKey, ResolvedVersion};
use crate::registry::PackageMetadata;
use crate::registry::pypi_release::{PypiFile, PypiFileKind, PypiRelease};
use std::sync::Arc;

fn lookup(package: &str, published: &[&str]) -> MetadataLookup {
    let files = published
        .iter()
        .enumerate()
        .map(|(i, sha)| PypiFile {
            filename: format!("f{i}.whl"),
            url: format!("https://files/f{i}.whl"),
            sha256: Some((*sha).to_string()),
            kind: PypiFileKind::Wheel,
            size: None,
            yanked: false,
        })
        .collect();
    MetadataLookup {
        package: package.into(),
        ecosystem: Ecosystem::PyPI,
        version: Some("==1.0".into()),
        resolved_version: Some("1.0".into()),
        unresolved_version: false,
        exists: true,
        metadata: Some(PackageMetadata {
            pypi_release: Some(PypiRelease {
                version: "1.0".into(),
                files,
            }),
            ..Default::default()
        }),
    }
}

fn dep(name: &str) -> Dependency {
    Dependency {
        name: name.into(),
        version: Some("==1.0".into()),
        ecosystem: Ecosystem::PyPI,
        actual_name: None,
    }
}

fn registry(hashes: &[&str], other: bool) -> PythonLockedSource {
    PythonLockedSource::Registry {
        sha256: hashes.iter().map(|h| h.to_string()).collect(),
        other_algorithms: other,
    }
}

fn resolution(
    deps: &[Dependency],
    source: ResolutionSource,
    entries: Vec<(&str, PythonLockedSource)>,
) -> ResolutionResult {
    let mut result = ResolutionResult::default();
    for dep in deps {
        result.exact_versions.insert(
            ResolutionKey::from(dep),
            ResolvedVersion {
                version: "1.0".into(),
                source: source.clone(),
            },
        );
    }
    let mut hashes = PythonLockfileHashes::new("poetry.lock");
    for (name, locked) in entries {
        hashes.insert(name, "1.0", format!("{name} 1.0"), locked);
    }
    result.python_hashes = Some(Arc::new(hashes));
    result
}

fn run(
    lookups: Vec<MetadataLookup>,
    deps: Vec<Dependency>,
    entries: Vec<(&str, PythonLockedSource)>,
) -> Vec<Issue> {
    let resolution = resolution(&deps, ResolutionSource::Lockfile, entries);
    check_python_lockfile_hashes(&lookups, &deps, &resolution)
}

#[test]
fn locked_hashes_that_pypi_serves_pass() {
    let issues = run(
        vec![lookup("requests", &["aa", "bb", "cc"])],
        vec![dep("requests")],
        vec![("requests", registry(&["aa", "cc"], false))],
    );
    assert!(issues.is_empty(), "{issues:?}");
}

#[test]
fn a_hash_pypi_never_served_is_a_blocking_mismatch() {
    let issues = run(
        vec![lookup("requests", &["aa", "bb"])],
        vec![dep("requests")],
        vec![("requests", registry(&["aa", "evil"], false))],
    );
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].check, "metadata/lockfile-integrity-mismatch");
    assert_eq!(issues[0].severity, Severity::Error);
    assert!(issues[0].message.contains("sha256:evil"));
    assert!(!issues[0].message.contains("sha256:aa"));
}

#[test]
fn name_spelling_differences_still_match_the_entry() {
    let issues = run(
        vec![lookup("Typing_Extensions", &["aa"])],
        vec![dep("Typing_Extensions")],
        vec![("typing-extensions", registry(&["zz"], false))],
    );
    assert_eq!(issues[0].check, "metadata/lockfile-integrity-mismatch");
}

#[test]
fn entry_with_no_hashes_is_unverified() {
    let issues = run(
        vec![lookup("requests", &["aa"])],
        vec![dep("requests")],
        vec![("requests", registry(&[], false))],
    );
    assert_eq!(issues[0].check, "metadata/lockfile-integrity-unverified");
    assert!(issues[0].message.contains("records no hashes"));
}

#[test]
fn only_non_sha256_hashes_are_unverified() {
    let issues = run(
        vec![lookup("requests", &["aa"])],
        vec![dep("requests")],
        vec![("requests", registry(&[], true))],
    );
    assert_eq!(issues[0].check, "metadata/lockfile-integrity-unverified");
    assert!(issues[0].message.contains("no sha256"));
}

#[test]
fn release_without_published_digests_is_unverified_not_passed() {
    let mut l = lookup("requests", &["aa"]);
    for file in &mut l.metadata.as_mut().unwrap().pypi_release.as_mut().unwrap().files {
        file.sha256 = None;
    }
    let issues = run(
        vec![l],
        vec![dep("requests")],
        vec![("requests", registry(&["aa"], false))],
    );
    assert_eq!(issues[0].check, "metadata/lockfile-integrity-unverified");
}

#[test]
fn lockfile_resolved_version_without_an_entry_is_unverified() {
    let issues = run(vec![lookup("requests", &["aa"])], vec![dep("requests")], vec![]);
    assert_eq!(issues[0].check, "metadata/lockfile-integrity-unverified");
    assert!(issues[0].message.contains("no entry"));
}

#[test]
fn manifest_pinned_version_without_an_entry_is_not_this_checks_business() {
    let deps = vec![dep("requests")];
    let resolution = resolution(&deps, ResolutionSource::ManifestExact, vec![]);
    let issues = check_python_lockfile_hashes(&[lookup("requests", &["aa"])], &deps, &resolution);
    assert!(issues.is_empty());
}

#[test]
fn non_registry_entries_are_left_to_source_policy() {
    let issues = run(
        vec![lookup("internal", &["aa"])],
        vec![dep("internal")],
        vec![("internal", PythonLockedSource::NotRegistry)],
    );
    assert!(issues.is_empty());
}

#[test]
fn no_python_lockfile_means_no_findings() {
    let deps = vec![dep("requests")];
    let mut resolution = resolution(&deps, ResolutionSource::Lockfile, vec![]);
    resolution.python_hashes = None;
    assert!(check_python_lockfile_hashes(&[lookup("requests", &["aa"])], &deps, &resolution).is_empty());
}

#[test]
fn many_unknown_hashes_are_summarized() {
    let issues = run(
        vec![lookup("requests", &["aa"])],
        vec![dep("requests")],
        vec![("requests", registry(&["b1", "b2", "b3", "b4", "b5"], false))],
    );
    assert!(issues[0].message.contains("and 2 more"));
}
