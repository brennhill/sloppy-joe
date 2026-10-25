//! Compare the artifact hashes a Python lockfile records for a package
//! version with the sha256 digests PyPI publishes for that version's files.
//!
//! pip installs whatever artifact matches the lockfile hash, so a hash PyPI
//! does not serve means the lockfile points at an artifact the registry
//! never published (an attacker's file, or a deleted one). A lockfile lists a
//! subset of a version's files (`uv.lock` keeps only the wheels it resolved),
//! so the rule is containment: every recorded sha256 must be one PyPI serves.
//!
//! Fail closed: a recorded hash PyPI does not serve is a blocking
//! `metadata/lockfile-integrity-mismatch`. A public-PyPI entry with no
//! sha256, a lockfile-resolved version with no entry, or a release with no
//! published digests is a blocking `metadata/lockfile-integrity-unverified`.

use super::metadata::MetadataLookup;
use crate::Dependency;
use crate::Ecosystem;
use crate::lockfiles::python_hashes::{PythonLockedSource, normalize_name};
use crate::lockfiles::{ResolutionResult, ResolutionSource};
use crate::names;
use crate::report::{Issue, Severity, sanitize_for_terminal};
use std::collections::{BTreeSet, HashSet};

pub(crate) fn check_python_lockfile_hashes(
    lookups: &[MetadataLookup],
    deps: &[Dependency],
    resolution: &ResolutionResult,
) -> Vec<Issue> {
    let Some(recorded) = resolution.python_hashes.as_deref() else {
        return Vec::new();
    };
    let lockfile_resolved: HashSet<(String, &str)> = deps
        .iter()
        .filter(|dep| dep.ecosystem == Ecosystem::PyPI)
        .filter_map(|dep| {
            let resolved = resolution.resolved_version(dep)?;
            (resolved.source == ResolutionSource::Lockfile).then(|| {
                (
                    normalize_name(dep.package_name()),
                    resolved.version.as_str(),
                )
            })
        })
        .collect();

    let mut seen = HashSet::new();
    let mut issues = Vec::new();
    for lookup in lookups {
        if lookup.ecosystem != Ecosystem::PyPI {
            continue;
        }
        let Some(release) = lookup
            .metadata
            .as_ref()
            .and_then(|meta| meta.pypi_release.as_ref())
        else {
            continue;
        };
        if lookup.resolved_version.as_deref() != Some(release.version.as_str()) {
            continue;
        }
        let package = lookup.package.as_str();
        let version = release.version.as_str();
        if !seen.insert((normalize_name(package), version)) {
            continue;
        }
        let label = format!("{package}=={version}");
        let published: BTreeSet<&str> = release
            .files
            .iter()
            .filter_map(|file| file.sha256.as_deref())
            .collect();

        let Some(entries) = recorded.get(package, version) else {
            if lockfile_resolved.contains(&(normalize_name(package), version)) {
                issues.push(unverified(
                    package,
                    &label,
                    &recorded.lockfile,
                    "the lockfile resolves this version but sloppy-joe found no entry for it",
                ));
            }
            continue;
        };
        for entry in entries {
            let PythonLockedSource::Registry {
                sha256,
                other_algorithms,
            } = &entry.source
            else {
                continue;
            };
            let problem = if sha256.is_empty() {
                let why = if *other_algorithms {
                    "records no sha256 hash (PyPI publishes sha256, so other algorithms cannot be compared)"
                } else {
                    "records no hashes"
                };
                Err(format!("the lockfile entry '{}' {why}", entry.location))
            } else if published.is_empty() {
                Err("PyPI published no sha256 digests for this version".to_string())
            } else {
                let unknown: Vec<&str> = sha256
                    .iter()
                    .map(String::as_str)
                    .filter(|hash| !published.contains(hash))
                    .collect();
                if unknown.is_empty() {
                    Ok(())
                } else {
                    issues.push(mismatch(
                        package,
                        &label,
                        &recorded.lockfile,
                        &entry.location,
                        &unknown,
                    ));
                    break;
                }
            };
            if let Err(reason) = problem {
                issues.push(unverified(package, &label, &recorded.lockfile, &reason));
                break;
            }
        }
    }
    issues
}

fn mismatch(package: &str, label: &str, lockfile: &str, location: &str, unknown: &[&str]) -> Issue {
    let shown: Vec<String> = unknown
        .iter()
        .take(3)
        .map(|hash| format!("sha256:{}", sanitize_for_terminal(hash)))
        .collect();
    let more = unknown.len().saturating_sub(3);
    let suffix = if more > 0 {
        format!(" and {more} more")
    } else {
        String::new()
    };
    Issue::new(package, names::METADATA_LOCKFILE_INTEGRITY_MISMATCH, Severity::Error)
        .message(format!(
            "The {lockfile} entry '{}' for '{label}' records {}{suffix}, which PyPI does not publish for that version. The lockfile points at an artifact the registry never served, and pip installs whatever matches the lockfile hash.",
            sanitize_for_terminal(location),
            shown.join(", ")
        ))
        .fix(format!(
            "Do not install from this lockfile. Find out how the {lockfile} entry for '{label}' changed (review its history), then regenerate it from PyPI and review the diff."
        ))
}

fn unverified(package: &str, label: &str, lockfile: &str, reason: &str) -> Issue {
    Issue::new(package, names::METADATA_LOCKFILE_INTEGRITY_UNVERIFIED, Severity::Error)
        .message(format!(
            "Could not verify that the {lockfile} hashes for '{label}' match PyPI: {}. The lockfile may point at a different artifact than PyPI serves.",
            sanitize_for_terminal(reason)
        ))
        .fix(format!(
            "Regenerate {lockfile} so the entry for '{label}' records PyPI's sha256 hashes, then review the diff."
        ))
}

#[cfg(test)]
#[path = "python_lockfile_hashes_tests.rs"]
mod tests;
