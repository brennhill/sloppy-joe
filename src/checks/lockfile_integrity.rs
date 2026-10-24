//! Compare the integrity an npm-family lockfile records for a package version
//! with the hash the registry packument publishes for that version.
//!
//! The package manager installs whatever artifact matches the lockfile hash.
//! Tarball verification (`checks::tarball_verification`) proves that the
//! registry tarball matches the packument; this check proves that the
//! lockfile points at that same artifact. It runs for every checked npm
//! package that has registry metadata, since the packument is already
//! fetched and no download is needed.
//!
//! Only like is compared with like: an algorithm is compared only when both
//! sides carry it (packument `dist.shasum` counts as SHA-1). Every algorithm
//! both sides carry must agree. When the two sides share no algorithm the
//! version is reported as unverified instead of passing.
//!
//! Fail closed: a disagreement is a blocking
//! `metadata/lockfile-integrity-mismatch`. A registry lockfile entry without
//! integrity, a lockfile-resolved version with no registry entry, or no
//! shared algorithm is a blocking `metadata/lockfile-integrity-unverified`.

use crate::Dependency;
use crate::Ecosystem;
use crate::checks::metadata::MetadataLookup;
use crate::lockfiles::integrity::LockedSource;
use crate::lockfiles::{ResolutionResult, ResolutionSource};
use crate::names;
use crate::registry::npm_tarball::base64_encode;
use crate::report::{Issue, Severity, sanitize_for_terminal};
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// Outcome of comparing one lockfile entry with registry metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Comparison {
    /// Every shared algorithm agrees; carries the strongest one.
    Match(&'static str),
    Mismatch {
        algorithm: &'static str,
        locked: String,
        registry: String,
    },
    NoCommonAlgorithm {
        locked: Vec<&'static str>,
        registry: Vec<&'static str>,
    },
}

/// Supported algorithms, strongest first.
const ALGORITHMS: [&str; 4] = ["sha512", "sha384", "sha256", "sha1"];

/// Base64 digests per supported algorithm.
type Digests = BTreeMap<&'static str, BTreeSet<String>>;

/// Supported entries of an SRI string (`alg-base64[?opts]`, space separated).
/// Unknown algorithms are ignored, so they can never produce a match.
fn sri_digests(sri: &str, into: &mut Digests) {
    for token in sri.split_whitespace() {
        let token = token.split('?').next().unwrap_or(token);
        let Some((algorithm, digest)) = token.split_once('-') else {
            continue;
        };
        let Some(algorithm) = ALGORITHMS.iter().find(|known| **known == algorithm) else {
            continue;
        };
        if !digest.is_empty() {
            into.entry(algorithm)
                .or_default()
                .insert(digest.to_string());
        }
    }
}

/// A 40-character SHA-1 hex digest as SRI base64; anything else is ignored.
fn sha1_hex_digest(hex: &str, into: &mut Digests) {
    let hex = hex.trim();
    if hex.len() != 40 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return;
    }
    let bytes: Vec<u8> = (0..40)
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();
    into.entry("sha1")
        .or_default()
        .insert(base64_encode(&bytes));
}

fn describe(algorithm: &str, digests: &BTreeSet<String>) -> String {
    digests
        .iter()
        .map(|digest| format!("{algorithm}-{digest}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn compare(
    locked_integrity: Option<&str>,
    locked_sha1_hex: Option<&str>,
    registry_integrity: Option<&str>,
    registry_shasum: Option<&str>,
) -> Comparison {
    let mut locked = Digests::new();
    if let Some(sri) = locked_integrity {
        sri_digests(sri, &mut locked);
    }
    if let Some(hex) = locked_sha1_hex {
        sha1_hex_digest(hex, &mut locked);
    }
    let mut registry = Digests::new();
    if let Some(sri) = registry_integrity {
        sri_digests(sri, &mut registry);
    }
    if let Some(hex) = registry_shasum {
        sha1_hex_digest(hex, &mut registry);
    }

    let mut strongest = None;
    for algorithm in ALGORITHMS {
        let (Some(ours), Some(theirs)) = (locked.get(algorithm), registry.get(algorithm)) else {
            continue;
        };
        if ours.is_disjoint(theirs) {
            return Comparison::Mismatch {
                algorithm,
                locked: describe(algorithm, ours),
                registry: describe(algorithm, theirs),
            };
        }
        strongest.get_or_insert(algorithm);
    }
    match strongest {
        Some(algorithm) => Comparison::Match(algorithm),
        None => Comparison::NoCommonAlgorithm {
            locked: locked.keys().copied().collect(),
            registry: registry.keys().copied().collect(),
        },
    }
}

pub(crate) fn check_lockfile_integrity(
    lookups: &[MetadataLookup],
    deps: &[Dependency],
    resolution: &ResolutionResult,
) -> Vec<Issue> {
    let Some(recorded) = resolution.npm_integrity.as_deref() else {
        return Vec::new();
    };
    // Versions the lockfile itself selected: those must have an entry.
    let lockfile_resolved: HashSet<(&str, &str)> = deps
        .iter()
        .filter(|dep| dep.ecosystem == Ecosystem::Npm)
        .filter_map(|dep| {
            let resolved = resolution.resolved_version(dep)?;
            (resolved.source == ResolutionSource::Lockfile)
                .then_some((dep.package_name(), resolved.version.as_str()))
        })
        .collect();

    let mut seen = HashSet::new();
    let mut issues = Vec::new();
    for lookup in lookups {
        if lookup.ecosystem != Ecosystem::Npm {
            continue;
        }
        let Some(reference) = lookup
            .metadata
            .as_ref()
            .and_then(|meta| meta.npm_tarball.as_ref())
        else {
            continue;
        };
        if lookup.resolved_version.as_deref() != Some(reference.version.as_str()) {
            continue;
        }
        let package = lookup.package.as_str();
        let version = reference.version.as_str();
        if !seen.insert((package, version)) {
            continue;
        }
        let label = format!("{package}@{version}");

        let entries: Vec<_> = recorded
            .get(package, version)
            .unwrap_or_default()
            .iter()
            .filter_map(|entry| match &entry.source {
                LockedSource::Registry {
                    integrity,
                    sha1_hex,
                } => Some((entry, integrity, sha1_hex)),
                LockedSource::NotRegistry => None,
            })
            .collect();
        if entries.is_empty() {
            let has_non_registry_entry = recorded.get(package, version).is_some();
            if !has_non_registry_entry && lockfile_resolved.contains(&(package, version)) {
                issues.push(unverified_issue(
                    package,
                    &label,
                    &recorded.lockfile,
                    "the lockfile resolves this version but sloppy-joe found no registry entry with integrity for it",
                ));
            }
            continue;
        }

        for (entry, integrity, sha1_hex) in entries {
            if integrity.is_none() && sha1_hex.is_none() {
                issues.push(unverified_issue(
                    package,
                    &label,
                    &recorded.lockfile,
                    &format!(
                        "the lockfile entry '{}' records no integrity",
                        entry.location
                    ),
                ));
                break;
            }
            match compare(
                integrity.as_deref(),
                sha1_hex.as_deref(),
                reference.integrity.as_deref(),
                reference.shasum.as_deref(),
            ) {
                Comparison::Match(_) => {}
                Comparison::Mismatch {
                    algorithm,
                    locked,
                    registry,
                } => {
                    issues.push(mismatch_issue(
                        package,
                        &label,
                        &recorded.lockfile,
                        &entry.location,
                        algorithm,
                        &locked,
                        &registry,
                    ));
                    break;
                }
                Comparison::NoCommonAlgorithm { locked, registry } => {
                    issues.push(unverified_issue(
                        package,
                        &label,
                        &recorded.lockfile,
                        &format!(
                            "the lockfile entry '{}' records {} but the registry metadata publishes {}; different hash algorithms cannot be compared",
                            entry.location,
                            algorithm_list(&locked),
                            algorithm_list(&registry)
                        ),
                    ));
                    break;
                }
            }
        }
    }
    issues
}

fn algorithm_list(algorithms: &[&str]) -> String {
    if algorithms.is_empty() {
        "no supported hash".to_string()
    } else {
        algorithms.join("/")
    }
}

fn mismatch_issue(
    package: &str,
    label: &str,
    lockfile: &str,
    location: &str,
    algorithm: &str,
    locked: &str,
    registry: &str,
) -> Issue {
    Issue::new(package, names::METADATA_LOCKFILE_INTEGRITY_MISMATCH, Severity::Error)
        .message(format!(
            "The {lockfile} entry '{}' for '{label}' records {algorithm} integrity {}, but the registry metadata for that version publishes {}. The lockfile points at a different artifact than the registry serves, and the package manager installs whatever matches the lockfile.",
            sanitize_for_terminal(location),
            sanitize_for_terminal(locked),
            sanitize_for_terminal(registry)
        ))
        .fix(format!(
            "Do not install from this lockfile. Find out how the {lockfile} entry for '{label}' changed (review its history), then regenerate it from the registry and review the diff."
        ))
}

fn unverified_issue(package: &str, label: &str, lockfile: &str, reason: &str) -> Issue {
    Issue::new(package, names::METADATA_LOCKFILE_INTEGRITY_UNVERIFIED, Severity::Error)
        .message(format!(
            "Could not verify that the {lockfile} integrity for '{label}' matches the registry: {}. The lockfile may point at a different artifact than the registry serves.",
            sanitize_for_terminal(reason)
        ))
        .fix(format!(
            "Regenerate {lockfile} so the entry for '{label}' records the registry's sha512 integrity, then review the diff."
        ))
}

#[cfg(test)]
#[path = "lockfile_integrity_tests.rs"]
mod tests;
