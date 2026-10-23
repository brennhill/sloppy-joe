//! Verify npm packuments against the tarballs npm actually installs.
//!
//! npm does not validate the registry packument against the tarball
//! ("manifest confusion"), yet npm runs the lifecycle scripts in the tarball's
//! own `package.json`. Install-script and dependency-count signals read from
//! the packument alone can therefore be forged. For the npm versions selected
//! here the tarball is fetched, hash-verified and read (see
//! `registry::npm_tarball`); any disagreement is a blocking
//! `metadata/manifest-inconsistency`, and the tarball's values replace the
//! packument's for downstream signals.
//!
//! Selection keeps request volume bounded: a version is verified when it is
//! flagged by any metadata or similarity signal, published within the last 30
//! days (or undated), belongs to a package created within 30 days, has fewer
//! than 1,000 downloads (or unknown downloads), or when policy requires every
//! version (`--paranoid`). At most `max_npm_tarball_verifications` (config,
//! default 100) tarballs are downloaded per scan; verified results are cached
//! by name, version and integrity.
//!
//! Fail closed: a selected version whose tarball cannot be fetched, verified
//! or read, or that falls beyond the per-scan limit, gets a blocking
//! `metadata/tarball-unverified`; a hash mismatch gets a blocking
//! `metadata/tarball-integrity-mismatch`.

use crate::Ecosystem;
use crate::cache;
use crate::checks::metadata::{MetadataLookup, age_in_hours, issues_from_lookups};
use crate::checks::names;
use crate::config::SloppyJoeConfig;
use crate::registry::npm_tarball::{
    IntegrityMismatch, NpmManifestFacts, NpmTarballRef, compare_facts,
};
use crate::registry::{PackageMetadata, Registry};
use crate::report::{Issue, Severity};
use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Per-scan cap on tarball downloads (cache hits do not count).
pub(crate) const DEFAULT_MAX_TARBALL_FETCHES: usize = 100;
const TARBALL_CONCURRENCY: usize = 8;
/// Versions and packages younger than this are always verified.
const RECENT_HOURS: u64 = 30 * 24;
/// Packages with fewer downloads than this are always verified (matches the
/// install-script risk amplifier).
const LOW_DOWNLOADS: u64 = 1_000;
/// Tarball contents are immutable per integrity; entries still expire so the
/// cache does not grow without bound.
const CACHE_TTL_SECS: u64 = 30 * 24 * 3600;

pub(crate) struct TarballVerificationOptions<'a> {
    pub cache_dir: Option<&'a Path>,
    /// Do not read (or write) the disk cache.
    pub no_cache: bool,
    /// Policy requires every npm version with registry metadata be verified.
    pub verify_all: bool,
    pub max_fetches: usize,
}

impl<'a> TarballVerificationOptions<'a> {
    pub(crate) fn from_scan(opts: &crate::ScanOptions<'a>, config: &SloppyJoeConfig) -> Self {
        Self {
            cache_dir: opts.cache_dir,
            no_cache: opts.no_cache,
            verify_all: opts.paranoid,
            max_fetches: config.max_npm_tarball_verifications,
        }
    }
}

pub(crate) fn tarball_cache_path(cache_dir: Option<&Path>) -> PathBuf {
    cache_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| cache::user_cache_dir().join("sloppy-joe"))
        .join("npm-tarball-manifests.json")
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct TarballCache {
    timestamp: u64,
    entries: BTreeMap<String, TarballCacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TarballCacheEntry {
    checked_at: u64,
    facts: NpmManifestFacts,
}

/// One distinct package version to verify, shared by every lookup of it.
struct Unit {
    package: String,
    reference: NpmTarballRef,
    key: Option<String>,
    priority: u8,
    lookups: Vec<usize>,
}

enum Outcome {
    Verified(NpmManifestFacts),
    Failed(Issue),
}

/// Why (and how urgently) a lookup needs verification; `None` = skip.
fn selection_priority(
    lookup: &MetadataLookup,
    meta: &PackageMetadata,
    flagged: &HashSet<String>,
    similarity_flagged: &HashSet<String>,
    verify_all: bool,
) -> Option<u8> {
    if flagged.contains(&lookup.package) || similarity_flagged.contains(&lookup.package) {
        return Some(0);
    }
    let young = |date: Option<&str>| date.and_then(age_in_hours).is_none_or(|h| h < RECENT_HOURS);
    if young(meta.latest_version_date.as_deref())
        || young(meta.created.as_deref())
        || meta.downloads.is_none_or(|d| d < LOW_DOWNLOADS)
    {
        return Some(1);
    }
    verify_all.then_some(2)
}

pub(crate) async fn verify_npm_tarballs(
    registry: &dyn Registry,
    lookups: &mut [MetadataLookup],
    config: &SloppyJoeConfig,
    similarity_flagged: &HashSet<String>,
    options: &TarballVerificationOptions<'_>,
) -> Vec<Issue> {
    let flagged: HashSet<String> = issues_from_lookups(lookups, config, similarity_flagged)
        .into_iter()
        .map(|issue| issue.package)
        .collect();

    let mut units: Vec<Unit> = Vec::new();
    let mut unit_index: HashMap<(String, String), usize> = HashMap::new();
    for (index, lookup) in lookups.iter().enumerate() {
        if lookup.ecosystem != Ecosystem::Npm {
            continue;
        }
        let Some(meta) = lookup.metadata.as_ref() else {
            continue;
        };
        let Some(reference) = meta.npm_tarball.as_ref() else {
            continue;
        };
        let Some(priority) = selection_priority(
            lookup,
            meta,
            &flagged,
            similarity_flagged,
            options.verify_all,
        ) else {
            continue;
        };
        let key = reference.cache_key(&lookup.package);
        let identity = (
            lookup.package.clone(),
            key.clone()
                .unwrap_or_else(|| format!("{}@{}", lookup.package, reference.version)),
        );
        let unit = *unit_index.entry(identity).or_insert_with(|| {
            units.push(Unit {
                package: lookup.package.clone(),
                reference: reference.clone(),
                key,
                priority,
                lookups: Vec::new(),
            });
            units.len() - 1
        });
        units[unit].priority = units[unit].priority.min(priority);
        units[unit].lookups.push(index);
    }
    if units.is_empty() {
        return Vec::new();
    }

    let now = cache::now_epoch();
    let cache_path = tarball_cache_path(options.cache_dir);
    let mut disk_cache = if options.no_cache {
        TarballCache::default()
    } else {
        cache::read_json_cache(&cache_path, CACHE_TTL_SECS, |c: &TarballCache| c.timestamp)
            .unwrap_or_default()
    };
    disk_cache.entries.retain(|_, entry| {
        now.checked_sub(entry.checked_at)
            .is_some_and(|age| age < CACHE_TTL_SECS)
    });

    let mut outcomes: Vec<Option<Outcome>> = (0..units.len()).map(|_| None).collect();
    let mut to_fetch = Vec::new();
    for (index, unit) in units.iter().enumerate() {
        match &unit.key {
            None => {
                outcomes[index] = Some(Outcome::Failed(unverified_issue(
                    unit,
                    "the registry metadata provides no dist.integrity or dist.shasum to verify the tarball against",
                )))
            }
            Some(key) => match disk_cache.entries.get(key) {
                Some(entry) => outcomes[index] = Some(Outcome::Verified(entry.facts.clone())),
                None => to_fetch.push(index),
            },
        }
    }

    to_fetch.sort_by(|a, b| {
        (units[*a].priority, &units[*a].package).cmp(&(units[*b].priority, &units[*b].package))
    });
    let overflow = to_fetch.split_off(to_fetch.len().min(options.max_fetches));
    let selected = to_fetch.len() + overflow.len();
    let skipped = overflow.len();
    for index in overflow {
        outcomes[index] = Some(Outcome::Failed(
            unverified_issue(
                &units[index],
                &format!(
                    "the per-scan tarball verification limit ({}) was reached; {skipped} of {selected} selected npm versions needing a download were not verified",
                    options.max_fetches
                ),
            )
            .fix(
                "Re-run the scan: verified tarballs are cached, so each run verifies more versions. To verify more per scan, raise max_npm_tarball_verifications (up to 1000) in the sloppy-joe config.",
            ),
        ));
    }

    let units_ref = &units;
    let fetched: Vec<_> = stream::iter(to_fetch)
        .map(|index| async move {
            let unit = &units_ref[index];
            let result = registry
                .verify_npm_tarball(&unit.package, &unit.reference)
                .await;
            (index, result)
        })
        .buffer_unordered(TARBALL_CONCURRENCY)
        .collect()
        .await;

    let mut cache_dirty = false;
    for (index, result) in fetched {
        let unit = &units[index];
        outcomes[index] = Some(match result {
            Ok(Some(facts)) => {
                if let Some(key) = &unit.key {
                    disk_cache.entries.insert(
                        key.clone(),
                        TarballCacheEntry {
                            checked_at: now,
                            facts: facts.clone(),
                        },
                    );
                    cache_dirty = true;
                }
                Outcome::Verified(facts)
            }
            Ok(None) => Outcome::Failed(unverified_issue(
                unit,
                "this registry client cannot download npm tarballs",
            )),
            Err(err) => match err.downcast_ref::<IntegrityMismatch>() {
                Some(mismatch) => Outcome::Failed(integrity_issue(unit, &mismatch.0)),
                None => Outcome::Failed(unverified_issue(unit, &format!("{err:#}"))),
            },
        });
    }

    if cache_dirty && !options.no_cache {
        disk_cache.timestamp = now;
        cache::atomic_write_json(&cache_path, &disk_cache);
    }

    let mut issues = Vec::new();
    for (unit, outcome) in units.iter().zip(outcomes) {
        match outcome {
            Some(Outcome::Verified(facts)) => {
                let differences = compare_facts(&unit.reference.declared, &facts);
                if !differences.is_empty() {
                    issues.push(inconsistency_issue(unit, &differences));
                }
                for &index in &unit.lookups {
                    if let Some(meta) = lookups[index].metadata.as_mut() {
                        apply_tarball_facts(meta, &unit.reference.version, &facts);
                    }
                }
            }
            Some(Outcome::Failed(issue)) => issues.push(issue),
            None => issues.push(unverified_issue(unit, "verification did not run")),
        }
    }
    issues
}

/// The tarball is the source of truth for install-script and dependency
/// signals. Install scripts are only ever added, never cleared.
fn apply_tarball_facts(meta: &mut PackageMetadata, version: &str, facts: &NpmManifestFacts) {
    let has_scripts = facts.has_install_scripts();
    meta.has_install_scripts |= has_scripts;
    meta.dependency_count = Some(facts.dependencies.len() as u64);
    for record in meta
        .version_history
        .iter_mut()
        .filter(|record| record.version == version)
    {
        record.has_install_scripts |= has_scripts;
    }
}

fn label(unit: &Unit) -> String {
    format!("{}@{}", unit.package, unit.reference.version)
}

fn inconsistency_issue(unit: &Unit, differences: &[String]) -> Issue {
    Issue::new(&unit.package, names::METADATA_MANIFEST_INCONSISTENCY, Severity::Error)
        .message(format!(
            "The registry metadata for '{}' does not match the package tarball: {}. npm does not validate published metadata against the tarball (manifest confusion) and runs the scripts in the tarball's package.json.",
            label(unit),
            differences.join("; ")
        ))
        .fix(format!(
            "Do not install this version until the tarball has been reviewed (npm pack {} and inspect package/package.json).",
            label(unit)
        ))
}

fn integrity_issue(unit: &Unit, detail: &str) -> Issue {
    Issue::new(&unit.package, names::METADATA_TARBALL_INTEGRITY, Severity::Error)
        .message(format!(
            "The tarball downloaded for '{}' does not match the registry's integrity hash ({}). It may have been tampered with in transit or the registry metadata is inconsistent.",
            label(unit),
            detail
        ))
        .fix("Retry the scan. If the mismatch persists, do not install this version and report it to the registry.")
}

fn unverified_issue(unit: &Unit, reason: &str) -> Issue {
    Issue::new(&unit.package, names::METADATA_TARBALL_UNVERIFIED, Severity::Error)
        .message(format!(
            "Could not verify the tarball of '{}' against its registry metadata: {}. Without it, install-script and dependency signals rely on unverified publisher-supplied metadata.",
            label(unit),
            reason
        ))
        .fix("Retry the scan when the registry is reachable. Verified tarballs are cached, so repeated scans also progress past the per-scan limit.")
}

#[cfg(test)]
#[path = "tarball_verification_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tarball_cap_tests.rs"]
mod cap_tests;
