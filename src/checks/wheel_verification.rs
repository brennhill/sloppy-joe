//! Inspect the PyPI wheels of selected versions for Python startup hooks.
//!
//! A wheel can install `*.pth` lines starting with `import`, `*.pth` directory
//! lines (searched for `sitecustomize`), `*.start` entry points (Python 3.15),
//! or a `sitecustomize`/`usercustomize` module, at the top of `site-packages`.
//! Python runs those at every interpreter start, before any application
//! code, so a compromised release does not need an install script or an
//! import of the package. Metadata cannot show this; the wheel must be read
//! (see `registry::wheel`: downloaded into memory, sha256-checked against
//! PyPI's published digest, never extracted).
//!
//! Selection keeps downloads bounded: a version is inspected when it is
//! flagged by name similarity, published within the last 30 days (or undated),
//! belongs to a package created within 30 days, or when policy requires every
//! version (`--paranoid`). At most `MAX_WHEEL_FETCHES` wheels are downloaded
//! per scan (cache hits do not count) and `MAX_WHEELS_PER_VERSION` per version.
//!
//! Fail closed: a selected wheel that cannot be fetched, verified or read, or
//! that falls beyond a limit, gives a blocking `metadata/wheel-unverified`; a
//! digest mismatch gives a blocking `metadata/wheel-integrity-mismatch`.
//!
//! A `<dist>.data/` file installed outside `site-packages`, into the standard
//! library or over the interpreter or activation scripts, is reported the same
//! way.
//!
//! A hook is `metadata/python-startup-hook`. Legitimate packages ship some
//! (namespace packages, `distutils-precedence.pth`), so a hook blocks when the
//! version is young or flagged, is a `sitecustomize` module or an overwrite
//! outside `site-packages`, could not be read, or runs code that spawns
//! processes or reaches the network; otherwise (a `--paranoid` look at an
//! established version) it is a warning.

use super::metadata::{MetadataLookup, age_in_hours};
use crate::Ecosystem;
use crate::cache;
use crate::lockfiles::python_hashes::normalize_name;
use crate::names;
use crate::registry::Registry;
use crate::registry::npm_tarball::IntegrityMismatch;
use crate::registry::pypi_release::{PypiFile, PypiFileKind};
use crate::registry::wheel::{HookKind, StartupHook, WheelFacts};
use crate::report::{Issue, Severity, sanitize_for_terminal};
use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Per-scan cap on wheel downloads (cache hits do not count).
pub(crate) const MAX_WHEEL_FETCHES: usize = 60;
/// Wheels inspected per version; a release can carry dozens (one per platform).
pub(crate) const MAX_WHEELS_PER_VERSION: usize = 32;
const WHEEL_CONCURRENCY: usize = 4;
/// Versions and packages younger than this are always inspected.
const RECENT_HOURS: u64 = 30 * 24;
/// Wheel contents are immutable per sha256; entries still expire.
const CACHE_TTL_SECS: u64 = 30 * 24 * 3600;
/// Hook code containing any of these runs processes or reaches the network.
const SUSPICIOUS_TOKENS: [&str; 12] = [
    "subprocess",
    "os.system",
    "popen",
    "exec(",
    "eval(",
    "base64",
    "urllib",
    "socket",
    "http",
    "ctypes",
    "marshal",
    "zlib",
];

pub(crate) struct WheelVerificationOptions<'a> {
    pub cache_dir: Option<&'a Path>,
    pub no_cache: bool,
    /// Policy requires every PyPI version with release data be inspected.
    pub verify_all: bool,
}

impl<'a> WheelVerificationOptions<'a> {
    pub(crate) fn from_scan(opts: &crate::ScanOptions<'a>) -> Self {
        Self {
            cache_dir: opts.cache_dir,
            no_cache: opts.no_cache,
            verify_all: opts.paranoid,
        }
    }
}

fn cache_path(cache_dir: Option<&Path>) -> PathBuf {
    cache_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| cache::user_cache_dir().join("sloppy-joe"))
        .join("python-wheel-hooks.json")
}

/// Version of what `registry::wheel::inspect_wheel` detects. A cache written by
/// an older inspector is discarded: a wheel it read as clean may hold a hook
/// the current one finds. Bump whenever detection widens.
const WHEEL_CACHE_FORMAT: u32 = 4;

#[derive(Debug, Default, Serialize, Deserialize)]
struct WheelCache {
    /// Absent (0) in caches written before the format was recorded.
    #[serde(default)]
    format: u32,
    timestamp: u64,
    entries: BTreeMap<String, WheelCacheEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WheelCacheEntry {
    checked_at: u64,
    facts: WheelFacts,
}

/// One package version whose wheels are inspected, shared by its lookups.
struct Unit {
    package: String,
    version: String,
    wheels: Vec<PypiFile>,
    /// Wheels beyond `MAX_WHEELS_PER_VERSION`, never inspected.
    over_cap: usize,
    priority: u8,
    lookups: Vec<usize>,
}

enum FileOutcome {
    Facts(WheelFacts),
    Integrity(String),
    Failed(String),
}

fn selection_priority(
    lookup: &MetadataLookup,
    similarity_flagged: &HashSet<String>,
    verify_all: bool,
) -> Option<u8> {
    let meta = lookup.metadata.as_ref()?;
    if similarity_flagged.contains(&lookup.package) {
        return Some(0);
    }
    let young = |date: Option<&str>| date.and_then(age_in_hours).is_none_or(|h| h < RECENT_HOURS);
    if young(meta.latest_version_date.as_deref()) || young(meta.created.as_deref()) {
        return Some(1);
    }
    verify_all.then_some(2)
}

fn collect_units(
    lookups: &[MetadataLookup],
    similarity_flagged: &HashSet<String>,
    verify_all: bool,
) -> Vec<Unit> {
    let mut units: Vec<Unit> = Vec::new();
    let mut by_identity: HashMap<(String, String), usize> = HashMap::new();
    for (index, lookup) in lookups.iter().enumerate() {
        if lookup.ecosystem != Ecosystem::PyPI || lookup.unresolved_version {
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
        let Some(priority) = selection_priority(lookup, similarity_flagged, verify_all) else {
            continue;
        };
        let wheels: Vec<PypiFile> = release
            .files
            .iter()
            .filter(|file| file.kind == PypiFileKind::Wheel)
            .cloned()
            .collect();
        if wheels.is_empty() {
            continue;
        }
        let identity = (normalize_name(&lookup.package), release.version.clone());
        let unit = *by_identity.entry(identity).or_insert_with(|| {
            let over_cap = wheels.len().saturating_sub(MAX_WHEELS_PER_VERSION);
            units.push(Unit {
                package: lookup.package.clone(),
                version: release.version.clone(),
                wheels: wheels.into_iter().take(MAX_WHEELS_PER_VERSION).collect(),
                over_cap,
                priority,
                lookups: Vec::new(),
            });
            units.len() - 1
        });
        units[unit].priority = units[unit].priority.min(priority);
        units[unit].lookups.push(index);
    }
    units
}

fn load_cache(path: &Path, no_cache: bool, now: u64) -> WheelCache {
    let mut loaded = if no_cache {
        WheelCache::default()
    } else {
        cache::read_json_cache(path, CACHE_TTL_SECS, |c: &WheelCache| c.timestamp)
            .filter(|c: &WheelCache| c.format == WHEEL_CACHE_FORMAT)
            .unwrap_or_default()
    };
    loaded.format = WHEEL_CACHE_FORMAT;
    loaded.entries.retain(|_, entry| {
        now.checked_sub(entry.checked_at)
            .is_some_and(|age| age < CACHE_TTL_SECS)
    });
    loaded
}

/// Files to download: distinct by sha256, most urgent unit first, capped.
/// Files with no published digest fail immediately (unhashed bytes are never read).
fn plan_downloads(
    units: &[Unit],
    cached: &WheelCache,
    outcomes: &mut HashMap<String, FileOutcome>,
) -> (Vec<PypiFile>, usize) {
    let mut priority_of: BTreeMap<String, (u8, String, PypiFile)> = BTreeMap::new();
    for unit in units {
        for file in &unit.wheels {
            let Some(sha) = file.sha256.as_deref() else {
                continue;
            };
            if let Some(entry) = cached.entries.get(sha) {
                outcomes.insert(sha.to_string(), FileOutcome::Facts(entry.facts.clone()));
                continue;
            }
            let candidate = (unit.priority, unit.package.clone(), file.clone());
            priority_of
                .entry(sha.to_string())
                .and_modify(|best| {
                    if candidate.0 < best.0 {
                        *best = candidate.clone();
                    }
                })
                .or_insert(candidate);
        }
    }
    let mut jobs: Vec<(u8, String, PypiFile)> = priority_of.into_values().collect();
    jobs.sort_by(|a, b| (a.0, &a.1, &a.2.filename).cmp(&(b.0, &b.1, &b.2.filename)));
    let overflow = jobs.len().saturating_sub(MAX_WHEEL_FETCHES);
    jobs.truncate(MAX_WHEEL_FETCHES);
    (
        jobs.into_iter().map(|(_, _, file)| file).collect(),
        overflow,
    )
}

fn classify(result: anyhow::Result<Option<WheelFacts>>) -> FileOutcome {
    match result {
        Ok(Some(facts)) => FileOutcome::Facts(facts),
        Ok(None) => FileOutcome::Failed("this registry client cannot download wheels".into()),
        Err(err) => match err.downcast_ref::<IntegrityMismatch>() {
            Some(mismatch) => FileOutcome::Integrity(mismatch.0.clone()),
            None => FileOutcome::Failed(format!("{err:#}")),
        },
    }
}

pub(crate) async fn inspect_python_wheels(
    registry: &dyn Registry,
    lookups: &mut [MetadataLookup],
    similarity_flagged: &HashSet<String>,
    options: &WheelVerificationOptions<'_>,
) -> Vec<Issue> {
    let units = collect_units(lookups, similarity_flagged, options.verify_all);
    if units.is_empty() {
        return Vec::new();
    }
    let now = cache::now_epoch();
    let path = cache_path(options.cache_dir);
    let mut disk_cache = load_cache(&path, options.no_cache, now);

    let mut outcomes: HashMap<String, FileOutcome> = HashMap::new();
    let (jobs, overflow) = plan_downloads(&units, &disk_cache, &mut outcomes);
    let owners: HashMap<String, String> = units
        .iter()
        .flat_map(|unit| {
            unit.wheels
                .iter()
                .map(|f| (f.url.clone(), unit.package.clone()))
        })
        .collect();
    let fetched: Vec<_> = stream::iter(jobs)
        .map(|file| {
            let package = owners.get(&file.url).cloned().unwrap_or_default();
            async move {
                let result = registry.inspect_pypi_wheel(&package, &file).await;
                (file, result)
            }
        })
        .buffer_unordered(WHEEL_CONCURRENCY)
        .collect()
        .await;

    let mut dirty = false;
    for (file, result) in fetched {
        let Some(sha) = file.sha256.clone() else {
            continue;
        };
        if let Ok(Some(facts)) = &result {
            disk_cache.entries.insert(
                sha.clone(),
                WheelCacheEntry {
                    checked_at: now,
                    facts: facts.clone(),
                },
            );
            dirty = true;
        }
        outcomes.insert(sha, classify(result));
    }
    if dirty && !options.no_cache {
        disk_cache.timestamp = now;
        cache::atomic_write_json(&path, &disk_cache);
    }
    apply_outcomes(&units, &outcomes, overflow, lookups)
}

fn apply_outcomes(
    units: &[Unit],
    outcomes: &HashMap<String, FileOutcome>,
    overflow: usize,
    lookups: &mut [MetadataLookup],
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for unit in units {
        let report = unit_report(unit, outcomes);
        issues.extend(report.integrity.iter().map(|d| integrity_issue(unit, d)));
        let mut problems = report.problems;
        if unit.over_cap > 0 {
            problems.insert(format!(
                "the release has more than {MAX_WHEELS_PER_VERSION} wheels; {} were not inspected",
                unit.over_cap
            ));
        }
        if report.not_downloaded && overflow > 0 {
            problems.insert(format!(
                "the per-scan wheel limit ({MAX_WHEEL_FETCHES}) was reached; {overflow} wheels were not inspected"
            ));
        }
        if !problems.is_empty() {
            issues.push(unverified_issue(unit, &problems));
        }
        if !report.hooks.is_empty() {
            issues.push(hook_issue(unit, &report.hooks));
            for &index in &unit.lookups {
                if let Some(meta) = lookups[index].metadata.as_mut() {
                    meta.has_install_scripts = true;
                }
            }
        }
    }
    issues
}

struct UnitReport {
    hooks: Vec<StartupHook>,
    integrity: BTreeSet<String>,
    problems: BTreeSet<String>,
    /// Some wheel had no outcome because it was never downloaded.
    not_downloaded: bool,
}

fn unit_report(unit: &Unit, outcomes: &HashMap<String, FileOutcome>) -> UnitReport {
    let mut report = UnitReport {
        hooks: Vec::new(),
        integrity: BTreeSet::new(),
        problems: BTreeSet::new(),
        not_downloaded: false,
    };
    let mut seen_hooks = BTreeSet::new();
    for file in &unit.wheels {
        let Some(sha) = file.sha256.as_deref() else {
            report.problems.insert(format!(
                "PyPI publishes no sha256 digest for {}",
                file.filename
            ));
            continue;
        };
        match outcomes.get(sha) {
            Some(FileOutcome::Facts(facts)) => {
                for hook in &facts.startup_hooks {
                    if seen_hooks.insert((hook.path.clone(), hook.code.clone())) {
                        report.hooks.push(hook.clone());
                    }
                }
            }
            Some(FileOutcome::Integrity(detail)) => {
                report
                    .integrity
                    .insert(format!("{}: {detail}", file.filename));
            }
            Some(FileOutcome::Failed(reason)) => {
                report
                    .problems
                    .insert(format!("{}: {reason}", file.filename));
            }
            None => report.not_downloaded = true,
        }
    }
    report
}

fn hook_is_suspicious(hook: &StartupHook) -> bool {
    hook.unreadable.is_some()
        || matches!(
            hook.kind,
            HookKind::CustomizeModule | HookKind::StdlibOverwrite | HookKind::EnvironmentOverwrite
        )
        || hook.code.iter().any(|line| {
            let lower = line.to_ascii_lowercase();
            SUSPICIOUS_TOKENS.iter().any(|token| lower.contains(token))
        })
}

fn describe_hook(hook: &StartupHook) -> String {
    let path = sanitize_for_terminal(&hook.path);
    if let Some(reason) = &hook.unreadable {
        return format!("{path} (unreadable: {})", sanitize_for_terminal(reason));
    }
    let Some(line) = hook.code.first().map(|l| sanitize_for_terminal(l)) else {
        return match hook.kind {
            HookKind::StdlibOverwrite => format!(
                "{path} (installed outside site-packages, where it replaces or shadows a standard library module)"
            ),
            HookKind::EnvironmentOverwrite => format!(
                "{path} (installed outside site-packages, where it replaces the interpreter, a shared library it loads, its configuration or an activation script)"
            ),
            _ => format!("{path} (runs at every interpreter start)"),
        };
    };
    match hook.kind {
        HookKind::PthPath => format!(
            "{path} adds '{line}' to sys.path, where a sitecustomize/usercustomize module runs at startup"
        ),
        HookKind::StartEntryPoint => format!("{path} calls {line} at startup"),
        HookKind::PthImport
        | HookKind::CustomizeModule
        | HookKind::StdlibOverwrite
        | HookKind::EnvironmentOverwrite => format!("{path}: {line}"),
    }
}

fn label(unit: &Unit) -> String {
    format!("{}=={}", unit.package, unit.version)
}

fn hook_issue(unit: &Unit, hooks: &[StartupHook]) -> Issue {
    let blocking = unit.priority <= 1 || hooks.iter().any(hook_is_suspicious);
    let severity = if blocking {
        Severity::Error
    } else {
        Severity::Warning
    };
    let listed: Vec<String> = hooks.iter().take(3).map(describe_hook).collect();
    let more = hooks.len().saturating_sub(3);
    let suffix = if more > 0 {
        format!(" (+{more} more)")
    } else {
        String::new()
    };
    Issue::new(&unit.package, names::METADATA_PYTHON_STARTUP_HOOK, severity)
        .message(format!(
            "A wheel of '{}' installs code that Python runs before any application code, at interpreter start or in place of the standard library or interpreter: {}{suffix}. Compromised releases (LiteLLM 1.82.8, the Hades campaign) used startup hooks to run without being imported.",
            label(unit),
            listed.join("; ")
        ))
        .fix(format!(
            "Unpack the wheel (pip download {} --no-deps, then unzip) and review the hook before installing. Pin to a version you have reviewed if this one is not expected to ship it.",
            label(unit)
        ))
}

fn unverified_issue(unit: &Unit, problems: &BTreeSet<String>) -> Issue {
    let shown: Vec<&str> = problems.iter().take(3).map(String::as_str).collect();
    Issue::new(&unit.package, names::METADATA_WHEEL_UNVERIFIED, Severity::Error)
        .message(format!(
            "Could not inspect every wheel of '{}' for Python startup hooks: {}. A hook in an uninspected wheel would run at every interpreter start.",
            label(unit),
            sanitize_for_terminal(&shown.join("; "))
        ))
        .fix("Retry the scan when PyPI is reachable. Inspected wheels are cached, so repeated scans progress past the per-scan limit.")
}

fn integrity_issue(unit: &Unit, detail: &str) -> Issue {
    Issue::new(&unit.package, names::METADATA_WHEEL_INTEGRITY, Severity::Error)
        .message(format!(
            "A wheel downloaded for '{}' does not match the sha256 PyPI published ({}). It may have been tampered with in transit or the registry metadata is inconsistent.",
            label(unit),
            sanitize_for_terminal(detail)
        ))
        .fix("Retry the scan. If the mismatch persists, do not install this version and report it to PyPI.")
}

#[cfg(test)]
#[path = "wheel_verification_tests.rs"]
mod tests;
