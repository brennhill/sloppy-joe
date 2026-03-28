#![forbid(unsafe_code)]

pub(crate) mod cache;
pub mod checks;
pub mod ecosystem;
pub use ecosystem::Ecosystem;
pub mod config;
pub(crate) mod lockfiles;
pub mod parsers;
pub mod registry;
pub mod report;
mod version;

use anyhow::Result;
use checks::malicious::OsvClient;
use registry::Registry;
use report::{Issue, ScanReport, Severity};

/// Run all checks on the detected or specified project type.
///
/// `config_path` must point to a file outside the project directory.
/// If None, only existence and similarity checks run (no canonical check).
///
/// Three tiers of packages:
/// - **internal**: skip ALL checks (your org's packages, change constantly)
/// - **allowed**: skip existence + similarity, still subject to canonical + age gate
/// - **everything else**: full checks
///
/// Run all checks, loading config from a file path or URL.
/// Prefer this over `scan()` — it supports `--config https://...`.
pub async fn scan_with_source(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config_source: Option<&str>,
    deep: bool,
) -> Result<ScanReport> {
    scan_with_source_full(
        project_dir,
        project_type,
        config_source,
        deep,
        false,
        false,
        None,
    )
    .await
}

/// Warm the cache by running a full scan without the manifest hash skip.
/// Returns the report so callers can show how many packages were indexed.
pub async fn warm_cache(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config_source: Option<&str>,
    deep: bool,
    paranoid: bool,
    cache_dir: Option<&std::path::Path>,
) -> Result<ScanReport> {
    let config = config::load_config_from_source(config_source, Some(project_dir))
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let opts = ScanOptions {
        deep,
        paranoid,
        no_cache: false,
        cache_dir,
        disable_osv_disk_cache: false,
        skip_hash_check: true,
    };
    scan_with_config(project_dir, project_type, config, &opts).await
}

pub async fn scan_with_source_full(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config_source: Option<&str>,
    deep: bool,
    paranoid: bool,
    no_cache: bool,
    cache_dir: Option<&std::path::Path>,
) -> Result<ScanReport> {
    let config = config::load_config_from_source(config_source, Some(project_dir))
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let opts = ScanOptions {
        deep,
        paranoid,
        no_cache,
        cache_dir,
        disable_osv_disk_cache: false,
        skip_hash_check: false,
    };
    scan_with_config(project_dir, project_type, config, &opts).await
}

pub async fn scan(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config_path: Option<&std::path::Path>,
) -> Result<ScanReport> {
    let config = config::load_config_with_project(config_path, Some(project_dir))
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    scan_with_config(project_dir, project_type, config, &ScanOptions::default()).await
}

/// Compute a hash of dependency tuples + lockfile content for change detection.
/// Includes lockfile so that resolved version changes (e.g., a compromised upstream
/// version satisfying the same range) invalidate the cache even when the manifest
/// is unchanged.
fn scan_hash(project_dir: &std::path::Path, deps: &[Dependency]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();

    // Hash sorted dep tuples (manifest content)
    let mut tuples: Vec<(&str, Option<&str>, &str)> = deps
        .iter()
        .map(|d| (d.name.as_str(), d.version.as_deref(), d.ecosystem.as_str()))
        .collect();
    tuples.sort();
    tuples.hash(&mut hasher);

    // Hash lockfile content (resolved versions) — catches upstream version changes
    for lockfile in &[
        "package-lock.json",
        "npm-shrinkwrap.json",
        "Cargo.lock",
        "Gemfile.lock",
        "poetry.lock",
    ] {
        let path = project_dir.join(lockfile);
        if let Ok(content) = std::fs::read(&path) {
            lockfile.hash(&mut hasher);
            content.hash(&mut hasher);
        }
    }

    hasher.finish()
}

/// Cache entry for manifest hash skip.
#[derive(serde::Serialize, serde::Deserialize)]
struct ScanHashCache {
    timestamp: u64,
    hash: u64,
}

async fn scan_with_config(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config: config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> Result<ScanReport> {
    // When project_type is specified, scan only that ecosystem (original behavior).
    // When auto-detecting, scan ALL ecosystems found in the project.
    let dep_sets: Vec<Vec<Dependency>> = if project_type.is_some() {
        vec![parsers::parse_dependencies(project_dir, project_type)?]
    } else {
        let all = parsers::parse_all_ecosystems(project_dir);
        if all.is_empty() {
            // Fall back to parse_dependencies for the error message
            vec![parsers::parse_dependencies(project_dir, None)?]
        } else {
            all
        }
    };

    // Flatten all deps for hash check
    let all_deps: Vec<Dependency> = dep_sets.iter().flatten().cloned().collect();

    // Skip scan if deps haven't changed (manifest + lockfile hash check)
    if !opts.no_cache && !opts.skip_hash_check && !all_deps.is_empty() {
        let hash = scan_hash(project_dir, &all_deps);
        let cache_base = opts
            .cache_dir
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| cache::user_cache_dir().join("sloppy-joe"));
        let hash_path = cache_base.join("scan-hash.json");
        if let Some(cached) =
            cache::read_json_cache::<ScanHashCache>(&hash_path, 7 * 24 * 3600, |c| c.timestamp)
            && cached.hash == hash
        {
            eprintln!("Dependencies unchanged, skipping scan.");
            return Ok(ScanReport::empty());
        }
    }

    // Scan each ecosystem separately, merge reports
    let client = registry::http_client();
    let osv_client = checks::malicious::RealOsvClient::with_client(client.clone());
    let mut total_packages = 0;
    let mut all_issues = Vec::new();

    for deps in &dep_sets {
        if deps.is_empty() {
            continue;
        }
        let ecosystem = deps[0].ecosystem;
        let registry = registry::registry_for_with_client(ecosystem, client.clone())?;
        let report = scan_with_services_inner(
            project_dir,
            config.clone(),
            deps.clone(),
            &*registry,
            &osv_client,
            opts,
        )
        .await?;
        total_packages += report.packages_checked;
        all_issues.extend(report.issues);
    }

    let report = ScanReport::from_issues(total_packages, all_issues);

    // Save hash after successful scan
    if !opts.no_cache && !all_deps.is_empty() {
        let hash = scan_hash(project_dir, &all_deps);
        let cache_base = opts
            .cache_dir
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| cache::user_cache_dir().join("sloppy-joe"));
        let hash_path = cache_base.join("scan-hash.json");
        cache::atomic_write_json(
            &hash_path,
            &ScanHashCache {
                timestamp: cache::now_epoch(),
                hash,
            },
        );
    }

    Ok(report)
}

async fn scan_with_services_inner(
    project_dir: &std::path::Path,
    config: config::SloppyJoeConfig,
    deps: Vec<Dependency>,
    registry: &dyn Registry,
    osv_client: &dyn OsvClient,
    opts: &ScanOptions<'_>,
) -> Result<ScanReport> {
    if deps.is_empty() {
        return Ok(ScanReport::empty());
    }

    let ecosystem = deps[0].ecosystem;

    // Classify deps into three tiers
    let (checkable, non_internal, internal) = classify_deps(&deps, &config, ecosystem);

    // Parse lockfile once
    let mut lockfile_data = lockfiles::LockfileData::parse(project_dir, &non_internal)?;

    // Build context + accumulator, run pipeline on direct deps
    let pipeline = checks::pipeline::default_pipeline();
    let ctx = checks::CheckContext {
        checkable_deps: &checkable,
        non_internal_deps: &non_internal,
        config: &config,
        registry,
        osv_client,
        resolution: &lockfile_data.resolution,
        ecosystem,
        opts,
    };
    let mut acc = checks::ScanAccumulator::new();
    for check in &pipeline {
        check.run(&ctx, &mut acc).await?;
    }
    mark_source(&mut acc.issues, "direct");

    // Run OSV on internal packages (they skip all other checks but still need vuln scanning)
    if !internal.is_empty() {
        let internal_resolution = lockfiles::LockfileData::parse(project_dir, &internal)
            .map(|ld| ld.resolution)
            .unwrap_or_default();
        let internal_ctx = checks::CheckContext {
            checkable_deps: &[],
            non_internal_deps: &internal,
            config: &config,
            registry,
            osv_client,
            resolution: &internal_resolution,
            ecosystem,
            opts,
        };
        let mut internal_acc = checks::ScanAccumulator::new();
        let osv_check: Box<dyn checks::Check> = Box::new(checks::pipeline::MaliciousCheck);
        osv_check.run(&internal_ctx, &mut internal_acc).await?;
        mark_source(&mut internal_acc.issues, "direct");
        acc.issues.extend(internal_acc.issues);
    }

    // Transitive dependency scanning
    let mut transitive_deps = std::mem::take(&mut lockfile_data.transitive_deps);
    transitive_deps.retain(|dep| {
        !config.is_internal(ecosystem.as_str(), &dep.name)
            && !config.is_allowed(ecosystem.as_str(), &dep.name)
    });

    if !transitive_deps.is_empty() {
        let trans_resolution = lockfile_data.resolve_transitive(&transitive_deps)?;

        // Build transitive pipeline (skip similarity unless --deep)
        let trans_pipeline: Vec<Box<dyn checks::Check>> = if opts.deep {
            checks::pipeline::default_pipeline()
        } else {
            // All checks except similarity for transitive deps
            vec![
                Box::new(checks::pipeline::CanonicalCheck),
                Box::new(checks::pipeline::MetadataCheck),
                Box::new(checks::pipeline::ExistenceCheck),
                Box::new(checks::pipeline::MaliciousCheck),
            ]
        };

        let trans_ctx = checks::CheckContext {
            checkable_deps: &transitive_deps,
            non_internal_deps: &transitive_deps,
            config: &config,
            registry,
            osv_client,
            resolution: &trans_resolution,
            ecosystem,
            opts,
        };
        let mut trans_acc = checks::ScanAccumulator::new();
        // Carry forward similarity_flagged from direct deps
        trans_acc.similarity_flagged = acc.similarity_flagged.clone();
        for check in &trans_pipeline {
            check.run(&trans_ctx, &mut trans_acc).await?;
        }
        mark_source(&mut trans_acc.issues, "transitive");
        acc.issues.extend(trans_acc.issues);
    }

    Ok(ScanReport::from_issues(
        non_internal.len() + transitive_deps.len(),
        acc.issues,
    ))
}

/// Classify deps into three tiers. Returns (checkable, non_internal, internal).
/// - checkable: full checks (similarity, existence, canonical, metadata, osv)
/// - non_internal: allowed + checkable (canonical, metadata, osv)
/// - internal: OSV only (skip similarity, existence, canonical, metadata)
fn classify_deps(
    deps: &[Dependency],
    config: &config::SloppyJoeConfig,
    ecosystem: Ecosystem,
) -> (Vec<Dependency>, Vec<Dependency>, Vec<Dependency>) {
    let eco_str = ecosystem.as_str();
    let (internal, rest): (Vec<&Dependency>, Vec<&Dependency>) = deps
        .iter()
        .partition(|dep| config.is_internal(eco_str, &dep.name));

    let (allowed, checkable): (Vec<&Dependency>, Vec<&Dependency>) = rest
        .iter()
        .copied()
        .partition(|dep| config.is_allowed(eco_str, &dep.name));

    if !internal.is_empty() {
        let names: Vec<_> = internal.iter().map(|d| d.name.as_str()).collect();
        eprintln!(
            "Running OSV-only on {} internal package(s): {}",
            names.len(),
            names.join(", ")
        );
    }

    if !allowed.is_empty() {
        let names: Vec<_> = allowed.iter().map(|d| d.name.as_str()).collect();
        eprintln!(
            "Skipping existence/similarity for {} allowed package(s): {}",
            names.len(),
            names.join(", ")
        );
    }

    let checkable_owned: Vec<Dependency> = checkable.into_iter().cloned().collect();
    let non_internal: Vec<Dependency> = rest.into_iter().cloned().collect();
    let internal_owned: Vec<Dependency> = internal.into_iter().cloned().collect();

    (checkable_owned, non_internal, internal_owned)
}

fn mark_source(issues: &mut [Issue], source: &str) {
    for issue in issues.iter_mut() {
        if issue.source.is_none() {
            issue.source = Some(source.to_string());
        }
    }
}

/// Options that control scan behavior, set from CLI flags.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions<'a> {
    /// Enable similarity checks on transitive dependencies (--deep).
    pub deep: bool,
    /// Enable expensive mutation generators like bitflip (--paranoid).
    pub paranoid: bool,
    /// Disable reading from disk caches (--no-cache). Writes still happen.
    pub no_cache: bool,
    /// Override the default cache directory (--cache-dir).
    pub cache_dir: Option<&'a std::path::Path>,
    /// Disable OSV disk cache entirely (for testing).
    pub disable_osv_disk_cache: bool,
    /// Skip the manifest hash check (used by `cache` command to always run).
    pub skip_hash_check: bool,
}

/// A dependency parsed from a project manifest file (package.json, Cargo.toml, etc.).
#[derive(Debug, Clone)]
pub struct Dependency {
    /// Package name as it appears in the manifest (e.g., "react", "@types/node").
    pub name: String,
    /// Version requirement from the manifest (e.g., "^18.0", "==2.31.0"). None if unspecified.
    pub version: Option<String>,
    /// Which ecosystem this dependency belongs to.
    pub ecosystem: Ecosystem,
}

impl Dependency {
    pub fn exact_version(&self) -> Option<String> {
        self.version
            .as_deref()
            .and_then(|version| version::exact_version(version, self.ecosystem))
    }

    pub fn has_unresolved_version(&self) -> bool {
        self.exact_version().is_none()
    }
}

pub(crate) fn unresolved_version_policy_issues(
    deps: &[Dependency],
    resolution: &lockfiles::ResolutionResult,
    config: &config::SloppyJoeConfig,
) -> Vec<Issue> {
    let severity = if config.allow_unresolved_versions {
        Severity::Warning
    } else {
        Severity::Error
    };

    deps.iter()
        .filter(|dep| resolution.is_unresolved(dep))
        .map(|dep| {
            let message = if let Some(requirement) = dep.version.as_deref() {
                format!(
                    "'{}' uses the unresolved version requirement '{}'. Without a resolved version, the following checks are skipped: version-age, install-script-risk, dependency-explosion, maintainer-change, and known-vulnerability (OSV).",
                    dep.name, requirement
                )
            } else {
                format!(
                    "'{}' does not declare an exact version and no trusted lockfile resolution was available. The following checks are skipped: version-age, install-script-risk, dependency-explosion, maintainer-change, and known-vulnerability (OSV).",
                    dep.name
                )
            };

            Issue::new(&dep.name, checks::names::RESOLUTION_NO_EXACT_VERSION, severity)
                .message(message)
                .fix("Pin an exact version or provide a trusted lockfile entry. To continue with reduced accuracy, set allow_unresolved_versions to true in the config.")
        })
        .collect()
}

/// Shared test helpers for creating test dependencies.
#[cfg(test)]
pub(crate) mod test_helpers {
    use super::{Dependency, Ecosystem};

    /// Create a test dependency with the given name and Npm ecosystem.
    pub fn npm_dep(name: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: None,
            ecosystem: Ecosystem::Npm,
        }
    }

    /// Create a test dependency with name, optional version, and ecosystem.
    pub fn dep_with(name: &str, version: Option<&str>, ecosystem: Ecosystem) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.map(|v| v.to_string()),
            ecosystem,
        }
    }
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
