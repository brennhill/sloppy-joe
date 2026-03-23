#![forbid(unsafe_code)]

pub(crate) mod cache;
pub mod checks;
pub mod ecosystem;
pub use ecosystem::Ecosystem;
pub mod config;
pub mod lockfiles;
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
    scan_with_source_full(project_dir, project_type, config_source, deep, false, None).await
}

pub async fn scan_with_source_full(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config_source: Option<&str>,
    deep: bool,
    no_cache: bool,
    cache_dir: Option<&std::path::Path>,
) -> Result<ScanReport> {
    let config = config::load_config_from_source(config_source, Some(project_dir))
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    let opts = ScanOptions { deep, no_cache, cache_dir, disable_osv_disk_cache: false };
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

async fn scan_with_config(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config: config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> Result<ScanReport> {
    let deps = parsers::parse_dependencies(project_dir, project_type)?;
    let ecosystem = deps
        .first()
        .map(|dep| dep.ecosystem)
        .unwrap_or(Ecosystem::Npm);
    let client = registry::http_client();
    let registry = registry::registry_for_with_client(ecosystem, client.clone())?;
    let osv_client = checks::malicious::RealOsvClient::with_client(client);
    scan_with_services_inner(project_dir, config, deps, &*registry, &osv_client, opts).await
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
    let (checkable, non_internal) = classify_deps(&deps, &config, ecosystem);

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
        deps.len() + transitive_deps.len(),
        acc.issues,
    ))
}

/// Classify deps into checkable (full checks) and non-internal (canonical + metadata + osv).
fn classify_deps(
    deps: &[Dependency],
    config: &config::SloppyJoeConfig,
    ecosystem: Ecosystem,
) -> (Vec<Dependency>, Vec<Dependency>) {
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
            "Skipping {} internal package(s): {}",
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

    (checkable_owned, non_internal)
}

fn mark_source(issues: &mut [Issue], source: &str) {
    for issue in issues.iter_mut() {
        issue.source = Some(source.to_string());
    }
}

/// Options that control scan behavior.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions<'a> {
    pub deep: bool,
    pub no_cache: bool,
    pub cache_dir: Option<&'a std::path::Path>,
    pub disable_osv_disk_cache: bool,
}

/// A dependency parsed from a project file.
#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub version: Option<String>,
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

            Issue {
                package: dep.name.clone(),
                check: "resolution/no-exact-version".to_string(),
                severity,
                message,
                fix: "Pin an exact version or provide a trusted lockfile entry. To continue with reduced accuracy, set allow_unresolved_versions to true in the config.".to_string(),
                suggestion: None,
                registry_url: None,
                source: None,
            }
        })
        .collect()
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;

