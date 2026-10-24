#![forbid(unsafe_code)]
pub mod bootstrap;
mod ecosystems;
mod engine;
#[cfg(test)]
pub(crate) use ecosystems::first_existing_lockfile;
pub(crate) use ecosystems::selected_lockfile_path;
#[cfg(test)]
pub(crate) use ecosystems::test_access::*;
pub(crate) use engine::*;
pub mod cache;
pub mod checks;
pub mod ecosystem;
mod fsutil;
mod http;
pub mod names;
pub use ecosystem::Ecosystem;
pub mod config;
mod gradle_plugin_scan;
pub(crate) mod lockfiles;
mod npm_config;
pub mod parsers;
mod project;
pub(crate) use project::*;
pub mod registry;
pub mod report;
mod version;

use anyhow::Result;
use checks::Check;
use checks::malicious::OsvClient;
use parsers::python_scope::PythonRootExtras;
use registry::Registry;
use report::{Issue, ScanReport, Severity};

/// Run all checks on the detected or specified project type.
///
/// `config_path` must point to a file outside the project directory.
/// If None, only existence and similarity checks run (no canonical check).
///
/// Three tiers of packages:
/// - **internal**: OSV-only package checks (your org's packages)
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
        scan_mode: ScanMode::Full,
        deep,
        paranoid,
        no_cache: false,
        cache_dir,
        disable_osv_disk_cache: false,
        skip_hash_check: true,
        review_exceptions: false,
        python_groups: Vec::new(),
        python_extras: Vec::new(),
        python_platform: None,
        python_arch: None,
        python_version: None,
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
    let opts = ScanOptions {
        scan_mode: ScanMode::Full,
        deep,
        paranoid,
        no_cache,
        cache_dir,
        disable_osv_disk_cache: false,
        skip_hash_check: false,
        review_exceptions: false,
        python_groups: Vec::new(),
        python_extras: Vec::new(),
        python_platform: None,
        python_arch: None,
        python_version: None,
    };
    scan_with_source_full_options(project_dir, project_type, config_source, &opts).await
}

pub async fn scan_with_source_full_options(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config_source: Option<&str>,
    opts: &ScanOptions<'_>,
) -> Result<ScanReport> {
    let config = config::load_config_from_source(config_source, Some(project_dir))
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    scan_with_config(project_dir, project_type, config, opts).await
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

#[cfg(test)]
#[path = "python_manifest_coverage_tests.rs"]
mod python_manifest_coverage_tests;

#[cfg(test)]
#[path = "python_group_scope_tests.rs"]
mod python_group_scope_tests;

#[cfg(test)]
#[path = "requirements_index_allowlist_tests.rs"]
mod requirements_index_allowlist_tests;

#[cfg(test)]
#[path = "uv_lock_groups_tests.rs"]
mod uv_lock_groups_tests;

/// Options that control scan behavior, set from CLI flags.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions<'a> {
    /// High-level scan behavior: fast local guardrail vs full online scan.
    pub scan_mode: ScanMode,
    /// Enable similarity checks on transitive dependencies (--deep).
    pub deep: bool,
    /// Enable expensive mutation generators like bitflip (--paranoid).
    pub paranoid: bool,
    /// Disable reading from disk caches (--no-cache).
    pub no_cache: bool,
    /// Override the default cache directory (--cache-dir).
    pub cache_dir: Option<&'a std::path::Path>,
    /// Disable OSV disk cache entirely (for testing).
    pub disable_osv_disk_cache: bool,
    /// Skip the manifest hash check (used by `cache` command to always run).
    pub skip_hash_check: bool,
    /// Emit structured exception review candidates for supported findings.
    pub review_exceptions: bool,
    /// Selected Python dependency groups to include.
    pub python_groups: Vec<String>,
    /// Selected Python extras to include.
    pub python_extras: Vec<String>,
    /// Override the Python target platform for marker evaluation.
    pub python_platform: Option<String>,
    /// Override the Python target architecture for marker evaluation.
    pub python_arch: Option<String>,
    /// Override the Python target version for marker evaluation.
    pub python_version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanMode {
    Fast,
    #[default]
    Full,
    Ci,
}

impl ScanMode {
    fn runs_full_checks(self) -> bool {
        !matches!(self, Self::Fast)
    }
}

/// A dependency parsed from a project manifest file (package.json, Cargo.toml, etc.).
#[derive(Debug, Clone)]
pub struct Dependency {
    /// Package key as it appears in the manifest (e.g., "react", "@types/node", or an npm alias).
    pub name: String,
    /// Version requirement from the manifest (e.g., "^18.0", "==2.31.0"). None if unspecified.
    pub version: Option<String>,
    /// Which ecosystem this dependency belongs to.
    pub ecosystem: Ecosystem,
    /// Underlying published package identity when the manifest key is an alias.
    pub actual_name: Option<String>,
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

    pub fn package_name(&self) -> &str {
        self.actual_name.as_deref().unwrap_or(&self.name)
    }
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
            actual_name: None,
        }
    }

    /// Create a test dependency with name, optional version, and ecosystem.
    pub fn dep_with(name: &str, version: Option<&str>, ecosystem: Ecosystem) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.map(|v| v.to_string()),
            ecosystem,
            actual_name: None,
        }
    }
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "lib_manifest_discovery_tests.rs"]
mod manifest_discovery_tests;

#[cfg(test)]
#[path = "npm_registry_redirect_tests.rs"]
mod npm_registry_redirect_tests;

#[cfg(test)]
#[path = "cache_boundary_tests.rs"]
mod cache_boundary_tests;

#[cfg(test)]
#[path = "lockfile_redteam_tests.rs"]
mod lockfile_redteam_tests;

#[cfg(test)]
#[path = "yarn_orphan_scan_tests.rs"]
mod yarn_orphan_scan_tests;

#[cfg(test)]
#[path = "empty_manifest_lockfile_tests.rs"]
mod empty_manifest_lockfile_tests;

#[cfg(test)]
#[path = "pipfile_lock_tests.rs"]
mod pipfile_lock_tests;

#[cfg(test)]
#[path = "lockfile_integrity_scan_tests.rs"]
mod lockfile_integrity_scan_tests;

#[cfg(test)]
#[path = "go_sum_preflight_tests.rs"]
mod go_sum_preflight_tests;
