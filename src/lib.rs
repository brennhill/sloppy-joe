#![forbid(unsafe_code)]

pub(crate) mod cache;
pub mod checks;
pub(crate) mod error_budget;
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
use std::collections::HashSet;

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
        .map(|dep| dep.ecosystem.as_str())
        .unwrap_or("npm");
    let client = registry::http_client();
    let registry = registry::registry_for_with_client(ecosystem, client.clone())?;
    let osv_client = checks::malicious::RealOsvClient::with_client(client);
    scan_with_services(project_dir, config, deps, &*registry, &osv_client, opts).await
}

async fn scan_with_services(
    project_dir: &std::path::Path,
    config: config::SloppyJoeConfig,
    deps: Vec<Dependency>,
    registry: &dyn Registry,
    osv_client: &dyn OsvClient,
    opts: &ScanOptions<'_>,
) -> Result<ScanReport> {
    scan_with_services_inner(project_dir, config, deps, registry, osv_client, opts).await
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

    let ecosystem = deps[0].ecosystem.clone();

    // Classify deps into three tiers
    let (checkable, non_internal) = classify_deps(&deps, &config, &ecosystem);

    // Parse lockfile once
    let lockfile_data = lockfiles::LockfileData::parse(project_dir, &non_internal)?;
    let error_budget = error_budget::ErrorBudget::new();

    // Build context + accumulator, run pipeline on direct deps
    let pipeline = checks::pipeline::default_pipeline();
    let ctx = checks::CheckContext {
        checkable_deps: &checkable,
        non_internal_deps: &non_internal,
        config: &config,
        registry,
        osv_client,
        resolution: &lockfile_data.resolution,
        error_budget: &error_budget,
        ecosystem: &ecosystem,
        opts,
    };
    let mut acc = checks::ScanAccumulator::new();
    for check in &pipeline {
        check.run(&ctx, &mut acc).await?;
    }
    mark_source(&mut acc.issues, "direct");

    // Transitive dependency scanning
    let mut transitive_deps = lockfile_data.transitive_deps;
    transitive_deps.retain(|dep| {
        !config.is_internal(&ecosystem, &dep.name)
            && !config.is_allowed(&ecosystem, &dep.name)
    });

    if !transitive_deps.is_empty() {
        let trans_resolution = lockfiles::resolve_versions(project_dir, &transitive_deps)?;

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
            error_budget: &error_budget,
            ecosystem: &ecosystem,
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
    ecosystem: &str,
) -> (Vec<Dependency>, Vec<Dependency>) {
    let (internal, rest): (Vec<&Dependency>, Vec<&Dependency>) = deps
        .iter()
        .partition(|dep| config.is_internal(ecosystem, &dep.name));

    let (allowed, checkable): (Vec<&Dependency>, Vec<&Dependency>) = rest
        .iter()
        .copied()
        .partition(|dep| config.is_allowed(ecosystem, &dep.name));

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
    let non_internal: Vec<Dependency> = deps
        .iter()
        .filter(|dep| !config.is_internal(ecosystem, &dep.name))
        .cloned()
        .collect();

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
    pub ecosystem: String,
}

impl Dependency {
    pub fn exact_version(&self) -> Option<String> {
        self.version
            .as_deref()
            .and_then(|version| version::exact_version(version, &self.ecosystem))
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
mod tests {
    use super::*;
    use crate::registry::{PackageMetadata, RegistryExistence, RegistryMetadata};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct FakeRegistry {
        existing: Vec<String>,
    }

    #[async_trait]
    impl RegistryExistence for FakeRegistry {
        async fn exists(&self, package_name: &str) -> Result<bool> {
            Ok(self.existing.iter().any(|name| name == package_name))
        }

        fn ecosystem(&self) -> &str {
            "npm"
        }
    }

    #[async_trait]
    impl RegistryMetadata for FakeRegistry {
        async fn metadata(
            &self,
            package_name: &str,
            _version: Option<&str>,
        ) -> Result<Option<PackageMetadata>> {
            if self.existing.iter().any(|name| name == package_name) {
                Ok(Some(PackageMetadata {
                    created: Some("2020-01-01T00:00:00Z".to_string()),
                    latest_version_date: Some("2020-01-01T00:00:00Z".to_string()),
                    downloads: Some(50000),
                    has_install_scripts: false,
                    dependency_count: None,
                    previous_dependency_count: None,
                    current_publisher: None,
                    previous_publisher: None,
                }))
            } else {
                Ok(None)
            }
        }
    }

    struct FakeOsvClient;

    #[async_trait]
    impl OsvClient for FakeOsvClient {
        async fn query(
            &self,
            _name: &str,
            _ecosystem: &str,
            _version: Option<&str>,
        ) -> Result<Vec<String>> {
            Ok(vec![])
        }
    }

    struct RecordingRegistry {
        existing: Vec<String>,
        versions: Arc<Mutex<Vec<Option<String>>>>,
    }

    #[async_trait]
    impl RegistryExistence for RecordingRegistry {
        async fn exists(&self, package_name: &str) -> Result<bool> {
            Ok(self.existing.iter().any(|name| name == package_name))
        }

        fn ecosystem(&self) -> &str {
            "npm"
        }
    }

    #[async_trait]
    impl RegistryMetadata for RecordingRegistry {
        async fn metadata(
            &self,
            package_name: &str,
            version: Option<&str>,
        ) -> Result<Option<PackageMetadata>> {
            self.versions
                .lock()
                .unwrap()
                .push(version.map(str::to_string));
            if self.existing.iter().any(|name| name == package_name) {
                Ok(Some(PackageMetadata {
                    created: Some("2020-01-01T00:00:00Z".to_string()),
                    latest_version_date: Some("2020-01-01T00:00:00Z".to_string()),
                    downloads: Some(50000),
                    has_install_scripts: false,
                    dependency_count: None,
                    previous_dependency_count: None,
                    current_publisher: None,
                    previous_publisher: None,
                }))
            } else {
                Ok(None)
            }
        }
    }

    struct RecordingOsvClient {
        versions: Arc<Mutex<Vec<Option<String>>>>,
    }

    #[async_trait]
    impl OsvClient for RecordingOsvClient {
        async fn query(
            &self,
            _name: &str,
            _ecosystem: &str,
            version: Option<&str>,
        ) -> Result<Vec<String>> {
            self.versions
                .lock()
                .unwrap()
                .push(version.map(str::to_string));
            Ok(vec![])
        }
    }

    async fn scan_with_services_no_osv_cache(
        project_dir: &std::path::Path,
        project_type: Option<&str>,
        config: config::SloppyJoeConfig,
        registry: &dyn Registry,
        osv_client: &dyn OsvClient,
    ) -> Result<ScanReport> {
        let deps = parsers::parse_dependencies(project_dir, project_type)?;
        let opts = ScanOptions { no_cache: true, disable_osv_disk_cache: true, ..Default::default() };
        scan_with_services_inner(project_dir, config, deps, registry, osv_client, &opts).await
    }

    fn unique_dir() -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sj-lib-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn scan_empty_project_returns_empty_report() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package.json"),
            r#"{"name": "test", "version": "1.0"}"#,
        )
        .unwrap();
        let registry = FakeRegistry { existing: vec![] };
        let report = scan_with_services(
            &dir,
            Default::default(),
            parsers::parse_dependencies(&dir, Some("npm")).unwrap(),
            &registry,
            &FakeOsvClient,
            &ScanOptions { no_cache: true, ..Default::default() },
        )
        .await
        .unwrap();
        assert_eq!(report.packages_checked, 0);
        assert!(!report.has_issues());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn scan_with_deps_returns_report() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"react": "^18.0"}}"#,
        )
        .unwrap();
        let registry = FakeRegistry {
            existing: vec!["react".to_string()],
        };
        let report = scan_with_services(
            &dir,
            Default::default(),
            parsers::parse_dependencies(&dir, Some("npm")).unwrap(),
            &registry,
            &FakeOsvClient,
            &ScanOptions { no_cache: true, ..Default::default() },
        )
        .await
        .unwrap();
        assert_eq!(report.packages_checked, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn scan_with_internal_skips_all_checks() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"react": "^18.0", "@myorg/utils": "1.0"}}"#,
        )
        .unwrap();
        let config_dir = unique_dir();
        let config_path = config_dir.join("config.json");
        std::fs::write(
            &config_path,
            r#"{"canonical":{},"internal":{"npm":["@myorg/*"]},"allowed":{}}"#,
        )
        .unwrap();
        let config = config::load_config(Some(config_path.as_path())).unwrap();
        let registry = FakeRegistry {
            existing: vec!["react".to_string()],
        };
        let report = scan_with_services(&dir, config, parsers::parse_dependencies(&dir, Some("npm")).unwrap(), &registry, &FakeOsvClient, &ScanOptions { no_cache: true, ..Default::default() })
            .await
            .unwrap();
        assert_eq!(report.packages_checked, 2);
        // @myorg/utils should not appear in any issues
        let myorg_issues: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.package.contains("myorg"))
            .collect();
        assert!(myorg_issues.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&config_dir);
    }

    #[tokio::test]
    async fn scan_with_canonical_config_flags_alternatives() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"moment": "^2.0"}}"#,
        )
        .unwrap();
        let config_dir = unique_dir();
        let config_path = config_dir.join("config.json");
        std::fs::write(
            &config_path,
            r#"{"canonical":{"npm":{"dayjs":["moment"]}},"internal":{},"allowed":{}}"#,
        )
        .unwrap();
        let config = config::load_config(Some(config_path.as_path())).unwrap();
        let registry = FakeRegistry {
            existing: vec!["moment".to_string()],
        };
        let report = scan_with_services(&dir, config, parsers::parse_dependencies(&dir, Some("npm")).unwrap(), &registry, &FakeOsvClient, &ScanOptions { no_cache: true, ..Default::default() })
            .await
            .unwrap();
        let canonical_issues: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.check == "canonical")
            .collect();
        assert_eq!(canonical_issues.len(), 1);
        assert_eq!(canonical_issues[0].package, "moment");
        assert_eq!(canonical_issues[0].suggestion, Some("dayjs".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&config_dir);
    }

    #[tokio::test]
    async fn scan_rejects_config_inside_project_dir() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package.json"),
            r#"{"name": "test", "version": "1.0"}"#,
        )
        .unwrap();
        let config_path = dir.join("sloppy-joe.json");
        std::fs::write(
            &config_path,
            r#"{"canonical":{},"internal":{},"allowed":{}}"#,
        )
        .unwrap();

        let err = scan_with_source(&dir, Some("npm"), Some(config_path.to_str().unwrap()), false)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("outside the project directory"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn scan_uses_npm_lockfile_version_for_metadata_and_osv() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"react": "^18.2.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{
              "name": "demo",
              "lockfileVersion": 3,
              "packages": {
                "": {"name": "demo", "dependencies": {"react": "^18.2.0"}},
                "node_modules/react": {"version": "18.3.1"}
              }
            }"#,
        )
        .unwrap();

        let metadata_versions = Arc::new(Mutex::new(Vec::new()));
        let osv_versions = Arc::new(Mutex::new(Vec::new()));
        let registry = RecordingRegistry {
            existing: vec!["react".to_string()],
            versions: metadata_versions.clone(),
        };
        let osv = RecordingOsvClient {
            versions: osv_versions.clone(),
        };

        let report =
            scan_with_services_no_osv_cache(&dir, Some("npm"), Default::default(), &registry, &osv)
                .await
                .unwrap();

        assert!(
            !report
                .issues
                .iter()
                .any(|issue| issue.check == "metadata/unresolved-version")
        );
        assert!(
            !report
                .issues
                .iter()
                .any(|issue| issue.check == "malicious/unresolved-version")
        );
        assert_eq!(
            metadata_versions.lock().unwrap().as_slice(),
            &[Some("18.3.1".to_string())]
        );
        assert_eq!(
            osv_versions.lock().unwrap().as_slice(),
            &[Some("18.3.1".to_string())]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn scan_reports_out_of_sync_lockfile_state() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"react": "18.2.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{
              "name": "demo",
              "lockfileVersion": 3,
              "packages": {
                "": {"name": "demo", "dependencies": {"react": "18.2.0"}},
                "node_modules/react": {"version": "18.3.1"}
              }
            }"#,
        )
        .unwrap();

        let metadata_versions = Arc::new(Mutex::new(Vec::new()));
        let osv_versions = Arc::new(Mutex::new(Vec::new()));
        let registry = RecordingRegistry {
            existing: vec!["react".to_string()],
            versions: metadata_versions.clone(),
        };
        let osv = RecordingOsvClient {
            versions: osv_versions.clone(),
        };

        let report =
            scan_with_services_no_osv_cache(&dir, Some("npm"), Default::default(), &registry, &osv)
                .await
                .unwrap();

        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.check == "resolution/lockfile-out-of-sync")
        );
        assert!(
            !report
                .issues
                .iter()
                .any(|issue| issue.check == "metadata/unresolved-version")
        );
        assert!(
            !report
                .issues
                .iter()
                .any(|issue| issue.check == "malicious/unresolved-version")
        );
        assert_eq!(
            metadata_versions.lock().unwrap().as_slice(),
            &[Some("18.2.0".to_string())]
        );
        assert_eq!(
            osv_versions.lock().unwrap().as_slice(),
            &[Some("18.2.0".to_string())]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn scan_versionless_dependency_blocks_by_default() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = { workspace = true }
"#,
        )
        .unwrap();

        let metadata_versions = Arc::new(Mutex::new(Vec::new()));
        let osv_versions = Arc::new(Mutex::new(Vec::new()));
        let registry = RecordingRegistry {
            existing: vec!["serde".to_string()],
            versions: metadata_versions,
        };
        let osv = RecordingOsvClient {
            versions: osv_versions.clone(),
        };

        let report = scan_with_services_no_osv_cache(
            &dir,
            Some("cargo"),
            Default::default(),
            &registry,
            &osv,
        )
        .await
        .unwrap();

        let issue = report
            .issues
            .iter()
            .find(|issue| issue.check == "resolution/no-exact-version")
            .unwrap();
        assert_eq!(issue.severity, report::Severity::Error);
        assert!(
            !report
                .issues
                .iter()
                .any(|issue| issue.check == "metadata/unresolved-version")
        );
        assert!(
            !report
                .issues
                .iter()
                .any(|issue| issue.check == "malicious/unresolved-version")
        );
        assert!(report.has_issues());
        assert!(report.has_errors());
        assert!(osv_versions.lock().unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn scan_versionless_dependency_warns_when_allowed() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("Cargo.toml"),
            r#"
[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = { workspace = true }
"#,
        )
        .unwrap();

        let registry = RecordingRegistry {
            existing: vec!["serde".to_string()],
            versions: Arc::new(Mutex::new(Vec::new())),
        };
        let osv = RecordingOsvClient {
            versions: Arc::new(Mutex::new(Vec::new())),
        };
        let config = config::SloppyJoeConfig {
            allow_unresolved_versions: true,
            ..Default::default()
        };

        let report = scan_with_services_no_osv_cache(&dir, Some("cargo"), config, &registry, &osv)
            .await
            .unwrap();

        let issue = report
            .issues
            .iter()
            .find(|issue| issue.check == "resolution/no-exact-version")
            .unwrap();
        assert_eq!(issue.severity, report::Severity::Warning);
        assert!(report.has_issues());
        assert!(!report.has_errors());

        let _ = std::fs::remove_dir_all(&dir);
    }

    struct VulnOsvClient {
        vulnerable: Vec<String>,
    }

    #[async_trait]
    impl OsvClient for VulnOsvClient {
        async fn query(
            &self,
            name: &str,
            _ecosystem: &str,
            _version: Option<&str>,
        ) -> Result<Vec<String>> {
            if self.vulnerable.contains(&name.to_string()) {
                Ok(vec!["GHSA-1234-5678".to_string()])
            } else {
                Ok(vec![])
            }
        }
    }

    #[tokio::test]
    async fn transitive_dep_with_osv_hit_has_transitive_source() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"react": "18.3.1"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{
              "name": "demo",
              "lockfileVersion": 3,
              "packages": {
                "": {"name": "demo", "dependencies": {"react": "18.3.1"}},
                "node_modules/react": {"version": "18.3.1"},
                "node_modules/evil-transitive": {"version": "1.0.0"}
              }
            }"#,
        )
        .unwrap();

        let registry = FakeRegistry {
            existing: vec!["react".to_string(), "evil-transitive".to_string()],
        };
        let osv = VulnOsvClient {
            vulnerable: vec!["evil-transitive".to_string()],
        };

        let report = scan_with_services_inner(
            &dir,
            Default::default(),
            parsers::parse_dependencies(&dir, Some("npm")).unwrap(),
            &registry,
            &osv,
            &ScanOptions { no_cache: true, disable_osv_disk_cache: true, ..Default::default() },
        )
        .await
        .unwrap();

        // evil-transitive should have a malicious issue with source=transitive
        let trans_issue = report
            .issues
            .iter()
            .find(|i| i.package == "evil-transitive" && i.check.contains("malicious"));
        assert!(
            trans_issue.is_some(),
            "Expected OSV issue for evil-transitive"
        );
        assert_eq!(
            trans_issue.unwrap().source,
            Some("transitive".to_string())
        );

        // react issues should be source=direct
        let react_issues: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.package == "react")
            .collect();
        for issue in &react_issues {
            assert_eq!(issue.source, Some("direct".to_string()));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn deep_flag_does_not_crash_and_scans_transitive() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"react": "18.3.1"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{
              "name": "demo",
              "lockfileVersion": 3,
              "packages": {
                "": {"name": "demo", "dependencies": {"react": "18.3.1"}},
                "node_modules/react": {"version": "18.3.1"},
                "node_modules/loose-envify": {"version": "1.4.0"}
              }
            }"#,
        )
        .unwrap();

        let registry = FakeRegistry {
            existing: vec!["react".to_string(), "loose-envify".to_string()],
        };

        // With deep=true, the scan should complete without errors and
        // include transitive deps in the package count
        let report = scan_with_services_inner(
            &dir,
            Default::default(),
            parsers::parse_dependencies(&dir, Some("npm")).unwrap(),
            &registry,
            &FakeOsvClient,
            &ScanOptions { deep: true, no_cache: true, disable_osv_disk_cache: true, ..Default::default() },
        )
        .await
        .unwrap();

        // packages_checked should include transitive deps
        assert_eq!(report.packages_checked, 2); // react (direct) + loose-envify (transitive)

        // Without deep, similarity on transitive is skipped but scan still works
        let report_no_deep = scan_with_services_inner(
            &dir,
            Default::default(),
            parsers::parse_dependencies(&dir, Some("npm")).unwrap(),
            &registry,
            &FakeOsvClient,
            &ScanOptions { no_cache: true, disable_osv_disk_cache: true, ..Default::default() },
        )
        .await
        .unwrap();
        assert_eq!(report_no_deep.packages_checked, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn transitive_internal_deps_are_skipped() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies": {"react": "18.3.1"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{
              "name": "demo",
              "lockfileVersion": 3,
              "packages": {
                "": {"name": "demo", "dependencies": {"react": "18.3.1"}},
                "node_modules/react": {"version": "18.3.1"},
                "node_modules/@myorg/internal-lib": {"version": "1.0.0"}
              }
            }"#,
        )
        .unwrap();

        let config_dir = unique_dir();
        let config_path = config_dir.join("config.json");
        std::fs::write(
            &config_path,
            r#"{"canonical":{},"internal":{"npm":["@myorg/*"]},"allowed":{}}"#,
        )
        .unwrap();
        let config = config::load_config(Some(config_path.as_path())).unwrap();

        let registry = FakeRegistry {
            existing: vec!["react".to_string()],
        };

        let report = scan_with_services_inner(
            &dir,
            config,
            parsers::parse_dependencies(&dir, Some("npm")).unwrap(),
            &registry,
            &FakeOsvClient,
            &ScanOptions { no_cache: true, disable_osv_disk_cache: true, ..Default::default() },
        )
        .await
        .unwrap();

        // @myorg/internal-lib should not appear in any issues
        let internal_issues: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.package.contains("myorg"))
            .collect();
        assert!(
            internal_issues.is_empty(),
            "Internal transitive deps should be skipped"
        );

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&config_dir);
    }
}
