#![forbid(unsafe_code)]

pub mod checks;
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
) -> Result<ScanReport> {
    let config = config::load_config_from_source(config_source, Some(project_dir))
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    scan_with_config(project_dir, project_type, config).await
}

pub async fn scan(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config_path: Option<&std::path::Path>,
) -> Result<ScanReport> {
    let config = config::load_config_with_project(config_path, Some(project_dir))
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    scan_with_config(project_dir, project_type, config).await
}

async fn scan_with_config(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config: config::SloppyJoeConfig,
) -> Result<ScanReport> {
    let deps = parsers::parse_dependencies(project_dir, project_type)?;
    let ecosystem = deps
        .first()
        .map(|dep| dep.ecosystem.as_str())
        .unwrap_or("npm");
    let registry = registry::registry_for(ecosystem);
    let osv_client = checks::malicious::RealOsvClient::new();
    scan_with_services(project_dir, project_type, config, &*registry, &osv_client).await
}

async fn scan_with_services(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config: config::SloppyJoeConfig,
    registry: &dyn Registry,
    osv_client: &dyn OsvClient,
) -> Result<ScanReport> {
    scan_with_services_inner(
        project_dir,
        project_type,
        config,
        registry,
        osv_client,
        false,
    )
    .await
}

async fn scan_with_services_inner(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config: config::SloppyJoeConfig,
    registry: &dyn Registry,
    osv_client: &dyn OsvClient,
    disable_osv_disk_cache: bool,
) -> Result<ScanReport> {
    let deps = parsers::parse_dependencies(project_dir, project_type)?;

    if deps.is_empty() {
        return Ok(ScanReport::empty());
    }

    let ecosystem = deps[0].ecosystem.clone();

    // Split deps into three tiers
    let (internal, rest): (Vec<&Dependency>, Vec<&Dependency>) = deps
        .iter()
        .partition(|dep| config.is_internal(&ecosystem, &dep.name));

    let (allowed, checkable): (Vec<&Dependency>, Vec<&Dependency>) = rest
        .iter()
        .copied()
        .partition(|dep| config.is_allowed(&ecosystem, &dep.name));

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

    // Checkable deps get full checks
    let checkable_owned: Vec<Dependency> = checkable.into_iter().cloned().collect();
    let similarity_results = checks::similarity::check_similarity(&checkable_owned, &ecosystem);

    // Build set of similarity-flagged package names for signal amplifier
    let similarity_flagged: HashSet<String> = similarity_results
        .iter()
        .map(|issue| issue.package.clone())
        .collect();

    // Canonical check runs on all non-internal deps (allowed + checkable)
    let non_internal: Vec<Dependency> = deps
        .iter()
        .filter(|dep| !config.is_internal(&ecosystem, &dep.name))
        .cloned()
        .collect();
    let canonical_results = checks::canonical::check_canonical(&non_internal, &config, &ecosystem);
    let resolution = lockfiles::resolve_versions(project_dir, &non_internal)?;
    let mut resolution_issues = resolution.issues.clone();
    resolution_issues.extend(unresolved_version_policy_issues(
        &non_internal,
        &resolution,
        &config,
    ));

    let supports_metadata_registry = matches!(
        ecosystem.as_str(),
        "npm" | "pypi" | "cargo" | "ruby" | "jvm"
    );

    let (existence_results, metadata_results) = if supports_metadata_registry {
        let lookups =
            checks::metadata::fetch_metadata(registry, &non_internal, &resolution).await?;
        let mut metadata_results = resolution_issues;
        metadata_results.extend(checks::metadata::issues_from_lookups(
            &lookups,
            &config,
            &similarity_flagged,
        ));
        (
            checks::existence::check_existence_from_metadata(
                &ecosystem,
                &checkable_owned,
                &lookups,
            ),
            metadata_results,
        )
    } else {
        let mut metadata_results = resolution_issues;
        metadata_results.extend(
            checks::metadata::check_metadata(
                registry,
                &non_internal,
                &config,
                &similarity_flagged,
                &resolution,
            )
            .await?,
        );
        (
            checks::existence::check_existence(registry, &checkable_owned).await?,
            metadata_results,
        )
    };

    // Malicious/vulnerability check runs on all non-internal deps
    let malicious_results = if disable_osv_disk_cache {
        checks::malicious::check_malicious_with_cache(osv_client, &non_internal, &resolution, None)
            .await?
    } else {
        checks::malicious::check_malicious(osv_client, &non_internal, &resolution).await?
    };

    Ok(ScanReport::new(
        deps.len(),
        existence_results,
        similarity_results,
        canonical_results,
        metadata_results,
        malicious_results,
    ))
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

fn unresolved_version_policy_issues(
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
                    "'{}' uses the unresolved version requirement '{}'. No exact version could be proven, so version-sensitive checks were skipped.",
                    dep.name, requirement
                )
            } else {
                format!(
                    "'{}' does not declare an exact version and no trusted lockfile resolution was available. Version-sensitive checks were skipped.",
                    dep.name
                )
            };

            Issue {
                package: dep.name.clone(),
                check: "resolution/no-exact-version".to_string(),
                severity: severity.clone(),
                message,
                fix: "Pin an exact version or provide a trusted lockfile entry. To continue with reduced accuracy, set allow_unresolved_versions to true in the config.".to_string(),
                suggestion: None,
                registry_url: None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::PackageMetadata;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct FakeRegistry {
        existing: Vec<String>,
    }

    #[async_trait]
    impl Registry for FakeRegistry {
        async fn exists(&self, package_name: &str) -> Result<bool> {
            Ok(self.existing.iter().any(|name| name == package_name))
        }

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

        fn ecosystem(&self) -> &str {
            "npm"
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
    impl Registry for RecordingRegistry {
        async fn exists(&self, package_name: &str) -> Result<bool> {
            Ok(self.existing.iter().any(|name| name == package_name))
        }

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

        fn ecosystem(&self) -> &str {
            "npm"
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
        scan_with_services_inner(
            project_dir,
            project_type,
            config,
            registry,
            osv_client,
            true,
        )
        .await
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
            Some("npm"),
            Default::default(),
            &registry,
            &FakeOsvClient,
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
            Some("npm"),
            Default::default(),
            &registry,
            &FakeOsvClient,
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
        let report = scan_with_services(&dir, Some("npm"), config, &registry, &FakeOsvClient)
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
        let report = scan_with_services(&dir, Some("npm"), config, &registry, &FakeOsvClient)
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

        let err = scan_with_source(&dir, Some("npm"), Some(config_path.to_str().unwrap()))
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
}
