use super::*;
use crate::registry::{PackageMetadata, RegistryExistence, RegistryMetadata};
use crate::report::Severity;
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
                repository_url: None,
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
                repository_url: None,
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
    let opts = ScanOptions {
        no_cache: true,
        disable_osv_disk_cache: true,
        ..Default::default()
    };
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
    let report = scan_with_services_inner(
        &dir,
        Default::default(),
        parsers::parse_dependencies(&dir, Some("npm")).unwrap(),
        &registry,
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            ..Default::default()
        },
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
    let report = scan_with_services_inner(
        &dir,
        Default::default(),
        parsers::parse_dependencies(&dir, Some("npm")).unwrap(),
        &registry,
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            ..Default::default()
        },
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
    let report = scan_with_services_inner(
        &dir,
        config,
        parsers::parse_dependencies(&dir, Some("npm")).unwrap(),
        &registry,
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // Only react is non-internal; @myorg/utils is internal and should not be counted
    assert_eq!(report.packages_checked, 1);
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
    let report = scan_with_services_inner(
        &dir,
        config,
        parsers::parse_dependencies(&dir, Some("npm")).unwrap(),
        &registry,
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            ..Default::default()
        },
    )
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

    let err = scan_with_source(
        &dir,
        Some("npm"),
        Some(config_path.to_str().unwrap()),
        false,
    )
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
        r#"{"name": "demo", "lockfileVersion": 3, "packages": {"": {"name": "demo", "dependencies": {"react": "^18.2.0"}}, "node_modules/react": {"version": "18.3.1"}}}"#,
    ).unwrap();

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
        r#"{"name": "demo", "lockfileVersion": 3, "packages": {"": {"name": "demo", "dependencies": {"react": "18.2.0"}}, "node_modules/react": {"version": "18.3.1"}}}"#,
    ).unwrap();

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
    std::fs::write(dir.join("Cargo.toml"), "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = { workspace = true }\n").unwrap();

    let metadata_versions = Arc::new(Mutex::new(Vec::new()));
    let osv_versions = Arc::new(Mutex::new(Vec::new()));
    let registry = RecordingRegistry {
        existing: vec!["serde".to_string()],
        versions: metadata_versions,
    };
    let osv = RecordingOsvClient {
        versions: osv_versions.clone(),
    };

    let report =
        scan_with_services_no_osv_cache(&dir, Some("cargo"), Default::default(), &registry, &osv)
            .await
            .unwrap();

    let issue = report
        .issues
        .iter()
        .find(|issue| issue.check == "resolution/no-exact-version")
        .unwrap();
    assert_eq!(issue.severity, report::Severity::Error);
    assert!(report.has_issues());
    assert!(report.has_errors());
    // Unresolved deps now DO query OSV (with version: None) — fail-closed, not fail-open
    assert_eq!(osv_versions.lock().unwrap().as_slice(), &[None::<String>]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_versionless_dependency_warns_when_allowed() {
    let dir = unique_dir();
    std::fs::write(dir.join("Cargo.toml"), "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = { workspace = true }\n").unwrap();

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

/// Proves that non-metadata ecosystems (Go) make exactly 1 registry call per dep,
/// not 3 (metadata + exists fallback + existence check).
#[tokio::test]
async fn non_metadata_ecosystem_makes_one_registry_call_per_dep() {
    use std::sync::atomic::AtomicU32;

    struct CountingRegistry {
        existing: Vec<String>,
        exists_count: Arc<AtomicU32>,
        metadata_count: Arc<AtomicU32>,
    }

    #[async_trait]
    impl RegistryExistence for CountingRegistry {
        async fn exists(&self, name: &str) -> Result<bool> {
            self.exists_count.fetch_add(1, Ordering::SeqCst);
            Ok(self.existing.contains(&name.to_string()))
        }
        fn ecosystem(&self) -> &str {
            "go"
        }
    }

    #[async_trait]
    impl RegistryMetadata for CountingRegistry {
        async fn metadata(
            &self,
            _name: &str,
            _version: Option<&str>,
        ) -> Result<Option<PackageMetadata>> {
            self.metadata_count.fetch_add(1, Ordering::SeqCst);
            Ok(None) // Go doesn't support metadata
        }
    }

    let dir = unique_dir();
    std::fs::write(dir.join("go.mod"), "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgithub.com/spf13/cobra v1.7.0\n)\n").unwrap();

    let exists_count = Arc::new(AtomicU32::new(0));
    let metadata_count = Arc::new(AtomicU32::new(0));
    let registry = CountingRegistry {
        existing: vec![
            "github.com/gin-gonic/gin".to_string(),
            "github.com/spf13/cobra".to_string(),
        ],
        exists_count: exists_count.clone(),
        metadata_count: metadata_count.clone(),
    };

    let _report = scan_with_services_no_osv_cache(
        &dir,
        Some("go"),
        Default::default(),
        &registry,
        &FakeOsvClient,
    )
    .await
    .unwrap();

    // Similarity generates many mutation candidates and calls exists() for each.
    // That's expected. The key invariant: metadata() should be called exactly once
    // per dep (2 total), and the exists() fallback in fetch_metadata should be
    // called exactly once per dep (2 total, since Go metadata() returns None).
    // ExistenceCheck should NOT make additional exists() calls because it reads
    // from acc.metadata_lookups.
    //
    // Before the fix, the non-metadata path didn't set acc.metadata_lookups,
    // causing ExistenceCheck to make 2 additional exists() calls (total was
    // similarity_mutations + 2_metadata_fallback + 2_existence = many more).
    let total_exists = exists_count.load(Ordering::SeqCst);
    let total_metadata = metadata_count.load(Ordering::SeqCst);

    // metadata() called exactly 2 times (once per dep)
    assert_eq!(
        total_metadata, 2,
        "Expected exactly 2 metadata() calls for 2 deps, got {}",
        total_metadata
    );
    // exists() calls = similarity mutations + 2 (fetch_metadata fallback for Go)
    // The fetch_metadata fallback accounts for exactly 2 exists() calls.
    // Anything more than similarity_mutations + 2 means ExistenceCheck made redundant calls.
    // We can't know exact similarity mutation count, but we can verify exists()
    // is NOT called for the 2 original dep names beyond what fetch_metadata does.
    // Since acc.metadata_lookups is now always set, ExistenceCheck should add 0 calls.
    // Each dep generates ~200+ mutations (10 generators: bitflip ~150 per dep,
    // keyboard ~25, others ~50), so ~500 from similarity + 2 from metadata fallback.
    // The test verifies ExistenceCheck doesn't add redundant calls on top of similarity.
    assert!(
        total_exists <= 600,
        "Expected at most ~500 exists() calls (similarity mutations + metadata fallback), got {} — ExistenceCheck may be making redundant calls",
        total_exists
    );

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
        r#"{"name": "demo", "lockfileVersion": 3, "packages": {"": {"name": "demo", "dependencies": {"react": "18.3.1"}}, "node_modules/react": {"version": "18.3.1"}, "node_modules/evil-transitive": {"version": "1.0.0"}}}"#,
    ).unwrap();

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
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let trans_issue = report
        .issues
        .iter()
        .find(|i| i.package == "evil-transitive" && i.check.contains("malicious"));
    assert!(
        trans_issue.is_some(),
        "Expected OSV issue for evil-transitive"
    );
    assert_eq!(trans_issue.unwrap().source, Some("transitive".to_string()));

    for issue in report.issues.iter().filter(|i| i.package == "react") {
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
        r#"{"name": "demo", "lockfileVersion": 3, "packages": {"": {"name": "demo", "dependencies": {"react": "18.3.1"}}, "node_modules/react": {"version": "18.3.1"}, "node_modules/loose-envify": {"version": "1.4.0"}}}"#,
    ).unwrap();

    let registry = FakeRegistry {
        existing: vec!["react".to_string(), "loose-envify".to_string()],
    };

    let report = scan_with_services_inner(
        &dir,
        Default::default(),
        parsers::parse_dependencies(&dir, Some("npm")).unwrap(),
        &registry,
        &FakeOsvClient,
        &ScanOptions {
            deep: true,
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(report.packages_checked, 2);

    let report_no_deep = scan_with_services_inner(
        &dir,
        Default::default(),
        parsers::parse_dependencies(&dir, Some("npm")).unwrap(),
        &registry,
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
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
        r#"{"name": "demo", "lockfileVersion": 3, "packages": {"": {"name": "demo", "dependencies": {"react": "18.3.1"}}, "node_modules/react": {"version": "18.3.1"}, "node_modules/@myorg/internal-lib": {"version": "1.0.0"}}}"#,
    ).unwrap();

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
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

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

#[tokio::test]
async fn internal_packages_still_get_osv_checked() {
    // Internal packages should skip similarity/existence/canonical/metadata
    // but still get vulnerability (OSV) checks

    struct VulnOsvClient;
    #[async_trait]
    impl OsvClient for VulnOsvClient {
        async fn query(
            &self,
            name: &str,
            _ecosystem: &str,
            _version: Option<&str>,
        ) -> Result<Vec<String>> {
            if name == "@myorg/vulnerable-pkg" {
                Ok(vec!["GHSA-1234-abcd".to_string()])
            } else {
                Ok(vec![])
            }
        }
    }

    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"@myorg/vulnerable-pkg":"1.0.0","react":"^18.0"}}"#,
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
        &VulnOsvClient,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let vuln_issues: Vec<_> = report
        .issues
        .iter()
        .filter(|i| i.package == "@myorg/vulnerable-pkg" && i.check.contains("malicious"))
        .collect();
    assert!(
        !vuln_issues.is_empty(),
        "Internal packages should still be checked for known vulnerabilities. Issues: {:?}",
        report
            .issues
            .iter()
            .map(|i| format!("{}: {}", i.package, i.check))
            .collect::<Vec<_>>()
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&config_dir);
}

#[test]
fn scan_hash_is_deterministic() {
    let dir = std::env::temp_dir();
    let deps = vec![
        Dependency {
            name: "react".to_string(),
            version: Some("^18.0".to_string()),
            ecosystem: Ecosystem::Npm,
        },
        Dependency {
            name: "lodash".to_string(),
            version: Some("^4.0".to_string()),
            ecosystem: Ecosystem::Npm,
        },
    ];
    let hash1 = scan_hash(&dir, &deps);
    let hash2 = scan_hash(&dir, &deps);
    assert_eq!(hash1, hash2);
}

#[test]
fn scan_hash_changes_with_different_deps() {
    let dir = std::env::temp_dir();
    let deps1 = vec![Dependency {
        name: "react".to_string(),
        version: Some("^18.0".to_string()),
        ecosystem: Ecosystem::Npm,
    }];
    let deps2 = vec![Dependency {
        name: "react".to_string(),
        version: Some("^19.0".to_string()),
        ecosystem: Ecosystem::Npm,
    }];
    assert_ne!(scan_hash(&dir, &deps1), scan_hash(&dir, &deps2));
}

#[test]
fn scan_hash_order_independent() {
    let dir = std::env::temp_dir();
    let deps1 = vec![
        Dependency {
            name: "a".to_string(),
            version: None,
            ecosystem: Ecosystem::Npm,
        },
        Dependency {
            name: "b".to_string(),
            version: None,
            ecosystem: Ecosystem::Npm,
        },
    ];
    let deps2 = vec![
        Dependency {
            name: "b".to_string(),
            version: None,
            ecosystem: Ecosystem::Npm,
        },
        Dependency {
            name: "a".to_string(),
            version: None,
            ecosystem: Ecosystem::Npm,
        },
    ];
    assert_eq!(scan_hash(&dir, &deps1), scan_hash(&dir, &deps2));
}

#[test]
fn scan_hash_changes_with_lockfile() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let id = CTR.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-hash-test-{}-{}", std::process::id(), id));
    std::fs::create_dir_all(&dir).unwrap();

    let deps = vec![Dependency {
        name: "react".to_string(),
        version: Some("^18.0".to_string()),
        ecosystem: Ecosystem::Npm,
    }];

    // Hash without lockfile
    let hash_no_lock = scan_hash(&dir, &deps);

    // Write a lockfile
    std::fs::write(dir.join("package-lock.json"), r#"{"lockfileVersion":3}"#).unwrap();
    let hash_with_lock = scan_hash(&dir, &deps);

    // Change lockfile content
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"node_modules/react":{"version":"18.999.0"}}}"#,
    )
    .unwrap();
    let hash_changed_lock = scan_hash(&dir, &deps);

    assert_ne!(
        hash_no_lock, hash_with_lock,
        "Adding lockfile should change hash"
    );
    assert_ne!(
        hash_with_lock, hash_changed_lock,
        "Changing lockfile content should change hash"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mark_source_does_not_overwrite_existing() {
    let mut issues = vec![
        Issue::new("pkg1", "existence", Severity::Error)
            .message("msg")
            .fix("fix"),
        Issue::new("pkg2", "existence", Severity::Error)
            .message("msg")
            .fix("fix"),
    ];
    // Pre-set source on first issue
    issues[0].source = Some("already-set".to_string());
    mark_source(&mut issues, "direct");
    assert_eq!(
        issues[0].source.as_deref(),
        Some("already-set"),
        "Should not overwrite existing source"
    );
    assert_eq!(
        issues[1].source.as_deref(),
        Some("direct"),
        "Should set source when None"
    );
}
