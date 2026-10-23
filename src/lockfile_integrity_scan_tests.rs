//! End-to-end: a package-lock.json entry whose integrity differs from the
//! registry packument blocks the scan, for direct and transitive packages.

use super::*;
use crate::registry::npm_tarball::NpmTarballRef;
use crate::registry::{PackageMetadata, RegistryExistence, RegistryMetadata};
use crate::report::Severity;
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir() -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "sj-lock-integrity-scan-{}-{}",
        std::process::id(),
        id
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Old, popular packages: nothing selects them for tarball verification, so
/// only the lockfile comparison can flag them.
struct PackumentRegistry;

#[async_trait]
impl RegistryExistence for PackumentRegistry {
    async fn exists(&self, _package_name: &str) -> Result<bool> {
        Ok(true)
    }

    fn ecosystem(&self) -> &str {
        "npm"
    }
}

#[async_trait]
impl RegistryMetadata for PackumentRegistry {
    async fn metadata(
        &self,
        package_name: &str,
        version: Option<&str>,
    ) -> Result<Option<PackageMetadata>> {
        let version = version.unwrap_or("1.0.0");
        Ok(Some(PackageMetadata {
            created: Some("2015-01-01T00:00:00Z".to_string()),
            latest_version_date: Some("2020-01-01T00:00:00Z".to_string()),
            downloads: Some(5_000_000),
            repository_url: Some(format!("https://github.com/acme/{package_name}")),
            dependency_count: Some(1),
            npm_tarball: Some(NpmTarballRef {
                version: version.to_string(),
                tarball: Some(format!(
                    "https://registry.npmjs.org/{package_name}/-/{package_name}-{version}.tgz"
                )),
                integrity: Some(format!("sha512-{package_name}GOOD")),
                shasum: None,
                declared: Default::default(),
            }),
            ..Default::default()
        }))
    }
}

struct NoOsv;

#[async_trait]
impl OsvClient for NoOsv {
    async fn query(&self, _: &str, _: &str, _: Option<&str>) -> Result<Vec<String>> {
        Ok(vec![])
    }
}

fn write_project(dir: &std::path::Path, left_integrity: &str, right_integrity: &str) {
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"fixture","version":"1.0.0","dependencies":{"left":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        serde_json::json!({
            "name":"fixture","version":"1.0.0","lockfileVersion":3,"requires":true,
            "packages":{
                "":{"name":"fixture","version":"1.0.0","dependencies":{"left":"1.0.0"}},
                "node_modules/left":{"version":"1.0.0","resolved":"https://registry.npmjs.org/left/-/left-1.0.0.tgz","integrity":left_integrity,"dependencies":{"right":"2.0.0"}},
                "node_modules/right":{"version":"2.0.0","resolved":"https://registry.npmjs.org/right/-/right-2.0.0.tgz","integrity":right_integrity}
            }
        })
        .to_string(),
    )
    .unwrap();
}

async fn scan(dir: &std::path::Path) -> ScanReport {
    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(dir, Some("npm"), &config).unwrap();
    let mut issues = preflight_project_inputs(dir, &specs, &config).unwrap();
    let projects = parse_project_inputs(dir, &specs, &config).unwrap();
    let opts = ScanOptions {
        no_cache: true,
        disable_osv_disk_cache: true,
        ..Default::default()
    };
    let mut packages = 0;
    for project in &projects {
        let report =
            scan_parsed_project(project, config.clone(), &PackumentRegistry, &NoOsv, &opts)
                .await
                .unwrap();
        packages += report.packages_checked;
        issues.extend(report.issues);
    }
    ScanReport::from_issues(packages, issues)
}

fn integrity_issues(report: &ScanReport) -> Vec<(String, String, Severity, Option<String>)> {
    report
        .issues
        .iter()
        .filter(|i| i.check.starts_with("metadata/lockfile-integrity"))
        .map(|i| {
            (
                i.package.clone(),
                i.check.clone(),
                i.severity,
                i.source.clone(),
            )
        })
        .collect()
}

#[tokio::test]
async fn lockfile_integrity_mismatch_blocks_direct_and_transitive() {
    let dir = unique_dir();
    write_project(&dir, "sha512-leftEVIL", "sha512-rightEVIL");
    let report = scan(&dir).await;
    let mut found = integrity_issues(&report);
    found.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        found,
        vec![
            (
                "left".to_string(),
                checks::names::METADATA_LOCKFILE_INTEGRITY_MISMATCH.to_string(),
                Severity::Error,
                Some("direct".to_string())
            ),
            (
                "right".to_string(),
                checks::names::METADATA_LOCKFILE_INTEGRITY_MISMATCH.to_string(),
                Severity::Error,
                Some("transitive".to_string())
            ),
        ],
        "{:?}",
        report.issues
    );
    assert!(report.has_errors());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn matching_lockfile_integrity_adds_no_issue() {
    let dir = unique_dir();
    write_project(&dir, "sha512-leftGOOD", "sha512-rightGOOD");
    let report = scan(&dir).await;
    assert!(integrity_issues(&report).is_empty(), "{:?}", report.issues);
    let _ = std::fs::remove_dir_all(&dir);
}
