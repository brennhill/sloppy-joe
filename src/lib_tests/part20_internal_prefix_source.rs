//! An `internal` prefix pattern names packages, it does not prove where they come from
//! (red-team finding RT18). A prefix match is only exempted from public checks when the public
//! registry proves it cannot be the source; otherwise the scan blocks.

use super::*;

struct FailingRegistry;

#[async_trait]
impl RegistryExistence for FailingRegistry {
    async fn exists(&self, _package_name: &str) -> Result<bool> {
        anyhow::bail!("registry unreachable")
    }

    fn ecosystem(&self) -> &str {
        "npm"
    }
}

#[async_trait]
impl RegistryMetadata for FailingRegistry {
    async fn metadata(
        &self,
        _package_name: &str,
        _version: Option<&str>,
    ) -> Result<Option<PackageMetadata>> {
        anyhow::bail!("registry unreachable")
    }
}

fn internal_config(patterns: &[&str]) -> config::SloppyJoeConfig {
    config::SloppyJoeConfig {
        internal: std::collections::HashMap::from([(
            "npm".to_string(),
            patterns.iter().map(|p| p.to_string()).collect(),
        )]),
        ..Default::default()
    }
}

fn npm_project(manifest: &str, lockfile: Option<&str>) -> std::path::PathBuf {
    let dir = unique_dir();
    std::fs::write(dir.join("package.json"), manifest).unwrap();
    if let Some(lockfile) = lockfile {
        std::fs::write(dir.join("package-lock.json"), lockfile).unwrap();
    }
    dir
}

async fn scan(
    dir: &std::path::Path,
    config: config::SloppyJoeConfig,
    registry: &dyn registry::Registry,
) -> ScanReport {
    scan_with_services_inner(
        dir,
        config,
        parsers::parse_dependencies(dir, Some("npm")).unwrap(),
        registry,
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
}

fn unproven<'a>(report: &'a ScanReport, package: &str) -> Vec<&'a report::Issue> {
    report
        .issues
        .iter()
        .filter(|issue| {
            issue.package == package
                && issue.check == checks::names::RESOLUTION_INTERNAL_SOURCE_UNPROVEN
        })
        .collect()
}

#[tokio::test]
async fn internal_prefix_match_published_on_the_public_registry_blocks() {
    let dir = npm_project(r#"{"dependencies": {"acme-utils": "1.0.0"}}"#, None);
    let registry = FakeRegistry {
        existing: vec!["acme-utils".to_string()],
    };
    let report = scan(&dir, internal_config(&["acme-*"]), &registry).await;
    let issues = unproven(&report, "acme-utils");
    assert_eq!(issues.len(), 1, "{:?}", report.issues);
    assert_eq!(issues[0].severity, Severity::Error);
    assert_eq!(issues[0].source.as_deref(), Some("direct"));
    assert!(issues[0].message.contains("acme-*"), "{}", issues[0].message);
    assert!(report.has_errors());
    // Unproven, it is scanned like any other package rather than OSV-only.
    assert_eq!(report.packages_checked, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn internal_prefix_match_absent_from_the_public_registry_stays_internal() {
    let dir = npm_project(r#"{"dependencies": {"acme-utils": "1.0.0"}}"#, None);
    let registry = FakeRegistry { existing: vec![] };
    let report = scan(&dir, internal_config(&["acme-*"]), &registry).await;
    assert!(
        report.issues.iter().all(|issue| issue.package != "acme-utils"),
        "{:?}",
        report.issues
    );
    assert_eq!(report.packages_checked, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn exact_internal_name_is_a_deliberate_decision_and_needs_no_lookup() {
    let dir = npm_project(r#"{"dependencies": {"acme-utils": "1.0.0"}}"#, None);
    let report = scan(&dir, internal_config(&["acme-utils"]), &FailingRegistry).await;
    assert!(unproven(&report, "acme-utils").is_empty(), "{:?}", report.issues);
    assert_eq!(report.packages_checked, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn internal_prefix_proof_that_cannot_be_queried_blocks() {
    let dir = npm_project(r#"{"dependencies": {"acme-utils": "1.0.0"}}"#, None);
    let report = scan(&dir, internal_config(&["acme-*"]), &FailingRegistry).await;
    let issues = unproven(&report, "acme-utils");
    assert_eq!(issues.len(), 1, "{:?}", report.issues);
    assert_eq!(issues[0].severity, Severity::Error);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn transitive_internal_prefix_match_on_the_public_registry_blocks() {
    let dir = npm_project(
        r#"{"dependencies": {"react": "18.3.1"}}"#,
        Some(
            r#"{"name": "demo", "lockfileVersion": 3, "packages": {"": {"name": "demo", "dependencies": {"react": "18.3.1"}}, "node_modules/react": {"version": "18.3.1"}, "node_modules/@myorg/evil": {"version": "1.0.0"}}}"#,
        ),
    );
    let registry = FakeRegistry {
        existing: vec!["react".to_string(), "@myorg/evil".to_string()],
    };
    let report = scan(&dir, internal_config(&["@myorg/*"]), &registry).await;
    let issues = unproven(&report, "@myorg/evil");
    assert_eq!(issues.len(), 1, "{:?}", report.issues);
    assert_eq!(issues[0].source.as_deref(), Some("transitive"));
    let _ = std::fs::remove_dir_all(&dir);
}
