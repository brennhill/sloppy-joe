//! A scanned repository's `.npmrc` can redirect packages to another registry.
//! Such a redirect is repo-controlled input and must never opt packages out of
//! name-based advisory checks, and in CI it must be allowlisted out of repo.
use super::*;
use crate::registry::{PackageMetadata, RegistryExistence, RegistryMetadata};
use crate::report::Severity;
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir() -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-npm-redirect-{}-{}", std::process::id(), id));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct NoPublicRegistry;

#[async_trait]
impl RegistryExistence for NoPublicRegistry {
    async fn exists(&self, _package_name: &str) -> Result<bool> {
        Ok(true)
    }

    fn ecosystem(&self) -> &str {
        "npm"
    }
}

#[async_trait]
impl RegistryMetadata for NoPublicRegistry {
    async fn metadata(
        &self,
        _package_name: &str,
        _version: Option<&str>,
    ) -> Result<Option<PackageMetadata>> {
        Ok(Some(PackageMetadata {
            created: Some("2020-01-01T00:00:00Z".to_string()),
            latest_version_date: Some("2020-01-01T00:00:00Z".to_string()),
            downloads: Some(50000),
            ..Default::default()
        }))
    }
}

struct VulnOsv(Vec<&'static str>);

#[async_trait]
impl OsvClient for VulnOsv {
    async fn query(
        &self,
        name: &str,
        _ecosystem: &str,
        _version: Option<&str>,
    ) -> Result<Vec<String>> {
        Ok(if self.0.contains(&name) {
            vec!["MAL-2026-0001".to_string()]
        } else {
            vec![]
        })
    }
}

/// Mirrors red-team repro repo-b: a typosquat routed through a repo `.npmrc`.
fn write_redirected_project(dir: &std::path::Path, npmrc: &str) {
    std::fs::write(dir.join(".npmrc"), npmrc).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"fixture","version":"1.0.0","dependencies":{"lodahs":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        serde_json::json!({
            "name":"fixture","version":"1.0.0","lockfileVersion":3,"requires":true,
            "packages":{
                "":{"name":"fixture","version":"1.0.0","dependencies":{"lodahs":"1.0.0"}},
                "node_modules/lodahs":{"version":"1.0.0","resolved":"https://npm.example.com/lodahs/-/lodahs-1.0.0.tgz","integrity":"sha512-demo","dependencies":{"helpr":"2.0.0"}},
                "node_modules/helpr":{"version":"2.0.0","resolved":"https://npm.example.com/helpr/-/helpr-2.0.0.tgz","integrity":"sha512-demo"}
            }
        })
        .to_string(),
    )
    .unwrap();
}

async fn scan(
    dir: &std::path::Path,
    config: config::SloppyJoeConfig,
    osv: &dyn OsvClient,
    scan_mode: ScanMode,
) -> ScanReport {
    let specs = detected_project_inputs_with_config(dir, Some("npm"), &config).unwrap();
    let mut issues = preflight_project_inputs(dir, &specs, &config).unwrap();
    let projects = parse_project_inputs(dir, &specs, &config).unwrap();
    let opts = ScanOptions {
        scan_mode,
        no_cache: true,
        disable_osv_disk_cache: true,
        ..Default::default()
    };
    let mut packages = 0;
    for project in &projects {
        let report = scan_parsed_project(project, config.clone(), &NoPublicRegistry, osv, &opts)
            .await
            .unwrap();
        packages += report.packages_checked;
        issues.extend(report.issues);
    }
    ScanReport::from_issues(packages, issues)
}

fn trusting(name: &str, source: &str) -> config::SloppyJoeConfig {
    let mut config = config::SloppyJoeConfig::default();
    config.trusted_registries.insert(
        "npm".to_string(),
        vec![config::TrustedRegistry {
            name: name.to_string(),
            source: source.to_string(),
        }],
    );
    config
}

fn has(report: &ScanReport, package: &str, check: &str, severity: Severity) -> bool {
    report
        .issues
        .iter()
        .any(|i| i.package == package && i.check == check && i.severity == severity)
}

#[tokio::test]
async fn repo_npmrc_default_registry_redirect_does_not_skip_osv() {
    let dir = unique_dir();
    write_redirected_project(&dir, "registry=https://npm.example.com/\n");
    let report = scan(
        &dir,
        config::SloppyJoeConfig::default(),
        &VulnOsv(vec!["lodahs", "helpr"]),
        ScanMode::Full,
    )
    .await;
    for (package, source) in [("lodahs", "direct"), ("helpr", "transitive")] {
        assert!(
            report.issues.iter().any(|i| i.package == package
                && i.check == checks::names::MALICIOUS_KNOWN_VULNERABILITY
                && i.severity == Severity::Error
                && i.source.as_deref() == Some(source)),
            "OSV must still run for {package} routed by repo .npmrc: {:?}",
            report.issues
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn repo_npmrc_scoped_registry_redirect_does_not_skip_osv() {
    let dir = unique_dir();
    std::fs::write(
        dir.join(".npmrc"),
        "@company:registry=https://registry.example/private/\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"app","dependencies":{"@company/client":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("package-lock.json"), serde_json::json!({
        "lockfileVersion":3,"packages": {
            "":{"dependencies":{"@company/client":"1.0.0"}},
            "node_modules/@company/client":{"version":"1.0.0","resolved":"https://registry.example/private/client.tgz","integrity":"sha512-demo"}
        }
    }).to_string()).unwrap();
    let report = scan(
        &dir,
        trusting("@company", "https://registry.example/private/"),
        &VulnOsv(vec!["@company/client"]),
        ScanMode::Ci,
    )
    .await;
    assert!(
        has(
            &report,
            "@company/client",
            checks::names::MALICIOUS_KNOWN_VULNERABILITY,
            Severity::Error
        ),
        "{:?}",
        report.issues
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn ci_blocks_unallowlisted_repo_npmrc_registry_redirect() {
    let dir = unique_dir();
    write_redirected_project(&dir, "registry=https://npm.example.com/\n");
    let report = scan(
        &dir,
        config::SloppyJoeConfig::default(),
        &VulnOsv(vec![]),
        ScanMode::Ci,
    )
    .await;
    assert!(report.has_errors(), "{:?}", report.issues);
    for package in ["lodahs", "helpr"] {
        assert!(
            has(
                &report,
                package,
                checks::names::RESOLUTION_UNTRUSTED_REGISTRY_SOURCE,
                Severity::Error
            ),
            "{package}: {:?}",
            report.issues
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn non_ci_unallowlisted_registry_redirect_warns_without_blocking() {
    let dir = unique_dir();
    write_redirected_project(&dir, "registry=https://npm.example.com/\n");
    let report = scan(
        &dir,
        config::SloppyJoeConfig::default(),
        &VulnOsv(vec![]),
        ScanMode::Full,
    )
    .await;
    assert!(!report.has_errors(), "{:?}", report.issues);
    assert!(has(
        &report,
        "lodahs",
        checks::names::RESOLUTION_PRIVATE_REGISTRY_UNVETTED,
        Severity::Warning
    ));
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn ci_accepts_registry_redirect_allowlisted_in_external_config() {
    let dir = unique_dir();
    write_redirected_project(&dir, "registry=https://npm.example.com\n");
    let report = scan(
        &dir,
        trusting("default", "https://npm.example.com/"),
        &VulnOsv(vec![]),
        ScanMode::Ci,
    )
    .await;
    assert!(!report.has_errors(), "{:?}", report.issues);
    assert!(has(
        &report,
        "lodahs",
        checks::names::RESOLUTION_PRIVATE_REGISTRY_UNVETTED,
        Severity::Warning
    ));
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn trusting_a_scoped_route_does_not_trust_the_default_route() {
    let dir = unique_dir();
    write_redirected_project(&dir, "registry=https://npm.example.com/\n");
    let report = scan(
        &dir,
        trusting("@company", "https://npm.example.com/"),
        &VulnOsv(vec![]),
        ScanMode::Ci,
    )
    .await;
    assert!(
        has(
            &report,
            "lodahs",
            checks::names::RESOLUTION_UNTRUSTED_REGISTRY_SOURCE,
            Severity::Error
        ),
        "{:?}",
        report.issues
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn trusting_a_different_registry_url_does_not_trust_the_route() {
    let dir = unique_dir();
    write_redirected_project(&dir, "registry=https://npm.example.com/\n");
    let report = scan(
        &dir,
        trusting("default", "https://npm.example.com/other/"),
        &VulnOsv(vec![]),
        ScanMode::Ci,
    )
    .await;
    assert!(
        has(
            &report,
            "lodahs",
            checks::names::RESOLUTION_UNTRUSTED_REGISTRY_SOURCE,
            Severity::Error
        ),
        "{:?}",
        report.issues
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn npm_trusted_registry_config_rejects_invalid_names_and_sources() {
    for (name, source) in [
        ("company", "https://registry.example/"),
        ("@company", "http://registry.example/"),
        ("default", "not a url"),
        ("@company", "https://user:pw@registry.example/"),
    ] {
        let errors = trusting(name, source).validate();
        assert!(
            !errors.is_empty(),
            "{name} {source} should be rejected for npm"
        );
    }
    assert!(
        trusting("@company", "https://registry.example/private/")
            .validate()
            .is_empty()
    );
    assert!(
        trusting("default", "https://registry.example/")
            .validate()
            .is_empty()
    );
}
