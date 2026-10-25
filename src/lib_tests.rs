use super::*;

use crate::registry::{PackageMetadata, RegistryExistence, RegistryMetadata};

use crate::report::Severity;

use async_trait::async_trait;

use serde::Deserialize;

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
                ..Default::default()
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
                ..Default::default()
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

struct RecordingNameRegistry {
    existing: Vec<String>,
    exists_names: Arc<Mutex<Vec<String>>>,
    metadata_names: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl RegistryExistence for RecordingNameRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.exists_names
            .lock()
            .unwrap()
            .push(package_name.to_string());
        Ok(self.existing.iter().any(|name| name == package_name))
    }

    fn ecosystem(&self) -> &str {
        "npm"
    }
}

#[async_trait]
impl RegistryMetadata for RecordingNameRegistry {
    async fn metadata(
        &self,
        package_name: &str,
        _version: Option<&str>,
    ) -> Result<Option<PackageMetadata>> {
        self.metadata_names
            .lock()
            .unwrap()
            .push(package_name.to_string());
        if self.existing.iter().any(|name| name == package_name) {
            Ok(Some(PackageMetadata {
                created: Some("2020-01-01T00:00:00Z".to_string()),
                latest_version_date: Some("2020-01-01T00:00:00Z".to_string()),
                downloads: Some(50000),
                ..Default::default()
            }))
        } else {
            Ok(None)
        }
    }
}

struct RecordingNameOsvClient {
    queried_names: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl OsvClient for RecordingNameOsvClient {
    async fn query(
        &self,
        name: &str,
        _ecosystem: &str,
        _version: Option<&str>,
    ) -> Result<Vec<String>> {
        self.queried_names.lock().unwrap().push(name.to_string());
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

fn python_config(enforcement: config::PythonEnforcement) -> config::SloppyJoeConfig {
    config::SloppyJoeConfig {
        python_enforcement: enforcement,
        ..Default::default()
    }
}

fn python_config_with_poetry_policy(
    enforcement: config::PythonEnforcement,
    poetry_lock_policy: config::PoetryLockPolicy,
) -> config::SloppyJoeConfig {
    config::SloppyJoeConfig {
        python_enforcement: enforcement,
        poetry_lock_policy,
        ..Default::default()
    }
}

fn python_profile_opts<'a>(
    groups: &[&str],
    extras: &[&str],
    version: Option<&str>,
) -> ScanOptions<'a> {
    ScanOptions {
        python_groups: groups.iter().map(|value| value.to_string()).collect(),
        python_extras: extras.iter().map(|value| value.to_string()).collect(),
        python_version: version.map(str::to_string),
        ..Default::default()
    }
}

fn python_profile_opts_with_arch<'a>(
    groups: &[&str],
    extras: &[&str],
    version: Option<&str>,
    arch: Option<&str>,
) -> ScanOptions<'a> {
    ScanOptions {
        python_groups: groups.iter().map(|value| value.to_string()).collect(),
        python_extras: extras.iter().map(|value| value.to_string()).collect(),
        python_version: version.map(str::to_string),
        python_arch: arch.map(str::to_string),
        ..Default::default()
    }
}

fn trusted_poetry_content_hash(pyproject: &str) -> String {
    crate::lockfiles::python::poetry_content_hash_for_test(pyproject)
        .expect("test pyproject should produce a valid Poetry content-hash")
}

fn write_poetry_project(dir: &std::path::Path, pyproject: &str, lock_template: &str) {
    std::fs::write(dir.join("pyproject.toml"), pyproject).unwrap();
    let lock = lock_template.replace("__CONTENT_HASH__", &trusted_poetry_content_hash(pyproject));
    std::fs::write(dir.join("poetry.lock"), lock).unwrap();
}

fn unique_dir() -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-lib-{}-{}", std::process::id(), id));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture_dir(case: &str) -> std::path::PathBuf {
    repo_root().join("fixtures").join("npm").join(case)
}

fn ecosystem_fixture_dir(ecosystem: &str, case: &str) -> std::path::PathBuf {
    repo_root().join("fixtures").join(ecosystem).join(case)
}

#[derive(Debug, Deserialize)]
struct FixtureMetadata {
    ecosystem: String,
    expected: String,
}

fn load_fixture_metadata(dir: &std::path::Path) -> FixtureMetadata {
    let content = std::fs::read_to_string(dir.join("fixture.json")).unwrap();
    serde_json::from_str(&content).unwrap()
}

fn fixture_project_type(ecosystem: &str) -> Option<&'static str> {
    match ecosystem {
        "cargo" => Some("cargo"),
        "dotnet" => Some("dotnet"),
        "go" => Some("go"),
        "jvm" => Some("jvm"),
        "php" => Some("php"),
        "python" => Some("pypi"),
        "ruby" => Some("ruby"),
        _ => None,
    }
}

fn fixture_config(case: &str) -> config::SloppyJoeConfig {
    let path = fixture_dir(case).join("sloppy-joe.json");
    config::load_config(Some(&path)).expect("fixture config should remain valid")
}

fn parsed_npm_fixture_projects(
    case: &str,
) -> (
    std::path::PathBuf,
    config::SloppyJoeConfig,
    Vec<ParsedProject>,
) {
    let dir = fixture_dir(case);
    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("npm"), &config).unwrap();
    let projects = parse_project_inputs(&dir, &specs, &config).unwrap();
    (dir, config, projects)
}

async fn scan_fixture_with_fake_services(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config: config::SloppyJoeConfig,
    registry: &dyn Registry,
    osv_client: &dyn OsvClient,
    opts: &ScanOptions<'_>,
) -> Result<ScanReport> {
    let specs = detected_project_inputs_with_config(project_dir, project_type, &config)?;
    let preflight_warnings = preflight_project_inputs(project_dir, &specs, &config)?;
    let projects = parse_project_inputs(project_dir, &specs, &config)?;

    let mut total_packages = 0;
    let mut all_issues = preflight_warnings;
    let mut all_review_candidates = Vec::new();

    for project in &projects {
        if project.deps.is_empty() {
            continue;
        }
        let report =
            scan_parsed_project(project, config.clone(), registry, osv_client, opts).await?;
        total_packages += report.packages_checked;
        all_issues.extend(report.issues);
        all_review_candidates.extend(report.review_candidates);
    }

    Ok(ScanReport::from_issues_with_review_candidates(
        total_packages,
        all_issues,
        all_review_candidates,
    ))
}

fn assert_fixture_preflight_outcome(ecosystem: &str, case: &str) {
    let dir = ecosystem_fixture_dir(ecosystem, case);
    let meta = load_fixture_metadata(&dir);
    let project_type = fixture_project_type(&meta.ecosystem);
    let config_path = dir.join("sloppy-joe.json");
    let config = if config_path.is_file() {
        config::load_config(Some(&config_path)).expect("fixture config should remain valid")
    } else {
        config::SloppyJoeConfig::default()
    };
    let preflight = detected_project_inputs_with_config(&dir, project_type, &config)
        .and_then(|specs| preflight_project_inputs(&dir, &specs, &config));

    match meta.expected.as_str() {
        "pass" => {
            let warnings = preflight.expect("fixture should pass preflight");
            assert!(
                warnings.is_empty(),
                "pass fixture {ecosystem}/{case} unexpectedly produced warnings: {warnings:?}"
            );
        }
        "warn" => {
            let warnings = preflight.expect("fixture should warn, not fail");
            assert!(
                !warnings.is_empty(),
                "warn fixture {ecosystem}/{case} produced no warnings"
            );
        }
        "fail" => {
            preflight.expect_err("fixture should fail strict preflight");
        }
        other => panic!("unknown fixture outcome '{other}'"),
    }
}

#[cfg(unix)]
fn symlink_path(link: &std::path::Path, target: &std::path::Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

fn tracked_repo_files() -> std::collections::HashSet<std::path::PathBuf> {
    let output = std::process::Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(repo_root())
        .output()
        .expect("git ls-files should run for repo health checks");
    assert!(
        output.status.success(),
        "git ls-files failed for repo health checks: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            std::path::PathBuf::from(
                std::str::from_utf8(entry).expect("git ls-files should return valid utf-8 paths"),
            )
        })
        .collect()
}

fn collect_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("fixture directories must be readable") {
            let entry = entry.expect("fixture directory entries must be readable");
            let path = entry.path();
            let file_type = entry
                .file_type()
                .expect("fixture directory entries must have a file type");
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                files.push(path);
            }
        }
    }

    files
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

#[path = "lib_tests/part01_repo_self_check.rs"]
mod part01_repo_self_check;

#[path = "lib_tests/part02_preflight_blocks_go.rs"]
mod part02_preflight_blocks_go;

#[path = "lib_tests/part03_preflight_accepts_workspace.rs"]
mod part03_preflight_accepts_workspace;

#[path = "lib_tests/part04_preflight_blocks_bun.rs"]
mod part04_preflight_blocks_bun;

#[path = "lib_tests/part05_preflight_blocks_yarn.rs"]
mod part05_preflight_blocks_yarn;

#[path = "lib_tests/part06_preflight_blocks_invalid.rs"]
mod part06_preflight_blocks_invalid;

#[path = "lib_tests/part07_scan_uses_real.rs"]
mod part07_scan_uses_real;

#[path = "lib_tests/part08_npm_fixture_v1.rs"]
mod part08_npm_fixture_v1;

#[path = "lib_tests/part09_poetry_non_exact.rs"]
mod part09_poetry_non_exact;

#[path = "lib_tests/part10_uv_explicit_extra.rs"]
mod part10_uv_explicit_extra;

#[path = "lib_tests/part11_scan_hash_changes.rs"]
mod part11_scan_hash_changes;

#[path = "lib_tests/part12_strict_poetry_accepts.rs"]
mod part12_strict_poetry_accepts;

#[path = "lib_tests/part13_cargo_private_registry.rs"]
mod part13_cargo_private_registry;

#[path = "lib_tests/part14_preflight_does_not.rs"]
mod part14_preflight_does_not;

#[path = "lib_tests/part15_cargo_scan_allows.rs"]
mod part15_cargo_scan_allows;

#[path = "lib_tests/part16_version_age_cannot.rs"]
mod part16_version_age_cannot;

#[path = "lib_tests/part17_npm_default_registry.rs"]
mod part17_npm_default_registry;

#[path = "lib_tests/part18_npm_workspace_members.rs"]
mod part18_npm_workspace_members;

#[path = "lib_tests/part19_python_ci_strictness.rs"]
mod part19_python_ci_strictness;

#[path = "lib_tests/part20_internal_prefix_source.rs"]
mod part20_internal_prefix_source;

#[path = "lib_tests/part20_python_marker_coverage.rs"]
mod part20_python_marker_coverage;

#[path = "lib_tests/part21_uv_conflict_markers.rs"]
mod part21_uv_conflict_markers;

#[path = "lib_tests/part22_python_coverage_roots.rs"]
mod part22_python_coverage_roots;

#[path = "lib_tests/part23_python_gated_direct_deps.rs"]
mod part23_python_gated_direct_deps;

#[path = "lib_tests/part24_lookup_failure_cause.rs"]
mod part24_lookup_failure_cause;
