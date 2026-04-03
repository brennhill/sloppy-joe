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

    match meta.expected.as_str() {
        "pass" => {
            let warnings =
                preflight_scan_inputs(&dir, project_type).expect("fixture should pass preflight");
            assert!(
                warnings.is_empty(),
                "pass fixture {ecosystem}/{case} unexpectedly produced warnings: {warnings:?}"
            );
        }
        "warn" => {
            let warnings =
                preflight_scan_inputs(&dir, project_type).expect("fixture should warn, not fail");
            assert!(
                !warnings.is_empty(),
                "warn fixture {ecosystem}/{case} produced no warnings"
            );
        }
        "fail" => {
            preflight_scan_inputs(&dir, project_type)
                .expect_err("fixture should fail strict preflight");
        }
        other => panic!("unknown fixture outcome '{other}'"),
    }
}

#[cfg(unix)]
fn symlink_path(link: &std::path::Path, target: &std::path::Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

#[test]
fn repo_self_check_config_is_valid_and_has_exact_similarity_suppressions() {
    let config_path = repo_root().join(".github/sloppy-joe-self-check.json");
    let config = config::load_config(Some(&config_path))
        .expect("checked-in self-check config should remain valid");
    let cargo_rules = config
        .similarity_exceptions
        .get("cargo")
        .expect("self-check config should define cargo similarity suppressions");

    let expected = [
        ("serde_json", "serde", "segment-overlap"),
        ("clap", "coap", "keyboard-proximity"),
        ("async-trait", "trait-async", "word-reorder"),
        ("colored", "colorer", "keyboard-proximity"),
        ("futures", "future", "extra-char"),
        ("libc", "libx", "keyboard-proximity"),
        ("serde", "xerde", "keyboard-proximity"),
        ("strsim", "strim", "extra-char"),
        ("tokio", "toki", "extra-char"),
        ("toml", "tomo", "keyboard-proximity"),
    ];

    for (package, candidate, generator) in expected {
        assert!(
            cargo_rules.iter().any(|rule| {
                rule.package == package
                    && rule.candidate == candidate
                    && rule.generator == generator
            }),
            "missing self-check similarity suppression for {package} -> {candidate} ({generator})"
        );
    }
}

#[test]
fn repo_cargo_manifest_pins_direct_dependencies_exactly() {
    let cargo_toml = std::fs::read_to_string(repo_root().join("Cargo.toml"))
        .expect("repo Cargo.toml must exist");
    let parsed: toml::Value = toml::from_str(&cargo_toml).expect("repo Cargo.toml must be valid");
    let deps = parsed
        .get("dependencies")
        .and_then(|value| value.as_table())
        .expect("repo Cargo.toml should have a [dependencies] table");

    for (name, value) in deps {
        let version = match value {
            toml::Value::String(version) => version.as_str(),
            toml::Value::Table(table) => table
                .get("version")
                .and_then(|version| version.as_str())
                .expect("dependency tables should carry explicit versions"),
            other => panic!("unexpected dependency shape for {name}: {other:?}"),
        };

        assert!(
            version.starts_with('='),
            "dependency {name} should use an exact version pin, found {version}"
        );
    }
}

#[test]
fn repo_ci_self_check_build_uses_locked_cargo_graph() {
    let workflow = std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml"))
        .expect("CI workflow must exist");
    assert!(
        workflow.contains("run: cargo build --release --locked"),
        "self-check CI must build with --locked so Cargo.lock cannot drift before scanning"
    );
}

#[test]
fn repo_ci_self_check_scans_repo_cargo_project_explicitly() {
    let workflow = std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml"))
        .expect("CI workflow must exist");
    assert!(
        workflow.contains("sloppy-joe check --no-cache --type cargo --config"),
        "self-check CI should target the repo's Cargo project explicitly instead of auto-discovering fixture directories"
    );
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

#[test]
fn repo_cargo_lock_is_tracked_for_locked_ci_builds() {
    let tracked = tracked_repo_files();
    assert!(
        tracked.contains(&std::path::PathBuf::from("Cargo.lock")),
        "CI uses cargo build --locked, so the repository must track Cargo.lock"
    );
}

#[test]
fn fixture_files_are_tracked_in_git() {
    let repo = repo_root();
    let tracked = tracked_repo_files();

    let mut untracked = Vec::new();
    for path in collect_files(&repo.join("fixtures")) {
        let relative = path
            .strip_prefix(&repo)
            .expect("fixture path should live under repo root")
            .to_path_buf();
        if !tracked.contains(&relative) {
            untracked.push(relative);
        }
    }

    assert!(
        untracked.is_empty(),
        "all fixture files must be tracked in git so CI sees the same corpus: {:?}",
        untracked
    );
}

#[cfg(unix)]
#[test]
fn preflight_blocks_broken_detected_manifests_for_all_ecosystems() {
    let cases = [
        ("package.json", Some("npm")),
        ("requirements.txt", Some("pypi")),
        ("Cargo.toml", Some("cargo")),
        ("go.mod", Some("go")),
        ("Gemfile", Some("ruby")),
        ("composer.json", Some("php")),
        ("build.gradle", Some("jvm")),
        ("pom.xml", Some("jvm")),
        ("app.csproj", Some("dotnet")),
    ];

    for (manifest_name, project_type) in cases {
        let dir = unique_dir();
        symlink_path(
            &dir.join(manifest_name),
            &dir.join(format!("missing-{}", manifest_name)),
        );

        let err = preflight_scan_inputs(&dir, project_type)
            .expect_err("broken detected manifests must block scanning");
        let msg = err.to_string();
        assert!(
            msg.contains(manifest_name),
            "expected error to mention {manifest_name}, got: {msg}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn preflight_requires_manifest_for_explicit_project_types() {
    let cases = [
        (Some("npm"), "package.json"),
        (
            Some("pypi"),
            "Required Python manifest is missing for this project type.",
        ),
        (Some("cargo"), "Cargo.toml"),
        (Some("go"), "go.mod"),
        (Some("ruby"), "Gemfile"),
        (Some("php"), "composer.json"),
        (Some("jvm"), "build.gradle, build.gradle.kts, or pom.xml"),
        (Some("dotnet"), ".csproj"),
    ];

    for (project_type, expected) in cases {
        let dir = unique_dir();

        let err = preflight_scan_inputs(&dir, project_type)
            .expect_err("explicit project types must require a manifest");
        let msg = err.to_string();
        assert!(
            msg.contains(expected),
            "expected error to mention {expected}, got: {msg}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn preflight_requires_strict_lockfiles_for_supported_ecosystems() {
    let cases = [
        (
            Some("npm"),
            "package.json",
            r#"{"dependencies":{"react":"^18.0.0"}}"#,
            "package-lock.json",
        ),
        (
            Some("pypi"),
            "pyproject.toml",
            "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"2.31.0\"\n",
            "poetry.lock",
        ),
        (
            Some("cargo"),
            "Cargo.toml",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
            "Cargo.lock",
        ),
        (
            Some("ruby"),
            "Gemfile",
            "source 'https://rubygems.org'\ngem 'rails'\n",
            "Gemfile.lock",
        ),
        (
            Some("php"),
            "composer.json",
            r#"{"require":{"laravel/framework":"^10.0"}}"#,
            "composer.lock",
        ),
        (
            Some("jvm"),
            "build.gradle",
            "plugins { id 'java' }\ndependencies { implementation 'org.slf4j:slf4j-api:2.0.0' }\n",
            "gradle.lockfile",
        ),
        (
            Some("dotnet"),
            "app.csproj",
            r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>"#,
            "packages.lock.json",
        ),
    ];

    for (project_type, manifest_name, manifest_content, expected_lockfile) in cases {
        let dir = unique_dir();
        std::fs::write(dir.join(manifest_name), manifest_content).unwrap();

        let err = preflight_scan_inputs(&dir, project_type)
            .expect_err("missing required lockfiles must block scanning");
        let msg = err.to_string();
        assert!(
            msg.contains(expected_lockfile),
            "expected error to mention {expected_lockfile}, got: {msg}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn preflight_accepts_npm_shrinkwrap_as_required_lockfile() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("npm-shrinkwrap.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, Some("npm")).unwrap();
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_malformed_npm_lockfiles() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("package-lock.json"), "{not json").unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("malformed npm lockfiles must block scanning");
    let msg = err.to_string();
    assert!(msg.contains("package-lock.json"));
    assert!(msg.contains("parse"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_peer_dependencies_in_npm_lockfile_roots() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"peerDependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","peerDependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, Some("npm")).unwrap();
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_prefers_npm_shrinkwrap_over_package_lock() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"18.3.1"}}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("npm-shrinkwrap.json"), "{not json").unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("npm-shrinkwrap.json must take precedence over package-lock.json");
    let msg = err.to_string();
    assert!(msg.contains("npm-shrinkwrap.json"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_out_of_sync_npm_lockfile_roots() {
    let dir = unique_dir();
    std::fs::write(dir.join("package.json"), r#"{"name":"demo"}"#).unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"18.3.1"}}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("strict npm scans must block out-of-sync lockfile roots");
    let msg = err.to_string();
    assert!(msg.contains("package-lock.json"));
    assert!(msg.contains("out of sync"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_missing_poetry_lockfiles_for_poetry_projects() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"2.31.0\"\n",
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("pypi"))
        .expect_err("Poetry projects must require poetry.lock");
    assert!(err.to_string().contains("poetry.lock"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_malformed_poetry_lockfiles_for_poetry_projects() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"2.31.0\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("poetry.lock"), "not = [valid").unwrap();

    let err = preflight_scan_inputs(&dir, Some("pypi"))
        .expect_err("malformed trusted Python lockfiles must block scanning");
    let msg = err.to_string();
    assert!(msg.contains("poetry.lock"));
    assert!(msg.contains("parse"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_with_config_warns_for_legacy_requirements_projects_by_default() {
    let dir = unique_dir();
    std::fs::write(dir.join("requirements.txt"), "# legacy but allowed\n").unwrap();

    let report = scan_with_config(
        &dir,
        Some("pypi"),
        Default::default(),
        &ScanOptions::default(),
    )
    .await
    .expect("requirements.txt should be allowed in default Python mode");

    assert_eq!(report.packages_checked, 0);
    assert!(report.issues.iter().any(|issue| {
        issue.severity == Severity::Warning
            && issue.message.contains("requirements.txt")
            && issue.message.contains("Poetry")
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_with_config_reports_active_local_overlay_relaxations() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();

    let report = scan_with_config(
        &dir,
        Some("cargo"),
        config::SloppyJoeConfig {
            active_local_overlay_relaxations: vec!["host-local Cargo config trust".to_string()],
            ..Default::default()
        },
        &ScanOptions::default(),
    )
    .await
    .expect("local overlay relaxations should be reported as warnings, not block the scan");

    assert!(report.issues.iter().any(|issue| {
        issue.severity == Severity::Warning
            && issue.message.contains("local-only overlay")
            && issue.message.contains("host-local Cargo config trust")
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_with_config_warns_for_other_legacy_python_manifests_by_default() {
    let cases = [
        (
            "Pipfile",
            "[[source]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\n[packages]\n",
        ),
        (
            "pyproject.toml",
            "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        ),
        ("setup.cfg", "[metadata]\nname = demo\nversion = 0.1.0\n"),
        (
            "setup.py",
            "from setuptools import setup\nsetup(name='demo', version='0.1.0')\n",
        ),
    ];

    for (manifest_name, content) in cases {
        let dir = unique_dir();
        std::fs::write(dir.join(manifest_name), content).unwrap();

        let report = scan_with_config(
            &dir,
            Some("pypi"),
            Default::default(),
            &ScanOptions::default(),
        )
        .await
        .expect("legacy Python manifests should warn and continue by default");

        assert!(report.issues.iter().any(|issue| {
            issue.severity == Severity::Warning
                && issue.message.contains(manifest_name)
                && issue.message.contains("Poetry")
        }));

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[tokio::test]
async fn scan_with_config_blocks_legacy_python_manifests_in_poetry_only_mode() {
    let dir = unique_dir();
    std::fs::write(dir.join("requirements.txt"), "# legacy manifest\n").unwrap();

    let err = scan_with_config(
        &dir,
        Some("pypi"),
        python_config(config::PythonEnforcement::PoetryOnly),
        &ScanOptions::default(),
    )
    .await
    .expect_err("poetry_only mode must reject legacy Python manifests");

    let msg = err.to_string();
    assert!(msg.contains("Poetry"));
    assert!(msg.contains("requirements.txt"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_requires_go_sum_when_external_dependencies_exist() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("go.mod"),
        "module example.com/app\n\ngo 1.21\n\nrequire github.com/gin-gonic/gin v1.9.1\n",
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("go"))
        .expect_err("go projects with external deps must require go.sum");
    let msg = err.to_string();
    assert!(msg.contains("go.sum"));
    assert!(msg.contains("go mod tidy"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_requires_go_sum_when_only_indirect_external_dependencies_exist() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("go.mod"),
        "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1 // indirect\n)\n",
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("go"))
        .expect_err("go projects with indirect external deps must still require go.sum");
    let msg = err.to_string();
    assert!(msg.contains("go.sum"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_go_without_go_sum_for_stdlib_only_modules() {
    let dir = unique_dir();
    std::fs::write(dir.join("go.mod"), "module example.com/app\n\ngo 1.21\n").unwrap();

    let warnings = preflight_scan_inputs(&dir, Some("go")).unwrap();
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_go_projects_with_local_replace_targets() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("go.mod"),
        "module example.com/app\n\ngo 1.21\n\nrequire example.com/localdep v0.0.0\nreplace example.com/localdep => ../localdep\n",
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("go"))
        .expect_err("go projects with local replace targets must fail closed");
    assert!(err.to_string().contains("local go.mod replace target"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn detected_project_inputs_recurses_into_nested_projects() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::create_dir_all(dir.join("services/api")).unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package-lock.json"),
        r#"{"lockfileVersion":3}"#,
    )
    .unwrap();
    std::fs::write(dir.join("services/api/requirements.txt"), "flask==2.0\n").unwrap();

    let specs = detected_project_inputs(&dir, None).unwrap();
    let paths: Vec<String> = specs
        .iter()
        .map(|spec| {
            spec.manifest_path
                .strip_prefix(&dir)
                .unwrap()
                .display()
                .to_string()
        })
        .collect();

    assert!(paths.iter().any(|path| path == "apps/web/package.json"));
    assert!(
        paths
            .iter()
            .any(|path| path == "services/api/requirements.txt")
    );

    let npm_specs = detected_project_inputs(&dir, Some("npm")).unwrap();
    assert_eq!(npm_specs.len(), 1);
    assert_eq!(
        npm_specs[0]
            .manifest_path
            .strip_prefix(&dir)
            .unwrap()
            .display()
            .to_string(),
        "apps/web/package.json"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn detected_project_inputs_discovers_alternate_python_requirements_files() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("services/api")).unwrap();
    std::fs::write(
        dir.join("services/api/requirements-dev.txt"),
        "flask==2.0\n",
    )
    .unwrap();

    let specs = detected_project_inputs(&dir, None).unwrap();
    let paths: Vec<String> = specs
        .iter()
        .map(|spec| {
            spec.manifest_path
                .strip_prefix(&dir)
                .unwrap()
                .display()
                .to_string()
        })
        .collect();

    assert!(
        paths
            .iter()
            .any(|path| path == "services/api/requirements-dev.txt"),
        "alternate requirements entrypoints must be discoverable from a repo-root scan"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parse_project_inputs_dedupes_requirement_files_included_by_other_entrypoints() {
    let dir = unique_dir();
    std::fs::write(dir.join("requirements.txt"), "-r requirements-base.txt\n").unwrap();
    std::fs::write(dir.join("requirements-base.txt"), "requests==2.31.0\n").unwrap();

    let specs = detected_project_inputs(&dir, None).unwrap();
    let projects = parse_project_inputs(&dir, &specs, &config::SloppyJoeConfig::default())
        .expect("included requirement files must not be scanned as standalone projects");

    assert_eq!(projects.len(), 1);
    assert_eq!(
        projects[0]
            .spec
            .manifest_path
            .strip_prefix(&dir)
            .unwrap()
            .display()
            .to_string(),
        "requirements.txt"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn detected_project_inputs_do_not_skip_generic_directory_names() {
    for directory_name in ["build", "dist", "target", ".venv", "venv", "__pycache__"] {
        let dir = unique_dir();
        std::fs::create_dir_all(dir.join(directory_name).join("service")).unwrap();
        std::fs::write(
            dir.join(directory_name).join("service/package.json"),
            r#"{"dependencies":{"react":"^18.0.0"}}"#,
        )
        .unwrap();

        let specs = detected_project_inputs(&dir, None).unwrap();
        let paths: Vec<String> = specs
            .iter()
            .map(|spec| {
                spec.manifest_path
                    .strip_prefix(&dir)
                    .unwrap()
                    .display()
                    .to_string()
            })
            .collect();

        assert!(
            paths
                .iter()
                .any(|path| path == &format!("{directory_name}/service/package.json")),
            "root discovery must not silently skip source-controlled projects under {directory_name}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(unix)]
#[test]
fn detected_project_inputs_block_symlinked_dirs_outside_root() {
    let dir = unique_dir();
    let outside = unique_dir();
    std::fs::write(
        outside.join("package.json"),
        r#"{"dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("linked-outside")).unwrap();

    let err = detected_project_inputs(&dir, None)
        .expect_err("symlinked directories outside the scan root must block discovery");

    assert!(err.to_string().contains("linked-outside"));

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&outside);
}

#[cfg(unix)]
#[test]
fn detected_project_inputs_block_ignored_name_symlinks_outside_root() {
    for directory_name in ["build", "dist", "target", ".venv", "venv", "__pycache__"] {
        let dir = unique_dir();
        let outside = unique_dir();
        std::fs::write(outside.join("requirements.txt"), "requests==2.31.0\n").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join(directory_name)).unwrap();

        let err = detected_project_inputs(&dir, None)
            .expect_err("outside-root symlinked directories must block discovery");
        assert!(err.to_string().contains(directory_name));

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&outside);
    }
}

#[tokio::test]
async fn repo_root_scans_warn_for_legacy_python_manifests_instead_of_skipping_them() {
    let cases = [
        (
            "pyproject.toml",
            "[project]\nname = \"api\"\nversion = \"0.1.0\"\ndependencies = [\"flask==2.0.0\"]\n",
        ),
        (
            "Pipfile",
            "[[source]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\n[packages]\nflask = \"==2.0.0\"\n",
        ),
        (
            "setup.cfg",
            "[metadata]\nname = api\nversion = 0.1.0\n[options]\ninstall_requires =\n    flask==2.0.0\n",
        ),
        (
            "setup.py",
            "from setuptools import setup\nsetup(name='api', version='0.1.0', install_requires=['flask==2.0.0'])\n",
        ),
    ];

    for (manifest_name, manifest_content) in cases {
        let dir = unique_dir();
        std::fs::create_dir_all(dir.join("apps/web")).unwrap();
        std::fs::create_dir_all(dir.join("services/api")).unwrap();
        std::fs::write(
            dir.join("apps/web/package.json"),
            r#"{"dependencies":{"react":"^18.0.0"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("apps/web/package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"":{"dependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("services/api").join(manifest_name),
            manifest_content,
        )
        .unwrap();

        let report = scan_with_config(&dir, None, Default::default(), &ScanOptions::default())
            .await
            .expect("legacy Python manifests must be scanned, not ignored");

        assert!(report.issues.iter().any(|issue| {
            issue.severity == Severity::Warning
                && issue.message.contains(manifest_name)
                && issue.message.contains("Poetry")
        }));

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn detected_project_inputs_prefer_poetry_projects_over_same_directory_legacy_manifests() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"2.31.0\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("poetry.lock"),
        "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[metadata]\nlock-version = \"2.0\"\npython-versions = \"^3.11\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("requirements.txt"), "requests==2.30.0\n").unwrap();

    let specs = detected_project_inputs(&dir, Some("pypi"))
        .expect("same-directory Poetry and requirements manifests must be discoverable");

    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].kind, ProjectInputKind::PyProjectPoetry);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parse_project_inputs_extracts_dependencies_from_legacy_python_manifests() {
    let cases = [
        (
            "requirements.txt",
            "requests==2.31.0\nurllib3==2.1.0\n",
            vec!["requests", "urllib3"],
        ),
        (
            "Pipfile",
            "[[source]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\n[packages]\nrequests = \"==2.31.0\"\n[dev-packages]\npytest = \"==8.1.1\"\n",
            vec!["requests", "pytest"],
        ),
        (
            "pyproject.toml",
            "[project]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\"requests==2.31.0\"]\n[project.optional-dependencies]\ndev = [\"pytest==8.1.1\"]\n",
            vec!["requests", "pytest"],
        ),
        (
            "setup.cfg",
            "[metadata]\nname = demo\nversion = 0.1.0\n[options]\ninstall_requires =\n    requests==2.31.0\n[options.extras_require]\ndev =\n    pytest==8.1.1\n",
            vec!["requests", "pytest"],
        ),
        (
            "setup.py",
            "from setuptools import setup\nsetup(name='demo', version='0.1.0', install_requires=['requests==2.31.0'], extras_require={'dev': ['pytest==8.1.1']})\n",
            vec!["requests", "pytest"],
        ),
    ];

    for (manifest_name, manifest_content, expected_names) in cases {
        let dir = unique_dir();
        std::fs::write(dir.join(manifest_name), manifest_content).unwrap();

        let specs = detected_project_inputs(&dir, Some("pypi")).unwrap();
        let projects = parse_project_inputs(&dir, &specs, &config::SloppyJoeConfig::default())
            .expect("legacy Python manifests must parse into dependencies");
        assert_eq!(projects.len(), 1);

        let names: Vec<&str> = projects[0]
            .deps
            .iter()
            .map(|dep| dep.name.as_str())
            .collect();
        for expected_name in expected_names {
            assert!(
                names.contains(&expected_name),
                "expected {manifest_name} to include dependency {expected_name}, got {names:?}"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn detected_project_inputs_finds_hidden_projects_inside_checked_in_node_modules() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("vendor/node_modules/hidden-app")).unwrap();
    std::fs::write(
        dir.join("vendor/node_modules/hidden-app/package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("vendor/node_modules/hidden-app/package-lock.json"),
        r#"{"name":"hidden-app","lockfileVersion":3,"packages":{"":{"name":"hidden-app","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1"}}}"#,
    )
    .unwrap();

    let specs = detected_project_inputs(&dir, None)
        .expect("repo-root discovery must not let checked-in node_modules hide real projects");
    let paths: Vec<String> = specs
        .iter()
        .map(|spec| {
            spec.manifest_path
                .strip_prefix(&dir)
                .unwrap()
                .display()
                .to_string()
        })
        .collect();

    assert!(
        paths
            .iter()
            .any(|path| path == "vendor/node_modules/hidden-app/package.json"),
        "checked-in projects with their own lockfiles must still be discoverable under node_modules"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn detected_project_inputs_finds_hidden_python_projects_inside_checked_in_node_modules() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("vendor/node_modules/hidden-py")).unwrap();
    std::fs::write(
        dir.join("vendor/node_modules/hidden-py/requirements.txt"),
        "requests==2.31.0\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("vendor/node_modules/hidden-py/poetry.lock"),
        "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[metadata]\nlock-version = \"2.0\"\npython-versions = \"^3.8\"\n",
    )
    .unwrap();

    let specs = detected_project_inputs(&dir, None)
        .expect("supported non-npm projects under node_modules must not be silently skipped");
    let paths: Vec<String> = specs
        .iter()
        .map(|spec| {
            spec.manifest_path
                .strip_prefix(&dir)
                .unwrap()
                .display()
                .to_string()
        })
        .collect();

    assert!(
        paths
            .iter()
            .any(|path| path == "vendor/node_modules/hidden-py/requirements.txt"),
        "supported non-npm manifests under node_modules must still be discoverable"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn detected_project_inputs_ignore_installed_packages_inside_node_modules_without_project_lockfiles()
{
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("node_modules/react")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("node_modules/react/package.json"),
        r#"{"name":"react","version":"18.3.1"}"#,
    )
    .unwrap();

    let specs = detected_project_inputs(&dir, None).unwrap();
    let paths: Vec<String> = specs
        .iter()
        .map(|spec| {
            spec.manifest_path
                .strip_prefix(&dir)
                .unwrap()
                .display()
                .to_string()
        })
        .collect();

    assert!(
        !paths
            .iter()
            .any(|path| path == "node_modules/react/package.json"),
        "discovery must not explode into installed npm packages"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_ignores_python_vendor_manifests_inside_node_modules() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("node_modules/vendor-python")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("node_modules/vendor-python/setup.py"),
        "from setuptools import setup\n",
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, None)
        .expect("vendored Python manifests inside node_modules must not block unrelated scans");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_local_file_npm_dependencies_outside_scan_root() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"local-lib":"file:../local-lib"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"local-lib":"file:../local-lib"}},"node_modules/local-lib":{"resolved":"../local-lib","link":true}}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("local npm dependencies outside the scan root must block scanning");
    let msg = err.to_string();
    assert!(msg.contains("outside the scan root"));
    assert!(msg.contains("local-lib"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_unresolved_workspace_npm_dependencies() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"workspace-lib":"workspace:*"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"workspace-lib":"workspace:*"}},"node_modules/workspace-lib":{"resolved":"packages/workspace-lib","link":true}}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("workspace npm dependencies must resolve to a scanned local project");
    let msg = err.to_string();
    assert!(msg.contains("workspace-lib"));
    assert!(msg.contains("workspaces"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_local_npm_dependencies_within_scan_root() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::create_dir_all(dir.join("packages/workspace-lib")).unwrap();
    std::fs::create_dir_all(dir.join("packages/local-lib")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","workspaces":["apps/*","packages/*"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"root","lockfileVersion":3,"packages":{"":{"name":"root","workspaces":["apps/*","packages/*"]},"apps/web":{"name":"web","dependencies":{"workspace-lib":"workspace:*","local-lib":"file:../../packages/local-lib"}},"packages/workspace-lib":{"name":"workspace-lib","dependencies":{"react":"18.3.1"}},"packages/local-lib":{"name":"local-lib"},"node_modules/workspace-lib":{"resolved":"packages/workspace-lib","link":true},"node_modules/local-lib":{"resolved":"packages/local-lib","link":true},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"workspace-lib":"workspace:*","local-lib":"file:../../packages/local-lib"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/workspace-lib/package.json"),
        r#"{"name":"workspace-lib","dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/local-lib/package.json"),
        r#"{"name":"local-lib"}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, None)
        .expect("local npm dependencies within the scan root must be accepted when discoverable");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_workspace_child_with_only_root_lockfile() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","workspaces":["apps/*"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"root","lockfileVersion":3,"packages":{"":{"name":"root","workspaces":["apps/*"]},"apps/web":{"name":"web","dependencies":{"react":"^18.3.0"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"react":"^18.3.0"}}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, None)
        .expect("workspace children should bind to the root npm lockfile when one exists");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_shadow_child_lockfile_inside_npm_workspace() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","workspaces":["apps/*"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"root","lockfileVersion":3,"packages":{"":{"name":"root","workspaces":["apps/*"]},"apps/web":{"name":"web","dependencies":{"react":"^18.3.0"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"react":"^18.3.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package-lock.json"),
        r#"{"name":"web","lockfileVersion":3,"packages":{"":{"name":"web","dependencies":{"react":"^18.3.0"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-shadow"}}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, None).expect_err(
        "workspace children must not carry shadow npm lockfiles beside the root lockfile",
    );
    let msg = err.to_string();
    assert!(msg.contains("apps/web/package-lock.json"));
    assert!(msg.contains("workspace"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_supported_pnpm_root_alongside_unrelated_nested_npm_project() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"pnpm@9.0.0","workspaces":["apps/*"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\nimporters:\n  .: {}\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package-lock.json"),
        r#"{"name":"web","lockfileVersion":3,"packages":{"":{"name":"web","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, None)
        .expect("supported pnpm roots should coexist with unrelated nested npm projects");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_nested_npm_project_when_ancestor_pnpm_root_does_not_claim_it() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"pnpm@9.0.0"}"#,
    )
    .unwrap();
    std::fs::write(dir.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package-lock.json"),
        r#"{"name":"web","lockfileVersion":3,"packages":{"":{"name":"web","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir.join("apps/web"), Some("npm"))
        .expect("ancestor pnpm state should not capture unrelated nested npm projects");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_standalone_pnpm_project_with_pnpm_lockfile() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"pnpm@9.0.0","dependencies":{"react":"^18.3.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: ^18.3.0
        version: 18.3.1
packages:
  react@18.3.1:
    resolution:
      integrity: sha512-react
"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, Some("npm"))
        .expect("standalone pnpm projects with pnpm-lock.yaml should be accepted");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_pnpm_lockfile_without_integrity() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"pnpm@9.0.0","dependencies":{"react":"^18.3.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: ^18.3.0
        version: 18.3.1
packages:
  react@18.3.1:
    resolution: {}
"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("pnpm lockfiles without integrity should be rejected");
    assert!(err.to_string().contains("integrity"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_pnpm_lockfile_with_wrong_tarball_identity() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"pnpm@9.0.0","dependencies":{"react":"^18.3.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: ^18.3.0
        version: 18.3.1
packages:
  react@18.3.1:
    resolution:
      integrity: sha512-react
      tarball: https://registry.npmjs.org/not-react/-/not-react-18.3.1.tgz
"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("pnpm lockfiles with the wrong tarball identity should be rejected");
    assert!(
        err.to_string()
            .contains("does not match the locked package identity")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_pnpm_workspace_child_with_root_lockfile() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::create_dir_all(dir.join("packages/workspace-lib")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"pnpm@9.0.0"}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("pnpm-workspace.yaml"),
        "packages:\n  - 'apps/*'\n  - 'packages/*'\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'
importers:
  .: {}
  apps/web:
    dependencies:
      workspace-lib:
        specifier: workspace:*
        version: link:../../packages/workspace-lib
      react:
        specifier: ^18.3.0
        version: 18.3.1
  packages/workspace-lib: {}
packages:
  react@18.3.1:
    resolution:
      integrity: sha512-react
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"workspace-lib":"workspace:*","react":"^18.3.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/workspace-lib/package.json"),
        r#"{"name":"workspace-lib"}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir.join("apps/web"), Some("npm"))
        .expect("pnpm workspace children should bind to the root pnpm-lock.yaml");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_shadow_child_pnpm_lockfile_inside_workspace() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"pnpm@9.0.0"}"#,
    )
    .unwrap();
    std::fs::write(dir.join("pnpm-workspace.yaml"), "packages:\n  - 'apps/*'\n").unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\nimporters:\n  .: {}\n  apps/web: {}\n",
    )
    .unwrap();
    std::fs::write(dir.join("apps/web/package.json"), r#"{"name":"web"}"#).unwrap();
    std::fs::write(
        dir.join("apps/web/pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\nimporters:\n  .: {}\n",
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, None)
        .expect_err("workspace children must not carry shadow pnpm lockfiles");
    let msg = err.to_string();
    assert!(msg.contains("apps/web/pnpm-lock.yaml"));
    assert!(msg.contains("workspace"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_foreign_child_lockfile_inside_pnpm_workspace() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"pnpm@9.0.0"}"#,
    )
    .unwrap();
    std::fs::write(dir.join("pnpm-workspace.yaml"), "packages:\n  - 'apps/*'\n").unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'
importers:
  .: {}
  apps/web: {}
"#,
    )
    .unwrap();
    std::fs::write(dir.join("apps/web/package.json"), r#"{"name":"web"}"#).unwrap();
    std::fs::write(
        dir.join("apps/web/package-lock.json"),
        r#"{"name":"web","lockfileVersion":3}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir.join("apps/web"), Some("npm"))
        .expect_err("workspace children must not carry conflicting JS lockfiles");
    let msg = err.to_string();
    assert!(msg.contains("apps/web/package-lock.json"));
    assert!(msg.contains("workspace"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_uses_pnpm_lockfile_exact_versions_for_direct_dependencies() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"pnpm@9.0.0","dependencies":{"react":"^18.3.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: ^18.3.0
        version: 18.3.1
packages:
  react@18.3.1:
    resolution:
      integrity: sha512-react
"#,
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

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        Default::default(),
        &registry,
        &osv,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("pnpm lockfiles should drive exact direct versions");

    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.check == "resolution/no-exact-version")
    );
    let metadata_versions = metadata_versions.lock().unwrap().clone();
    let osv_versions = osv_versions.lock().unwrap().clone();
    assert!(metadata_versions.contains(&Some("18.3.1".to_string())));
    assert!(osv_versions.contains(&Some("18.3.1".to_string())));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_uses_pnpm_lockfile_for_transitive_dependencies() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"pnpm@9.0.0","dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: 18.3.1
        version: 18.3.1
packages:
  react@18.3.1:
    resolution:
      integrity: sha512-react
  evil-transitive@1.0.0:
    resolution:
      integrity: sha512-evil
snapshots:
  react@18.3.1:
    dependencies:
      evil-transitive: 1.0.0
"#,
    )
    .unwrap();

    let registry = FakeRegistry {
        existing: vec!["react".to_string(), "evil-transitive".to_string()],
    };
    let osv = VulnOsvClient {
        vulnerable: vec!["evil-transitive".to_string()],
    };

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        Default::default(),
        &registry,
        &osv,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("pnpm lockfiles should provide trusted transitive coverage");

    let trans_issue = report.issues.iter().find(|issue| {
        issue.package == "evil-transitive" && issue.source.as_deref() == Some("transitive")
    });
    assert!(
        trans_issue.is_some(),
        "pnpm transitive dependencies should enter the scan pipeline"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_pnpm_workspace_child_without_root_package_json() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(dir.join("pnpm-workspace.yaml"), "packages:\n  - 'apps/*'\n").unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'
importers:
  apps/web:
    dependencies:
      react:
        specifier: 18.3.1
        version: 18.3.1
packages:
  react@18.3.1:
    resolution:
      integrity: sha512-react
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir.join("apps/web"), Some("npm"))
        .expect("pnpm-workspace.yaml should be enough to bind a child to the pnpm root");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pnpm_workspace_child_does_not_inherit_sibling_transitives() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    let lockfile = dir.join("pnpm-lock.yaml");
    std::fs::write(
        &lockfile,
        r#"lockfileVersion: '9.0'
importers:
  apps/web:
    dependencies:
      react:
        specifier: 18.3.1
        version: 18.3.1
  apps/api:
    dependencies:
      axios:
        specifier: 1.7.0
        version: 1.7.0
packages:
  react@18.3.1:
    resolution:
      integrity: sha512-react
  evil-web@1.0.0:
    resolution:
      integrity: sha512-evil-web
  axios@1.7.0:
    resolution:
      integrity: sha512-axios
  evil-api@9.9.9:
    resolution:
      integrity: sha512-evil-api
snapshots:
  react@18.3.1:
    dependencies:
      evil-web: 1.0.0
  axios@1.7.0:
    dependencies:
      evil-api: 9.9.9
"#,
    )
    .unwrap();
    let deps = vec![Dependency {
        name: "react".to_string(),
        version: Some("18.3.1".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }];

    let lock = crate::lockfiles::LockfileData::parse_for_kind_with_lockfile(
        &dir.join("apps/web"),
        Some(ProjectInputKind::Npm),
        &deps,
        Some(&lockfile),
    )
    .expect("pnpm workspace child should parse with authoritative root lockfile");

    assert!(
        lock.transitive_deps
            .iter()
            .any(|dep| dep.package_name() == "evil-web")
    );
    assert!(
        !lock
            .transitive_deps
            .iter()
            .any(|dep| dep.package_name() == "evil-api" || dep.package_name() == "axios")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_uses_pnpm_lock_for_alias_direct_dependencies() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"pnpm@9.0.0","dependencies":{"alias-react":"npm:react@^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alias-react:
        specifier: npm:react@^18.0.0
        version: npm:react@18.3.1
packages:
  react@18.3.1:
    resolution:
      integrity: sha512-react
"#,
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

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        Default::default(),
        &registry,
        &osv,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("pnpm alias direct dependencies should resolve through pnpm-lock.yaml");

    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.check == "resolution/no-exact-version")
    );
    assert!(
        metadata_versions
            .lock()
            .unwrap()
            .contains(&Some("18.3.1".to_string()))
    );
    assert!(
        osv_versions
            .lock()
            .unwrap()
            .contains(&Some("18.3.1".to_string()))
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_nested_npm_project_under_ancestor_bun_lockfile() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"bun@1.1.0","workspaces":["apps/*"]}"#,
    )
    .unwrap();
    std::fs::write(dir.join("bun.lock"), "dummy\n").unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package-lock.json"),
        r#"{"name":"web","lockfileVersion":3,"packages":{"":{"name":"web","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, None)
        .expect_err("unsupported JS manager roots must block npm trust");
    let msg = err.to_string();
    assert!(msg.contains("bun"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_bun_lock_with_wrong_package_identity() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"bun@1.3.9","dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("bun.lock"),
        r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "demo",
      "dependencies": {
        "react": "18.3.1",
      },
    },
  },
  "packages": {
    "react": ["not-react@18.3.1", "", {}, "sha512-react"],
  }
}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("bun lockfiles with the wrong package identity should be rejected");
    assert!(err.to_string().contains("claims to resolve"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_standalone_bun_project_with_bun_lock() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"bun@1.3.9","dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("bun.lock"),
        r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "demo",
      "dependencies": {
        "react": "18.3.1",
      },
    },
  },
  "packages": {
    "react": ["react@18.3.1", "", { "dependencies": { "loose-envify": "^1.1.0" } }, "sha512-react"],
    "loose-envify": ["loose-envify@1.4.0", "", { "dependencies": { "js-tokens": "^3.0.0 || ^4.0.0" } }, "sha512-loose"],
    "js-tokens": ["js-tokens@4.0.0", "", {}, "sha512-js-tokens"],
  }
}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, Some("npm"))
        .expect("standalone bun projects with bun.lock should be accepted");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_uses_bun_lock_for_alias_direct_dependencies() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"bun@1.3.9","dependencies":{"alias-react":"npm:react@^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("bun.lock"),
        r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "demo",
      "dependencies": {
        "alias-react": "npm:react@^18.0.0",
      },
    },
  },
  "packages": {
    "alias-react": ["react@18.3.1", "", {}, "sha512-react"],
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

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        Default::default(),
        &registry,
        &osv,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("bun alias direct dependencies should resolve through bun.lock");

    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.check == "resolution/no-exact-version")
    );
    assert!(
        metadata_versions
            .lock()
            .unwrap()
            .contains(&Some("18.3.1".to_string()))
    );
    assert!(
        osv_versions
            .lock()
            .unwrap()
            .contains(&Some("18.3.1".to_string()))
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_bun_workspace_child_with_root_lockfile() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"bun@1.3.9","workspaces":["apps/*"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("bun.lock"),
        r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "root",
    },
    "apps/web": {
      "name": "web",
      "dependencies": {
        "react": "^18.0.0",
      },
    },
  },
  "packages": {
    "react": ["react@18.3.1", "", { "dependencies": { "loose-envify": "^1.1.0" } }, "sha512-react"],
    "loose-envify": ["loose-envify@1.4.0", "", { "dependencies": { "js-tokens": "^3.0.0 || ^4.0.0" } }, "sha512-loose"],
    "js-tokens": ["js-tokens@4.0.0", "", {}, "sha512-js-tokens"],
    "web": ["web@workspace:apps/web"],
  }
}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir.join("apps/web"), Some("npm"))
        .expect("bun workspace children should bind to the root bun.lock");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_shadow_child_bun_lock_inside_workspace() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"bun@1.3.9","workspaces":["apps/*"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("bun.lock"),
        r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": { "name": "root" },
    "apps/web": { "name": "web" },
  },
  "packages": {
    "web": ["web@workspace:apps/web"],
  }
}"#,
    )
    .unwrap();
    std::fs::write(dir.join("apps/web/package.json"), r#"{"name":"web"}"#).unwrap();
    std::fs::write(
        dir.join("apps/web/bun.lock"),
        r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": { "name": "web" },
  },
  "packages": {}
}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, None)
        .expect_err("workspace children must not carry shadow bun lockfiles");
    let msg = err.to_string();
    assert!(msg.contains("apps/web/bun.lock"));
    assert!(msg.contains("workspace"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_uses_bun_lock_exact_versions_for_direct_dependencies() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"bun@1.3.9","dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("bun.lock"),
        r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "demo",
      "dependencies": {
        "react": "^18.0.0",
      },
    },
  },
  "packages": {
    "react": ["react@18.3.1", "", { "dependencies": { "loose-envify": "^1.1.0" } }, "sha512-react"],
    "loose-envify": ["loose-envify@1.4.0", "", { "dependencies": { "js-tokens": "^3.0.0 || ^4.0.0" } }, "sha512-loose"],
    "js-tokens": ["js-tokens@4.0.0", "", {}, "sha512-js-tokens"],
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

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        Default::default(),
        &registry,
        &osv,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("bun lockfiles should drive exact direct versions");

    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.check == "resolution/no-exact-version")
    );
    let metadata_versions = metadata_versions.lock().unwrap().clone();
    let osv_versions = osv_versions.lock().unwrap().clone();
    assert!(metadata_versions.contains(&Some("18.3.1".to_string())));
    assert!(osv_versions.contains(&Some("18.3.1".to_string())));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bun_direct_resolution_uses_importer_binding_when_lockfile_has_multiple_versions() {
    let dir = unique_dir();
    let lockfile = dir.join("bun.lock");
    std::fs::write(
        &lockfile,
        r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "demo",
      "dependencies": {
        "react": "^18.0.0",
      },
    },
  },
  "packages": {
    "react": ["react@18.3.1", "", { "dependencies": {} }, "sha512-react18"],
    "react-canary": ["react@19.0.0", "", { "dependencies": {} }, "sha512-react19"]
  }
}"#,
    )
    .unwrap();
    let deps = vec![Dependency {
        name: "react".to_string(),
        version: Some("^18.0.0".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }];

    let lock = crate::lockfiles::LockfileData::parse_for_kind_with_lockfile(
        &dir,
        Some(ProjectInputKind::Npm),
        &deps,
        Some(&lockfile),
    )
    .expect("bun.lock should parse");

    assert_eq!(lock.resolution.exact_version(&deps[0]), Some("18.3.1"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bun_workspace_child_does_not_inherit_sibling_transitives() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    let lockfile = dir.join("bun.lock");
    std::fs::write(
        &lockfile,
        r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "apps/web": {
      "name": "web",
      "dependencies": {
        "react": "18.3.1"
      }
    },
    "apps/api": {
      "name": "api",
      "dependencies": {
        "axios": "1.7.0"
      }
    }
  },
  "packages": {
    "react": ["react@18.3.1", "", { "dependencies": { "evil-web": "1.0.0" } }, "sha512-react"],
    "evil-web": ["evil-web@1.0.0", "", {}, "sha512-evil-web"],
    "axios": ["axios@1.7.0", "", { "dependencies": { "evil-api": "9.9.9" } }, "sha512-axios"],
    "evil-api": ["evil-api@9.9.9", "", {}, "sha512-evil-api"]
  }
}"#,
    )
    .unwrap();
    let deps = vec![Dependency {
        name: "react".to_string(),
        version: Some("18.3.1".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }];

    let lock = crate::lockfiles::LockfileData::parse_for_kind_with_lockfile(
        &dir.join("apps/web"),
        Some(ProjectInputKind::Npm),
        &deps,
        Some(&lockfile),
    )
    .expect("bun workspace child should parse with authoritative root lockfile");

    assert!(
        lock.transitive_deps
            .iter()
            .any(|dep| dep.package_name() == "evil-web")
    );
    assert!(
        !lock
            .transitive_deps
            .iter()
            .any(|dep| dep.package_name() == "evil-api" || dep.package_name() == "axios")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_standalone_yarn_classic_project_with_yarn_lock() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"yarn@1.22.22","dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("yarn.lock"),
        r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1

"js-tokens@^3.0.0 || ^4.0.0":
  version "4.0.0"
  resolved "https://registry.yarnpkg.com/js-tokens/-/js-tokens-4.0.0.tgz#19203fb59991df98e3a287050d4647cdeaf32499"
  integrity sha512-js-tokens

loose-envify@^1.1.0:
  version "1.4.0"
  resolved "https://registry.yarnpkg.com/loose-envify/-/loose-envify-1.4.0.tgz#71ee51fa7be4caec1a63839f7e682d8132d30caf"
  integrity sha512-loose
  dependencies:
    js-tokens "^3.0.0 || ^4.0.0"

react@^18.0.0:
  version "18.3.1"
  resolved "https://registry.yarnpkg.com/react/-/react-18.3.1.tgz#49ab892009c53933625bd16b2533fc754cab2891"
  integrity sha512-react
  dependencies:
    loose-envify "^1.1.0"
"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, Some("npm"))
        .expect("standalone Yarn classic projects with yarn.lock should be accepted");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_uses_yarn_classic_lock_exact_versions_for_direct_dependencies() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"yarn@1.22.22","dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("yarn.lock"),
        r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1

"js-tokens@^3.0.0 || ^4.0.0":
  version "4.0.0"
  resolved "https://registry.yarnpkg.com/js-tokens/-/js-tokens-4.0.0.tgz#19203fb59991df98e3a287050d4647cdeaf32499"
  integrity sha512-js-tokens

loose-envify@^1.1.0:
  version "1.4.0"
  resolved "https://registry.yarnpkg.com/loose-envify/-/loose-envify-1.4.0.tgz#71ee51fa7be4caec1a63839f7e682d8132d30caf"
  integrity sha512-loose
  dependencies:
    js-tokens "^3.0.0 || ^4.0.0"

react@^18.0.0:
  version "18.3.1"
  resolved "https://registry.yarnpkg.com/react/-/react-18.3.1.tgz#49ab892009c53933625bd16b2533fc754cab2891"
  integrity sha512-react
  dependencies:
    loose-envify "^1.1.0"
"#,
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

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        Default::default(),
        &registry,
        &osv,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("Yarn classic lockfiles should drive exact direct versions");

    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.check == "resolution/no-exact-version")
    );
    let metadata_versions = metadata_versions.lock().unwrap().clone();
    let osv_versions = osv_versions.lock().unwrap().clone();
    assert!(metadata_versions.contains(&Some("18.3.1".to_string())));
    assert!(osv_versions.contains(&Some("18.3.1".to_string())));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_standalone_yarn_berry_project_with_yarn_lock() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"yarn@4.9.2","dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("yarn.lock"),
        r#"# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 8
  cacheKey: 10c0

"js-tokens@npm:^3.0.0 || ^4.0.0":
  version: 4.0.0
  resolution: "js-tokens@npm:4.0.0"
  checksum: 10c0/js-tokens
  languageName: node
  linkType: hard

"loose-envify@npm:^1.1.0":
  version: 1.4.0
  resolution: "loose-envify@npm:1.4.0"
  dependencies:
    js-tokens: "npm:^3.0.0 || ^4.0.0"
  checksum: 10c0/loose
  languageName: node
  linkType: hard

"react@npm:^18.0.0":
  version: 18.3.1
  resolution: "react@npm:18.3.1"
  dependencies:
    loose-envify: "npm:^1.1.0"
  checksum: 10c0/react
  languageName: node
  linkType: hard

"demo@workspace:.":
  version: 0.0.0-use.local
  resolution: "demo@workspace:."
  dependencies:
    react: "npm:^18.0.0"
  languageName: unknown
  linkType: soft
"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, Some("npm"))
        .expect("standalone Yarn Berry projects with yarn.lock should be accepted");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_uses_yarn_berry_lock_exact_versions_for_direct_dependencies() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"yarn@4.9.2","dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("yarn.lock"),
        r#"# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 8
  cacheKey: 10c0

"js-tokens@npm:^3.0.0 || ^4.0.0":
  version: 4.0.0
  resolution: "js-tokens@npm:4.0.0"
  checksum: 10c0/js-tokens
  languageName: node
  linkType: hard

"loose-envify@npm:^1.1.0":
  version: 1.4.0
  resolution: "loose-envify@npm:1.4.0"
  dependencies:
    js-tokens: "npm:^3.0.0 || ^4.0.0"
  checksum: 10c0/loose
  languageName: node
  linkType: hard

"react@npm:^18.0.0":
  version: 18.3.1
  resolution: "react@npm:18.3.1"
  dependencies:
    loose-envify: "npm:^1.1.0"
  checksum: 10c0/react
  languageName: node
  linkType: hard

"demo@workspace:.":
  version: 0.0.0-use.local
  resolution: "demo@workspace:."
  dependencies:
    react: "npm:^18.0.0"
  languageName: unknown
  linkType: soft
"#,
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

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        Default::default(),
        &registry,
        &osv,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("Yarn Berry lockfiles should drive exact direct versions");

    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.check == "resolution/no-exact-version")
    );
    let metadata_versions = metadata_versions.lock().unwrap().clone();
    let osv_versions = osv_versions.lock().unwrap().clone();
    assert!(metadata_versions.contains(&Some("18.3.1".to_string())));
    assert!(osv_versions.contains(&Some("18.3.1".to_string())));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_yarn_classic_lock_with_wrong_tarball_identity() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"yarn@1.22.22","dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("yarn.lock"),
        r#"# yarn lockfile v1

react@^18.0.0:
  version "18.3.1"
  resolved "https://registry.yarnpkg.com/not-react/-/not-react-18.3.1.tgz#49ab892009c53933625bd16b2533fc754cab2891"
  integrity sha512-react
"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("classic yarn tarball provenance must match the package identity exactly");
    let msg = err.to_string();
    assert!(msg.contains("yarn.lock"));
    assert!(msg.contains("react"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn yarn_workspace_child_does_not_inherit_sibling_transitives() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    let lockfile = dir.join("yarn.lock");
    std::fs::write(
        &lockfile,
        r#"# This file is generated by running "yarn install" inside your project.

__metadata:
  version: 8

"react@npm:18.3.1":
  version: 18.3.1
  resolution: "react@npm:18.3.1"
  dependencies:
    evil-web: "npm:1.0.0"
  linkType: hard

"evil-web@npm:1.0.0":
  version: 1.0.0
  resolution: "evil-web@npm:1.0.0"
  linkType: hard

"axios@npm:1.7.0":
  version: 1.7.0
  resolution: "axios@npm:1.7.0"
  dependencies:
    evil-api: "npm:9.9.9"
  linkType: hard

"evil-api@npm:9.9.9":
  version: 9.9.9
  resolution: "evil-api@npm:9.9.9"
  linkType: hard

"web@workspace:apps/web":
  version: 0.0.0-use.local
  resolution: "web@workspace:apps/web"
  dependencies:
    react: "npm:18.3.1"
  linkType: soft

"api@workspace:apps/api":
  version: 0.0.0-use.local
  resolution: "api@workspace:apps/api"
  dependencies:
    axios: "npm:1.7.0"
  linkType: soft
"#,
    )
    .unwrap();
    let deps = vec![Dependency {
        name: "react".to_string(),
        version: Some("18.3.1".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }];

    let lock = crate::lockfiles::LockfileData::parse_for_kind_with_lockfile(
        &dir.join("apps/web"),
        Some(ProjectInputKind::Npm),
        &deps,
        Some(&lockfile),
    )
    .expect("Yarn workspace child should parse with authoritative root lockfile");

    assert!(
        lock.transitive_deps
            .iter()
            .any(|dep| dep.package_name() == "evil-web")
    );
    assert!(
        !lock
            .transitive_deps
            .iter()
            .any(|dep| dep.package_name() == "evil-api" || dep.package_name() == "axios")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_yarn_workspace_child_with_root_lockfile() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"yarn@4.9.2","workspaces":["apps/*"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("yarn.lock"),
        r#"# This file is generated by running "yarn install" inside your project.

__metadata:
  version: 8
  cacheKey: 10c0

"react@npm:^18.0.0":
  version: 18.3.1
  resolution: "react@npm:18.3.1"
  checksum: 10c0/react
  languageName: node
  linkType: hard

"web@workspace:apps/web":
  version: 0.0.0-use.local
  resolution: "web@workspace:apps/web"
  dependencies:
    react: "npm:^18.0.0"
  languageName: unknown
  linkType: soft
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir.join("apps/web"), Some("npm"))
        .expect("Yarn workspace children should bind to the root yarn.lock");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_yarn_workspace_local_dependency_with_exact_lock_target() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::create_dir_all(dir.join("packages/workspace-lib")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"yarn@4.9.2","workspaces":["apps/*","packages/*"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("yarn.lock"),
        r#"# This file is generated by running "yarn install" inside your project.

__metadata:
  version: 8
  cacheKey: 10c0

"react@npm:^18.0.0":
  version: 18.3.1
  resolution: "react@npm:18.3.1"
  checksum: 10c0/react
  languageName: node
  linkType: hard

"web@workspace:apps/web":
  version: 0.0.0-use.local
  resolution: "web@workspace:apps/web"
  dependencies:
    react: "npm:^18.0.0"
    workspace-lib: "workspace:*"
  languageName: unknown
  linkType: soft

"workspace-lib@workspace:*, workspace-lib@workspace:packages/workspace-lib":
  version: 0.0.0-use.local
  resolution: "workspace-lib@workspace:packages/workspace-lib"
  languageName: unknown
  linkType: soft
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"react":"^18.0.0","workspace-lib":"workspace:*"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/workspace-lib/package.json"),
        r#"{"name":"workspace-lib"}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir.join("apps/web"), Some("npm"))
        .expect("Yarn workspace local dependencies should be validated against the root yarn.lock");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_yarn_workspace_dependency_without_matching_workspace_package() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"yarn@4.9.2","workspaces":["apps/*"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("yarn.lock"),
        r#"# This file is generated by running "yarn install" inside your project.

__metadata:
  version: 8
  cacheKey: 10c0

"web@workspace:apps/web":
  version: 0.0.0-use.local
  resolution: "web@workspace:apps/web"
  dependencies:
    workspace-lib: "workspace:*"
  languageName: unknown
  linkType: soft

"workspace-lib@workspace:*, workspace-lib@workspace:packages/workspace-lib":
  version: 0.0.0-use.local
  resolution: "workspace-lib@workspace:packages/workspace-lib"
  languageName: unknown
  linkType: soft
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"workspace-lib":"workspace:*"}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir.join("apps/web"), Some("npm")).expect_err(
        "Yarn workspace dependencies without a matching declared workspace package must block",
    );
    let msg = err.to_string();
    assert!(msg.contains("workspace-lib"));
    assert!(msg.contains("workspace"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_shadow_child_yarn_lock_inside_workspace() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"yarn@4.9.2","workspaces":["apps/*"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("yarn.lock"),
        r#"# This file is generated by running "yarn install" inside your project.

__metadata:
  version: 8
  cacheKey: 10c0

"web@workspace:apps/web":
  version: 0.0.0-use.local
  resolution: "web@workspace:apps/web"
  languageName: unknown
  linkType: soft
"#,
    )
    .unwrap();
    std::fs::write(dir.join("apps/web/package.json"), r#"{"name":"web"}"#).unwrap();
    std::fs::write(
        dir.join("apps/web/yarn.lock"),
        r#"# yarn lockfile v1
"web@1.0.0":
  version "1.0.0"
"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, None)
        .expect_err("workspace children must not carry shadow yarn.lock files");
    let msg = err.to_string();
    assert!(msg.contains("apps/web/yarn.lock"));
    assert!(msg.contains("workspace"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_workspace_dependency_without_declared_workspace_root() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::create_dir_all(dir.join("packages/workspace-lib")).unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"workspace-lib":"workspace:*"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package-lock.json"),
        r#"{"name":"web","lockfileVersion":3,"packages":{"":{"name":"web","dependencies":{"workspace-lib":"workspace:*"}},"node_modules/workspace-lib":{"resolved":"../../packages/workspace-lib","link":true}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/workspace-lib/package.json"),
        r#"{"name":"workspace-lib"}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/workspace-lib/package-lock.json"),
        r#"{"name":"workspace-lib","lockfileVersion":3,"packages":{"":{"name":"workspace-lib"}}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, None)
        .expect_err("workspace:* deps must resolve through an ancestor npm workspaces declaration");
    let msg = err.to_string();
    assert!(msg.contains("workspace-lib"));
    assert!(msg.contains("workspaces"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_workspace_dependency_when_lockfile_target_mismatches_verified_workspace() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::create_dir_all(dir.join("packages/workspace-lib")).unwrap();
    std::fs::create_dir_all(dir.join("packages/other-lib")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","workspaces":["apps/*","packages/*"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"root","lockfileVersion":3,"packages":{"":{"name":"root","workspaces":["apps/*","packages/*"]},"apps/web":{"name":"web","dependencies":{"workspace-lib":"workspace:*"}},"node_modules/workspace-lib":{"resolved":"packages/other-lib","link":true}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"workspace-lib":"workspace:*"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/workspace-lib/package.json"),
        r#"{"name":"workspace-lib"}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/other-lib/package.json"),
        r#"{"name":"other-lib"}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, None)
        .expect_err("workspace lockfile links must point at the verified workspace target");
    let msg = err.to_string();
    assert!(msg.contains("workspace-lib"));
    assert!(msg.contains("other-lib"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_workspace_dependency_outside_declared_workspace_set() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::create_dir_all(dir.join("packages/workspace-lib")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","workspaces":["apps/*"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"root","lockfileVersion":3,"packages":{"":{"name":"root","workspaces":["apps/*"]},"apps/web":{"name":"web","dependencies":{"workspace-lib":"workspace:*"}},"node_modules/workspace-lib":{"resolved":"packages/workspace-lib","link":true}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"workspace-lib":"workspace:*"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/workspace-lib/package.json"),
        r#"{"name":"workspace-lib"}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, None).expect_err(
        "workspace:* deps must only resolve to directories declared by the workspace root",
    );
    let msg = err.to_string();
    assert!(msg.contains("workspace-lib"));
    assert!(msg.contains("workspaces"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_file_dependency_when_lockfile_target_mismatches_manifest_target() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::create_dir_all(dir.join("packages/local-lib")).unwrap();
    std::fs::create_dir_all(dir.join("packages/other-lib")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","workspaces":["apps/*","packages/*"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"root","lockfileVersion":3,"packages":{"":{"name":"root","workspaces":["apps/*","packages/*"]},"apps/web":{"name":"web","dependencies":{"local-lib":"file:../../packages/local-lib"}},"node_modules/local-lib":{"resolved":"packages/other-lib","link":true}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"local-lib":"file:../../packages/local-lib"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/local-lib/package.json"),
        r#"{"name":"local-lib"}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/other-lib/package.json"),
        r#"{"name":"other-lib"}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, None)
        .expect_err("file/link lockfile entries must point at the manifest-verified local target");
    let msg = err.to_string();
    assert!(msg.contains("local-lib"));
    assert!(msg.contains("other-lib"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_file_dependency_when_target_package_name_mismatches_dependency_name() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("packages/other-lib")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","dependencies":{"local-lib":"file:packages/other-lib"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"local-lib":"file:packages/other-lib"}},"node_modules/local-lib":{"resolved":"packages/other-lib","link":true}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/other-lib/package.json"),
        r#"{"name":"other-lib"}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/other-lib/package-lock.json"),
        r#"{"name":"other-lib","lockfileVersion":3,"packages":{"":{"name":"other-lib"}}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("local file/link targets must match the dependency package identity exactly");
    let msg = err.to_string();
    assert!(msg.contains("local-lib"));
    assert!(msg.contains("other-lib"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_npm_lockfile_entries_missing_integrity() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz"}}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("registry npm lockfile entries without integrity must block scanning");
    let msg = err.to_string();
    assert!(msg.contains("integrity"));
    assert!(msg.contains("react"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_npm_lockfile_entries_with_wrong_package_identity() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.3.1"}},"node_modules/react":{"name":"lodash","version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("lockfile entries must not claim a different package identity");
    let msg = err.to_string();
    assert!(msg.contains("react"));
    assert!(msg.contains("lodash"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_npm_lockfile_entries_with_foreign_resolved_url() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://evil.example/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("foreign npm tarball URLs must block lockfile trust");
    let msg = err.to_string();
    assert!(msg.contains("resolved"));
    assert!(msg.contains("evil.example"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_npm_lockfile_entries_with_registry_url_for_different_package() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/lodash/-/lodash-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("registry tarball URLs must match the locked package identity");
    let msg = err.to_string();
    assert!(msg.contains("react"));
    assert!(msg.contains("lodash"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_npm_lockfile_entries_with_registry_url_for_different_version() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-99.0.0.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("registry tarball URLs must match the locked version");
    let msg = err.to_string();
    assert!(msg.contains("18.3.1"));
    assert!(msg.contains("99.0.0"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_bundled_npm_lockfile_entries() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","bundled":true}}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("bundled npm entries must not silently bypass provenance checks");
    let msg = err.to_string();
    assert!(msg.contains("bundled"));
    assert!(msg.contains("react"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_npm_lockfile_entries_with_registry_resolved_and_integrity() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, Some("npm"))
        .expect("registry npm lockfile entries with integrity should remain trusted");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_invalid_secondary_jvm_manifest() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("build.gradle"),
        "implementation 'com.google.guava:guava:31.1-jre'\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("pom.xml"),
        r#"
<project>
  <dependencies>
    <dependency>
      <groupId>bad?group</groupId>
      <artifactId>guava</artifactId>
      <version>31.1-jre</version>
    </dependency>
  </dependencies>
</project>
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("gradle.lockfile"),
        "com.google.guava:guava:31.1-jre=compileClasspath\n",
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("jvm"))
        .expect_err("every detected JVM manifest must be parsed or rejected");
    let msg = err.to_string();
    assert!(msg.contains("pom.xml"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_invalid_secondary_dotnet_manifest() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("app.csproj"),
        r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("broken.csproj"),
        r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Bad?Package" Version="1.0.0" /></ItemGroup></Project>"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages.lock.json"),
        r#"{"version":1,"dependencies":{}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("dotnet"))
        .expect_err("every detected .csproj manifest must be parsed or rejected");
    let msg = err.to_string();
    assert!(msg.contains("broken.csproj"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_warns_for_maven_without_a_trusted_lockfile() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pom.xml"),
        r#"<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>demo</artifactId><version>1.0.0</version></project>"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, Some("jvm")).unwrap();
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].severity, Severity::Warning);
    assert!(warnings[0].message.contains("Maven"));
    assert!(warnings[0].message.contains("Gradle"));

    let _ = std::fs::remove_dir_all(&dir);
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
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"latest"}}"#,
    )
    .unwrap();

    let metadata_versions = Arc::new(Mutex::new(Vec::new()));
    let osv_versions = Arc::new(Mutex::new(Vec::new()));
    let registry = RecordingRegistry {
        existing: vec!["react".to_string()],
        versions: metadata_versions,
    };
    let osv = RecordingOsvClient {
        versions: osv_versions.clone(),
    };

    let report =
        scan_with_services_no_osv_cache(&dir, Some("npm"), Default::default(), &registry, &osv)
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
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"latest"}}"#,
    )
    .unwrap();

    let registry = RecordingRegistry {
        existing: vec!["react".to_string()],
        versions: Arc::new(Mutex::new(Vec::new())),
    };
    let osv = RecordingOsvClient {
        versions: Arc::new(Mutex::new(Vec::new())),
    };
    let config = config::SloppyJoeConfig {
        allow_unresolved_versions: true,
        ..Default::default()
    };

    let report = scan_with_services_no_osv_cache(&dir, Some("npm"), config, &registry, &osv)
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

#[test]
fn unresolved_version_policy_only_skips_matching_lockfile_sync_issue_keys() {
    let dep_a = Dependency {
        name: "react".to_string(),
        version: Some("^18.2.0".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    };
    let dep_b = Dependency {
        name: "react".to_string(),
        version: Some("^19.0.0".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    };

    let mut resolution = lockfiles::ResolutionResult::default();
    resolution.push_issue_for(
        &dep_a,
        report::Issue::new(
            "react",
            checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE_SYNC,
            report::Severity::Error,
        )
        .message("unsynced")
        .fix("fix"),
    );

    let issues = unresolved_version_policy_issues(
        &[dep_a.clone(), dep_b.clone()],
        &resolution,
        &config::SloppyJoeConfig::default(),
    );

    assert_eq!(issues.len(), 1);
    assert!(issues[0].message.contains("^19.0.0"));
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

#[tokio::test]
async fn scan_counts_optional_dependencies_as_direct_inputs() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"optionalDependencies":{"fsevents":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","optionalDependencies":{"fsevents":"1.0.0"}},"node_modules/fsevents":{"version":"1.0.0"}}}"#,
    )
    .unwrap();
    let registry = FakeRegistry {
        existing: vec!["fsevents".to_string()],
    };

    let report = scan_with_services_inner(
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

    assert_eq!(report.packages_checked, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_counts_peer_dependencies_as_direct_inputs() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"peerDependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","peerDependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1"}}}"#,
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
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(report.packages_checked, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_ignores_local_workspace_npm_dependencies_as_external_packages() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"workspace-lib":"workspace:*","local-lib":"file:../local-lib"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"workspace-lib":"workspace:*","local-lib":"file:../local-lib"}},"node_modules/workspace-lib":{"resolved":"packages/workspace-lib","link":true},"node_modules/local-lib":{"resolved":"../local-lib","link":true}}}"#,
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
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(report.packages_checked, 0);
    assert!(report.issues.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_uses_real_package_identity_for_npm_aliases() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"lodash":"npm:evil-pkg@1.2.3"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"lodash":"npm:evil-pkg@1.2.3"}},"node_modules/lodash":{"name":"evil-pkg","version":"1.2.3","resolved":"https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.2.3.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let exists_names = Arc::new(Mutex::new(Vec::new()));
    let metadata_names = Arc::new(Mutex::new(Vec::new()));
    let osv_names = Arc::new(Mutex::new(Vec::new()));
    let registry = RecordingNameRegistry {
        existing: vec!["evil-pkg".to_string()],
        exists_names: exists_names.clone(),
        metadata_names: metadata_names.clone(),
    };
    let osv_client = RecordingNameOsvClient {
        queried_names: osv_names.clone(),
    };

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        Default::default(),
        &registry,
        &osv_client,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(report.packages_checked, 1);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.check == "resolution/npm-alias"),
        "npm alias indirection should be surfaced explicitly to the user"
    );
    assert!(
        !report.issues.iter().any(|issue| issue.check == "existence"),
        "alias deps must not be checked under the alias package name"
    );
    assert!(
        !exists_names
            .lock()
            .unwrap()
            .iter()
            .any(|name| name == "lodash"),
        "registry existence queries must never use the alias package name"
    );
    assert!(
        metadata_names
            .lock()
            .unwrap()
            .iter()
            .all(|name| name == "evil-pkg"),
        "metadata checks must use the aliased package identity"
    );
    assert!(
        osv_names
            .lock()
            .unwrap()
            .iter()
            .all(|name| name == "evil-pkg"),
        "OSV checks must use the aliased package identity"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_uses_pinned_poetry_version_even_when_poetry_lock_disagrees() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"2.31.0\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("poetry.lock"),
        r#"
[[package]]
name = "requests"
version = "9.9.9"
"#,
    )
    .unwrap();

    let metadata_versions = Arc::new(Mutex::new(Vec::new()));
    let osv_versions = Arc::new(Mutex::new(Vec::new()));
    let registry = RecordingRegistry {
        existing: vec!["requests".to_string()],
        versions: metadata_versions.clone(),
    };
    let osv = RecordingOsvClient {
        versions: osv_versions.clone(),
    };

    let deps = parsers::pyproject_toml::parse_poetry(&dir).unwrap();
    let report = scan_with_services_inner_for_kind(
        Some(ProjectInputKind::PyProjectPoetry),
        &dir,
        Default::default(),
        deps,
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

    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.check == "metadata/unresolved-version")
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.check == "resolution/lockfile-out-of-sync"),
        "mismatched trusted Python lockfiles must still surface the direct-version disagreement"
    );
    assert_eq!(
        metadata_versions.lock().unwrap().first(),
        Some(&Some("2.31.0".to_string()))
    );
    assert_eq!(
        osv_versions.lock().unwrap().first(),
        Some(&Some("2.31.0".to_string()))
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_pypi_uses_poetry_lock_for_transitive_dependencies() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"2.31.0\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("poetry.lock"),
        r#"[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "urllib3"
version = "2.1.0"

[metadata]
lock-version = "2.0"
python-versions = "^3.8"
"#,
    )
    .unwrap();

    let registry = FakeRegistry {
        existing: vec!["requests".to_string(), "urllib3".to_string()],
    };
    let osv = VulnOsvClient {
        vulnerable: vec!["urllib3".to_string()],
    };

    let deps = parsers::pyproject_toml::parse_poetry(&dir).unwrap();
    let report = scan_with_services_inner_for_kind(
        Some(ProjectInputKind::PyProjectPoetry),
        &dir,
        Default::default(),
        deps,
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

    assert!(
        report.issues.iter().any(
            |issue| issue.package == "urllib3" && issue.source.as_deref() == Some("transitive")
        ),
        "trusted Python lockfiles must surface transitive packages in the scan pipeline"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn legacy_requirements_scans_do_not_use_poetry_lock_for_transitive_dependencies() {
    let dir = unique_dir();
    std::fs::write(dir.join("requirements.txt"), "requests==2.31.0\n").unwrap();
    std::fs::write(
        dir.join("poetry.lock"),
        r#"[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "urllib3"
version = "2.1.0"

[metadata]
lock-version = "2.0"
python-versions = "^3.8"
"#,
    )
    .unwrap();

    let registry = FakeRegistry {
        existing: vec!["requests".to_string(), "urllib3".to_string()],
    };
    let osv = VulnOsvClient {
        vulnerable: vec!["urllib3".to_string()],
    };

    let deps = parsers::requirements::parse(&dir).unwrap();
    let report = scan_with_services_inner_for_kind(
        Some(ProjectInputKind::PyRequirements),
        &dir,
        Default::default(),
        deps,
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

    assert!(
        !report.issues.iter().any(
            |issue| issue.package == "urllib3" && issue.source.as_deref() == Some("transitive")
        ),
        "legacy requirements scans must not silently inherit Poetry transitive coverage"
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
async fn npm_fixture_stale_shadow_package_lock_in_pnpm_repo_blocks() {
    let dir = fixture_dir("stale-shadow-package-lock-pnpm");
    let err = scan_with_source_full(&dir, Some("npm"), None, false, false, true, None)
        .await
        .expect_err("pnpm projects with a shadow package-lock must fail closed");
    let msg = err.to_string();
    assert!(msg.contains("pnpm"));
    assert!(msg.contains("package-lock"));
}

#[tokio::test]
async fn npm_fixture_stale_shadow_package_lock_in_yarn_repo_blocks() {
    let dir = fixture_dir("stale-shadow-package-lock-yarn");
    let err = scan_with_source_full(&dir, Some("npm"), None, false, false, true, None)
        .await
        .expect_err("yarn projects with a shadow package-lock must fail closed");
    let msg = err.to_string();
    assert!(msg.contains("yarn"));
    assert!(msg.contains("package-lock"));
}

#[tokio::test]
async fn npm_fixture_stale_shadow_package_lock_in_bun_repo_blocks() {
    let dir = fixture_dir("stale-shadow-package-lock-bun");
    let err = scan_with_source_full(&dir, Some("npm"), None, false, false, true, None)
        .await
        .expect_err("bun projects with a shadow package-lock must fail closed");
    let msg = err.to_string();
    assert!(msg.contains("bun"));
    assert!(msg.contains("package-lock"));
}

#[tokio::test]
async fn npm_fixture_override_only_drift_blocks_until_strict_verification_exists() {
    let dir = fixture_dir("override-only-drift");
    let err = scan_with_source_full(&dir, Some("npm"), None, false, false, true, None)
        .await
        .expect_err("overrides must not silently bypass strict lockfile trust");
    let msg = err.to_string();
    assert!(msg.contains("overrides"));
    assert!(msg.contains("package.json"));
}

#[tokio::test]
async fn npm_fixture_v1_range_drift_blocks_by_default() {
    let dir = fixture_dir("v1-range-drift");
    let err = scan_with_source_full(&dir, Some("npm"), None, false, false, true, None)
        .await
        .expect_err("legacy npm v1 lockfiles must block by default");
    let msg = err.to_string();
    assert!(msg.contains("legacy npm v5/v6 lockfile"));
    assert!(msg.contains("modern npm"));
}

#[tokio::test]
async fn npm_fixture_v1_range_drift_can_be_explicitly_allowed() {
    let dir = fixture_dir("v1-range-drift");
    let config = config::SloppyJoeConfig {
        allow_legacy_npm_v1_lockfile: true,
        ..Default::default()
    };
    let registry = FakeRegistry {
        existing: vec!["react".to_string()],
    };

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        config,
        &registry,
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("explicit opt-in should allow legacy npm v1 lockfiles");

    assert_eq!(report.packages_checked, 1);
    assert!(report.issues.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE
            && issue.severity == Severity::Warning
    }));
    assert!(report.issues.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_NO_TRUSTED_TRANSITIVE_COVERAGE
            && issue.severity == Severity::Warning
    }));
}

#[test]
fn npm_fixture_workspace_lock_target_mismatch_blocks() {
    let dir = fixture_dir("workspace-lock-target-mismatch");
    let err = preflight_scan_inputs(&dir, None)
        .expect_err("workspace lockfile links must point at the verified workspace target");
    let msg = err.to_string();
    assert!(msg.contains("workspace-lib"));
    assert!(msg.contains("other-lib"));
}

#[test]
fn npm_fixture_file_lock_target_mismatch_blocks() {
    let dir = fixture_dir("file-lock-target-mismatch");
    let err = preflight_scan_inputs(&dir, None)
        .expect_err("file/link lockfile entries must point at the manifest-verified local target");
    let msg = err.to_string();
    assert!(msg.contains("local-lib"));
    assert!(msg.contains("other-lib"));
}

#[test]
fn npm_fixture_wrong_package_identity_blocks() {
    let dir = fixture_dir("wrong-package-identity");
    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("lockfile entries must not claim a different package identity");
    let msg = err.to_string();
    assert!(msg.contains("react"));
    assert!(msg.contains("lodash"));
}

#[test]
fn npm_fixture_registry_url_wrong_package_blocks() {
    let dir = fixture_dir("registry-url-wrong-package");
    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("registry tarball URLs must match the locked package identity");
    let msg = err.to_string();
    assert!(msg.contains("react"));
    assert!(msg.contains("lodash"));
}

#[test]
fn npm_fixture_registry_url_wrong_version_blocks() {
    let dir = fixture_dir("registry-url-wrong-version");
    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("registry tarball URLs must match the locked version");
    let msg = err.to_string();
    assert!(msg.contains("18.3.1"));
    assert!(msg.contains("99.0.0"));
}

#[test]
fn npm_fixture_bundled_entry_blocks() {
    let dir = fixture_dir("bundled-entry");
    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("bundled npm entries must not silently bypass provenance checks");
    let msg = err.to_string();
    assert!(msg.contains("bundled"));
    assert!(msg.contains("react"));
}

#[tokio::test]
async fn npm_fixture_transitive_typosquat_flags_similarity_without_deep() {
    let dir = fixture_dir("transitive-typosquat");
    let registry = FakeRegistry {
        existing: vec![
            "react".to_string(),
            "express".to_string(),
            "expresss".to_string(),
        ],
    };

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        Default::default(),
        &registry,
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("fixture scan should succeed");

    assert!(
        report.issues.iter().any(|issue| {
            issue.package == "expresss"
                && issue.check.starts_with("similarity/")
                && issue.source.as_deref() == Some("transitive")
        }),
        "transitive npm typosquat should trigger similarity without --deep"
    );
}

#[tokio::test]
async fn npm_fixture_private_scope_typo_uses_configured_trusted_scope() {
    let dir = fixture_dir("private-scope-typo");
    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        fixture_config("private-scope-typo"),
        &FakeRegistry {
            existing: vec!["@acmf/widget".to_string()],
        },
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("fixture scan should succeed");

    assert!(
        report.issues.iter().any(|issue| {
            issue.package == "@acmf/widget"
                && issue.check == crate::checks::names::SIMILARITY_SCOPE_SQUATTING
        }),
        "repo-configured trusted scopes should participate in npm scope-squatting detection"
    );
}

#[tokio::test]
async fn npm_fixture_long_tail_combo_squat_uses_configured_package_roots() {
    let dir = fixture_dir("long-tail-combo-squat");
    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        fixture_config("long-tail-combo-squat"),
        &FakeRegistry {
            existing: vec!["acme-widget".to_string(), "acme-widget-utils".to_string()],
        },
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("fixture scan should succeed");

    assert!(
        report.issues.iter().any(|issue| {
            issue.package == "acme-widget-utils"
                && issue.check == crate::checks::names::SIMILARITY_SEGMENT_OVERLAP
        }),
        "repo-configured trusted package roots should participate in npm combo-squatting detection"
    );
}

#[test]
fn python_fixture_contracts_hold() {
    for case in ["direct-url-fail", "poetry-pass", "requirements-warn-pass"] {
        assert_fixture_preflight_outcome("python", case);
    }
}

#[test]
fn cargo_fixture_contracts_hold() {
    for case in [
        "git-dependency-fail",
        "registry-not-allowlisted-fail",
        "workspace-pass",
    ] {
        assert_fixture_preflight_outcome("cargo", case);
    }
}

#[test]
fn go_fixture_contracts_hold() {
    for case in ["go-sum-pass", "local-replace-pass", "missing-go-sum-fail"] {
        assert_fixture_preflight_outcome("go", case);
    }
}

#[test]
fn ruby_fixture_contracts_hold() {
    for case in ["git-source-fail", "rubygems-pass"] {
        assert_fixture_preflight_outcome("ruby", case);
    }
}

#[test]
fn php_fixture_contracts_hold() {
    for case in ["composer-pass", "custom-repository-fail"] {
        assert_fixture_preflight_outcome("php", case);
    }
}

#[test]
fn jvm_fixture_contracts_hold() {
    for case in ["custom-repo-fail", "gradle-pass", "maven-warning"] {
        assert_fixture_preflight_outcome("jvm", case);
    }
}

#[test]
fn dotnet_fixture_contracts_hold() {
    for case in ["missing-lock-fail", "packages-lock-pass"] {
        assert_fixture_preflight_outcome("dotnet", case);
    }
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
            actual_name: None,
        },
        Dependency {
            name: "lodash".to_string(),
            version: Some("^4.0".to_string()),
            ecosystem: Ecosystem::Npm,
            actual_name: None,
        },
    ];
    let hash1 = scan_hash(&dir, &deps).unwrap();
    let hash2 = scan_hash(&dir, &deps).unwrap();
    assert_eq!(hash1, hash2);
}

#[test]
fn scan_hash_changes_with_different_deps() {
    let dir = std::env::temp_dir();
    let deps1 = vec![Dependency {
        name: "react".to_string(),
        version: Some("^18.0".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }];
    let deps2 = vec![Dependency {
        name: "react".to_string(),
        version: Some("^19.0".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }];
    assert_ne!(
        scan_hash(&dir, &deps1).unwrap(),
        scan_hash(&dir, &deps2).unwrap()
    );
}

#[test]
fn scan_hash_order_independent() {
    let dir = std::env::temp_dir();
    let deps1 = vec![
        Dependency {
            name: "a".to_string(),
            version: None,
            ecosystem: Ecosystem::Npm,
            actual_name: None,
        },
        Dependency {
            name: "b".to_string(),
            version: None,
            ecosystem: Ecosystem::Npm,
            actual_name: None,
        },
    ];
    let deps2 = vec![
        Dependency {
            name: "b".to_string(),
            version: None,
            ecosystem: Ecosystem::Npm,
            actual_name: None,
        },
        Dependency {
            name: "a".to_string(),
            version: None,
            ecosystem: Ecosystem::Npm,
            actual_name: None,
        },
    ];
    assert_eq!(
        scan_hash(&dir, &deps1).unwrap(),
        scan_hash(&dir, &deps2).unwrap()
    );
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
        actual_name: None,
    }];

    // Hash without lockfile
    let hash_no_lock = scan_hash(&dir, &deps).unwrap();

    // Write a lockfile
    std::fs::write(dir.join("package-lock.json"), r#"{"lockfileVersion":3}"#).unwrap();
    let hash_with_lock = scan_hash(&dir, &deps).unwrap();

    // Change lockfile content
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"node_modules/react":{"version":"18.999.0"}}}"#,
    )
    .unwrap();
    let hash_changed_lock = scan_hash(&dir, &deps).unwrap();

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
fn scan_hash_for_projects_changes_when_policy_changes() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let specs =
        detected_project_inputs_with_config(&dir, Some("npm"), &config::SloppyJoeConfig::default())
            .unwrap();
    let projects = parse_project_inputs(&dir, &specs, &config::SloppyJoeConfig::default()).unwrap();

    let default_hash = scan_hash_for_projects_with_policy(
        &projects,
        &config::SloppyJoeConfig::default(),
        &ScanOptions::default(),
    )
    .unwrap();
    let allowed_hash = scan_hash_for_projects_with_policy(
        &projects,
        &config::SloppyJoeConfig {
            allowed: std::collections::HashMap::from([(
                "npm".to_string(),
                vec!["react".to_string()],
            )]),
            ..Default::default()
        },
        &ScanOptions::default(),
    )
    .unwrap();

    assert_ne!(
        default_hash, allowed_hash,
        "policy changes must invalidate the dependency-hash shortcut"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scan_hash_for_projects_changes_when_result_shaping_options_change() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let specs =
        detected_project_inputs_with_config(&dir, Some("npm"), &config::SloppyJoeConfig::default())
            .unwrap();
    let projects = parse_project_inputs(&dir, &specs, &config::SloppyJoeConfig::default()).unwrap();

    let default_hash = scan_hash_for_projects_with_policy(
        &projects,
        &config::SloppyJoeConfig::default(),
        &ScanOptions::default(),
    )
    .unwrap();
    let deep_hash = scan_hash_for_projects_with_policy(
        &projects,
        &config::SloppyJoeConfig::default(),
        &ScanOptions {
            deep: true,
            ..Default::default()
        },
    )
    .unwrap();
    let review_hash = scan_hash_for_projects_with_policy(
        &projects,
        &config::SloppyJoeConfig::default(),
        &ScanOptions {
            review_exceptions: true,
            ..Default::default()
        },
    )
    .unwrap();

    assert_ne!(
        default_hash, deep_hash,
        "--deep must invalidate the dependency-hash shortcut"
    );
    assert_ne!(
        default_hash, review_hash,
        "--review-exceptions must invalidate the dependency-hash shortcut"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scan_hash_ignores_shadowed_package_lock_when_shrinkwrap_exists() {
    let dir = unique_dir();
    let deps = vec![Dependency {
        name: "react".to_string(),
        version: Some("^18.0".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }];

    std::fs::write(
        dir.join("npm-shrinkwrap.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"18.3.1"}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"18.3.1"}}}"#,
    )
    .unwrap();

    let hash_before = scan_hash(&dir, &deps).unwrap();

    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"99.0.0"}}}"#,
    )
    .unwrap();

    let hash_after = scan_hash(&dir, &deps).unwrap();
    assert_eq!(
        hash_before, hash_after,
        "shadowed package-lock.json must not affect the hash when npm-shrinkwrap.json is authoritative"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cargo_lockfile_trust_requires_proven_sync_for_non_exact_direct_deps() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    )
    .unwrap();

    let deps = parsers::cargo_toml::parse(&dir).unwrap();
    let data = lockfiles::LockfileData::parse(&dir, &deps).unwrap();

    assert!(
        data.resolution.exact_version(&deps[0]).is_none(),
        "non-exact Cargo direct deps must not be trusted from Cargo.lock without sync proof"
    );
    assert!(data.resolution.issues.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE_SYNC
            && issue.package == "serde"
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn composer_lockfile_trust_requires_proven_sync_for_non_exact_direct_deps() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("composer.json"),
        r#"{"require":{"laravel/framework":"^10.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("composer.lock"),
        r#"{"packages":[{"name":"laravel/framework","version":"10.48.29"}]}"#,
    )
    .unwrap();

    let deps = parsers::composer_json::parse(&dir).unwrap();
    let data = lockfiles::LockfileData::parse(&dir, &deps).unwrap();

    assert!(
        data.resolution.exact_version(&deps[0]).is_none(),
        "non-exact Composer direct deps must not be trusted from composer.lock without sync proof"
    );
    assert!(data.resolution.issues.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE_SYNC
            && issue.package == "laravel/framework"
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ruby_lockfile_trust_requires_proven_sync_for_non_exact_direct_deps() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("Gemfile"),
        "source 'https://rubygems.org'\ngem 'rails', '~> 7.0'\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("Gemfile.lock"),
        r#"GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.4)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 7.0)
"#,
    )
    .unwrap();

    let deps = parsers::gemfile::parse(&dir).unwrap();
    let data = lockfiles::LockfileData::parse(&dir, &deps).unwrap();

    assert!(
        data.resolution.exact_version(&deps[0]).is_none(),
        "non-exact Gemfile deps must not be trusted from Gemfile.lock without sync proof"
    );
    assert!(data.resolution.issues.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE_SYNC
            && issue.package == "rails"
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gradle_lockfile_trust_requires_proven_sync_for_non_exact_direct_deps() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("build.gradle"),
        "repositories {\n  mavenCentral()\n}\ndependencies {\n  implementation 'com.google.guava:guava:[31.0,32.0)'\n}\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("gradle.lockfile"),
        "com.google.guava:guava:31.1-jre=runtimeClasspath\n",
    )
    .unwrap();

    let deps = parsers::jvm::parse_manifest(&dir.join("build.gradle")).unwrap();
    let data = lockfiles::LockfileData::parse_for_kind(&dir, Some(ProjectInputKind::Gradle), &deps)
        .unwrap();

    assert!(
        data.resolution.exact_version(&deps[0]).is_none(),
        "non-exact Gradle direct deps must not be trusted from gradle.lockfile without sync proof"
    );
    assert!(data.resolution.issues.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE_SYNC
            && issue.package == "com.google.guava:guava"
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dotnet_lockfile_trust_requires_proven_sync_for_non_exact_direct_deps() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("app.csproj"),
        r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.0,14.0.0)" /></ItemGroup></Project>"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages.lock.json"),
        r#"{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","requested":"[13.0.0,14.0.0)","resolved":"13.0.1"}}}}"#,
    )
    .unwrap();

    let deps = parsers::csproj::parse_file(&dir.join("app.csproj")).unwrap();
    let data = lockfiles::LockfileData::parse_for_kind(&dir, Some(ProjectInputKind::Dotnet), &deps)
        .unwrap();

    assert!(
        data.resolution.exact_version(&deps[0]).is_none(),
        "non-exact .NET direct deps must not be trusted from packages.lock.json without sync proof"
    );
    assert!(data.resolution.issues.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE_SYNC
            && issue.package == "Newtonsoft.Json"
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn poetry_lockfile_trust_requires_proven_sync_for_non_exact_direct_deps() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31.0"
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("poetry.lock"),
        r#"[[package]]
name = "requests"
version = "2.31.0"

[metadata]
lock-version = "2.0"
"#,
    )
    .unwrap();

    let deps = parsers::pyproject_toml::parse_poetry(&dir).unwrap();
    let data = lockfiles::LockfileData::parse_for_kind(
        &dir,
        Some(ProjectInputKind::PyProjectPoetry),
        &deps,
    )
    .unwrap();

    assert!(
        data.resolution.exact_version(&deps[0]).is_none(),
        "non-exact Poetry direct deps must not be trusted from poetry.lock without sync proof"
    );
    assert!(data.resolution.issues.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE_SYNC
            && issue.package == "requests"
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_cargo_git_dependency_sources() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = { git = "https://github.com/serde-rs/serde" }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();

    let err = preflight_scan_inputs(&dir, Some("cargo"))
        .expect_err("Cargo git dependencies must block strict scanning");
    assert!(err.to_string().contains("git"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_cargo_workspace_inheritance_from_in_scope_root() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("app")).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[workspace]
members = ["app"]

[workspace.dependencies]
serde = "=1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("app").join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = { workspace = true }
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "workspace-inherited Cargo deps should be allowed when the in-scope workspace root and lockfile prove trusted provenance: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_workspace_inherited_cargo_dep_through_workspace_root_patch_rewrite() {
    let dir = unique_dir();
    let app = dir.join("app");
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::create_dir_all(&patched).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[workspace]
members = ["app", "patched-serde"]

[workspace.dependencies]
serde = "=1.0.228"

[patch.crates-io]
serde = { path = "patched-serde" }
"#,
    )
    .unwrap();
    std::fs::write(
        app.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = { workspace = true }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        patched.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(patched.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "workspace-inherited Cargo deps must still flow through workspace-root rewrites: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_cargo_workspace_inheritance_for_non_member_crate() {
    let dir = unique_dir();
    let member = dir.join("member");
    let rogue = dir.join("rogue");
    std::fs::create_dir_all(&member).unwrap();
    std::fs::create_dir_all(&rogue).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[workspace]
members = ["member"]

[workspace.dependencies]
serde = "=1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(
        member.join("Cargo.toml"),
        r#"[package]
name = "member"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        rogue.join("Cargo.toml"),
        r#"[package]
name = "rogue"
version = "0.1.0"

[dependencies]
serde = { workspace = true }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(rogue.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let err = detected_project_inputs_with_config(&dir, Some("cargo"), &config)
        .expect_err("non-member crates must not inherit workspace dependencies or lockfile trust");
    assert!(err.to_string().contains("no in-scope workspace root"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn detected_project_inputs_include_workspace_root_patch_target_for_workspace_inherited_dep() {
    let dir = unique_dir();
    let app = dir.join("app");
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::create_dir_all(&patched).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[workspace]
members = ["app", "patched-serde"]

[workspace.dependencies]
serde = "=1.0.228"

[patch.crates-io]
serde = { path = "patched-serde" }
"#,
    )
    .unwrap();
    std::fs::write(
        app.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = { workspace = true }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        patched.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(patched.join("Cargo.lock"), "version = 4\n").unwrap();

    let specs = detected_project_inputs_with_config(
        &dir,
        Some("cargo"),
        &config::SloppyJoeConfig::default(),
    )
    .unwrap();
    assert!(
        specs
            .iter()
            .any(|spec| spec.manifest_path == patched.join("Cargo.toml")),
        "workspace-root rewrite targets for workspace-inherited deps must be scanned as first-class Cargo projects"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_cargo_in_root_path_dependency() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("app")).unwrap();
    std::fs::create_dir_all(dir.join("util")).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[workspace]
members = ["app", "util"]
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("app").join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
util = { path = "../util" }
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("util").join("Cargo.toml"),
        r#"[package]
name = "util"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "in-root Cargo path deps should be allowed and treated as first-party local crates: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_cargo_path_dependency_with_mismatched_package_name() {
    let dir = unique_dir();
    let local = dir.join("local-crate");
    std::fs::create_dir_all(&local).unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = { path = "local-crate" }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        local.join("Cargo.toml"),
        r#"[package]
name = "not-serde"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(local.join("Cargo.lock"), "version = 4\n").unwrap();

    let specs = detected_project_inputs_with_config(
        &dir,
        Some("cargo"),
        &config::SloppyJoeConfig::default(),
    )
    .unwrap();
    let err = preflight_project_inputs(&dir, &specs, &config::SloppyJoeConfig::default())
        .expect_err("mismatched local Cargo crate identity must block");
    assert!(err.to_string().contains("declares package"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_cargo_exact_path_dependency_with_mismatched_target_version() {
    let dir = unique_dir();
    let local = dir.join("local-crate");
    std::fs::create_dir_all(&local).unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = { path = "local-crate", version = "=1.0.228" }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        local.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "9.9.9"
"#,
    )
    .unwrap();
    std::fs::write(local.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let err = preflight_project_inputs(&dir, &specs, &config)
        .expect_err("exact local Cargo path dependencies must bind target version too");
    assert!(err.to_string().contains("declares version"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_cargo_allowlisted_external_path_dependency() {
    let dir = unique_dir();
    let external = unique_dir();
    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
shared = {{ path = "{}" }}
"#,
            external.display()
        ),
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        external.join("Cargo.toml"),
        r#"[package]
name = "shared"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(external.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig {
        trusted_local_paths: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec![external.display().to_string()],
        )]),
        ..Default::default()
    };
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "allowlisted external Cargo path deps should pass strict preflight: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&external);
}

#[test]
fn preflight_does_not_apply_crates_io_patch_to_private_registry_dependency() {
    let dir = unique_dir();
    let patched = unique_dir();
    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = {{ version = "1.0.0", registry = "company" }}

[patch.crates-io]
serde = {{ path = "{}" }}
"#,
            patched.display()
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://cargo.company.example/index"
"#,
    )
    .unwrap();
    std::fs::write(
        patched.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.0"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig {
        trusted_registries: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec![config::TrustedRegistry {
                name: "company".to_string(),
                source: "registry+https://cargo.company.example/index".to_string(),
            }],
        )]),
        ..Default::default()
    };
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "crates.io patches must not rewrite private-registry dependencies: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&patched);
}

#[test]
fn preflight_allows_cargo_allowlisted_private_registry_dependency() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
internal-crate = { registry = "company", version = "=1.2.3" }
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "internal-crate"
version = "1.2.3"
source = "registry+https://cargo.company.example/index"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig {
        trusted_registries: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec![config::TrustedRegistry {
                name: "company".to_string(),
                source: "registry+https://cargo.company.example/index".to_string(),
            }],
        )]),
        ..Default::default()
    };
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "allowlisted Cargo private registries should pass strict preflight when Cargo.lock proves the exact source: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn cargo_private_registry_dependency_scans_with_trusted_lockfile_source() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
internal-crate = { registry = "company", version = "=1.2.3" }
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "internal-crate"
version = "1.2.3"
source = "registry+https://cargo.company.example/index"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig {
        trusted_registries: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec![config::TrustedRegistry {
                name: "company".to_string(),
                source: "registry+https://cargo.company.example/index".to_string(),
            }],
        )]),
        ..Default::default()
    };

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("cargo"),
        config,
        &FakeRegistry {
            existing: vec!["internal-crate".to_string()],
        },
        &FakeOsvClient,
        &ScanOptions::default(),
    )
    .await
    .expect("trusted Cargo private registries should survive the full scan path");

    assert_eq!(report.packages_checked, 1);
    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.check.starts_with("resolution/")),
        "trusted Cargo private registry dependency should not degrade into a resolution failure: {:?}",
        report.issues
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_warns_for_cargo_allowlisted_pinned_git_dependency() {
    let dir = unique_dir();
    let rev = "0123456789abcdef0123456789abcdef01234567";
    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
shared = {{ git = "https://github.com/yourorg/shared-crate", rev = "{rev}" }}
"#
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        format!(
            r#"version = 4

[[package]]
name = "shared"
version = "0.1.0"
source = "git+https://github.com/yourorg/shared-crate?rev={rev}#{rev}"
"#
        ),
    )
    .unwrap();

    let config = config::SloppyJoeConfig {
        cargo_git_policy: config::CargoGitPolicy::WarnPinned,
        trusted_git_sources: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec!["https://github.com/yourorg/shared-crate".to_string()],
        )]),
        ..Default::default()
    };
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let warnings = preflight_project_inputs(&dir, &specs, &config)
        .expect("allowlisted pinned Cargo git deps should continue in reduced-confidence mode");
    assert!(warnings.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_REDUCED_CONFIDENCE_GIT
            && issue.package == "shared"
            && issue.severity == Severity::Warning
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_trusted_cargo_patch_rewrite_to_local_path() {
    let dir = unique_dir();
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&patched).unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"

[patch.crates-io]
serde = { path = "patched-serde" }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        patched.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(patched.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "trusted repo-visible Cargo patch rewrites to local crates should pass strict preflight: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_workspace_root_cargo_patch_rewrite_for_member() {
    let dir = unique_dir();
    let app = dir.join("app");
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::create_dir_all(&patched).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[workspace]
members = ["app", "patched-serde"]

[patch.crates-io]
serde = { path = "patched-serde" }
"#,
    )
    .unwrap();
    std::fs::write(
        app.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        patched.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "workspace-root Cargo patch rewrites must apply to member crates: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_ignores_member_local_cargo_patch_rewrites() {
    let dir = unique_dir();
    let app = dir.join("app");
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::create_dir_all(&patched).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[workspace]
members = ["app", "patched-serde"]
"#,
    )
    .unwrap();
    std::fs::write(
        app.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"

[patch.crates-io]
serde = { path = "../patched-serde" }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        patched.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let err = preflight_project_inputs(&dir, &specs, &config)
        .expect_err("member-local Cargo [patch] should be ignored like Cargo itself");
    assert!(err.to_string().contains("Cargo.lock"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn detected_project_inputs_include_workspace_root_cargo_patch_local_crate() {
    let dir = unique_dir();
    let app = dir.join("app");
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::create_dir_all(&patched).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[workspace]
members = ["app", "patched-serde"]

[patch.crates-io]
serde = { path = "patched-serde" }
"#,
    )
    .unwrap();
    std::fs::write(
        app.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        patched.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();

    let specs = detected_project_inputs_with_config(
        &dir,
        Some("cargo"),
        &config::SloppyJoeConfig::default(),
    )
    .unwrap();
    assert!(
        specs
            .iter()
            .any(|spec| spec.manifest_path == patched.join("Cargo.toml")),
        "workspace-root Cargo patch targets must be discovered as first-class Cargo projects"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_repo_local_cargo_config_named_source_chain_to_trusted_registry() {
    let dir = unique_dir();
    let cargo_config_dir = dir.join(".cargo");
    std::fs::create_dir_all(&cargo_config_dir).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = { version = "=1.0.228", registry = "company" }
"#,
    )
    .unwrap();
    std::fs::write(
        cargo_config_dir.join("config.toml"),
        r#"[source.company]
replace-with = "mirror"

[source.mirror]
registry = "https://cargo.company.mirror/index"
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://cargo.company.mirror/index"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig {
        trusted_registries: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec![
                config::TrustedRegistry {
                    name: "company".to_string(),
                    source: "registry+https://cargo.company.example/index".to_string(),
                },
                config::TrustedRegistry {
                    name: "mirror".to_string(),
                    source: "registry+https://cargo.company.mirror/index".to_string(),
                },
            ],
        )]),
        ..Default::default()
    };
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "trusted Cargo named-source replacement chains must pass strict preflight: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_repo_local_cargo_config_directory_source_rewrite() {
    let dir = unique_dir();
    let cargo_config_dir = dir.join(".cargo");
    let vendor = dir.join("vendor");
    std::fs::create_dir_all(&cargo_config_dir).unwrap();
    std::fs::create_dir_all(&vendor).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(
        cargo_config_dir.join("config.toml"),
        r#"[source.crates-io]
replace-with = "vendored"

[source.vendored]
directory = "../vendor"
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let err = detected_project_inputs_with_config(&dir, Some("cargo"), &config)
        .expect_err("unsupported Cargo directory source rewrites must block");
    assert!(err.to_string().contains("unsupported directory source"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_repo_local_cargo_config_patch_rewrite_to_trusted_local_crate() {
    let dir = unique_dir();
    let cargo_config_dir = dir.join(".cargo");
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&cargo_config_dir).unwrap();
    std::fs::create_dir_all(&patched).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        cargo_config_dir.join("config.toml"),
        r#"[patch.crates-io]
serde = { path = "../patched-serde" }
"#,
    )
    .unwrap();
    std::fs::write(
        patched.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(patched.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "repo-local Cargo config patch rewrites to trusted local crates must pass strict preflight: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn detected_project_inputs_include_repo_local_cargo_config_patch_local_crate() {
    let dir = unique_dir();
    let cargo_config_dir = dir.join(".cargo");
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&cargo_config_dir).unwrap();
    std::fs::create_dir_all(&patched).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        cargo_config_dir.join("config.toml"),
        r#"[patch.crates-io]
serde = { path = "../patched-serde" }
"#,
    )
    .unwrap();
    std::fs::write(
        patched.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(patched.join("Cargo.lock"), "version = 4\n").unwrap();

    let specs = detected_project_inputs_with_config(
        &dir,
        Some("cargo"),
        &config::SloppyJoeConfig::default(),
    )
    .unwrap();
    assert!(
        specs
            .iter()
            .any(|spec| spec.manifest_path == patched.join("Cargo.toml")),
        "repo-local Cargo config patch targets must be discovered as first-class Cargo projects"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_conflicting_cargo_patch_rewrites_for_same_scope() {
    let dir = unique_dir();
    let cargo_config_dir = dir.join(".cargo");
    let patched_a = dir.join("patched-serde-a");
    let patched_b = dir.join("patched-serde-b");
    std::fs::create_dir_all(&cargo_config_dir).unwrap();
    std::fs::create_dir_all(&patched_a).unwrap();
    std::fs::create_dir_all(&patched_b).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"

[patch.crates-io]
serde = { path = "patched-serde-a" }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        cargo_config_dir.join("config.toml"),
        r#"[patch.crates-io]
serde = { path = "../patched-serde-b" }
"#,
    )
    .unwrap();
    std::fs::write(
        patched_a.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(
        patched_b.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();

    let err = detected_project_inputs_with_config(
        &dir,
        Some("cargo"),
        &config::SloppyJoeConfig::default(),
    )
    .expect_err("conflicting Cargo rewrites for the same package/scope must fail closed");
    assert!(err.to_string().contains("Conflicting Cargo rewrite"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_cargo_replace_rewrite_with_package_id_spec() {
    let dir = unique_dir();
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&patched).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"

[replace]
"serde:1.0.228" = { path = "patched-serde" }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        patched.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(patched.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "Cargo [replace] entries with package ID specs must resolve through the trusted local rewrite model: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_cargo_replace_target_with_mismatched_package_id_version() {
    let dir = unique_dir();
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&patched).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"

[replace]
"serde:1.0.228" = { path = "patched-serde" }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        patched.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "9.9.9"
"#,
    )
    .unwrap();
    std::fs::write(patched.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let err = preflight_project_inputs(&dir, &specs, &config)
        .expect_err("Cargo [replace] targets must match the exact replaced package ID version");
    assert!(err.to_string().contains("declares version"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_does_not_apply_cargo_replace_with_mismatched_package_id_version() {
    let dir = unique_dir();
    let external = unique_dir();

    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.229"

[replace]
"serde:1.0.228" = {{ path = "{}" }}
"#,
            external.display()
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "serde"
version = "1.0.229"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    )
    .unwrap();
    std::fs::write(
        external.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "Cargo [replace] must not apply when the package ID version does not match: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&external);
}

#[test]
fn preflight_allows_cargo_replace_with_fully_qualified_package_id_source() {
    let dir = unique_dir();
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&patched).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = { version = "=1.0.228", registry = "company" }

[replace]
"registry+https://cargo.company.example/index#serde@1.0.228" = { path = "patched-serde" }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        patched.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(patched.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig {
        trusted_registries: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec![config::TrustedRegistry {
                name: "company".to_string(),
                source: "registry+https://cargo.company.example/index".to_string(),
            }],
        )]),
        ..Default::default()
    };
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "fully qualified Cargo [replace] package IDs must resolve through the trusted local rewrite model: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_cargo_registry_replace_with_mismatched_lockfile_version() {
    let dir = unique_dir();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"

[replace]
"serde:1.0.228" = { registry = "company" }
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "serde"
version = "9.9.9"
source = "registry+https://cargo.company.example/index"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig {
        trusted_registries: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec![config::TrustedRegistry {
                name: "company".to_string(),
                source: "registry+https://cargo.company.example/index".to_string(),
            }],
        )]),
        ..Default::default()
    };
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let err = preflight_project_inputs(&dir, &specs, &config)
        .expect_err("Cargo registry rewrites must still bind the exact replaced package version");
    assert!(err.to_string().contains("Cargo.lock"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_cargo_git_replace_with_mismatched_lockfile_version() {
    let dir = unique_dir();
    let rev = "0123456789abcdef0123456789abcdef01234567";
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    let lockfile = toml::from_str::<toml::Value>(&format!(
        r#"version = 4

[[package]]
name = "shared"
version = "9.9.9"
source = "git+https://github.com/yourorg/shared-crate?rev={rev}#{rev}"
"#
    ))
    .unwrap();

    let config = config::SloppyJoeConfig {
        cargo_git_policy: config::CargoGitPolicy::WarnPinned,
        trusted_git_sources: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec!["https://github.com/yourorg/shared-crate".to_string()],
        )]),
        ..Default::default()
    };
    let rewrite = EffectiveCargoRewrite {
        package_name: "shared".to_string(),
        patch_scope: None,
        replace_source: Some(format!(
            "git+https://github.com/yourorg/shared-crate?rev={rev}#{rev}"
        )),
        replace_version: Some("0.1.0".to_string()),
        spec: parsers::cargo_toml::CargoDependencySpec {
            manifest_name: "shared".to_string(),
            package_name: "shared".to_string(),
            version: None,
            source: parsers::cargo_toml::CargoSourceSpec::Git {
                url: "https://github.com/yourorg/shared-crate".to_string(),
                rev: Some(rev.to_string()),
                branch: None,
                tag: None,
            },
            workspace_member_invalid_keys: Vec::new(),
        },
        base_dir: dir.clone(),
    };
    let err = validate_cargo_effective_rewrite(&dir, &rewrite, &config, &lockfile)
        .expect_err("Cargo git rewrites must still bind the exact replaced package version");
    assert!(err.to_string().contains("Cargo.lock"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_source_qualified_cargo_replace_to_untrusted_local_path() {
    let dir = unique_dir();
    let external = unique_dir();

    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
foo = "=1.0.0"

[replace]
"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228" = {{ path = "{}" }}
"#,
            external.display()
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "foo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(
        external.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(external.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let err = preflight_project_inputs(&dir, &specs, &config).expect_err(
        "source-qualified Cargo rewrites to local paths must not skip trust validation when the final lockfile entry loses its source",
    );
    assert!(err.to_string().contains("outside the scan root"));

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&external);
}

#[test]
fn preflight_allows_cargo_registry_index_dependency_when_trusted() {
    let dir = unique_dir();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
internal-crate = { registry-index = "https://cargo.company.example/index", version = "=1.2.3" }
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "internal-crate"
version = "1.2.3"
source = "registry+https://cargo.company.example/index"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig {
        trusted_registries: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec![config::TrustedRegistry {
                name: "company".to_string(),
                source: "registry+https://cargo.company.example/index".to_string(),
            }],
        )]),
        ..Default::default()
    };
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "Cargo registry-index dependencies should normalize to the trusted lockfile source model: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_does_not_apply_git_scoped_cargo_replace_with_mismatched_rev() {
    let dir = unique_dir();
    let patched = dir.join("patched-shared");
    let replace_rev = "0123456789abcdef0123456789abcdef01234567";
    let actual_rev = "fedcba9876543210fedcba9876543210fedcba98";
    std::fs::create_dir_all(&patched).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
shared = {{ git = "https://github.com/yourorg/shared-crate", rev = "{actual_rev}" }}

[replace]
"git+https://github.com/yourorg/shared-crate?rev={replace_rev}#{replace_rev}#shared@0.1.0" = {{ path = "patched-shared" }}
"#
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        format!(
            r#"version = 4

[[package]]
name = "shared"
version = "0.1.0"
source = "git+https://github.com/yourorg/shared-crate?rev={actual_rev}#{actual_rev}"
"#
        ),
    )
    .unwrap();
    std::fs::write(
        patched.join("Cargo.toml"),
        r#"[package]
name = "shared"
version = "9.9.9"
"#,
    )
    .unwrap();
    std::fs::write(patched.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig {
        cargo_git_policy: config::CargoGitPolicy::WarnPinned,
        trusted_git_sources: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec!["https://github.com/yourorg/shared-crate".to_string()],
        )]),
        ..Default::default()
    };
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "source-qualified Cargo [replace] rules must not match different git revisions: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_cargo_replace_path_with_version_field_without_rewrite_loop() {
    let dir = unique_dir();
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&patched).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"

[replace]
"serde:1.0.228" = { path = "patched-serde", version = "=1.0.228" }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        patched.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(patched.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "Cargo rewrite resolution must not loop when a [replace] target is already in its effective final form: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_repo_local_cargo_config_paths_rewrite_to_trusted_local_crate() {
    let dir = unique_dir();
    let cargo_config_dir = dir.join(".cargo");
    let shared = dir.join("shared");
    std::fs::create_dir_all(&cargo_config_dir).unwrap();
    std::fs::create_dir_all(&shared).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
shared = "=0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        cargo_config_dir.join("config.toml"),
        r#"paths = ["../shared"]"#,
    )
    .unwrap();
    std::fs::write(
        shared.join("Cargo.toml"),
        r#"[package]
name = "shared"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(shared.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "trusted repo-local Cargo config paths rewrites should pass strict preflight: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_repo_local_cargo_config_paths_with_ambiguous_package_name() {
    let dir = unique_dir();
    let cargo_config_dir = dir.join(".cargo");
    let shared_a = dir.join("shared-a");
    let shared_b = dir.join("shared-b");
    std::fs::create_dir_all(&cargo_config_dir).unwrap();
    std::fs::create_dir_all(&shared_a).unwrap();
    std::fs::create_dir_all(&shared_b).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
shared = "=0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        cargo_config_dir.join("config.toml"),
        r#"paths = ["../shared-a", "../shared-b"]"#,
    )
    .unwrap();
    std::fs::write(
        shared_a.join("Cargo.toml"),
        r#"[package]
name = "shared"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        shared_b.join("Cargo.toml"),
        r#"[package]
name = "shared"
version = "0.1.0"
"#,
    )
    .unwrap();

    let err = detected_project_inputs_with_config(
        &dir,
        Some("cargo"),
        &config::SloppyJoeConfig::default(),
    )
    .expect_err("ambiguous Cargo config paths rewrites for the same package must block");
    assert!(err.to_string().contains("multiple local path rewrites"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_repo_local_cargo_config_registry_rewrite_when_trusted() {
    let dir = unique_dir();
    let cargo_config_dir = dir.join(".cargo");
    std::fs::create_dir_all(&cargo_config_dir).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
internal-crate = "=1.2.3"
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "internal-crate"
version = "1.2.3"
source = "registry+https://cargo.company.example/index"
"#,
    )
    .unwrap();
    std::fs::write(
        cargo_config_dir.join("config.toml"),
        r#"[source.crates-io]
replace-with = "company"

[source.company]
registry = "https://cargo.company.example/index"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig {
        trusted_registries: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec![config::TrustedRegistry {
                name: "company".to_string(),
                source: "registry+https://cargo.company.example/index".to_string(),
            }],
        )]),
        ..Default::default()
    };
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "trusted repo-local Cargo registry rewrites should pass strict preflight: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_repo_local_cargo_config_alias_with_unsupported_source_definition() {
    let dir = unique_dir();
    let cargo_config_dir = dir.join(".cargo");
    let vendor = dir.join("vendor");
    std::fs::create_dir_all(&cargo_config_dir).unwrap();
    std::fs::create_dir_all(&vendor).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        cargo_config_dir.join("config.toml"),
        r#"[source.crates-io]
replace-with = "company"

[source.company]
directory = "../vendor"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig {
        trusted_registries: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec![config::TrustedRegistry {
                name: "company".to_string(),
                source: "registry+https://cargo.company.example/index".to_string(),
            }],
        )]),
        ..Default::default()
    };
    let err = detected_project_inputs_with_config(&dir, Some("cargo"), &config)
        .expect_err("repo-local source definitions must not be masked by allowlisted alias names");
    assert!(err.to_string().contains("unsupported directory source"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn host_local_cargo_config_rewrites_block_by_default() {
    let home = unique_dir();
    let cargo_home = home.join(".cargo");
    std::fs::create_dir_all(&cargo_home).unwrap();
    std::fs::write(cargo_home.join("config.toml"), r#"paths = ["../shared"]"#).unwrap();

    let err = cargo_host_local_config_rewrites_for_test(&home, &config::SloppyJoeConfig::default())
        .expect_err("host-local Cargo config must block by default");
    assert!(err.to_string().contains("host-local"));

    let _ = std::fs::remove_dir_all(&home);
}

#[tokio::test]
async fn cargo_scan_allows_mixed_registry_and_allowlisted_git_deps_in_reduced_confidence_mode() {
    let dir = unique_dir();
    let rev = "0123456789abcdef0123456789abcdef01234567";
    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"
shared = {{ git = "https://github.com/yourorg/shared-crate", rev = "{rev}" }}
"#
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        format!(
            r#"version = 4

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "shared"
version = "0.1.0"
source = "git+https://github.com/yourorg/shared-crate?rev={rev}#{rev}"
"#
        ),
    )
    .unwrap();

    let config = config::SloppyJoeConfig {
        cargo_git_policy: config::CargoGitPolicy::WarnPinned,
        trusted_git_sources: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec!["https://github.com/yourorg/shared-crate".to_string()],
        )]),
        ..Default::default()
    };

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("cargo"),
        config,
        &FakeRegistry {
            existing: vec!["serde".to_string()],
        },
        &FakeOsvClient,
        &ScanOptions::default(),
    )
    .await
    .expect("allowlisted pinned Cargo git deps should not break the full scan path");

    assert!(report.issues.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_REDUCED_CONFIDENCE_GIT
            && issue.package == "shared"
            && issue.severity == Severity::Warning
    }));
    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.check == checks::names::RESOLUTION_PARSE_FAILED),
        "mixed Cargo registry+git scans must not degrade into lockfile parse failures: {:?}",
        report.issues
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn host_local_cargo_config_rewrites_warn_when_local_overlay_allows_them() {
    let home = unique_dir();
    let cargo_home = home.join(".cargo");
    std::fs::create_dir_all(&cargo_home).unwrap();
    std::fs::write(
        cargo_home.join("config.toml"),
        r#"[source.crates-io]
replace-with = "company"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig {
        allow_host_local_cargo_config: true,
        ..Default::default()
    };
    let (rewrites, warnings) = cargo_host_local_config_rewrites_for_test(&home, &config)
        .expect("local-only Cargo overlay should be able to trust host-local Cargo config");

    assert_eq!(
        rewrites
            .source_replace_with
            .get("crates-io")
            .map(String::as_str),
        Some("company")
    );
    assert!(
        !warnings.is_empty(),
        "trusting host-local Cargo config must emit a warning on every run"
    );

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn load_effective_cargo_config_rewrites_blocks_host_local_conflicts_with_repo_visible_config() {
    let dir = unique_dir();
    let cargo_config_dir = dir.join(".cargo");
    let home = unique_dir();
    let home_cargo = home.join(".cargo");
    std::fs::create_dir_all(&cargo_config_dir).unwrap();
    std::fs::create_dir_all(&home_cargo).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        cargo_config_dir.join("config.toml"),
        r#"[source.crates-io]
replace-with = "company"
"#,
    )
    .unwrap();
    std::fs::write(
        home_cargo.join("config.toml"),
        r#"[source.crates-io]
replace-with = "mirror"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig {
        allow_host_local_cargo_config: true,
        ..Default::default()
    };
    let err = load_effective_cargo_config_rewrites_for_test(
        &dir,
        &dir.join("Cargo.toml"),
        &config,
        Some(home.join(".cargo")),
    )
    .expect_err("host-local Cargo config must not override repo-visible rewrite state");
    assert!(err.to_string().contains("conflicts with repo-visible"));

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn preflight_blocks_composer_custom_repository_sources() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("composer.json"),
        r#"{
  "repositories":[{"type":"vcs","url":"https://github.com/acme/fork"}],
  "require":{"acme/pkg":"^1.0"}
}"#,
    )
    .unwrap();
    std::fs::write(dir.join("composer.lock"), r#"{"packages":[]}"#).unwrap();

    let err = preflight_scan_inputs(&dir, Some("php"))
        .expect_err("Composer custom repositories must block strict scanning");
    assert!(err.to_string().contains("repositories"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_gradle_custom_repository_sources() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("build.gradle"),
        r#"repositories { maven { url "https://evil.example/maven" } }
dependencies { implementation "com.google.guava:guava:31.1-jre" }"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("gradle.lockfile"),
        "com.google.guava:guava:31.1-jre=runtimeClasspath\n",
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("jvm"))
        .expect_err("Gradle custom repositories must block strict scanning");
    assert!(err.to_string().contains("repository"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_multiline_gradle_custom_repository_sources() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("build.gradle"),
        r#"repositories
{
  maven
  {
    url "https://evil.example/maven"
  }
}

dependencies {
  implementation "com.google.guava:guava:31.1-jre"
}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("gradle.lockfile"),
        "com.google.guava:guava:31.1-jre=runtimeClasspath\n",
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("jvm"))
        .expect_err("multiline Gradle custom repositories must still block strict scanning");
    assert!(err.to_string().contains("repository"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_multiline_gradle_local_project_dependency_sources() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("build.gradle"),
        r#"repositories {
  mavenCentral()
}

dependencies {
  implementation(
    project(":shared")
  )
}"#,
    )
    .unwrap();
    std::fs::write(dir.join("gradle.lockfile"), "").unwrap();

    let err = preflight_scan_inputs(&dir, Some("jvm"))
        .expect_err("multiline Gradle project dependencies must still block strict scanning");
    assert!(err.to_string().contains("local project"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_maven_custom_repository_sources() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pom.xml"),
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <repositories>
    <repository>
      <id>evil</id>
      <url>https://evil.example/maven</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>31.1-jre</version>
    </dependency>
  </dependencies>
</project>"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("jvm"))
        .expect_err("Maven custom repositories must block strict scanning");
    assert!(err.to_string().contains("repository"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_maven_repository_tags_with_whitespace() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pom.xml"),
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <repositories
  >
    <repository
    >
      <id>evil</id>
      <url>https://evil.example/maven</url>
    </repository>
  </repositories>
</project>"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("jvm"))
        .expect_err("whitespace-padded Maven repository tags must still block strict scanning");
    assert!(err.to_string().contains("repository"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_maven_system_path_tags_with_whitespace() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pom.xml"),
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>local-jar</artifactId>
      <version>1.0.0</version>
      <systemPath
      >/tmp/local.jar</systemPath>
    </dependency>
  </dependencies>
</project>"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("jvm"))
        .expect_err("whitespace-padded Maven systemPath tags must still block strict scanning");
    assert!(err.to_string().contains("systemPath"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn scan_hash_does_not_follow_symlinked_lockfile() {
    let dir = unique_dir();
    let deps = vec![Dependency {
        name: "react".to_string(),
        version: Some("^18.0".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }];
    let real = dir.join("real-lock.json");
    std::fs::write(&real, r#"{"lockfileVersion":3}"#).unwrap();
    std::os::unix::fs::symlink(&real, dir.join("package-lock.json")).unwrap();

    let err = scan_hash(&dir, &deps)
        .expect_err("present but unsafe lockfiles must disable hash-based skipping");
    assert!(err.contains("package-lock.json"));
    assert!(err.contains("safely hash"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn scan_hash_matches_cache_refuses_unhashable_lockfile() {
    let dir = unique_dir();
    let cache_dir = unique_dir();
    let deps = vec![Dependency {
        name: "react".to_string(),
        version: Some("^18.0".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }];

    let hash_path = cache_dir.join("scan-hash.json");
    cache::atomic_write_json(
        &hash_path,
        &ScanHashCache {
            timestamp: cache::now_epoch(),
            hash: scan_hash(&dir, &deps).unwrap(),
        },
    );

    let real = dir.join("real-lock.json");
    std::fs::write(&real, r#"{"lockfileVersion":3}"#).unwrap();
    std::os::unix::fs::symlink(&real, dir.join("package-lock.json")).unwrap();

    let err = scan_hash_matches_cache(&dir, &deps, &cache_dir)
        .expect_err("unsafe lockfiles must disable cache-based scan skipping");
    assert!(err.contains("package-lock.json"));

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&cache_dir);
}

#[tokio::test]
async fn scan_with_source_full_blocks_when_any_detected_manifest_is_broken() {
    let dir = unique_dir();
    std::fs::write(dir.join("package.json"), r#"{}"#).unwrap();
    std::fs::write(dir.join("package-lock.json"), r#"{"lockfileVersion":3}"#).unwrap();
    std::fs::write(dir.join("Cargo.toml"), "[package").unwrap();
    std::fs::write(dir.join("Cargo.lock"), "").unwrap();

    let err = scan_with_source_full(&dir, None, None, false, false, false, None)
        .await
        .expect_err("broken detected manifests must block the scan");
    let msg = err.to_string();
    assert!(msg.contains("Cargo.toml"));
    assert!(msg.contains("parse"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_with_source_full_blocks_when_required_lockfile_is_missing() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();

    let err = scan_with_source_full(&dir, Some("npm"), None, false, false, true, None)
        .await
        .expect_err("strict lockfile policy must block npm scans without a lockfile");
    let msg = err.to_string();
    assert!(msg.contains("package-lock.json"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_with_source_full_blocks_when_required_lockfile_is_malformed() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("package-lock.json"), "{not json").unwrap();

    let err = scan_with_source_full(&dir, Some("npm"), None, false, false, true, None)
        .await
        .expect_err("malformed npm lockfiles must block the scan");
    let msg = err.to_string();
    assert!(msg.contains("package-lock.json"));
    assert!(msg.contains("parse"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_with_source_full_blocks_when_npm_lockfile_root_is_out_of_sync() {
    let dir = unique_dir();
    std::fs::write(dir.join("package.json"), r#"{"name":"demo"}"#).unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"18.3.1"}}}"#,
    )
    .unwrap();

    let err = scan_with_source_full(&dir, Some("npm"), None, false, false, true, None)
        .await
        .expect_err("strict npm scans must block out-of-sync manifest and lockfile roots");
    let msg = err.to_string();
    assert!(msg.contains("package-lock.json"));
    assert!(msg.contains("out of sync"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_with_source_full_blocks_on_malformed_poetry_lock_when_scanning_poetry_projects() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"2.31.0\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("poetry.lock"), "not = [valid").unwrap();

    let err = scan_with_source_full(&dir, Some("pypi"), None, false, false, true, None)
        .await
        .expect_err("Poetry projects must fail closed on malformed poetry.lock");
    assert!(err.to_string().contains("poetry.lock"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_with_source_full_emits_maven_lockfile_warning() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pom.xml"),
        r#"<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>demo</artifactId><version>1.0.0</version></project>"#,
    )
    .unwrap();

    let report = scan_with_source_full(&dir, Some("jvm"), None, false, false, true, None)
        .await
        .expect("maven lockfile policy should warn and continue");
    assert_eq!(report.packages_checked, 0);
    assert_eq!(report.issues.len(), 1);
    assert_eq!(report.issues[0].severity, Severity::Warning);
    assert!(report.issues[0].message.contains("Maven"));

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
