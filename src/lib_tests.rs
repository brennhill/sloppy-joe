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

#[cfg(unix)]
fn symlink_path(link: &std::path::Path, target: &std::path::Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
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
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"18.3.1"}}}"#,
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
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","peerDependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"18.3.1"}}}"#,
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
fn preflight_allows_go_without_go_sum_when_all_deps_are_local_replaces() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("go.mod"),
        "module example.com/app\n\ngo 1.21\n\nrequire example.com/localdep v0.0.0\nreplace example.com/localdep => ../localdep\n",
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, Some("go")).unwrap();
    assert!(warnings.is_empty());

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
    let projects = parse_project_inputs(&dir, &specs)
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
            r#"{"lockfileVersion":3,"packages":{"":{"dependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"18.3.1"}}}"#,
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
        let projects = parse_project_inputs(&dir, &specs)
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
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1"}}}"#,
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
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1"}}}"#,
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
    assert!(msg.contains("scan root"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_local_npm_dependencies_within_scan_root() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::create_dir_all(dir.join("packages/workspace-lib")).unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"dependencies":{"workspace-lib":"workspace:*","local-lib":"file:../../packages/workspace-lib"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package-lock.json"),
        r#"{"name":"web","lockfileVersion":3,"packages":{"":{"name":"web","dependencies":{"workspace-lib":"workspace:*","local-lib":"file:../../packages/workspace-lib"}},"node_modules/workspace-lib":{"resolved":"../../packages/workspace-lib","link":true},"node_modules/local-lib":{"resolved":"../../packages/workspace-lib","link":true}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/workspace-lib/package.json"),
        r#"{"name":"workspace-lib","dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/workspace-lib/package-lock.json"),
        r#"{"name":"workspace-lib","lockfileVersion":3,"packages":{"":{"name":"workspace-lib","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1"}}}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, None)
        .expect("local npm dependencies within the scan root must be accepted when discoverable");
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
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"lodash":"npm:evil-pkg@1.2.3"}},"node_modules/lodash":{"name":"evil-pkg","version":"1.2.3"}}}"#,
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

    let report = scan_with_services_no_osv_cache(
        &dir,
        Some("npm"),
        Default::default(),
        &registry,
        &osv_client,
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
