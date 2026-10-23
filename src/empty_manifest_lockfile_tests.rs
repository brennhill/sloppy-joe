//! A manifest that declares no dependencies next to a lockfile that lists
//! packages is exactly how an attacker smuggles an installable package past a
//! scanner that only follows declared roots. These tests pin that every
//! ecosystem with a lockfile reader still validates and scans (or blocks, or
//! flags as stale) the lockfile contents of a zero-dependency project, while a
//! truly empty project stays a pass.
use super::*;
use crate::registry::{PackageMetadata, RegistryExistence, RegistryMetadata};
use crate::report::Severity;
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

static COUNTER: AtomicU64 = AtomicU64::new(0);

const GHOST: &str = "zzghost";

fn unique_dir() -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-empty-lock-{}-{}", std::process::id(), id));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &std::path::Path, name: &str, content: &str) {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<String>>>);

impl Recorder {
    fn saw(&self, needle: &str) -> bool {
        self.0
            .lock()
            .unwrap()
            .iter()
            .any(|name| name.contains(needle))
    }
}

/// A registry where only `known` packages exist.
struct KnownRegistry {
    ecosystem: &'static str,
    known: Vec<&'static str>,
    queried: Recorder,
}

#[async_trait]
impl RegistryExistence for KnownRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        self.queried
            .0
            .lock()
            .unwrap()
            .push(package_name.to_string());
        Ok(self.known.contains(&package_name))
    }

    fn ecosystem(&self) -> &str {
        self.ecosystem
    }
}

#[async_trait]
impl RegistryMetadata for KnownRegistry {
    async fn metadata(
        &self,
        package_name: &str,
        _version: Option<&str>,
    ) -> Result<Option<PackageMetadata>> {
        self.queried
            .0
            .lock()
            .unwrap()
            .push(package_name.to_string());
        Ok(self.known.contains(&package_name).then(|| PackageMetadata {
            created: Some("2020-01-01T00:00:00Z".to_string()),
            latest_version_date: Some("2020-01-01T00:00:00Z".to_string()),
            downloads: Some(50000),
            ..Default::default()
        }))
    }
}

struct RecordingOsv(Recorder);

#[async_trait]
impl OsvClient for RecordingOsv {
    async fn query(
        &self,
        name: &str,
        _ecosystem: &str,
        _version: Option<&str>,
    ) -> Result<Vec<String>> {
        self.0.0.lock().unwrap().push(name.to_string());
        Ok(vec![])
    }
}

struct Outcome {
    result: Result<ScanReport>,
    queried: Recorder,
}

impl Outcome {
    fn describe(&self) -> String {
        match &self.result {
            Ok(report) => format!("{:#?}", report.issues),
            Err(err) => format!("error: {err:#}"),
        }
    }

    /// The smuggled package either blocked preflight or produced a blocking
    /// finding: it can never pass silently.
    fn assert_ghost_blocks(&self) {
        match &self.result {
            Err(err) => eprintln!("blocked in preflight: {err:#}"),
            Ok(report) => {
                assert!(
                    report.has_errors(),
                    "lockfile-only package must block: {}",
                    self.describe()
                );
                assert!(
                    report
                        .issues
                        .iter()
                        .any(|issue| issue.severity == Severity::Error
                            && (issue.package.contains(GHOST) || issue.message.contains(GHOST))),
                    "a blocking finding must name the lockfile-only package: {}",
                    self.describe()
                );
            }
        }
    }

    /// The smuggled package was reported to the scanner pipeline (queried).
    fn assert_ghost_scanned(&self) {
        self.assert_ghost_blocks();
        if self.result.is_ok() {
            assert!(
                self.queried.saw(GHOST),
                "lockfile-only package must be scanned: {}",
                self.describe()
            );
        }
    }

    fn assert_passes(&self) {
        match &self.result {
            Ok(report) => assert!(!report.has_errors(), "{}", self.describe()),
            Err(err) => panic!("empty project must pass: {err:#}"),
        }
    }
}

async fn scan_dir(
    dir: &std::path::Path,
    project_type: &str,
    ecosystem: &'static str,
    known: Vec<&'static str>,
) -> Outcome {
    let queried = Recorder::default();
    let registry = KnownRegistry {
        ecosystem,
        known,
        queried: queried.clone(),
    };
    let osv = RecordingOsv(queried.clone());
    let opts = ScanOptions {
        scan_mode: ScanMode::Ci,
        no_cache: true,
        disable_osv_disk_cache: true,
        ..Default::default()
    };
    let config = config::SloppyJoeConfig::default();
    let result = async {
        let specs = detected_project_inputs_with_config(dir, Some(project_type), &config)?;
        let mut issues = preflight_project_inputs_with_options(dir, &specs, &config, &opts)?;
        let projects = parse_project_inputs_with_options(dir, &specs, &config, &opts)?;
        for project in &projects {
            let report =
                scan_parsed_project(project, config.clone(), &registry, &osv, &opts).await?;
            issues.extend(report.issues);
        }
        Ok(ScanReport::from_issues(0, issues))
    }
    .await;
    Outcome { result, queried }
}

// ---------------------------------------------------------------- npm family

#[tokio::test]
async fn npm_empty_manifest_scans_package_lock_entries() {
    let dir = unique_dir();
    write(&dir, "package.json", r#"{"name":"app","version":"1.0.0"}"#);
    write(
        &dir,
        "package-lock.json",
        r#"{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{
  "":{"name":"app","version":"1.0.0"},
  "node_modules/zzghost":{"version":"9.0.0","resolved":"https://registry.npmjs.org/zzghost/-/zzghost-9.0.0.tgz","integrity":"sha512-abc"}
}}"#,
    );
    scan_dir(&dir, "npm", "npm", vec![])
        .await
        .assert_ghost_scanned();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn pnpm_empty_manifest_does_not_hide_lockfile_packages() {
    let dir = unique_dir();
    write(
        &dir,
        "package.json",
        r#"{"name":"app","version":"1.0.0","packageManager":"pnpm@9.0.0"}"#,
    );
    write(
        &dir,
        "pnpm-lock.yaml",
        "lockfileVersion: '9.0'\nimporters:\n  .: {}\npackages:\n  zzghost@9.0.0:\n    resolution: {integrity: sha512-x}\nsnapshots:\n  zzghost@9.0.0: {}\n",
    );
    let outcome = scan_dir(&dir, "npm", "npm", vec![]).await;
    // A standalone importer whose graph resolves completely: the entry is
    // stale (pnpm never installs it) and is flagged rather than scanned.
    let report = outcome
        .result
        .as_ref()
        .unwrap_or_else(|err| panic!("{err:#}"));
    assert!(!report.has_errors(), "{}", outcome.describe());
    let orphan = report
        .issues
        .iter()
        .find(|issue| issue.check == "lockfile/orphan-entries")
        .unwrap_or_else(|| panic!("{}", outcome.describe()));
    assert!(
        orphan.message.contains("zzghost@9.0.0"),
        "{}",
        orphan.message
    );
    assert!(!outcome.queried.saw(GHOST));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn yarn_standalone_empty_manifest_flags_lockfile_entries_as_stale() {
    let dir = unique_dir();
    write(
        &dir,
        "package.json",
        r#"{"name":"app","version":"1.0.0","packageManager":"yarn@1.22.22"}"#,
    );
    write(
        &dir,
        "yarn.lock",
        "# yarn lockfile v1\n\n\nzzghost@^9.0.0:\n  version \"9.0.0\"\n  resolved \"https://registry.yarnpkg.com/zzghost/-/zzghost-9.0.0.tgz#a\"\n  integrity sha512-a\n",
    );
    let outcome = scan_dir(&dir, "npm", "npm", vec![]).await;
    let report = outcome
        .result
        .as_ref()
        .unwrap_or_else(|err| panic!("{err:#}"));
    assert!(!report.has_errors(), "{}", outcome.describe());
    let orphan = report
        .issues
        .iter()
        .find(|issue| issue.check == "lockfile/orphan-entries")
        .unwrap_or_else(|| panic!("{}", outcome.describe()));
    assert_eq!(orphan.severity, Severity::Warning);
    assert!(
        orphan.message.contains("zzghost@9.0.0"),
        "{}",
        orphan.message
    );
    assert!(!outcome.queried.saw(GHOST), "stale entries are not queried");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn yarn_workspace_root_with_no_dependencies_scans_lockfile_entries() {
    let dir = unique_dir();
    write(
        &dir,
        "package.json",
        r#"{"name":"app","version":"1.0.0","private":true,"packageManager":"yarn@1.22.22","workspaces":["packages/*"]}"#,
    );
    write(
        &dir,
        "packages/lib/package.json",
        r#"{"name":"lib","version":"1.0.0"}"#,
    );
    write(
        &dir,
        "yarn.lock",
        "# yarn lockfile v1\n\n\nzzghost@^9.0.0:\n  version \"9.0.0\"\n  resolved \"https://registry.yarnpkg.com/zzghost/-/zzghost-9.0.0.tgz#a\"\n  integrity sha512-a\n",
    );
    scan_dir(&dir, "npm", "npm", vec![])
        .await
        .assert_ghost_scanned();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn bun_empty_manifest_scans_lockfile_packages() {
    let dir = unique_dir();
    write(
        &dir,
        "package.json",
        r#"{"name":"app","version":"1.0.0","packageManager":"bun@1.3.9"}"#,
    );
    write(
        &dir,
        "bun.lock",
        r#"{"lockfileVersion":1,"workspaces":{"":{"name":"app"}},"packages":{"zzghost":["zzghost@9.0.0","",{},"sha512-x"]}}"#,
    );
    scan_dir(&dir, "npm", "npm", vec![])
        .await
        .assert_ghost_scanned();
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------ other ecosystems

#[tokio::test]
async fn cargo_empty_manifest_scans_cargo_lock_packages() {
    let dir = unique_dir();
    write(
        &dir,
        "Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write(
        &dir,
        "Cargo.lock",
        "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"zzghost\"\nversion = \"9.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"1111111111111111111111111111111111111111111111111111111111111111\"\n",
    );
    scan_dir(&dir, "cargo", "cargo", vec![])
        .await
        .assert_ghost_scanned();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn ruby_empty_gemfile_scans_gemfile_lock_specs() {
    let dir = unique_dir();
    write(&dir, "Gemfile", "source \"https://rubygems.org\"\n");
    write(
        &dir,
        "Gemfile.lock",
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    zzghost (9.0.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n\nBUNDLED WITH\n   2.5.0\n",
    );
    scan_dir(&dir, "ruby", "rubygems", vec![])
        .await
        .assert_ghost_scanned();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn php_empty_composer_json_scans_composer_lock_packages() {
    let dir = unique_dir();
    write(
        &dir,
        "composer.json",
        r#"{"name":"fixture/app","require":{}}"#,
    );
    write(
        &dir,
        "composer.lock",
        r#"{"_readme":["fixture"],"content-hash":"x","packages":[{"name":"zzghost/zzghost","version":"9.0.0"}],"packages-dev":[]}"#,
    );
    scan_dir(&dir, "php", "packagist", vec![])
        .await
        .assert_ghost_scanned();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn poetry_empty_dependencies_scans_poetry_lock_packages() {
    let dir = unique_dir();
    let pyproject = "[tool.poetry]\nname = \"app\"\nversion = \"0.1.0\"\ndescription = \"\"\nauthors = [\"A <a@example.com>\"]\n\n[tool.poetry.dependencies]\npython = \"^3.11\"\n";
    write(&dir, "pyproject.toml", pyproject);
    let content_hash = crate::lockfiles::python::poetry_content_hash_for_test(pyproject).unwrap();
    write(
        &dir,
        "poetry.lock",
        &format!(
            "[[package]]\nname = \"zzghost\"\nversion = \"9.0.0\"\ndescription = \"\"\noptional = false\npython-versions = \">=3.8\"\nfiles = [\n    {{ file = \"zzghost-9.0.0-py3-none-any.whl\", hash = \"sha256:5555555555555555555555555555555555555555555555555555555555555555\" }},\n]\n\n[metadata]\nlock-version = \"2.0\"\npython-versions = \"^3.11\"\ncontent-hash = \"{content_hash}\"\n"
        ),
    );
    scan_dir(&dir, "pypi", "pypi", vec![])
        .await
        .assert_ghost_scanned();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn uv_empty_dependencies_scans_uv_lock_packages() {
    let dir = unique_dir();
    write(
        &dir,
        "pyproject.toml",
        "[project]\nname = \"demo\"\nversion = \"0.1.0\"\nrequires-python = \">=3.12\"\ndependencies = []\n\n[tool.uv]\n",
    );
    write(
        &dir,
        "uv.lock",
        "version = 1\nrevision = 2\nrequires-python = \">=3.12\"\n\n[[package]]\nname = \"demo\"\nversion = \"0.1.0\"\nsource = { virtual = \".\" }\n\n[package.metadata]\nrequires-dist = []\n\n[[package]]\nname = \"zzghost\"\nversion = \"9.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\nsdist = { url = \"https://files.pythonhosted.org/packages/aa/bb/zzghost-9.0.0.tar.gz\", hash = \"sha256:1111111111111111111111111111111111111111111111111111111111111111\", size = 1 }\nwheels = [\n    { url = \"https://files.pythonhosted.org/packages/aa/bb/zzghost-9.0.0-py3-none-any.whl\", hash = \"sha256:2222222222222222222222222222222222222222222222222222222222222222\", size = 1 },\n]\n",
    );
    scan_dir(&dir, "pypi", "pypi", vec![])
        .await
        .assert_ghost_scanned();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn pipenv_empty_pipfile_scans_pipfile_lock_packages() {
    let dir = unique_dir();
    write(
        &dir,
        "Pipfile",
        "[[source]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\n\n[packages]\n",
    );
    write(
        &dir,
        "Pipfile.lock",
        r#"{"_meta":{"sources":[{"name":"pypi","url":"https://pypi.org/simple","verify_ssl":true}]},"default":{"zzghost":{"hashes":["sha256:1111111111111111111111111111111111111111111111111111111111111111"],"index":"pypi","version":"==9.0.0"}},"develop":{}}"#,
    );
    scan_dir(&dir, "pypi", "pypi", vec![])
        .await
        .assert_ghost_scanned();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn dotnet_empty_project_with_locked_packages_blocks() {
    let dir = unique_dir();
    write(
        &dir,
        "App.csproj",
        "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    <TargetFramework>net8.0</TargetFramework>\n  </PropertyGroup>\n</Project>\n",
    );
    write(
        &dir,
        "packages.lock.json",
        r#"{"version":1,"dependencies":{"net8.0":{"ZzGhost":{"type":"Transitive","resolved":"9.0.0","contentHash":"x"}}}}"#,
    );
    scan_dir(&dir, "dotnet", "nuget", vec![])
        .await
        .assert_ghost_blocks();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn gradle_empty_build_with_locked_packages_blocks() {
    let dir = unique_dir();
    write(&dir, "build.gradle", "plugins {\n    id 'java'\n}\n");
    write(
        &dir,
        "gradle.lockfile",
        "com.example:zzghost:9.0.0=runtimeClasspath\nempty=\n",
    );
    scan_dir(&dir, "jvm", "maven", vec![])
        .await
        .assert_ghost_blocks();
    let _ = std::fs::remove_dir_all(&dir);
}

// --------------------------------------------------------- truly empty passes

#[tokio::test]
async fn truly_empty_projects_with_empty_lockfiles_pass() {
    let npm = unique_dir();
    write(&npm, "package.json", r#"{"name":"app","version":"1.0.0"}"#);
    write(
        &npm,
        "package-lock.json",
        r#"{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"app","version":"1.0.0"}}}"#,
    );
    scan_dir(&npm, "npm", "npm", vec![]).await.assert_passes();

    let cargo = unique_dir();
    write(
        &cargo,
        "Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write(
        &cargo,
        "Cargo.lock",
        "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n",
    );
    scan_dir(&cargo, "cargo", "cargo", vec![])
        .await
        .assert_passes();

    let ruby = unique_dir();
    write(&ruby, "Gemfile", "source \"https://rubygems.org\"\n");
    write(
        &ruby,
        "Gemfile.lock",
        "GEM\n  remote: https://rubygems.org/\n  specs:\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n\nBUNDLED WITH\n   2.5.0\n",
    );
    scan_dir(&ruby, "ruby", "rubygems", vec![])
        .await
        .assert_passes();

    let uv = unique_dir();
    write(
        &uv,
        "pyproject.toml",
        "[project]\nname = \"demo\"\nversion = \"0.1.0\"\nrequires-python = \">=3.12\"\ndependencies = []\n\n[tool.uv]\n",
    );
    write(
        &uv,
        "uv.lock",
        "version = 1\nrevision = 2\nrequires-python = \">=3.12\"\n\n[[package]]\nname = \"demo\"\nversion = \"0.1.0\"\nsource = { virtual = \".\" }\n\n[package.metadata]\nrequires-dist = []\n",
    );
    scan_dir(&uv, "pypi", "pypi", vec![]).await.assert_passes();

    for dir in [npm, cargo, ruby, uv] {
        let _ = std::fs::remove_dir_all(dir);
    }
}

// ------------------------------------------------------------ pnpm orphans

const PNPM_WORKSPACE_LOCK: &str = "lockfileVersion: '9.0'\nimporters:\n  .: {}\n  packages/lib:\n    dependencies:\n      react:\n        specifier: 18.3.1\n        version: 18.3.1\npackages:\n  react@18.3.1:\n    resolution: {integrity: sha512-a}\n  zzghost@9.0.0:\n    resolution: {integrity: sha512-a}\nsnapshots:\n  react@18.3.1: {}\n  zzghost@9.0.0: {}\n";

fn pnpm_scan(lock: &str, importer: &str) -> (Vec<String>, Vec<Issue>) {
    let value: serde_yaml::Value = serde_yaml::from_str(lock).unwrap();
    let (deps, issues) = crate::lockfiles::pnpm::parse_for_importer_with_orphans(
        &value,
        importer,
        std::path::Path::new("pnpm-lock.yaml"),
    )
    .unwrap();
    (deps.into_iter().map(|dep| dep.name).collect(), issues)
}

#[test]
fn pnpm_workspace_root_scans_entries_no_importer_reaches() {
    let (names, issues) = pnpm_scan(PNPM_WORKSPACE_LOCK, ".");
    assert!(names.contains(&GHOST.to_string()), "{names:?}");
    assert!(issues.is_empty(), "{issues:?}");
}

#[test]
fn pnpm_workspace_member_scans_only_its_own_graph() {
    let (names, issues) = pnpm_scan(PNPM_WORKSPACE_LOCK, "packages/lib");
    assert_eq!(names, vec!["react".to_string()]);
    assert!(issues.is_empty(), "{issues:?}");
}

#[test]
fn pnpm_member_scans_orphans_when_lockfile_has_no_root_importer() {
    let lock = PNPM_WORKSPACE_LOCK.replace("  .: {}\n", "");
    let (names, _) = pnpm_scan(&lock, "packages/lib");
    assert!(names.contains(&GHOST.to_string()), "{names:?}");
}

#[test]
fn pnpm_standalone_unresolved_edge_fails_closed_by_scanning_orphans() {
    let lock = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      react:\n        specifier: 18.3.1\n        version: 18.3.1\npackages:\n  zzghost@9.0.0:\n    resolution: {integrity: sha512-a}\n";
    let (names, issues) = pnpm_scan(lock, ".");
    assert!(names.contains(&GHOST.to_string()), "{names:?}");
    assert!(issues.is_empty(), "{issues:?}");
}

#[test]
fn pnpm_standalone_orphans_are_flagged_and_real_transitives_scanned() {
    let lock = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      react:\n        specifier: 18.3.1\n        version: 18.3.1\npackages:\n  react@18.3.1:\n    resolution: {integrity: sha512-a}\n  loose-envify@1.4.0:\n    resolution: {integrity: sha512-a}\n  zzghost@9.0.0:\n    resolution: {integrity: sha512-a}\nsnapshots:\n  react@18.3.1:\n    dependencies:\n      loose-envify: 1.4.0\n  loose-envify@1.4.0: {}\n  zzghost@9.0.0: {}\n";
    let (names, issues) = pnpm_scan(lock, ".");
    assert!(names.contains(&"loose-envify".to_string()), "{names:?}");
    assert!(!names.contains(&GHOST.to_string()), "{names:?}");
    assert_eq!(issues.len(), 1, "{issues:?}");
    assert_eq!(issues[0].check, "lockfile/orphan-entries");
    assert!(issues[0].message.contains("zzghost@9.0.0"));
}
