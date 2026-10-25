//! Legacy Python manifests without a lockfile: their transitive dependencies are projected from
//! PyPI metadata and scanned through the normal transitive pipeline, labeled as projected.
use super::*;
use crate::registry::pypi_release::PypiVersionListing;
use crate::registry::{PackageMetadata, RegistryExistence, RegistryMetadata};
use async_trait::async_trait;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir() -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-pyproj-{}-{}", std::process::id(), id));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// PyPI with `requests` -> `urllib3`, `ghost-helper` (which PyPI does not list).
struct FakePypi {
    calls: Mutex<Vec<String>>,
}

impl FakePypi {
    fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
        }
    }

    fn versions(name: &str) -> Option<Vec<&'static str>> {
        match name {
            "requests" => Some(vec!["2.0.0", "2.31.0"]),
            "urllib3" => Some(vec!["1.26.18", "2.2.1", "3.0.0"]),
            _ => None,
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl RegistryExistence for FakePypi {
    async fn exists(&self, name: &str) -> Result<bool> {
        Ok(Self::versions(name).is_some())
    }

    fn ecosystem(&self) -> &str {
        "pypi"
    }
}

#[async_trait]
impl RegistryMetadata for FakePypi {
    async fn metadata(&self, name: &str, _: Option<&str>) -> Result<Option<PackageMetadata>> {
        Ok(Self::versions(name).map(|_| PackageMetadata {
            created: Some("2015-01-01T00:00:00Z".to_string()),
            latest_version_date: Some("2020-01-01T00:00:00Z".to_string()),
            downloads: Some(5_000_000),
            repository_url: Some("https://example.com/repo".to_string()),
            ..Default::default()
        }))
    }

    async fn pypi_versions(&self, name: &str) -> Result<Option<Vec<PypiVersionListing>>> {
        self.calls.lock().unwrap().push(format!("versions {name}"));
        Ok(Self::versions(name).map(|versions| {
            versions
                .into_iter()
                .map(|version| PypiVersionListing {
                    version: version.to_string(),
                    yanked: false,
                })
                .collect()
        }))
    }

    async fn pypi_requires_dist(&self, name: &str, version: &str) -> Result<Option<Vec<String>>> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("requires {name} {version}"));
        Ok(match name {
            "requests" => Some(vec![
                "urllib3<3,>=1.21.1".to_string(),
                "ghost-helper>=1".to_string(),
            ]),
            _ => Self::versions(name).map(|_| Vec::new()),
        })
    }
}

/// OSV knows one advisory: urllib3 2.2.1.
struct OneAdvisory;

#[async_trait]
impl OsvClient for OneAdvisory {
    async fn query(&self, name: &str, _: &str, version: Option<&str>) -> Result<Vec<String>> {
        Ok(if name == "urllib3" && version == Some("2.2.1") {
            vec!["GHSA-test-urllib3".to_string()]
        } else {
            Vec::new()
        })
    }
}

async fn scan_requirements(
    requirements: &str,
    config: config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
    registry: &FakePypi,
) -> ScanReport {
    let dir = unique_dir();
    std::fs::write(dir.join("requirements.txt"), requirements).unwrap();
    let deps = vec![crate::test_helpers::dep_with(
        "requests",
        Some(">=2"),
        Ecosystem::PyPI,
    )];
    let report = scan_with_services_inner_for_kind(
        Some(ProjectInputKind::PyRequirements),
        &dir,
        config,
        deps,
        registry,
        &OneAdvisory,
        opts,
    )
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    report
}

fn find<'a>(report: &'a ScanReport, package: &str, check: &str) -> Option<&'a Issue> {
    report
        .issues
        .iter()
        .find(|issue| issue.package == package && issue.check == check)
}

#[tokio::test]
async fn transitive_dependencies_of_a_lockless_requirements_file_are_projected_and_scanned() {
    let registry = FakePypi::new();
    let report = scan_requirements(
        "requests>=2\n",
        config::SloppyJoeConfig::default(),
        &ScanOptions::default(),
        &registry,
    )
    .await;

    let ghost = find(&report, "ghost-helper", checks::names::EXISTENCE)
        .expect("a hallucinated transitive dependency must be checked for existence");
    assert_eq!(ghost.severity, Severity::Error);
    assert_eq!(ghost.source.as_deref(), Some("transitive"));
    assert!(
        ghost.message.contains("[projected transitive"),
        "{}",
        ghost.message
    );

    let advisory = find(
        &report,
        "urllib3",
        checks::names::MALICIOUS_KNOWN_VULNERABILITY,
    )
    .expect("the projected version gets the advisory check");
    assert_eq!(advisory.source.as_deref(), Some("transitive"));
    assert!(advisory.message.contains("projected from PyPI metadata"));

    let summary = report
        .issues
        .iter()
        .find(|issue| issue.check == checks::names::RESOLUTION_PYTHON_PROJECTED_TRANSITIVES)
        .expect("the projection is announced");
    assert_eq!(summary.severity, Severity::Warning);
    assert!(
        summary.message.contains("PROJECTED 2"),
        "{}",
        summary.message
    );
    assert!(summary.fix.contains("uv lock") && summary.fix.contains("fix-lockfile"));

    let legacy = report
        .issues
        .iter()
        .find(|issue| issue.check == checks::names::RESOLUTION_PYTHON_LEGACY_MANIFEST)
        .expect("the legacy warning stays");
    assert!(
        !legacy.message.contains("are not scanned"),
        "{}",
        legacy.message
    );
    assert!(report.packages_checked >= 3, "{}", report.packages_checked);
}

#[tokio::test]
async fn a_requirements_file_with_another_index_is_not_projected_from_pypi() {
    let registry = FakePypi::new();
    let mut config = config::SloppyJoeConfig::default();
    config.trusted_indexes.insert(
        "pypi".to_string(),
        vec![config::normalize_python_index_url(
            "https://packages.example.com/simple",
        )],
    );
    let report = scan_requirements(
        "--extra-index-url https://packages.example.com/simple\nrequests>=2\n",
        config,
        &ScanOptions::default(),
        &registry,
    )
    .await;
    assert!(registry.calls().is_empty(), "{:?}", registry.calls());
    let warning = report
        .issues
        .iter()
        .find(|issue| issue.check == checks::names::RESOLUTION_PYTHON_UNPROJECTABLE)
        .expect("unprojectable manifests say so");
    assert_eq!(warning.severity, Severity::Warning);
    assert!(warning.message.contains("packages.example.com"));
    assert!(find(&report, "ghost-helper", checks::names::EXISTENCE).is_none());
}

#[tokio::test]
async fn fast_scans_do_not_project() {
    let registry = FakePypi::new();
    let opts = ScanOptions {
        scan_mode: ScanMode::Fast,
        ..ScanOptions::default()
    };
    let report = scan_requirements(
        "requests>=2\n",
        config::SloppyJoeConfig::default(),
        &opts,
        &registry,
    )
    .await;
    assert!(registry.calls().is_empty(), "{:?}", registry.calls());
    assert!(find(&report, "ghost-helper", checks::names::EXISTENCE).is_none());
}

#[tokio::test]
async fn projected_packages_get_similarity_only_with_deep() {
    for deep in [false, true] {
        let registry = FakePypi::new();
        let opts = ScanOptions {
            deep,
            ..ScanOptions::default()
        };
        let report = scan_requirements(
            "requests>=2\n",
            config::SloppyJoeConfig::default(),
            &opts,
            &registry,
        )
        .await;
        let summary = report
            .issues
            .iter()
            .find(|issue| issue.check == checks::names::RESOLUTION_PYTHON_PROJECTED_TRANSITIVES)
            .unwrap();
        assert_eq!(summary.message.contains("because of --deep"), deep);
    }
}

#[test]
fn only_manifests_without_a_lockfile_are_projected() {
    let spec = |kind, manifest: &str, lock: Option<&str>| {
        let dir = unique_dir();
        std::fs::write(dir.join(manifest), "").unwrap();
        if let Some(lock) = lock {
            std::fs::write(dir.join(lock), "{}").unwrap();
        }
        ProjectInputSpec {
            kind,
            manifest_path: dir.join(manifest),
            lockfile_path_override: None,
            js_binding: None,
        }
    };
    let projected = |spec: &ProjectInputSpec| python_projects_transitives(spec);
    assert!(projected(&spec(
        ProjectInputKind::PyRequirements,
        "requirements.txt",
        None
    )));
    assert!(projected(&spec(
        ProjectInputKind::PySetupPy,
        "setup.py",
        None
    )));
    assert!(projected(&spec(
        ProjectInputKind::PySetupCfg,
        "setup.cfg",
        None
    )));
    assert!(projected(&spec(
        ProjectInputKind::PyProjectLegacy,
        "pyproject.toml",
        None
    )));
    assert!(projected(&spec(
        ProjectInputKind::PyPipfile,
        "Pipfile",
        None
    )));
    assert!(!projected(&spec(
        ProjectInputKind::PyPipfile,
        "Pipfile",
        Some("Pipfile.lock")
    )));
    assert!(!projected(&spec(
        ProjectInputKind::PyRequirementsTrusted,
        "requirements.txt",
        None
    )));
    assert!(!projected(&spec(
        ProjectInputKind::PyProjectPoetry,
        "pyproject.toml",
        Some("poetry.lock")
    )));
    assert!(!projected(&spec(
        ProjectInputKind::PyProjectUv,
        "pyproject.toml",
        Some("uv.lock")
    )));
}
