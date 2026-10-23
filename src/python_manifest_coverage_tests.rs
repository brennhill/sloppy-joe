//! Red-team regressions for Python manifest coverage that crosses the parser/scan boundary:
//! build tooling that no lockfile records, and monorepo discovery of requirements layouts.

use super::*;
use crate::registry::{PackageMetadata, RegistryExistence, RegistryMetadata};
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir() -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-pycov-{}-{}", std::process::id(), id));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct NamedRegistry {
    existing: Vec<&'static str>,
}

#[async_trait]
impl RegistryExistence for NamedRegistry {
    async fn exists(&self, package_name: &str) -> Result<bool> {
        Ok(self.existing.contains(&package_name))
    }

    fn ecosystem(&self) -> &str {
        "pypi"
    }
}

#[async_trait]
impl RegistryMetadata for NamedRegistry {
    async fn metadata(
        &self,
        package_name: &str,
        _version: Option<&str>,
    ) -> Result<Option<PackageMetadata>> {
        if self.existing.contains(&package_name) {
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

struct NoVulnOsv;

#[async_trait]
impl OsvClient for NoVulnOsv {
    async fn query(
        &self,
        _name: &str,
        _ecosystem: &str,
        _version: Option<&str>,
    ) -> Result<Vec<String>> {
        Ok(vec![])
    }
}

fn write_poetry_project_with_build_system(dir: &std::path::Path) {
    let pyproject = r#"[build-system]
requires = ["poetry-core>=2.0", "evil-backend>=1"]
build-backend = "poetry.core.masonry.api"

[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
requests = "2.31.0"
"#;
    std::fs::write(dir.join("pyproject.toml"), pyproject).unwrap();
    let hash = crate::lockfiles::python::poetry_content_hash_for_test(pyproject).unwrap();
    std::fs::write(
        dir.join("poetry.lock"),
        format!(
            r#"[[package]]
name = "requests"
version = "2.31.0"
optional = false
python-versions = ">=3.8"
files = [{{ file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }}]

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
content-hash = "{hash}"
"#
        ),
    )
    .unwrap();
}

#[test]
fn build_system_requires_become_a_separate_unlocked_tooling_project() {
    let dir = unique_dir();
    write_poetry_project_with_build_system(&dir);
    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config).unwrap();

    // Build tooling is not in poetry.lock; preflight must not treat it as lockfile drift.
    preflight_project_inputs(&dir, &specs, &config).unwrap();

    let projects = parse_project_inputs(&dir, &specs, &config).unwrap();
    let main = projects
        .iter()
        .find(|project| !project.unlocked_tooling)
        .unwrap();
    assert!(main.deps.iter().all(|dep| dep.name != "evil-backend"));
    let tooling = projects
        .iter()
        .find(|project| project.unlocked_tooling)
        .expect("build-system requires must be scanned");
    let names: Vec<&str> = tooling.deps.iter().map(|dep| dep.name.as_str()).collect();
    assert_eq!(names, vec!["poetry-core", "evil-backend"]);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn unlocked_tooling_scan_blocks_unknown_build_backend_but_only_warns_on_ranges() {
    let dir = unique_dir();
    write_poetry_project_with_build_system(&dir);
    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config).unwrap();
    let projects = parse_project_inputs(&dir, &specs, &config).unwrap();
    let tooling = projects
        .iter()
        .find(|project| project.unlocked_tooling)
        .unwrap();

    let registry = NamedRegistry {
        existing: vec!["poetry-core", "requests"],
    };
    let report = scan_parsed_project(
        tooling,
        config.clone(),
        &registry,
        &NoVulnOsv,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.package == "evil-backend"
                && issue.severity == Severity::Error
                && issue.check.starts_with("existence")),
        "nonexistent build backends must block: {:#?}",
        report.issues
    );
    let unresolved: Vec<_> = report
        .issues
        .iter()
        .filter(|issue| issue.check == checks::names::RESOLUTION_NO_EXACT_VERSION)
        .collect();
    assert!(
        unresolved
            .iter()
            .any(|issue| issue.package == "poetry-core"),
        "skipped version checks must be reported: {:#?}",
        report.issues
    );
    assert!(
        unresolved
            .iter()
            .all(|issue| issue.severity == Severity::Warning),
        "build tooling has no lockfile, so unresolved ranges are warnings: {unresolved:#?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
