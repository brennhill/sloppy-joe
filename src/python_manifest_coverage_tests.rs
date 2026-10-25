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

#[test]
fn monorepo_walk_discovers_requirements_directory_layouts() {
    let dir = unique_dir();
    let reqs = dir.join("py").join("requirements");
    std::fs::create_dir_all(&reqs).unwrap();
    std::fs::write(reqs.join("base.txt"), "evil-reqdir==1\n").unwrap();
    std::fs::write(reqs.join("prod.txt"), "-r base.txt\n").unwrap();
    std::fs::write(reqs.join("lint.txt"), "evil-lint==1\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, None, &config).unwrap();
    let manifests: Vec<_> = specs
        .iter()
        .filter(|spec| spec.kind == ProjectInputKind::PyRequirements)
        .map(|spec| spec.manifest_path.file_name().unwrap().to_owned())
        .collect();
    assert!(manifests.contains(&"prod.txt".into()), "{manifests:?}");
    assert!(manifests.contains(&"lint.txt".into()), "{manifests:?}");

    let projects = parse_project_inputs(&dir, &specs, &config).unwrap();
    let names: Vec<&str> = projects
        .iter()
        .flat_map(|project| project.deps.iter().map(|dep| dep.name.as_str()))
        .collect();
    assert!(names.contains(&"evil-reqdir"), "{names:?}");
    assert!(names.contains(&"evil-lint"), "{names:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn monorepo_walk_discovers_suffix_named_requirements_files() {
    let dir = unique_dir();
    std::fs::write(dir.join("dev-requirements.txt"), "evil-dev==1\n").unwrap();
    std::fs::write(dir.join("test_requirements.txt"), "evil-test==1\n").unwrap();
    std::fs::write(dir.join("notes.txt"), "not a manifest\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, None, &config).unwrap();
    let manifests: Vec<_> = specs
        .iter()
        .map(|spec| spec.manifest_path.file_name().unwrap().to_owned())
        .collect();
    assert!(
        manifests.contains(&"dev-requirements.txt".into()),
        "{manifests:?}"
    );
    assert!(
        manifests.contains(&"test_requirements.txt".into()),
        "{manifests:?}"
    );
    assert!(!manifests.contains(&"notes.txt".into()), "{manifests:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn requirements_beside_a_poetry_project_are_scanned_not_ignored() {
    let dir = unique_dir();
    write_poetry_project_with_build_system(&dir);
    std::fs::write(dir.join("requirements.txt"), "evil-sibling==1.0\n").unwrap();
    std::fs::create_dir_all(dir.join("requirements")).unwrap();
    std::fs::write(
        dir.join("requirements").join("export.txt"),
        "evil-export==1.0\n",
    )
    .unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config).unwrap();
    assert!(
        specs
            .iter()
            .any(|spec| spec.kind == ProjectInputKind::PyProjectPoetry),
        "{specs:#?}"
    );
    preflight_project_inputs(&dir, &specs, &config).unwrap();
    let names = scanned_dependency_names(&dir);
    for expected in ["requests", "evil-sibling", "evil-export"] {
        assert!(
            names.iter().any(|name| name == expected),
            "{expected} missing from {names:?}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn requirements_beside_a_uv_project_are_scanned_not_ignored() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        "[project]\nname = \"demo\"\nversion = \"0.1.0\"\nrequires-python = \">=3.10\"\ndependencies = []\n\n[tool.uv]\npackage = false\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("uv.lock"),
        "version = 1\nrevision = 3\nrequires-python = \">=3.10\"\n\n[[package]]\nname = \"demo\"\nversion = \"0.1.0\"\nsource = { virtual = \".\" }\n\n[package.metadata]\nrequires-dist = []\n",
    )
    .unwrap();
    std::fs::write(dir.join("requirements-dev.txt"), "evil-dev==1.0\n").unwrap();

    let names = scanned_dependency_names(&dir);
    assert!(names.iter().any(|name| name == "evil-dev"), "{names:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

const SIX_HASH_LOCKED: &str = "six==1.17.0 --hash=sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274 --hash=sha256:ff70335d468e7eb6ec65b95b99d3a2836546063f63acc5171de367e834932a81\n";

fn scanned_dependency_names(dir: &std::path::Path) -> Vec<String> {
    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(dir, Some("pypi"), &config).unwrap();
    parse_project_inputs(dir, &specs, &config)
        .unwrap()
        .iter()
        .flat_map(|project| project.deps.iter().map(|dep| dep.name.clone()))
        .collect()
}

#[test]
fn a_hash_locked_requirements_file_does_not_hide_sibling_manifests() {
    let dir = unique_dir();
    std::fs::write(dir.join("requirements.txt"), SIX_HASH_LOCKED).unwrap();
    std::fs::write(dir.join("requirements-dev.txt"), "evil-dev==1.0\n").unwrap();
    std::fs::write(
        dir.join("setup.cfg"),
        "[metadata]\nname = demo\n\n[options]\ninstall_requires =\n    evil-cfg==1.0\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("setup.py"),
        "from setuptools import setup\nsetup(name=\"demo\", install_requires=[\"evil-py==1.0\"])\n",
    )
    .unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config).unwrap();
    assert!(
        specs
            .iter()
            .any(|spec| spec.kind == ProjectInputKind::PyRequirementsTrusted),
        "{specs:#?}"
    );
    let names = scanned_dependency_names(&dir);
    for expected in ["six", "evil-dev", "evil-cfg", "evil-py"] {
        assert!(
            names.iter().any(|name| name == expected),
            "{expected} missing from {names:?}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
