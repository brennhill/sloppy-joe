//! uv.lock records dependency groups under the root package's `[package.dev-dependencies]` and
//! `[package.metadata.requires-dev]`, and extras under `[package.optional-dependencies]` (root and
//! registry packages alike). These tests pin that sloppy-joe reads those sections, follows them
//! transitively, and checks them against pyproject.toml in both directions.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir() -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-uvgroups-{}-{}", std::process::id(), id));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A registry package entry as uv writes it, with `extra` appended verbatim (dependencies,
/// optional-dependencies tables, ...).
fn registry_package(name: &str, version: &str, extra: &str) -> String {
    let stem = name.replace('-', "_");
    // Inline keys come before the artifacts; sub-tables such as
    // `[package.optional-dependencies]` follow them, as in real uv output.
    let (inline, tables) = match extra.find("[package.") {
        Some(index) => extra.split_at(index),
        None => (extra, ""),
    };
    format!(
        r#"[[package]]
name = "{name}"
version = "{version}"
source = {{ registry = "https://pypi.org/simple" }}
{inline}sdist = {{ url = "https://files.pythonhosted.org/packages/aa/bb/{stem}-{version}.tar.gz", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", size = 1 }}
wheels = [
    {{ url = "https://files.pythonhosted.org/packages/aa/bb/{stem}-{version}-py3-none-any.whl", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222", size = 1 }},
]

{tables}"#
    )
}

const PYPROJECT: &str = r#"[project]
name = "demo"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = ["requests==2.32.3"]

[project.optional-dependencies]
docs = ["mkdocs==1.6.0"]

[dependency-groups]
dev = ["ruff==0.6.9", "httpx[http2]==0.27.2", { include-group = "test" }]
test = ["pytest==8.3.3"]

[tool.uv]
"#;

const ROOT_PACKAGE: &str = r#"[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
]

[package.optional-dependencies]
docs = [
    { name = "mkdocs" },
]

[package.dev-dependencies]
dev = [
    { name = "httpx", extra = ["http2"] },
    { name = "pytest" },
    { name = "ruff" },
]
test = [
    { name = "pytest" },
]

[package.metadata]
requires-dist = [
    { name = "mkdocs", marker = "extra == 'docs'", specifier = "==1.6.0" },
    { name = "requests", specifier = "==2.32.3" },
]
provides-extras = ["docs"]

[package.metadata.requires-dev]
dev = [
    { name = "httpx", extras = ["http2"], specifier = "==0.27.2" },
    { name = "pytest", specifier = "==8.3.3" },
    { name = "ruff", specifier = "==0.6.9" },
]
test = [{ name = "pytest", specifier = "==8.3.3" }]

"#;

fn lock_with_root(root: &str) -> String {
    let mut lock = String::from("version = 1\nrevision = 2\nrequires-python = \">=3.12\"\n\n");
    lock.push_str(root);
    lock.push_str(&registry_package("h2", "4.1.0", ""));
    lock.push_str(&registry_package(
        "httpx",
        "0.27.2",
        "dependencies = [\n    { name = \"idna\" },\n]\n\n[package.optional-dependencies]\nhttp2 = [\n    { name = \"h2\" },\n]\n\n",
    ));
    lock.push_str(&registry_package("idna", "3.10", ""));
    lock.push_str(&registry_package("mkdocs", "1.6.0", ""));
    lock.push_str(&registry_package("pluggy", "1.5.0", ""));
    lock.push_str(&registry_package(
        "pytest",
        "8.3.3",
        "dependencies = [\n    { name = \"pluggy\" },\n]\n",
    ));
    lock.push_str(&registry_package(
        "requests",
        "2.32.3",
        "dependencies = [\n    { name = \"idna\" },\n]\n",
    ));
    lock.push_str(&registry_package("ruff", "0.6.9", ""));
    lock
}

fn write_project(pyproject: &str, lock: &str) -> std::path::PathBuf {
    let dir = unique_dir();
    std::fs::write(dir.join("pyproject.toml"), pyproject).unwrap();
    std::fs::write(dir.join("uv.lock"), lock).unwrap();
    dir
}

fn preflight(dir: &std::path::Path, opts: &ScanOptions<'_>) -> Result<Vec<Issue>> {
    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(dir, Some("pypi"), &config).unwrap();
    assert!(
        specs
            .iter()
            .any(|spec| spec.kind == ProjectInputKind::PyProjectUv),
        "{specs:#?}"
    );
    preflight_project_inputs_with_options(dir, &specs, &config, opts)
}

fn main_project(dir: &std::path::Path, opts: &ScanOptions<'_>) -> ParsedProject {
    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(dir, Some("pypi"), &config).unwrap();
    parse_project_inputs_with_options(dir, &specs, &config, opts)
        .unwrap()
        .into_iter()
        .find(|project| !project.unlocked_tooling)
        .unwrap()
}

fn transitive_names(project: &ParsedProject, opts: &ScanOptions<'_>) -> Vec<String> {
    let config = config::SloppyJoeConfig::default();
    let data = lockfile_data_for_scan(project, &project.deps, &config, opts).unwrap();
    let mut names: Vec<String> = data
        .transitive_deps
        .iter()
        .map(|dep| dep.name.clone())
        .collect();
    names.sort();
    names
}

fn expect_block(dir: &std::path::Path, needle: &str) -> String {
    let err = preflight(dir, &ScanOptions::default())
        .expect_err("uv.lock group drift must block")
        .to_string();
    assert!(err.contains(needle), "{err}");
    err
}

#[test]
fn correctly_locked_groups_and_extras_pass_and_are_all_scanned() {
    let dir = write_project(PYPROJECT, &lock_with_root(ROOT_PACKAGE));
    preflight(&dir, &ScanOptions::default()).expect("a correctly locked uv project must pass");

    let project = main_project(&dir, &ScanOptions::default());
    let mut names: Vec<&str> = project.deps.iter().map(|dep| dep.name.as_str()).collect();
    names.sort();
    assert_eq!(names, vec!["httpx", "mkdocs", "pytest", "requests", "ruff"]);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn locked_extras_of_group_dependencies_are_followed_transitively() {
    let dir = write_project(PYPROJECT, &lock_with_root(ROOT_PACKAGE));
    let project = main_project(&dir, &ScanOptions::default());
    let names = transitive_names(&project, &ScanOptions::default());
    // h2 is only reachable through httpx's locked `http2` optional-dependencies section.
    assert!(names.contains(&"h2".to_string()), "{names:?}");
    assert!(names.contains(&"pluggy".to_string()), "{names:?}");
    assert!(names.contains(&"idna".to_string()), "{names:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn narrowed_group_selection_still_passes_and_skips_unselected_transitives() {
    let dir = write_project(PYPROJECT, &lock_with_root(ROOT_PACKAGE));
    let opts = ScanOptions {
        python_groups: vec!["test".to_string()],
        python_extras: vec!["none-selected".to_string()],
        ..Default::default()
    };
    preflight(&dir, &opts).expect("unselected locked groups are still declared in pyproject");
    let project = main_project(&dir, &opts);
    let mut names: Vec<&str> = project.deps.iter().map(|dep| dep.name.as_str()).collect();
    names.sort();
    assert_eq!(names, vec!["pytest", "requests"]);
    let transitives = transitive_names(&project, &opts);
    assert!(!transitives.contains(&"h2".to_string()), "{transitives:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn lock_only_dev_group_dependency_blocks() {
    let root = ROOT_PACKAGE
        .replace(
            "    { name = \"ruff\" },\n]",
            "    { name = \"ruff\" },\n    { name = \"evil-dev\" },\n]",
        )
        .replace(
            "    { name = \"ruff\", specifier = \"==0.6.9\" },\n]",
            "    { name = \"ruff\", specifier = \"==0.6.9\" },\n    { name = \"evil-dev\", specifier = \">=1\" },\n]",
        );
    let mut lock = lock_with_root(&root);
    lock.push_str(&registry_package("evil-dev", "1.0.0", ""));
    let dir = write_project(PYPROJECT, &lock);
    let err = expect_block(&dir, "evil-dev");
    assert!(err.contains("not declared"), "{err}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn lock_only_dev_group_resolution_without_metadata_blocks() {
    // A tampered lock that only adds the resolved entry, not the requires-dev metadata.
    let root = ROOT_PACKAGE.replace(
        "test = [\n    { name = \"pytest\" },\n]",
        "test = [\n    { name = \"pytest\" },\n    { name = \"evil-dev\" },\n]",
    );
    let mut lock = lock_with_root(&root);
    lock.push_str(&registry_package("evil-dev", "1.0.0", ""));
    let dir = write_project(PYPROJECT, &lock);
    expect_block(&dir, "evil-dev");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn lock_only_group_absent_from_manifest_blocks() {
    let root = ROOT_PACKAGE.replace(
        "test = [{ name = \"pytest\", specifier = \"==8.3.3\" }]",
        "test = [{ name = \"pytest\", specifier = \"==8.3.3\" }]\nlint = [{ name = \"evil-lint\", specifier = \"==1.0.0\" }]",
    );
    let root = root.replace(
        "test = [\n    { name = \"pytest\" },\n]",
        "test = [\n    { name = \"pytest\" },\n]\nlint = [\n    { name = \"evil-lint\" },\n]",
    );
    let mut lock = lock_with_root(&root);
    lock.push_str(&registry_package("evil-lint", "1.0.0", ""));
    let dir = write_project(PYPROJECT, &lock);
    expect_block(&dir, "evil-lint");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn lock_only_optional_dependency_blocks() {
    let root = ROOT_PACKAGE.replace(
        "docs = [\n    { name = \"mkdocs\" },\n]",
        "docs = [\n    { name = \"mkdocs\" },\n    { name = \"evil-extra\" },\n]",
    );
    let mut lock = lock_with_root(&root);
    lock.push_str(&registry_package("evil-extra", "1.0.0", ""));
    let dir = write_project(PYPROJECT, &lock);
    expect_block(&dir, "evil-extra");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn lock_only_main_dependency_blocks() {
    let root = ROOT_PACKAGE.replace(
        "dependencies = [\n    { name = \"requests\" },\n]",
        "dependencies = [\n    { name = \"requests\" },\n    { name = \"evil-main\" },\n]",
    );
    let mut lock = lock_with_root(&root);
    lock.push_str(&registry_package("evil-main", "1.0.0", ""));
    let dir = write_project(PYPROJECT, &lock);
    expect_block(&dir, "evil-main");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn extra_dependency_moved_into_main_dependencies_blocks() {
    // mkdocs is declared only under the `docs` extra; the lock installs it unconditionally.
    let root = ROOT_PACKAGE.replace(
        "dependencies = [\n    { name = \"requests\" },\n]",
        "dependencies = [\n    { name = \"requests\" },\n    { name = \"mkdocs\" },\n]",
    );
    let dir = write_project(PYPROJECT, &lock_with_root(&root));
    expect_block(&dir, "mkdocs");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn manifest_group_dependency_missing_from_lock_blocks() {
    let pyproject = PYPROJECT.replace(
        "test = [\"pytest==8.3.3\"]",
        "test = [\"pytest==8.3.3\", \"coverage==7.6.1\"]",
    );
    let dir = write_project(&pyproject, &lock_with_root(ROOT_PACKAGE));
    let err = expect_block(&dir, "coverage");
    assert!(err.contains("missing"), "{err}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn manifest_group_specifier_out_of_sync_with_lock_blocks() {
    let pyproject = PYPROJECT.replace("ruff==0.6.9", "ruff==0.7.0");
    let dir = write_project(&pyproject, &lock_with_root(ROOT_PACKAGE));
    let err = expect_block(&dir, "ruff");
    assert!(err.contains("out of sync"), "{err}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unselected_group_drift_still_blocks_when_narrowed() {
    // Narrowing must not hide a lock/manifest disagreement in a group that was left out.
    let pyproject = PYPROJECT.replace("ruff==0.6.9", "ruff==0.7.0");
    let dir = write_project(&pyproject, &lock_with_root(ROOT_PACKAGE));
    let opts = ScanOptions {
        python_groups: vec!["test".to_string()],
        ..Default::default()
    };
    let err = preflight(&dir, &opts)
        .expect_err("stale requires-dev for an unselected group must still block")
        .to_string();
    assert!(err.contains("ruff"), "{err}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn registry_package_with_dev_dependencies_blocks() {
    let mut lock = lock_with_root(ROOT_PACKAGE);
    let ruff_wheels_end = "ruff-0.6.9-py3-none-any.whl\", hash = \"sha256:2222222222222222222222222222222222222222222222222222222222222222\", size = 1 },\n]\n";
    assert!(lock.contains(ruff_wheels_end));
    lock = lock.replace(
        ruff_wheels_end,
        &format!(
            "{ruff_wheels_end}\n[package.dev-dependencies]\ndev = [{{ name = \"evil-hidden\" }}]\n"
        ),
    );
    lock.push_str(&registry_package("evil-hidden", "1.0.0", ""));
    let dir = write_project(PYPROJECT, &lock);
    expect_block(&dir, "dev-dependencies");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn red_team_uv_dev_dependencies_fixture_is_locked_and_scanned() {
    // Shape of a real `uv lock` output for `[tool.uv] dev-dependencies`.
    let pyproject = r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["requests"]

[tool.uv]
dev-dependencies = ["evil-uv-dev>=1"]
"#;
    let lock = format!(
        r#"version = 1
revision = 2
requires-python = ">=3.9"

[[package]]
name = "demo"
version = "0.1.0"
source = {{ editable = "." }}
dependencies = [
    {{ name = "requests" }},
]

[package.dev-dependencies]
dev = [
    {{ name = "evil-uv-dev" }},
]

[package.metadata]
requires-dist = [{{ name = "requests" }}]

[package.metadata.requires-dev]
dev = [{{ name = "evil-uv-dev", specifier = ">=1" }}]

{}{}"#,
        registry_package("requests", "2.32.3", ""),
        registry_package("evil-uv-dev", "1.0.0", "")
    );
    let dir = write_project(pyproject, &lock);
    preflight(&dir, &ScanOptions::default()).expect("uv dev-dependencies are locked under dev");
    let project = main_project(&dir, &ScanOptions::default());
    assert!(
        project.deps.iter().any(|dep| dep.name == "evil-uv-dev"),
        "{:?}",
        project.deps
    );
    let config = config::SloppyJoeConfig::default();
    let data =
        lockfile_data_for_scan(&project, &project.deps, &config, &ScanOptions::default()).unwrap();
    let evil = project
        .deps
        .iter()
        .find(|dep| dep.name == "evil-uv-dev")
        .unwrap();
    assert_eq!(data.resolution.exact_version(evil), Some("1.0.0"));

    let _ = std::fs::remove_dir_all(&dir);
}
