//! Environment markers choose versions for the target; they never hide a package from source
//! policy or from the scan. A dependency gated on another platform is installed somewhere.
use super::*;

const PYPI_FILES: &str = "https://files.pythonhosted.org/packages/aa";

fn linux_target<'a>() -> ScanOptions<'a> {
    ScanOptions {
        python_platform: Some("linux".to_string()),
        python_arch: Some("x86_64".to_string()),
        python_version: Some("3.12".to_string()),
        ..Default::default()
    }
}

fn uv_artifacts(name: &str, host: &str) -> String {
    format!(
        "sdist = {{ url = \"{host}/{name}-1.tar.gz\", hash = \"sha256:{hash}\" }}\n",
        hash = "a".repeat(64)
    )
}

/// `click` depends on `colorama` only on Windows; `colorama` comes from `colorama_registry`.
fn write_uv_click_project(dir: &std::path::Path, root_deps: &str, colorama_registry: &str) {
    let colorama_host = if colorama_registry == "https://pypi.org/simple" {
        PYPI_FILES.to_string()
    } else {
        colorama_registry.trim_end_matches("/simple").to_string()
    };
    std::fs::write(
        dir.join("pyproject.toml"),
        format!(
            "[project]\nname = \"demo\"\nversion = \"0.1.0\"\nrequires-python = \">=3.10\"\ndependencies = [{root_deps}]\n\n[tool.uv]\npackage = false\n"
        ),
    )
    .unwrap();
    let colorama_root = root_deps.contains("colorama");
    let (root_dependency, root_requires) = if colorama_root {
        (
            "    { name = \"colorama\", marker = \"sys_platform == 'win32'\" },\n",
            ", { name = \"colorama\", marker = \"sys_platform == 'win32'\", specifier = \"==0.4.6\" }",
        )
    } else {
        ("", "")
    };
    std::fs::write(
        dir.join("uv.lock"),
        format!(
            r#"version = 1
revision = 3
requires-python = ">=3.10"

[[package]]
name = "click"
version = "8.1.7"
source = {{ registry = "https://pypi.org/simple" }}
dependencies = [
    {{ name = "colorama", marker = "sys_platform == 'win32'" }},
]
{click_artifacts}
[[package]]
name = "colorama"
version = "0.4.6"
source = {{ registry = "{colorama_registry}" }}
{colorama_artifacts}
[[package]]
name = "demo"
version = "0.1.0"
source = {{ virtual = "." }}
dependencies = [
    {{ name = "click" }},
{root_dependency}]

[package.metadata]
requires-dist = [{{ name = "click", specifier = "==8.1.7" }}{root_requires}]
"#,
            click_artifacts = uv_artifacts("click", PYPI_FILES),
            colorama_artifacts = uv_artifacts("colorama", &colorama_host),
        ),
    )
    .unwrap();
}

const POETRY_SIX_PYPROJECT: &str = r#"[tool.poetry]
name = "demo"
version = "0.1.0"
description = ""
authors = ["x <x@example.com>"]
package-mode = false

[tool.poetry.dependencies]
python = "^3.10"
six = "1.17.0"
"#;

/// `six` depends on `urllib3` only on Windows; `urllib3_source` is its `[package.source]`.
fn write_poetry_six_project(dir: &std::path::Path, urllib3_source: &str) {
    let hash = "b".repeat(64);
    write_poetry_project(
        dir,
        POETRY_SIX_PYPROJECT,
        &format!(
            r#"[[package]]
name = "six"
version = "1.17.0"
description = ""
optional = false
python-versions = ">=2.7"
groups = ["main"]
files = [{{file = "six-1.17.0-py2.py3-none-any.whl", hash = "sha256:{hash}"}}]

[package.dependencies]
urllib3 = {{version = "1.26.4", markers = "sys_platform == \"win32\""}}

[[package]]
name = "urllib3"
version = "1.26.4"
description = ""
optional = false
python-versions = ">=2.7"
groups = ["main"]
files = [{{file = "urllib3-1.26.4-py2.py3-none-any.whl", hash = "sha256:{hash}"}}]
{urllib3_source}
[metadata]
lock-version = "2.1"
python-versions = "^3.10"
content-hash = "__CONTENT_HASH__"
"#
        ),
    );
}

fn locked_scan_names(dir: &std::path::Path, opts: &ScanOptions<'_>) -> Vec<String> {
    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(dir, Some("pypi"), &config).unwrap();
    preflight_project_inputs_with_options(dir, &specs, &config, opts).unwrap();
    let mut names = Vec::new();
    for project in parse_project_inputs_with_options(dir, &specs, &config, opts).unwrap() {
        names.extend(project.deps.iter().map(|dep| dep.name.clone()));
        let data = ecosystems::lockfile_data(&config, opts, &project, &project.deps).unwrap();
        names.extend(data.transitive_deps.iter().map(|dep| dep.name.clone()));
    }
    names
}

fn preflight_error(dir: &std::path::Path, opts: &ScanOptions<'_>) -> String {
    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(dir, Some("pypi"), &config).unwrap();
    preflight_project_inputs_with_options(dir, &specs, &config, opts)
        .expect_err("the marker-gated package must still face source policy")
        .to_string()
}

#[test]
fn a_uv_package_behind_a_false_marker_still_faces_source_policy() {
    let dir = unique_dir();
    write_uv_click_project(&dir, "\"click==8.1.7\"", "https://evil.example.com/simple");
    let err = preflight_error(&dir, &linux_target());
    assert!(err.contains("colorama"), "{err}");
    assert!(err.contains("evil.example.com"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_uv_package_behind_a_false_marker_is_still_scanned() {
    let dir = unique_dir();
    write_uv_click_project(&dir, "\"click==8.1.7\"", "https://pypi.org/simple");
    let names = locked_scan_names(&dir, &linux_target());
    assert!(names.iter().any(|name| name == "colorama"), "{names:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_uv_direct_dependency_behind_a_false_marker_is_still_scanned() {
    let dir = unique_dir();
    write_uv_click_project(
        &dir,
        "\"click==8.1.7\", \"colorama==0.4.6; sys_platform == 'win32'\"",
        "https://pypi.org/simple",
    );
    let names = locked_scan_names(&dir, &linux_target());
    assert!(names.iter().any(|name| name == "colorama"), "{names:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_poetry_package_behind_a_false_marker_still_faces_source_policy() {
    let dir = unique_dir();
    write_poetry_six_project(
        &dir,
        "\n[package.source]\ntype = \"legacy\"\nurl = \"https://evil.example.com/simple\"\nreference = \"evil\"\n",
    );
    let err = preflight_error(&dir, &linux_target());
    assert!(err.contains("urllib3"), "{err}");
    assert!(err.contains("evil.example.com"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_poetry_package_behind_a_false_marker_is_still_scanned() {
    let dir = unique_dir();
    write_poetry_six_project(&dir, "");
    let names = locked_scan_names(&dir, &linux_target());
    assert!(names.iter().any(|name| name == "urllib3"), "{names:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_requirements_dependency_behind_a_false_marker_is_still_scanned() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("requirements.txt"),
        "six==1.17.0\nevil-win==1.0.0; sys_platform == \"win32\"\n",
    )
    .unwrap();
    let names = locked_scan_names(&dir, &linux_target());
    assert!(names.iter().any(|name| name == "evil-win"), "{names:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
