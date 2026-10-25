//! `[tool.uv] conflicts` make uv gate lock edges on encoded markers such as
//! `extra == 'extra-4-proj-b'`. They name the project's extra, not the requesting package's,
//! so they never hide a locked package from source policy or from the scan.
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

fn sdist(name: &str, host: &str) -> String {
    format!(
        "sdist = {{ url = \"{host}/{name}-1.tar.gz\", hash = \"sha256:{hash}\" }}\n",
        hash = "a".repeat(64)
    )
}

/// The shape `uv lock` (0.11) writes for conflicting extras `a` and `b`: httpx 0.23.0 reaches
/// rfc3986 only behind uv's conflict marker for `proj[b]`. rfc3986 comes from `registry`.
fn write_conflicting_extras_project(dir: &std::path::Path, registry: &str) {
    let host = if registry == "https://pypi.org/simple" {
        PYPI_FILES.to_string()
    } else {
        registry.trim_end_matches("/simple").to_string()
    };
    std::fs::write(
        dir.join("pyproject.toml"),
        r#"[project]
name = "proj"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = []

[project.optional-dependencies]
a = ["httpx==0.27.0"]
b = ["httpx==0.23.0"]

[tool.uv]
package = false
conflicts = [[{ extra = "a" }, { extra = "b" }]]
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("uv.lock"),
        format!(
            r#"version = 1
revision = 3
requires-python = ">=3.10"
conflicts = [[
    {{ package = "proj", extra = "a" }},
    {{ package = "proj", extra = "b" }},
]]

[[package]]
name = "httpx"
version = "0.23.0"
source = {{ registry = "https://pypi.org/simple" }}
dependencies = [
    {{ name = "rfc3986", marker = "extra == 'extra-4-proj-b'" }},
]
{httpx_old}
[[package]]
name = "httpx"
version = "0.27.0"
source = {{ registry = "https://pypi.org/simple" }}
{httpx_new}
[[package]]
name = "proj"
version = "0.1.0"
source = {{ virtual = "." }}

[package.optional-dependencies]
a = [
    {{ name = "httpx", version = "0.27.0", source = {{ registry = "https://pypi.org/simple" }} }},
]
b = [
    {{ name = "httpx", version = "0.23.0", source = {{ registry = "https://pypi.org/simple" }} }},
]

[package.metadata]
requires-dist = [
    {{ name = "httpx", marker = "extra == 'a'", specifier = "==0.27.0" }},
    {{ name = "httpx", marker = "extra == 'b'", specifier = "==0.23.0" }},
]
provides-extras = ["a", "b"]

[[package]]
name = "rfc3986"
version = "1.5.0"
source = {{ registry = "{registry}" }}
{rfc3986}"#,
            httpx_old = sdist("httpx-0.23.0", PYPI_FILES),
            httpx_new = sdist("httpx-0.27.0", PYPI_FILES),
            rfc3986 = sdist("rfc3986", &host),
        ),
    )
    .unwrap();
}

fn scanned_names(dir: &std::path::Path, opts: &ScanOptions<'_>) -> Vec<String> {
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

/// `--python-extras b`, for an explicit Linux target and for the host profile. With every
/// extra selected the two conflicting httpx pins cannot both hold and the scan fails closed.
fn selecting_b<'a>() -> [ScanOptions<'a>; 2] {
    [
        ScanOptions {
            python_extras: vec!["b".to_string()],
            ..linux_target()
        },
        ScanOptions {
            python_extras: vec!["b".to_string()],
            ..Default::default()
        },
    ]
}

#[test]
fn a_uv_package_behind_a_conflict_marker_faces_source_policy() {
    let dir = unique_dir();
    write_conflicting_extras_project(&dir, "https://evil.example.com/simple");
    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config).unwrap();
    for opts in selecting_b() {
        let err = preflight_project_inputs_with_options(&dir, &specs, &config, &opts)
            .expect_err("rfc3986 is installed by `uv sync --extra b` from an untrusted index")
            .to_string();
        assert!(err.contains("rfc3986"), "{err}");
        assert!(err.contains("evil.example.com"), "{err}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_uv_package_behind_a_conflict_marker_is_scanned() {
    let dir = unique_dir();
    write_conflicting_extras_project(&dir, "https://pypi.org/simple");
    for opts in selecting_b() {
        let names = scanned_names(&dir, &opts);
        assert!(names.iter().any(|name| name == "rfc3986"), "{names:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn conflicting_extras_selected_together_fail_closed() {
    let dir = unique_dir();
    write_conflicting_extras_project(&dir, "https://pypi.org/simple");
    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config).unwrap();
    for opts in [linux_target(), ScanOptions::default()] {
        let err = preflight_project_inputs_with_options(&dir, &specs, &config, &opts)
            .expect_err("both httpx pins are in scope at once")
            .to_string();
        assert!(err.contains("httpx"), "{err}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
