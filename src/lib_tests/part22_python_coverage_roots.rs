//! A manifest dependency whose marker is false for the scan target is still a declared,
//! installable dependency: it must be locked (as `uv lock --check` and Poetry require) and it
//! gets every direct-dependency check.
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

fn sdist(name: &str) -> String {
    format!(
        "sdist = {{ url = \"{PYPI_FILES}/{name}-1.tar.gz\", hash = \"sha256:{hash}\" }}\n",
        hash = "a".repeat(64)
    )
}

/// A uv project depending on `six` everywhere and on `extra_dep` (a full PEP 508 string) only
/// where its marker holds. `lock_root` is appended to the root's `dependencies`,
/// `lock_requires` to its `requires-dist`, and `lock_packages` to the lock.
fn write_uv_project(
    dir: &std::path::Path,
    extra_dep: &str,
    lock_root: &str,
    lock_requires: &str,
    lock_packages: &str,
) {
    std::fs::write(
        dir.join("pyproject.toml"),
        format!(
            "[project]\nname = \"demo\"\nversion = \"0.1.0\"\nrequires-python = \">=3.10\"\ndependencies = [\"six==1.17.0\", \"{extra_dep}\"]\n\n[tool.uv]\npackage = false\n"
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("uv.lock"),
        format!(
            "version = 1\nrevision = 3\nrequires-python = \">=3.10\"\n\n[[package]]\nname = \"demo\"\nversion = \"0.1.0\"\nsource = {{ virtual = \".\" }}\ndependencies = [\n    {{ name = \"six\" }},\n{lock_root}]\n\n[package.metadata]\nrequires-dist = [{{ name = \"six\", specifier = \"==1.17.0\" }}{lock_requires}]\n\n[[package]]\nname = \"six\"\nversion = \"1.17.0\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\n{six}{lock_packages}",
            six = sdist("six"),
        ),
    )
    .unwrap();
}

fn locked_package(name: &str, version: &str) -> String {
    format!(
        "\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\n{}",
        sdist(name)
    )
}

const WIN_MARKER: &str = "sys_platform == 'win32'";

fn preflight(dir: &std::path::Path, opts: &ScanOptions<'_>) -> Result<Vec<Issue>> {
    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(dir, Some("pypi"), &config).unwrap();
    preflight_project_inputs_with_options(dir, &specs, &config, opts)
}

fn assert_blocks(dir: &std::path::Path, needle: &str, what: &str) {
    for opts in [linux_target(), ScanOptions::default()] {
        let err = preflight(dir, &opts).expect_err(what).to_string();
        assert!(err.contains(needle), "{err}");
    }
}

#[test]
fn a_uv_dependency_behind_a_false_marker_missing_from_the_lock_blocks() {
    let dir = unique_dir();
    write_uv_project(
        &dir,
        &format!("zzz-not-a-real-pkg==1.0.0; {WIN_MARKER}"),
        "",
        "",
        "",
    );
    assert_blocks(
        &dir,
        "zzz-not-a-real-pkg",
        "uv lock --check rejects a declared dependency the lock does not record",
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_uv_dependency_behind_a_false_marker_without_a_locked_package_blocks() {
    let dir = unique_dir();
    write_uv_project(
        &dir,
        &format!("zzz-not-a-real-pkg==1.0.0; {WIN_MARKER}"),
        &format!("    {{ name = \"zzz-not-a-real-pkg\", marker = \"{WIN_MARKER}\" }},\n"),
        &format!(
            ", {{ name = \"zzz-not-a-real-pkg\", marker = \"{WIN_MARKER}\", specifier = \"==1.0.0\" }}"
        ),
        "",
    );
    assert_blocks(
        &dir,
        "zzz-not-a-real-pkg",
        "the lock has no package to install",
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_uv_dependency_behind_a_false_marker_out_of_sync_with_the_lock_blocks() {
    let dir = unique_dir();
    // The manifest pins 2.0.0; the lock still records (and installs) 1.0.0.
    write_uv_project(
        &dir,
        &format!("winpkg==2.0.0; {WIN_MARKER}"),
        &format!("    {{ name = \"winpkg\", marker = \"{WIN_MARKER}\" }},\n"),
        &format!(", {{ name = \"winpkg\", marker = \"{WIN_MARKER}\", specifier = \"==1.0.0\" }}"),
        &locked_package("winpkg", "1.0.0"),
    );
    assert_blocks(&dir, "winpkg", "the lock is out of sync with the manifest");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_uv_dependency_behind_a_false_marker_locked_at_another_version_blocks() {
    let dir = unique_dir();
    write_uv_project(
        &dir,
        &format!("winpkg==1.0.0; {WIN_MARKER}"),
        &format!("    {{ name = \"winpkg\", marker = \"{WIN_MARKER}\" }},\n"),
        &format!(", {{ name = \"winpkg\", marker = \"{WIN_MARKER}\", specifier = \"==1.0.0\" }}"),
        &locked_package("winpkg", "0.9.0"),
    );
    assert_blocks(&dir, "winpkg", "the locked package contradicts the pin");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_locked_uv_dependency_behind_a_false_marker_passes_preflight() {
    let dir = unique_dir();
    write_uv_project(
        &dir,
        &format!("winpkg>=1.0; {WIN_MARKER}"),
        &format!("    {{ name = \"winpkg\", marker = \"{WIN_MARKER}\" }},\n"),
        &format!(", {{ name = \"winpkg\", marker = \"{WIN_MARKER}\", specifier = \">=1.0\" }}"),
        &locked_package("winpkg", "1.2.0"),
    );
    for opts in [linux_target(), ScanOptions::default()] {
        preflight(&dir, &opts).unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_poetry_dependency_behind_a_false_marker_missing_from_the_lock_blocks() {
    let dir = unique_dir();
    let hash = "b".repeat(64);
    write_poetry_project(
        &dir,
        "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\ndescription = \"\"\nauthors = [\"x <x@example.com>\"]\npackage-mode = false\n\n[tool.poetry.dependencies]\npython = \"^3.10\"\nsix = \"1.17.0\"\nzzz-not-a-real-pkg = {version = \"1.0.0\", markers = \"sys_platform == 'win32'\"}\n",
        &format!(
            "[[package]]\nname = \"six\"\nversion = \"1.17.0\"\ndescription = \"\"\noptional = false\npython-versions = \">=2.7\"\ngroups = [\"main\"]\nfiles = [{{file = \"six-1.17.0-py2.py3-none-any.whl\", hash = \"sha256:{hash}\"}}]\n\n[metadata]\nlock-version = \"2.1\"\npython-versions = \"^3.10\"\ncontent-hash = \"__CONTENT_HASH__\"\n"
        ),
    );
    assert_blocks(
        &dir,
        "zzz-not-a-real-pkg",
        "poetry.lock has no entry for a declared dependency",
    );
    let _ = std::fs::remove_dir_all(&dir);
}
