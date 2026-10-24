use super::*;

fn project(files: &[(&str, &str)], manifest: &str, kind: ProjectInputKind) -> ProjectInputSpec {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sj-pytool-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for (name, content) in files {
        std::fs::write(dir.join(name), content).unwrap();
    }
    ProjectInputSpec {
        kind,
        manifest_path: dir.join(manifest),
        lockfile_path_override: None,
        js_binding: None,
    }
}

const PYPROJECT: &str = "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n";

#[test]
fn pdm_index_redirects_block() {
    let config = config::SloppyJoeConfig::default();
    let spec = project(
        &[
            ("pyproject.toml", PYPROJECT),
            (
                "pdm.toml",
                "[pypi]\nurl = \"https://evil.example/simple\"\n",
            ),
        ],
        "pyproject.toml",
        ProjectInputKind::PyProjectLegacy,
    );
    let err = reject_pdm_config(&spec, &config).unwrap_err().to_string();
    assert!(err.contains("pdm.toml"), "{err}");

    let source = format!(
        "{PYPROJECT}\n[[tool.pdm.source]]\nname = \"pypi\"\nurl = \"https://evil.example/simple\"\n"
    );
    let spec = project(
        &[("pyproject.toml", &source)],
        "pyproject.toml",
        ProjectInputKind::PyProjectLegacy,
    );
    assert!(reject_pdm_config(&spec, &config).is_err());

    // The default index under the reserved name, and an allowlisted private index, are fine.
    let default = format!(
        "{PYPROJECT}\n[[tool.pdm.source]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\n"
    );
    let spec = project(
        &[("pyproject.toml", &default)],
        "pyproject.toml",
        ProjectInputKind::PyProjectLegacy,
    );
    reject_pdm_config(&spec, &config).unwrap();
}

#[test]
fn hatch_toml_environment_dependencies_block() {
    let spec = project(
        &[
            ("pyproject.toml", PYPROJECT),
            (
                "hatch.toml",
                "[envs.default]\ndependencies = [\"evil-pkg\"]\n",
            ),
        ],
        "pyproject.toml",
        ProjectInputKind::PyProjectLegacy,
    );
    assert!(reject_hatch_toml(spec.project_dir()).is_err());
    let spec = project(
        &[
            ("pyproject.toml", PYPROJECT),
            ("hatch.toml", "[version]\npath = \"x.py\"\n"),
        ],
        "pyproject.toml",
        ProjectInputKind::PyProjectLegacy,
    );
    reject_hatch_toml(spec.project_dir()).unwrap();
}

#[test]
fn unscanned_install_files_warn_and_block_in_ci() {
    let spec = project(
        &[
            ("pyproject.toml", PYPROJECT),
            (
                "environment.yml",
                "dependencies:\n  - pip:\n    - evil-pkg\n",
            ),
            ("tox.ini", "[testenv]\ndeps =\n    evil-pkg\n"),
        ],
        "pyproject.toml",
        ProjectInputKind::PyProjectLegacy,
    );
    let warn = unscanned_tool_files(&spec, false).unwrap();
    assert_eq!(warn.len(), 2);
    assert!(warn.iter().all(|issue| issue.severity == Severity::Warning));
    let ci = unscanned_tool_files(&spec, true).unwrap();
    assert!(ci.iter().all(|issue| issue.severity == Severity::Error));

    // A tox.ini without installed dependencies is just tool configuration.
    let spec = project(
        &[
            ("pyproject.toml", PYPROJECT),
            ("tox.ini", "[flake8]\nmax-line-length = 100\n"),
        ],
        "pyproject.toml",
        ProjectInputKind::PyProjectLegacy,
    );
    assert!(unscanned_tool_files(&spec, true).unwrap().is_empty());
}

#[test]
fn legacy_manifests_beside_a_trusted_project_block_in_ci() {
    let spec = project(
        &[
            (
                "pyproject.toml",
                "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n",
            ),
            ("requirements.txt", "evil-pkg==1.0\n"),
            ("setup.cfg", "[options]\nsetup_requires = evil-build\n"),
        ],
        "pyproject.toml",
        ProjectInputKind::PyProjectPoetry,
    );
    let warn = trusted_python_preference_warnings(&spec, false).unwrap();
    assert_eq!(warn.len(), 2);
    assert!(warn.iter().all(|issue| issue.severity == Severity::Warning));
    let ci = trusted_python_preference_warnings(&spec, true).unwrap();
    assert!(ci.iter().all(|issue| issue.severity == Severity::Error));
}
