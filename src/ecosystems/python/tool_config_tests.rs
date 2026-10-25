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
fn other_tox_configuration_files_are_flagged_like_tox_ini() {
    for (file, content) in [
        ("tox.toml", "[env.py]\ndeps = [\"evil\"]\n"),
        (
            "setup.cfg",
            "[tox:tox]\nenvlist = py\n[testenv]\ndeps =\n    evil\n",
        ),
        (
            "pyproject.toml",
            "[project]\nname = \"d\"\nversion = \"1\"\n[tool.tox]\nrequires = [\"tox-evil\"]\n",
        ),
    ] {
        let spec = project(
            &[(file, content)],
            "pyproject.toml",
            ProjectInputKind::PyProjectLegacy,
        );
        let issues = unscanned_tool_files(&spec, true).unwrap();
        assert_eq!(issues.len(), 1, "{file}");
    }
    // A setup.cfg without tox sections is not a tox file.
    let spec = project(
        &[("setup.cfg", "[metadata]\nname = demo\n")],
        "pyproject.toml",
        ProjectInputKind::PyProjectLegacy,
    );
    assert!(unscanned_tool_files(&spec, true).unwrap().is_empty());
}

#[test]
fn tox_dependency_declarations_cannot_hide() {
    for (file, content) in [
        ("tox.toml", "env_run_base = { deps = [\"evil\"] }\n"),
        ("tox.toml", "env_run_base.deps = [\"evil\"]\n"),
        ("tox.toml", "[env_run_base]\n\"deps\" = [\"evil\"]\n"),
        (
            "pyproject.toml",
            "[project]\nname = \"d\"\nversion = \"1\"\n[tool.tox]\nenv_run_base = { deps = [\"evil\"] }\n",
        ),
        (
            "pyproject.toml",
            "[project]\nname = \"d\"\nversion = \"1\"\n[tool.tox]\nlegacy_tox_ini = \"\"\"\n[testenv]\ndeps = evil\n\"\"\"\n",
        ),
    ] {
        let spec = project(
            &[(file, content)],
            "pyproject.toml",
            ProjectInputKind::PyProjectLegacy,
        );
        let issues = unscanned_tool_files(&spec, true).unwrap();
        assert_eq!(issues.len(), 1, "{file}: {content}");
    }
    // A lone carriage return hides `deps` from a line scanner but not from configparser.
    let spec = project(
        &[("tox.ini", "[testenv]\r deps = evil\n")],
        "pyproject.toml",
        ProjectInputKind::PyProjectLegacy,
    );
    assert!(unscanned_tool_files(&spec, true).is_err());
    // A tox.toml without dependencies stays quiet.
    let spec = project(
        &[("tox.toml", "env_list = [\"py\"]\n")],
        "pyproject.toml",
        ProjectInputKind::PyProjectLegacy,
    );
    assert!(unscanned_tool_files(&spec, true).unwrap().is_empty());
}
