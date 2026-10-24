use super::*;

fn project(files: &[(&str, &str)], manifest: &str) -> ProjectInputSpec {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sj-pyinterp-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for (name, content) in files {
        std::fs::write(dir.join(name), content).unwrap();
    }
    ProjectInputSpec {
        kind: ProjectInputKind::PyProjectUv,
        manifest_path: dir.join(manifest),
        lockfile_path_override: None,
        js_binding: None,
    }
}

const PYPROJECT: &str = "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n";

#[test]
fn python_version_naming_a_path_blocks() {
    for content in [
        "./tools/python3\n",
        "/tmp/py\n",
        "..\\py.exe\n",
        "3.12\n./x\n",
    ] {
        let spec = project(
            &[("pyproject.toml", PYPROJECT), (".python-version", content)],
            "pyproject.toml",
        );
        assert!(
            check_interpreter_config(&spec, true).is_err(),
            "{content:?}"
        );
    }
    for content in [
        "3.12\n",
        "cpython-3.12\n",
        ">=3.11\n",
        "# note\n3.12.1\n",
        "pypy3.10\n",
    ] {
        let spec = project(
            &[("pyproject.toml", PYPROJECT), (".python-version", content)],
            "pyproject.toml",
        );
        assert!(check_interpreter_config(&spec, true).is_ok(), "{content:?}");
    }
}

#[test]
fn poetry_toml_is_allowlisted() {
    for content in [
        "cache-dir = \".pcache\"\n",
        "[virtualenvs]\npath = \"./envs\"\n",
        "[repositories.evil]\nurl = \"https://evil.example/simple\"\n",
        "[certificates.evil]\ncert = \"x\"\n",
        "[installer]\nunknown = true\n",
        "[http-basic.pypi]\nusername = \"a\"\n",
    ] {
        let spec = project(
            &[("pyproject.toml", PYPROJECT), ("poetry.toml", content)],
            "pyproject.toml",
        );
        let err = check_interpreter_config(&spec, true)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Unsupported Poetry setting"),
            "{content}: {err}"
        );
    }
    let spec = project(
        &[
            ("pyproject.toml", PYPROJECT),
            (
                "poetry.toml",
                "[virtualenvs]\nin-project = true\ncreate = true\n[installer]\nparallel = false\n",
            ),
        ],
        "pyproject.toml",
    );
    assert!(check_interpreter_config(&spec, true).unwrap().is_empty());
}

#[test]
fn pipenv_dotenv_variables_that_steer_the_install_block() {
    for content in [
        "PYTHONPATH=./tools\n",
        "export PIP_INDEX_URL=https://evil.example/simple\n",
        "PIPENV_PYPI_MIRROR=https://evil.example\n",
        "UV_INDEX_URL=x\n",
        "DYLD_INSERT_LIBRARIES=x\n",
        "not a pair\n",
        "OK=1\rPYTHONPATH=x\n",
        "path=/evil\n",
    ] {
        let spec = project(&[("Pipfile", ""), (".env", content)], "Pipfile");
        assert!(
            check_interpreter_config(&spec, true).is_err(),
            "{content:?}"
        );
    }
    let spec = project(
        &[
            ("Pipfile", ""),
            (".env", "# c\nDEBUG=1\nexport NAME=\"x\"\n"),
        ],
        "Pipfile",
    );
    assert!(check_interpreter_config(&spec, true).unwrap().is_empty());
    // A `.env` beside a non-Pipfile project is not loaded by pipenv.
    let spec = project(
        &[("pyproject.toml", PYPROJECT), (".env", "PYTHONPATH=./x\n")],
        "pyproject.toml",
    );
    assert!(check_interpreter_config(&spec, true).unwrap().is_empty());
}

fn git_index(version: u8, paths: &[&str]) -> Vec<u8> {
    let mut index = b"DIRC\0\0\0".to_vec();
    index.push(version);
    for path in paths {
        index.extend_from_slice(path.as_bytes());
        index.push(0);
    }
    index
}

fn repo_with_venv(index: Option<Vec<u8>>) -> ProjectInputSpec {
    let spec = project(&[("pyproject.toml", PYPROJECT)], "pyproject.toml");
    let dir = spec.project_dir().to_path_buf();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    if let Some(index) = index {
        std::fs::write(dir.join(".git/index"), index).unwrap();
    }
    std::fs::create_dir_all(dir.join(".venv/bin")).unwrap();
    std::fs::write(dir.join(".venv/pyvenv.cfg"), "home = /usr\n").unwrap();
    spec
}

#[test]
fn a_tracked_venv_blocks_and_an_untracked_one_does_not() {
    let tracked = repo_with_venv(Some(git_index(2, &["pyproject.toml", ".venv/pyvenv.cfg"])));
    let err = check_interpreter_config(&tracked, false)
        .unwrap_err()
        .to_string();
    assert!(err.contains("Committed virtual environment"), "{err}");

    let untracked = repo_with_venv(Some(git_index(2, &["pyproject.toml"])));
    assert!(
        check_interpreter_config(&untracked, true)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn an_undecidable_venv_warns_and_blocks_in_ci() {
    for index in [None, Some(git_index(4, &["pyproject.toml"]))] {
        let spec = repo_with_venv(index);
        let warn = check_interpreter_config(&spec, false).unwrap();
        assert_eq!(warn.len(), 1);
        assert_eq!(warn[0].severity, Severity::Warning);
        let ci = check_interpreter_config(&spec, true).unwrap();
        assert_eq!(ci[0].severity, Severity::Error);
    }
}
