use super::*;

const CI_POETRY_PYPROJECT: &str = r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
requests = "2.31.0"
"#;

fn ci_options() -> ScanOptions<'static> {
    ScanOptions {
        scan_mode: ScanMode::Ci,
        ..Default::default()
    }
}

#[test]
fn the_ci_scan_blocks_a_poetry_lock_without_artifact_hashes() {
    let dir = unique_dir();
    std::fs::write(dir.join("pyproject.toml"), CI_POETRY_PYPROJECT).unwrap();
    std::fs::write(
        dir.join("poetry.lock"),
        r#"[[package]]
name = "requests"
version = "2.31.0"
description = ""
optional = false
python-versions = ">=3.8"
files = []

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
content-hash = "981cb674b020e2aa2e4686d20cf177bc0fe8b0f6003e339f61debabe80576858"
"#,
    )
    .unwrap();
    let config = python_config_with_poetry_policy(
        config::PythonEnforcement::PreferPoetry,
        config::PoetryLockPolicy::WarnMissingProofs,
    );
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config).unwrap();
    preflight_project_inputs(&dir, &specs, &config).expect("warn policy stays a warning");
    let err = preflight_project_inputs_with_options(&dir, &specs, &config, &ci_options())
        .expect_err("--ci must block a Poetry lock with no artifact identity");
    assert!(err.to_string().contains("artifact identity"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_ci_scan_blocks_a_legacy_manifest_beside_a_poetry_project() {
    let dir = unique_dir();
    std::fs::write(dir.join("pyproject.toml"), CI_POETRY_PYPROJECT).unwrap();
    std::fs::write(
        dir.join("poetry.lock"),
        r#"[[package]]
name = "requests"
version = "2.31.0"
description = ""
optional = false
python-versions = ">=3.8"
files = [
  { file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }
]

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
content-hash = "981cb674b020e2aa2e4686d20cf177bc0fe8b0f6003e339f61debabe80576858"
"#,
    )
    .unwrap();
    std::fs::write(dir.join("requirements.txt"), "evil-pkg==1.0\n").unwrap();
    let config = python_config_with_poetry_policy(
        config::PythonEnforcement::PreferPoetry,
        config::PoetryLockPolicy::WarnMissingProofs,
    );
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config).unwrap();
    let warnings = preflight_project_inputs(&dir, &specs, &config).unwrap();
    assert!(warnings.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_PYTHON_LEGACY_MANIFEST
            && issue.severity == Severity::Warning
    }));
    let ci = preflight_project_inputs_with_options(&dir, &specs, &config, &ci_options()).unwrap();
    assert!(ci.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_PYTHON_LEGACY_MANIFEST
            && issue.severity == Severity::Error
    }));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_uv_toml_index_redirect_blocks_a_plain_requirements_project() {
    let dir = unique_dir();
    std::fs::write(dir.join("requirements.txt"), "six==1.16.0\n").unwrap();
    std::fs::write(
        dir.join("uv.toml"),
        "no-index = true\nfind-links = [\"./wheels\"]\n",
    )
    .unwrap();
    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config).unwrap();
    let err = preflight_project_inputs(&dir, &specs, &config)
        .expect_err("uv.toml redirects apply to uv pip installs too");
    assert!(err.to_string().contains("uv setting"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}
