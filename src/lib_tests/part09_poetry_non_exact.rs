use super::*;

#[test]
fn poetry_non_exact_same_name_root_versions_fail_closed() {
    let dir = unique_dir();
    let pyproject = r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
widget = "^1.0.0"

[[tool.poetry.source]]
name = "evil"
url = "https://evil.example/simple"
priority = "explicit"
"#;
    write_poetry_project(
        &dir,
        pyproject,
        r#"[[package]]
name = "widget"
version = "1.1.0"
optional = false
python-versions = ">=3.8"
files = []

[[package]]
name = "widget"
version = "2.0.0"
optional = false
python-versions = ">=3.8"
files = []

[package.source]
type = "explicit"
url = "https://evil.example/simple"
reference = "evil"

[metadata]
lock-version = "2.0"
python-versions = "^3.12"
content-hash = "__CONTENT_HASH__"
"#,
    );

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config)
        .expect("fixture should detect cleanly");
    let err = preflight_project_inputs_with_options(
        &dir,
        &specs,
        &config,
        &python_profile_opts(&[], &[], Some("3.12")),
    )
    .expect_err("ambiguous non-exact Poetry roots must fail closed");
    assert!(
        err.to_string().contains("ambiguous")
            || err.to_string().contains("cannot be trusted exactly"),
        "unexpected error: {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn python_uv_selects_uv_lockfile_for_tool_uv_projects() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        r#"[project]
name = "demo"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["requests==2.32.3"]

[tool.uv]
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("uv.lock"),
        r#"version = 1
requires-python = ">=3.11"

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/example/requests-2.32.3.tar.gz", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", size = 1 }
wheels = [
    { url = "https://files.pythonhosted.org/packages/example/requests-2.32.3-py3-none-any.whl", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222", size = 1 },
]

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }

[package.metadata]
requires-dist = [{ name = "requests", specifier = "==2.32.3" }]
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("poetry.lock"),
        r#"[[package]]
name = "requests"
version = "0.1.0"

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config)
        .expect("uv-managed projects should still be detected");
    assert_eq!(specs.len(), 1);
    assert_eq!(selected_lockfile_path(&specs[0]), Some(dir.join("uv.lock")));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn python_uv_preflight_blocks_stale_or_unsupported_uv_lockfiles() {
    for case in ["uv-stale-fail", "uv-schema-fail"] {
        let dir = ecosystem_fixture_dir("python", case);
        preflight_scan_inputs(&dir, Some("pypi"))
            .expect_err("invalid trusted uv projects must fail closed");
    }
}

#[test]
fn pip_tools_hash_locked_requirements_warn_without_source_provenance() {
    let dir = ecosystem_fixture_dir("python", "pip-tools-pass");
    let warnings = preflight_scan_inputs(&dir, Some("pypi"))
        .expect("hash-locked pip-tools requirements should warn, not fail");
    assert!(
        warnings.iter().any(|issue| {
            issue.check == checks::names::RESOLUTION_PYTHON_HASH_LOCKED_REQUIREMENTS
        }),
        "hash-locked pip-tools requirements should warn about missing source provenance: {warnings:?}"
    );
}

#[test]
fn pip_tools_hash_locked_requirements_with_explicit_sources_pass_cleanly() {
    let dir = ecosystem_fixture_dir("python", "pip-tools-explicit-source-pass");
    let warnings = preflight_scan_inputs(&dir, Some("pypi"))
        .expect("explicit file-bound pip indexes should allow exact pip-tools provenance");
    assert!(
        warnings.is_empty(),
        "explicit file-bound pip sources should avoid reduced-confidence warnings: {warnings:?}"
    );
}

#[test]
fn pip_tools_hash_locked_requirements_with_untrusted_extra_index_fail_closed() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("requirements.txt"),
        "--index-url https://pypi.org/simple\n--extra-index-url https://packages.example.com/simple\nrequests==2.32.3 \\\n    --hash=sha256:1111111111111111111111111111111111111111111111111111111111111111\n",
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("pypi"))
        .expect_err("unallowlisted explicit pip indexes must fail closed");
    assert!(err.to_string().contains("untrusted Python index"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pip_tools_missing_hashes_or_nonexact_requirements_stay_legacy() {
    for case in ["pip-tools-missing-hash-fail", "pip-tools-nonexact-fail"] {
        let dir = ecosystem_fixture_dir("python", case);
        let warnings = preflight_scan_inputs(&dir, Some("pypi"))
            .expect("legacy pip-tools cases should warn, not fail");
        assert!(
            !warnings.is_empty(),
            "legacy pip-tools case {case} should produce warnings"
        );
    }
}

#[test]
fn pip_tools_included_requirements_must_also_be_hash_locked() {
    let dir = unique_dir();
    std::fs::write(dir.join("requirements.txt"), "-r base.txt\n").unwrap();
    std::fs::write(
        dir.join("base.txt"),
        "requests==2.32.3 \\\n    --hash=sha256:1111111111111111111111111111111111111111111111111111111111111111\nurllib3==2.6.3\n",
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, Some("pypi"))
        .expect("included requirements without full hashes should stay legacy, not fail");
    assert!(
        !warnings.is_empty(),
        "hashless included requirements should prevent trusted pip-tools promotion"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn poetry_default_profile_includes_dev_group_and_narrowing_excludes_it_with_warning() {
    let dir = unique_dir();
    let pyproject = r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
requests = "2.31.0"

[tool.poetry.dev-dependencies]
pytest = "8.1.1"
"#;
    write_poetry_project(
        &dir,
        pyproject,
        r#"[[package]]
name = "requests"
version = "2.31.0"
description = ""
optional = false
python-versions = ">=3.8"
files = []

[[package]]
name = "pytest"
version = "8.1.1"
description = ""
optional = false
python-versions = ">=3.8"
files = []

[metadata]
lock-version = "2.0"
python-versions = "^3.12"
content-hash = "__CONTENT_HASH__"
"#,
    );

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config).unwrap();
    let warnings =
        preflight_project_inputs_with_options(&dir, &specs, &config, &ScanOptions::default())
            .unwrap();
    assert!(!warnings.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_PYTHON_IMPLICIT_RUNTIME_PROFILE
            || issue.check == checks::names::RESOLUTION_PYTHON_GROUPS_NOT_SCANNED
    }));

    let projects =
        parse_project_inputs_with_options(&dir, &specs, &config, &ScanOptions::default()).unwrap();
    assert_eq!(projects.len(), 1);
    let names: Vec<_> = projects[0]
        .deps
        .iter()
        .map(|dep| dep.name.as_str())
        .collect();
    assert!(names.contains(&"requests"));
    assert!(names.contains(&"pytest"));

    let narrowed = python_profile_opts(&["main"], &[], None);
    let warnings = preflight_project_inputs_with_options(&dir, &specs, &config, &narrowed).unwrap();
    assert!(warnings.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_PYTHON_GROUPS_NOT_SCANNED
            && issue.message.contains("'dev'")
    }));
    let projects = parse_project_inputs_with_options(&dir, &specs, &config, &narrowed).unwrap();
    let names: Vec<_> = projects[0]
        .deps
        .iter()
        .map(|dep| dep.name.as_str())
        .collect();
    assert!(names.contains(&"requests"));
    assert!(!names.contains(&"pytest"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn poetry_explicit_group_includes_dev_group_dependencies() {
    let dir = unique_dir();
    let pyproject = r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
requests = "2.31.0"

[tool.poetry.dev-dependencies]
pytest = "8.1.1"
"#;
    write_poetry_project(
        &dir,
        pyproject,
        r#"[[package]]
name = "requests"
version = "2.31.0"
description = ""
optional = false
python-versions = ">=3.8"
files = []

[[package]]
name = "pytest"
version = "8.1.1"
description = ""
optional = false
python-versions = ">=3.8"
files = []

[metadata]
lock-version = "2.0"
python-versions = "^3.12"
content-hash = "__CONTENT_HASH__"
"#,
    );

    let config = config::SloppyJoeConfig::default();
    let opts = python_profile_opts(&["dev"], &[], Some("3.12"));
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config).unwrap();
    let warnings = preflight_project_inputs_with_options(&dir, &specs, &config, &opts).unwrap();
    assert!(
        !warnings.iter().any(|issue| {
            issue.check == checks::names::RESOLUTION_PYTHON_IMPLICIT_RUNTIME_PROFILE
        })
    );

    let projects = parse_project_inputs_with_options(&dir, &specs, &config, &opts).unwrap();
    let names: Vec<_> = projects[0]
        .deps
        .iter()
        .map(|dep| dep.name.as_str())
        .collect();
    assert!(names.contains(&"requests"));
    assert!(names.contains(&"pytest"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn uv_default_profile_includes_optional_extras_and_narrowing_excludes_them() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["requests==2.31.0"]

[project.optional-dependencies]
docs = ["mkdocs==1.6.0"]

[tool.uv]
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("uv.lock"),
        r#"version = 1
requires-python = ">=3.12"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/example/requests-2.31.0.tar.gz", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", size = 1 }
wheels = [
    { url = "https://files.pythonhosted.org/packages/example/requests-2.31.0-py3-none-any.whl", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222", size = 1 },
]

[[package]]
name = "mkdocs"
version = "1.6.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/example/mkdocs-1.6.0.tar.gz", hash = "sha256:3333333333333333333333333333333333333333333333333333333333333333", size = 1 }
wheels = [
    { url = "https://files.pythonhosted.org/packages/example/mkdocs-1.6.0-py3-none-any.whl", hash = "sha256:4444444444444444444444444444444444444444444444444444444444444444", size = 1 },
]

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "requests" }]

[package.optional-dependencies]
docs = [{ name = "mkdocs" }]

[package.metadata]
requires-dist = [
    { name = "requests", specifier = "==2.31.0" },
    { name = "mkdocs", marker = "extra == 'docs'", specifier = "==1.6.0" },
]
provides-extras = ["docs"]
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config).unwrap();
    let warnings =
        preflight_project_inputs_with_options(&dir, &specs, &config, &ScanOptions::default())
            .unwrap();
    assert!(!warnings.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_PYTHON_IMPLICIT_RUNTIME_PROFILE
            || issue.check == checks::names::RESOLUTION_PYTHON_GROUPS_NOT_SCANNED
    }));

    let projects =
        parse_project_inputs_with_options(&dir, &specs, &config, &ScanOptions::default()).unwrap();
    let names: Vec<_> = projects[0]
        .deps
        .iter()
        .map(|dep| dep.name.as_str())
        .collect();
    assert!(names.contains(&"requests"));
    assert!(names.contains(&"mkdocs"));

    let narrowed = python_profile_opts(&[], &["cli"], None);
    let warnings = preflight_project_inputs_with_options(&dir, &specs, &config, &narrowed).unwrap();
    assert!(warnings.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_PYTHON_GROUPS_NOT_SCANNED
            && issue.message.contains("'docs'")
    }));
    let projects = parse_project_inputs_with_options(&dir, &specs, &config, &narrowed).unwrap();
    let names: Vec<_> = projects[0]
        .deps
        .iter()
        .map(|dep| dep.name.as_str())
        .collect();
    assert!(names.contains(&"requests"));
    assert!(!names.contains(&"mkdocs"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn uv_explicit_extra_includes_optional_dependencies() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["requests==2.31.0"]

[project.optional-dependencies]
docs = ["mkdocs==1.6.0"]

[tool.uv]
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("uv.lock"),
        r#"version = 1
requires-python = ">=3.12"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/example/requests-2.31.0.tar.gz", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", size = 1 }
wheels = [
    { url = "https://files.pythonhosted.org/packages/example/requests-2.31.0-py3-none-any.whl", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222", size = 1 },
]

[[package]]
name = "mkdocs"
version = "1.6.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/example/mkdocs-1.6.0.tar.gz", hash = "sha256:3333333333333333333333333333333333333333333333333333333333333333", size = 1 }
wheels = [
    { url = "https://files.pythonhosted.org/packages/example/mkdocs-1.6.0-py3-none-any.whl", hash = "sha256:4444444444444444444444444444444444444444444444444444444444444444", size = 1 },
]

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "requests" }]

[package.optional-dependencies]
docs = [{ name = "mkdocs" }]

[package.metadata]
requires-dist = [
    { name = "requests", specifier = "==2.31.0" },
    { name = "mkdocs", marker = "extra == 'docs'", specifier = "==1.6.0" },
]
provides-extras = ["docs"]
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig::default();
    let opts = python_profile_opts(&[], &["docs"], Some("3.12"));
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config).unwrap();
    let warnings = preflight_project_inputs_with_options(&dir, &specs, &config, &opts).unwrap();
    assert!(
        !warnings.iter().any(|issue| {
            issue.check == checks::names::RESOLUTION_PYTHON_IMPLICIT_RUNTIME_PROFILE
        })
    );

    let projects = parse_project_inputs_with_options(&dir, &specs, &config, &opts).unwrap();
    let names: Vec<_> = projects[0]
        .deps
        .iter()
        .map(|dep| dep.name.as_str())
        .collect();
    assert!(names.contains(&"requests"));
    assert!(names.contains(&"mkdocs"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn poetry_default_profile_includes_dev_transitive_dependencies() {
    let dir = unique_dir();
    let pyproject = r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
requests = "2.31.0"

[tool.poetry.dev-dependencies]
pytest = "8.1.1"
"#;
    write_poetry_project(
        &dir,
        pyproject,
        r#"[[package]]
name = "requests"
version = "2.31.0"
optional = false
python-versions = ">=3.8"
files = [{ file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }]

[package.dependencies]
urllib3 = ">=2.0"

[[package]]
name = "urllib3"
version = "2.1.0"
optional = false
python-versions = ">=3.8"
files = [{ file = "urllib3-2.1.0-py3-none-any.whl", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222" }]

[[package]]
name = "pytest"
version = "8.1.1"
optional = false
python-versions = ">=3.8"
files = [{ file = "pytest-8.1.1-py3-none-any.whl", hash = "sha256:3333333333333333333333333333333333333333333333333333333333333333" }]

[package.dependencies]
pluggy = ">=1.0"

[[package]]
name = "pluggy"
version = "1.5.0"
optional = false
python-versions = ">=3.8"
files = [{ file = "pluggy-1.5.0-py3-none-any.whl", hash = "sha256:4444444444444444444444444444444444444444444444444444444444444444" }]

[metadata]
lock-version = "2.0"
python-versions = "^3.12"
content-hash = "__CONTENT_HASH__"
"#,
    );

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config).unwrap();
    let projects =
        parse_project_inputs_with_options(&dir, &specs, &config, &ScanOptions::default()).unwrap();
    let deps = projects[0].deps.clone();

    let registry = FakeRegistry {
        existing: vec![
            "requests".to_string(),
            "urllib3".to_string(),
            "pytest".to_string(),
            "pluggy".to_string(),
        ],
    };
    let osv = VulnOsvClient {
        vulnerable: vec!["urllib3".to_string(), "pluggy".to_string()],
    };

    let report = scan_with_services_inner_for_kind(
        Some(ProjectInputKind::PyProjectPoetry),
        &dir,
        config,
        deps,
        &registry,
        &osv,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert!(
        report.issues.iter().any(
            |issue| issue.package == "urllib3" && issue.source.as_deref() == Some("transitive")
        )
    );
    assert!(report.issues.iter().any(
        |issue| issue.package == "pluggy" && issue.source.as_deref() == Some("transitive")
    ));

    let _ = std::fs::remove_dir_all(&dir);
}
