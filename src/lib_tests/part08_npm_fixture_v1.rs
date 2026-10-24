use super::*;

#[tokio::test]
async fn npm_fixture_v1_range_drift_can_be_explicitly_allowed() {
    let dir = fixture_dir("v1-range-drift");
    let config = config::SloppyJoeConfig {
        allow_legacy_npm_v1_lockfile: true,
        ..Default::default()
    };
    let registry = FakeRegistry {
        existing: vec!["react".to_string()],
    };

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        config,
        &registry,
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("explicit opt-in should allow legacy npm v1 lockfiles");

    assert_eq!(report.packages_checked, 1);
    assert!(report.issues.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE
            && issue.severity == Severity::Warning
    }));
    assert!(report.issues.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_NO_TRUSTED_TRANSITIVE_COVERAGE
            && issue.severity == Severity::Warning
    }));
}

#[test]
fn npm_fixture_workspace_lock_target_mismatch_blocks() {
    let dir = fixture_dir("workspace-lock-target-mismatch");
    let err = preflight_scan_inputs(&dir, None)
        .expect_err("workspace lockfile links must point at the verified workspace target");
    let msg = err.to_string();
    assert!(msg.contains("workspace-lib"));
    assert!(msg.contains("other-lib"));
}

#[test]
fn npm_fixture_file_lock_target_mismatch_blocks() {
    let dir = fixture_dir("file-lock-target-mismatch");
    let err = preflight_scan_inputs(&dir, None)
        .expect_err("file/link lockfile entries must point at the manifest-verified local target");
    let msg = err.to_string();
    assert!(msg.contains("local-lib"));
    assert!(msg.contains("other-lib"));
}

#[test]
fn npm_fixture_wrong_package_identity_blocks() {
    let dir = fixture_dir("wrong-package-identity");
    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("lockfile entries must not claim a different package identity");
    let msg = err.to_string();
    assert!(msg.contains("react"));
    assert!(msg.contains("lodash"));
}

#[test]
fn npm_fixture_registry_url_wrong_package_blocks() {
    let dir = fixture_dir("registry-url-wrong-package");
    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("registry tarball URLs must match the locked package identity");
    let msg = err.to_string();
    assert!(msg.contains("react"));
    assert!(msg.contains("lodash"));
}

#[test]
fn npm_fixture_registry_url_wrong_version_blocks() {
    let dir = fixture_dir("registry-url-wrong-version");
    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("registry tarball URLs must match the locked version");
    let msg = err.to_string();
    assert!(msg.contains("18.3.1"));
    assert!(msg.contains("99.0.0"));
}

#[test]
fn npm_fixture_bundled_entry_blocks() {
    let dir = fixture_dir("bundled-entry");
    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("bundled npm entries must not silently bypass provenance checks");
    let msg = err.to_string();
    assert!(msg.contains("bundled"));
    assert!(msg.contains("react"));
}

#[tokio::test]
async fn npm_fixture_transitive_typosquat_flags_similarity_without_deep() {
    let dir = fixture_dir("transitive-typosquat");
    let registry = FakeRegistry {
        existing: vec![
            "react".to_string(),
            "express".to_string(),
            "expresss".to_string(),
        ],
    };

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        Default::default(),
        &registry,
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("fixture scan should succeed");

    assert!(
        report.issues.iter().any(|issue| {
            issue.package == "expresss"
                && issue.check.starts_with("similarity/")
                && issue.source.as_deref() == Some("transitive")
        }),
        "transitive npm typosquat should trigger similarity without --deep"
    );
}

#[tokio::test]
async fn npm_fixture_private_scope_typo_uses_configured_trusted_scope() {
    let dir = fixture_dir("private-scope-typo");
    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        fixture_config("private-scope-typo"),
        &FakeRegistry {
            existing: vec!["@acmf/widget".to_string()],
        },
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("fixture scan should succeed");

    assert!(
        report.issues.iter().any(|issue| {
            issue.package == "@acmf/widget"
                && issue.check == crate::names::SIMILARITY_SCOPE_SQUATTING
        }),
        "repo-configured trusted scopes should participate in npm scope-squatting detection"
    );
}

#[tokio::test]
async fn npm_fixture_long_tail_combo_squat_uses_configured_package_roots() {
    let dir = fixture_dir("long-tail-combo-squat");
    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        fixture_config("long-tail-combo-squat"),
        &FakeRegistry {
            existing: vec!["acme-widget".to_string(), "acme-widget-utils".to_string()],
        },
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("fixture scan should succeed");

    assert!(
        report.issues.iter().any(|issue| {
            issue.package == "acme-widget-utils"
                && issue.check == crate::names::SIMILARITY_SEGMENT_OVERLAP
        }),
        "repo-configured trusted package roots should participate in npm combo-squatting detection"
    );
}

#[test]
fn python_fixture_contracts_hold() {
    for case in [
        "direct-url-fail",
        "poetry-source-pass",
        "poetry-source-block",
        "poetry-source-mismatch-fail",
        "poetry-unused-source-warn",
        "poetry-pass",
        "requirements-warn-pass",
        "uv-source-pass",
        "uv-source-block",
        "uv-source-mismatch-fail",
        "uv-unused-source-warn",
        "uv-pass",
        "uv-stale-fail",
        "uv-schema-fail",
        "pip-tools-pass",
        "pip-tools-explicit-source-pass",
        "pip-tools-missing-hash-fail",
        "pip-tools-nonexact-fail",
    ] {
        assert_fixture_preflight_outcome("python", case);
    }
}

#[test]
fn unused_python_sources_warn_with_specific_check_name() {
    for case in ["poetry-unused-source-warn", "uv-unused-source-warn"] {
        let dir = ecosystem_fixture_dir("python", case);
        let specs = detected_project_inputs_with_config(
            &dir,
            Some("pypi"),
            &config::SloppyJoeConfig::default(),
        )
        .expect("warn fixtures should detect cleanly");
        let warnings = preflight_project_inputs(&dir, &specs, &config::SloppyJoeConfig::default())
            .expect("warn fixtures should not fail");
        assert!(
            warnings
                .iter()
                .any(|issue| issue.check == checks::names::RESOLUTION_UNUSED_DECLARED_SOURCE),
            "fixture {case} should emit resolution/unused-declared-source, got {warnings:?}"
        );
    }
}

#[test]
fn same_directory_pyproject_and_trusted_requirements_fail_closed() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["requests==2.31.0"]
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("requirements.txt"),
        "requests==2.31.0 \\\n    --hash=sha256:1111111111111111111111111111111111111111111111111111111111111111\n",
    )
    .unwrap();

    let specs = detected_project_inputs_with_config(
        &dir,
        Some("pypi"),
        &config::SloppyJoeConfig::default(),
    )
    .expect_err("mixed legacy pyproject and trusted requirements must fail closed");
    assert!(specs.to_string().contains("Ambiguous trusted Python roots"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unused_python_source_warning_tracks_source_identity_not_only_url() {
    let dir = unique_dir();
    let pyproject = r#"[tool.poetry]
name = "demo"
version = "0.1.0"
description = "Fixture"
authors = ["Fixture <fixture@example.com>"]

[tool.poetry.dependencies]
python = "^3.11"
torch = { version = "==2.6.0", source = "pytorch" }

[[tool.poetry.source]]
name = "pytorch"
url = "https://download.pytorch.org/whl/cu124"
priority = "explicit"

[[tool.poetry.source]]
name = "pytorch-mirror"
url = "https://download.pytorch.org/whl/cu124"
priority = "explicit"
"#;
    write_poetry_project(
        &dir,
        pyproject,
        r#"[[package]]
name = "torch"
version = "2.6.0"
description = "Fixture torch package"
optional = false
python-versions = ">=3.11"

[package.source]
type = "explicit"
url = "https://download.pytorch.org/whl/cu124"
reference = "pytorch"

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
content-hash = "__CONTENT_HASH__"
"#,
    );

    let mut config = config::SloppyJoeConfig::default();
    config.trusted_indexes.insert(
        "pypi".to_string(),
        vec!["https://download.pytorch.org/whl/cu124/".to_string()],
    );
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config)
        .expect("Poetry fixture should detect cleanly");
    let warnings =
        preflight_project_inputs(&dir, &specs, &config).expect("unused alias should warn only");
    assert!(
        warnings.iter().any(|issue| {
            issue.check == checks::names::RESOLUTION_UNUSED_DECLARED_SOURCE
                && issue.message.contains("pytorch-mirror")
        }),
        "duplicate URL alias should still warn when unused: {warnings:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn poetry_narrowed_profile_does_not_validate_dev_only_source_packages() {
    let dir = unique_dir();
    let pyproject = r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
requests = "2.31.0"

[tool.poetry.group.dev.dependencies]
private-test-helper = { version = "1.0.0", source = "private" }

[[tool.poetry.source]]
name = "private"
url = "https://private.example/simple"
priority = "explicit"
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

[[package]]
name = "private-test-helper"
version = "1.0.0"
optional = false
python-versions = ">=3.8"
files = []

[package.source]
type = "explicit"
url = "https://private.example/simple"
reference = "private"

[metadata]
lock-version = "2.0"
python-versions = "^3.12"
content-hash = "__CONTENT_HASH__"
"#,
    );

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config)
        .expect("fixture should detect cleanly");
    let warnings = preflight_project_inputs_with_options(
        &dir,
        &specs,
        &config,
        // Narrowed to the main dependencies: the dev group is explicitly excluded.
        &python_profile_opts(&["main"], &[], Some("3.12")),
    )
    .expect("narrowed profile should ignore dev-only private index package");
    assert!(
        warnings
            .iter()
            .any(|issue| issue.check == checks::names::RESOLUTION_UNUSED_DECLARED_SOURCE),
        "out-of-scope private source should warn as unused: {warnings:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn poetry_blocks_transitive_custom_source_not_authorized_by_in_scope_roots() {
    let dir = unique_dir();
    let pyproject = r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
private-lib = { version = "1.0.0", source = "internal" }

[[tool.poetry.source]]
name = "internal"
url = "https://internal.example/simple"
priority = "explicit"

[[tool.poetry.source]]
name = "mirror"
url = "https://mirror.example/simple"
priority = "explicit"
"#;
    write_poetry_project(
        &dir,
        pyproject,
        r#"[[package]]
name = "private-lib"
version = "1.0.0"
optional = false
python-versions = ">=3.8"
files = [
  { file = "private_lib-1.0.0-py3-none-any.whl", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }
]

[package.source]
type = "explicit"
url = "https://internal.example/simple"
reference = "internal"

[package.dependencies]
helper = "1.0.0"

[[package]]
name = "helper"
version = "1.0.0"
optional = false
python-versions = ">=3.8"
files = [
  { file = "helper-1.0.0-py3-none-any.whl", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222" }
]

[package.source]
type = "explicit"
url = "https://mirror.example/simple"
reference = "mirror"

[metadata]
lock-version = "2.0"
python-versions = "^3.12"
content-hash = "__CONTENT_HASH__"
"#,
    );

    let mut config = config::SloppyJoeConfig::default();
    config.trusted_indexes.insert(
        "pypi".to_string(),
        vec![
            "https://internal.example/simple/".to_string(),
            "https://mirror.example/simple/".to_string(),
        ],
    );
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config)
        .expect("fixture should detect cleanly");
    let err = preflight_project_inputs_with_options(
        &dir,
        &specs,
        &config,
        &python_profile_opts(&[], &[], Some("3.12")),
    )
    .expect_err(
        "transitive custom sources should not be authorized solely because they are declared",
    );
    assert!(
        err.to_string().contains("not authorized") || err.to_string().contains("unexpected source"),
        "unexpected error: {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn uv_source_policy_ignores_unreachable_same_name_version() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["widget==1.0.0"]

[tool.uv]
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("uv.lock"),
        r#"version = 1
requires-python = ">=3.12"

[[package]]
name = "widget"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/example/widget-1.0.0.tar.gz", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", size = 1 }
wheels = [
    { url = "https://files.pythonhosted.org/packages/example/widget-1.0.0-py3-none-any.whl", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222", size = 1 },
]

[[package]]
name = "widget"
version = "2.0.0"
source = { registry = "https://evil.example/simple" }
sdist = { url = "https://evil.example/packages/widget-2.0.0.tar.gz", hash = "sha256:3333333333333333333333333333333333333333333333333333333333333333", size = 1 }
wheels = [
    { url = "https://evil.example/packages/widget-2.0.0-py3-none-any.whl", hash = "sha256:4444444444444444444444444444444444444444444444444444444444444444", size = 1 },
]

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "widget", version = "1.0.0" }]

[package.metadata]
requires-dist = [
    { name = "widget", specifier = "==1.0.0" },
]
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config)
        .expect("fixture should detect cleanly");
    preflight_project_inputs_with_options(
        &dir,
        &specs,
        &config,
        &python_profile_opts(&[], &[], Some("3.12")),
    )
    .expect("unreachable same-name package version should not participate in source policy");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn uv_blocks_transitive_custom_source_not_authorized_by_in_scope_roots() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["private-lib==1.0.0"]

[tool.uv]

[tool.uv.sources]
private-lib = { index = "internal" }

[[tool.uv.index]]
name = "internal"
url = "https://internal.example/simple"

[[tool.uv.index]]
name = "mirror"
url = "https://mirror.example/simple"
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("uv.lock"),
        r#"version = 1
requires-python = ">=3.12"

[[package]]
name = "private-lib"
version = "1.0.0"
source = { registry = "https://internal.example/simple" }
sdist = { url = "https://internal.example/files/private-lib-1.0.0.tar.gz", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", size = 1 }
wheels = [
  { url = "https://internal.example/files/private-lib-1.0.0-py3-none-any.whl", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222", size = 1 },
]
dependencies = [{ name = "helper", version = "1.0.0" }]

[[package]]
name = "helper"
version = "1.0.0"
source = { registry = "https://mirror.example/simple" }
sdist = { url = "https://mirror.example/files/helper-1.0.0.tar.gz", hash = "sha256:3333333333333333333333333333333333333333333333333333333333333333", size = 1 }
wheels = [
  { url = "https://mirror.example/files/helper-1.0.0-py3-none-any.whl", hash = "sha256:4444444444444444444444444444444444444444444444444444444444444444", size = 1 },
]

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "private-lib", version = "1.0.0" }]

[package.metadata]
requires-dist = [{ name = "private-lib", specifier = "==1.0.0" }]
"#,
    )
    .unwrap();

    let mut config = config::SloppyJoeConfig::default();
    config.trusted_indexes.insert(
        "pypi".to_string(),
        vec![
            "https://internal.example/simple/".to_string(),
            "https://mirror.example/simple/".to_string(),
        ],
    );
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config)
        .expect("fixture should detect cleanly");
    let err = preflight_project_inputs_with_options(
        &dir,
        &specs,
        &config,
        &python_profile_opts(&[], &[], Some("3.12")),
    )
    .expect_err(
        "transitive uv custom sources should not be authorized solely because they are declared",
    );
    assert!(
        err.to_string().contains("not authorized") || err.to_string().contains("unexpected source"),
        "unexpected error: {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn poetry_source_intents_ignore_unselected_group_for_same_package_name() {
    // Narrowed to the main dependencies: the dev group is explicitly excluded.
    let dir = unique_dir();
    let pyproject = r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
private-lib = "^1.0.0"

[tool.poetry.group.dev.dependencies]
private-lib = { version = "^1.0.0", source = "internal" }

[[tool.poetry.source]]
name = "internal"
url = "https://packages.example.com/simple"
priority = "explicit"
"#;
    write_poetry_project(
        &dir,
        pyproject,
        r#"[[package]]
name = "private-lib"
version = "1.2.0"
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
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config)
        .expect("fixture should detect cleanly");
    preflight_project_inputs_with_options(
        &dir,
        &specs,
        &config,
        &python_profile_opts(&["main"], &[], Some("3.12")),
    )
    .expect("narrowed profile should ignore dev-only source intent for same package");

    let _ = std::fs::remove_dir_all(&dir);
}
