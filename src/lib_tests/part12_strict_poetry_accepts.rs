use super::*;

#[test]
fn strict_poetry_accepts_version_scoped_metadata_files_identity() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
requests = "2.31.0"
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("poetry.lock"),
        r#"[[package]]
name = "requests"
version = "2.31.0"
description = ""
optional = false
python-versions = ">=3.8"

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
content-hash = "a2bc317d8861d66a7774092d6797ba6ee5daaddd501c46bf86524f04aa57d234"

[metadata.files]
requests = [
  { file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }
]
"#,
    )
    .unwrap();

    let config = python_config_with_poetry_policy(
        config::PythonEnforcement::PreferPoetry,
        config::PoetryLockPolicy::Strict,
    );
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config)
        .expect("fixture should detect cleanly");
    let warnings = preflight_project_inputs(&dir, &specs, &config)
        .expect("version-scoped metadata.files should pass");
    assert!(
        warnings.is_empty(),
        "strict Poetry artifact proof should stay clean: {warnings:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn strict_poetry_rejects_pkg_files_that_do_not_match_package_version() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
requests = "2.31.0"
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("poetry.lock"),
        r#"[[package]]
name = "requests"
version = "2.31.0"
description = ""
optional = false
python-versions = ">=3.8"
files = [
  { file = "urllib3-2.1.0-py3-none-any.whl", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }
]

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
content-hash = "a2bc317d8861d66a7774092d6797ba6ee5daaddd501c46bf86524f04aa57d234"
"#,
    )
    .unwrap();

    let config = python_config_with_poetry_policy(
        config::PythonEnforcement::PreferPoetry,
        config::PoetryLockPolicy::Strict,
    );
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config)
        .expect("fixture should detect cleanly");
    let err = preflight_project_inputs(&dir, &specs, &config)
        .expect_err("pkg.files entries must match the package/version they claim to prove");
    assert!(err.to_string().contains("artifact identity"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parse_project_inputs_respects_explicit_python_arch_for_marker_evaluation() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = [
  "arm-only==1.0.0; platform_machine == 'aarch64'",
  "x86-only==2.0.0; platform_machine == 'x86_64'",
]
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config)
        .expect("fixture should detect cleanly");
    let arm = parse_project_inputs_with_options(
        &dir,
        &specs,
        &config,
        &python_profile_opts_with_arch(&[], &[], Some("3.12"), Some("aarch64")),
    )
    .expect("explicit aarch64 profile should parse");
    assert!(arm[0].deps.iter().any(|dep| dep.name == "arm-only"));
    assert!(!arm[0].deps.iter().any(|dep| dep.name == "x86-only"));

    let x86 = parse_project_inputs_with_options(
        &dir,
        &specs,
        &config,
        &python_profile_opts_with_arch(&[], &[], Some("3.12"), Some("x86_64")),
    )
    .expect("explicit x86_64 profile should parse");
    assert!(x86[0].deps.iter().any(|dep| dep.name == "x86-only"));
    assert!(!x86[0].deps.iter().any(|dep| dep.name == "arm-only"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_cargo_git_dependency_sources() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = { git = "https://github.com/serde-rs/serde" }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();

    let err = preflight_scan_inputs(&dir, Some("cargo"))
        .expect_err("Cargo git dependencies must block strict scanning");
    assert!(err.to_string().contains("git"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_cargo_workspace_inheritance_from_in_scope_root() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("app")).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[workspace]
members = ["app"]

[workspace.dependencies]
serde = "=1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("app").join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = { workspace = true }
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "workspace-inherited Cargo deps should be allowed when the in-scope workspace root and lockfile prove trusted provenance: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_workspace_inherited_cargo_dep_through_workspace_root_patch_rewrite() {
    let dir = unique_dir();
    let app = dir.join("app");
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::create_dir_all(&patched).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[workspace]
members = ["app", "patched-serde"]

[workspace.dependencies]
serde = "=1.0.228"

[patch.crates-io]
serde = { path = "patched-serde" }
"#,
    )
    .unwrap();
    std::fs::write(
        app.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = { workspace = true }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        patched.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(patched.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "workspace-inherited Cargo deps must still flow through workspace-root rewrites: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_cargo_workspace_inheritance_for_non_member_crate() {
    let dir = unique_dir();
    let member = dir.join("member");
    let rogue = dir.join("rogue");
    std::fs::create_dir_all(&member).unwrap();
    std::fs::create_dir_all(&rogue).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[workspace]
members = ["member"]

[workspace.dependencies]
serde = "=1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(
        member.join("Cargo.toml"),
        r#"[package]
name = "member"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        rogue.join("Cargo.toml"),
        r#"[package]
name = "rogue"
version = "0.1.0"

[dependencies]
serde = { workspace = true }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(rogue.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let err = detected_project_inputs_with_config(&dir, Some("cargo"), &config)
        .expect_err("non-member crates must not inherit workspace dependencies or lockfile trust");
    assert!(err.to_string().contains("no in-scope workspace root"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn detected_project_inputs_include_workspace_root_patch_target_for_workspace_inherited_dep() {
    let dir = unique_dir();
    let app = dir.join("app");
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::create_dir_all(&patched).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[workspace]
members = ["app", "patched-serde"]

[workspace.dependencies]
serde = "=1.0.228"

[patch.crates-io]
serde = { path = "patched-serde" }
"#,
    )
    .unwrap();
    std::fs::write(
        app.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = { workspace = true }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        patched.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(patched.join("Cargo.lock"), "version = 4\n").unwrap();

    let specs = detected_project_inputs_with_config(
        &dir,
        Some("cargo"),
        &config::SloppyJoeConfig::default(),
    )
    .unwrap();
    assert!(
        specs
            .iter()
            .any(|spec| spec.manifest_path == patched.join("Cargo.toml")),
        "workspace-root rewrite targets for workspace-inherited deps must be scanned as first-class Cargo projects"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_cargo_in_root_path_dependency() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("app")).unwrap();
    std::fs::create_dir_all(dir.join("util")).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[workspace]
members = ["app", "util"]
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("app").join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
util = { path = "../util" }
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("util").join("Cargo.toml"),
        r#"[package]
name = "util"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "in-root Cargo path deps should be allowed and treated as first-party local crates: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_cargo_path_dependency_with_mismatched_package_name() {
    let dir = unique_dir();
    let local = dir.join("local-crate");
    std::fs::create_dir_all(&local).unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = { path = "local-crate" }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        local.join("Cargo.toml"),
        r#"[package]
name = "not-serde"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(local.join("Cargo.lock"), "version = 4\n").unwrap();

    let specs = detected_project_inputs_with_config(
        &dir,
        Some("cargo"),
        &config::SloppyJoeConfig::default(),
    )
    .unwrap();
    let err = preflight_project_inputs(&dir, &specs, &config::SloppyJoeConfig::default())
        .expect_err("mismatched local Cargo crate identity must block");
    assert!(err.to_string().contains("declares package"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_cargo_exact_path_dependency_with_mismatched_target_version() {
    let dir = unique_dir();
    let local = dir.join("local-crate");
    std::fs::create_dir_all(&local).unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = { path = "local-crate", version = "=1.0.228" }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        local.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "9.9.9"
"#,
    )
    .unwrap();
    std::fs::write(local.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let err = preflight_project_inputs(&dir, &specs, &config)
        .expect_err("exact local Cargo path dependencies must bind target version too");
    assert!(err.to_string().contains("declares version"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_cargo_allowlisted_external_path_dependency() {
    let dir = unique_dir();
    let external = unique_dir();
    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
shared = {{ path = "{}" }}
"#,
            external.display()
        ),
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        external.join("Cargo.toml"),
        r#"[package]
name = "shared"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(external.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig {
        trusted_local_paths: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec![external.display().to_string()],
        )]),
        ..Default::default()
    };
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "allowlisted external Cargo path deps should pass strict preflight: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&external);
}

#[test]
fn preflight_does_not_apply_crates_io_patch_to_private_registry_dependency() {
    let dir = unique_dir();
    let patched = unique_dir();
    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = {{ version = "1.0.0", registry = "company" }}

[patch.crates-io]
serde = {{ path = "{}" }}
"#,
            patched.display()
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://cargo.company.example/index"
"#,
    )
    .unwrap();
    std::fs::write(
        patched.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.0"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig {
        trusted_registries: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec![config::TrustedRegistry {
                name: "company".to_string(),
                source: "registry+https://cargo.company.example/index".to_string(),
            }],
        )]),
        ..Default::default()
    };
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "crates.io patches must not rewrite private-registry dependencies: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&patched);
}

#[test]
fn preflight_accepts_cargo_lock_versions_with_build_metadata_suffixes() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde_yaml = "=0.9.34"
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "serde_yaml"
version = "0.9.34+deprecated"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "Cargo exact pins should trust lockfile entries that differ only by build metadata: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_cargo_allowlisted_private_registry_dependency() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
internal-crate = { registry = "company", version = "=1.2.3" }
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "internal-crate"
version = "1.2.3"
source = "registry+https://cargo.company.example/index"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig {
        trusted_registries: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec![config::TrustedRegistry {
                name: "company".to_string(),
                source: "registry+https://cargo.company.example/index".to_string(),
            }],
        )]),
        ..Default::default()
    };
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "allowlisted Cargo private registries should pass strict preflight when Cargo.lock proves the exact source: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
