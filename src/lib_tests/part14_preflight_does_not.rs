use super::*;

#[test]
fn preflight_does_not_apply_cargo_replace_with_mismatched_package_id_version() {
    let dir = unique_dir();
    let external = unique_dir();

    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.229"

[replace]
"serde:1.0.228" = {{ path = "{}" }}
"#,
            external.display()
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "serde"
version = "1.0.229"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abababababababababababababababababababababababababababababababab"
"#,
    )
    .unwrap();
    std::fs::write(
        external.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "Cargo [replace] must not apply when the package ID version does not match: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&external);
}

#[test]
fn preflight_allows_cargo_replace_with_fully_qualified_package_id_source() {
    let dir = unique_dir();
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&patched).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = { version = "=1.0.228", registry = "company" }

[replace]
"registry+https://cargo.company.example/index#serde@1.0.228" = { path = "patched-serde" }
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
        "fully qualified Cargo [replace] package IDs must resolve through the trusted local rewrite model: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_cargo_registry_replace_with_mismatched_lockfile_version() {
    let dir = unique_dir();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"

[replace]
"serde:1.0.228" = { registry = "company" }
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "serde"
version = "9.9.9"
source = "registry+https://cargo.company.example/index"
checksum = "abababababababababababababababababababababababababababababababab"
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
    let err = preflight_project_inputs(&dir, &specs, &config)
        .expect_err("Cargo registry rewrites must still bind the exact replaced package version");
    assert!(err.to_string().contains("Cargo.lock"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_cargo_git_replace_with_mismatched_lockfile_version() {
    let dir = unique_dir();
    let rev = "0123456789abcdef0123456789abcdef01234567";
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    let lockfile = toml::from_str::<toml::Value>(&format!(
        r#"version = 4

[[package]]
name = "shared"
version = "9.9.9"
source = "git+https://github.com/yourorg/shared-crate?rev={rev}#{rev}"
"#
    ))
    .unwrap();

    let config = config::SloppyJoeConfig {
        cargo_git_policy: config::CargoGitPolicy::WarnPinned,
        trusted_git_sources: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec!["https://github.com/yourorg/shared-crate".to_string()],
        )]),
        ..Default::default()
    };
    let rewrite = EffectiveCargoRewrite {
        package_name: "shared".to_string(),
        patch_scope: None,
        replace_source: Some(format!(
            "git+https://github.com/yourorg/shared-crate?rev={rev}#{rev}"
        )),
        replace_version: Some("0.1.0".to_string()),
        spec: parsers::cargo_toml::CargoDependencySpec {
            manifest_name: "shared".to_string(),
            package_name: "shared".to_string(),
            version: None,
            source: parsers::cargo_toml::CargoSourceSpec::Git {
                url: "https://github.com/yourorg/shared-crate".to_string(),
                rev: Some(rev.to_string()),
                branch: None,
                tag: None,
            },
            workspace_member_invalid_keys: Vec::new(),
        },
        base_dir: dir.clone(),
    };
    let err = validate_cargo_effective_rewrite(&dir, &rewrite, &config, &lockfile)
        .expect_err("Cargo git rewrites must still bind the exact replaced package version");
    assert!(err.to_string().contains("Cargo.lock"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_source_qualified_cargo_replace_to_untrusted_local_path() {
    let dir = unique_dir();
    let external = unique_dir();

    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
foo = "=1.0.0"

[replace]
"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228" = {{ path = "{}" }}
"#,
            external.display()
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "foo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abababababababababababababababababababababababababababababababab"

[[package]]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(
        external.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(external.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let err = preflight_project_inputs(&dir, &specs, &config).expect_err(
        "source-qualified Cargo rewrites to local paths must not skip trust validation when the final lockfile entry loses its source",
    );
    assert!(err.to_string().contains("outside the scan root"));

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&external);
}

#[test]
fn preflight_allows_cargo_registry_index_dependency_when_trusted() {
    let dir = unique_dir();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
internal-crate = { registry-index = "https://cargo.company.example/index", version = "=1.2.3" }
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
checksum = "abababababababababababababababababababababababababababababababab"
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
        "Cargo registry-index dependencies should normalize to the trusted lockfile source model: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_does_not_apply_git_scoped_cargo_replace_with_mismatched_rev() {
    let dir = unique_dir();
    let patched = dir.join("patched-shared");
    let replace_rev = "0123456789abcdef0123456789abcdef01234567";
    let actual_rev = "fedcba9876543210fedcba9876543210fedcba98";
    std::fs::create_dir_all(&patched).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
shared = {{ git = "https://github.com/yourorg/shared-crate", rev = "{actual_rev}" }}

[replace]
"git+https://github.com/yourorg/shared-crate?rev={replace_rev}#{replace_rev}#shared@0.1.0" = {{ path = "patched-shared" }}
"#
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        format!(
            r#"version = 4

[[package]]
name = "shared"
version = "0.1.0"
source = "git+https://github.com/yourorg/shared-crate?rev={actual_rev}#{actual_rev}"
"#
        ),
    )
    .unwrap();
    std::fs::write(
        patched.join("Cargo.toml"),
        r#"[package]
name = "shared"
version = "9.9.9"
"#,
    )
    .unwrap();
    std::fs::write(patched.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig {
        cargo_git_policy: config::CargoGitPolicy::WarnPinned,
        trusted_git_sources: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec!["https://github.com/yourorg/shared-crate".to_string()],
        )]),
        ..Default::default()
    };
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "source-qualified Cargo [replace] rules must not match different git revisions: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_cargo_replace_path_with_version_field_without_rewrite_loop() {
    let dir = unique_dir();
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&patched).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"

[replace]
"serde:1.0.228" = { path = "patched-serde", version = "=1.0.228" }
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
        "Cargo rewrite resolution must not loop when a [replace] target is already in its effective final form: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_repo_local_cargo_config_paths_rewrite_to_trusted_local_crate() {
    let dir = unique_dir();
    let cargo_config_dir = dir.join(".cargo");
    let shared = dir.join("shared");
    std::fs::create_dir_all(&cargo_config_dir).unwrap();
    std::fs::create_dir_all(&shared).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
shared = "=0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        cargo_config_dir.join("config.toml"),
        r#"paths = ["../shared"]"#,
    )
    .unwrap();
    std::fs::write(
        shared.join("Cargo.toml"),
        r#"[package]
name = "shared"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(shared.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "trusted repo-local Cargo config paths rewrites should pass strict preflight: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_repo_local_cargo_config_paths_with_ambiguous_package_name() {
    let dir = unique_dir();
    let cargo_config_dir = dir.join(".cargo");
    let shared_a = dir.join("shared-a");
    let shared_b = dir.join("shared-b");
    std::fs::create_dir_all(&cargo_config_dir).unwrap();
    std::fs::create_dir_all(&shared_a).unwrap();
    std::fs::create_dir_all(&shared_b).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
shared = "=0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        cargo_config_dir.join("config.toml"),
        r#"paths = ["../shared-a", "../shared-b"]"#,
    )
    .unwrap();
    std::fs::write(
        shared_a.join("Cargo.toml"),
        r#"[package]
name = "shared"
version = "0.1.0"
"#,
    )
    .unwrap();
    std::fs::write(
        shared_b.join("Cargo.toml"),
        r#"[package]
name = "shared"
version = "0.1.0"
"#,
    )
    .unwrap();

    let err = detected_project_inputs_with_config(
        &dir,
        Some("cargo"),
        &config::SloppyJoeConfig::default(),
    )
    .expect_err("ambiguous Cargo config paths rewrites for the same package must block");
    assert!(err.to_string().contains("multiple local path rewrites"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_repo_local_cargo_config_registry_rewrite_when_trusted() {
    let dir = unique_dir();
    let cargo_config_dir = dir.join(".cargo");
    std::fs::create_dir_all(&cargo_config_dir).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
internal-crate = "=1.2.3"
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
checksum = "abababababababababababababababababababababababababababababababab"
"#,
    )
    .unwrap();
    std::fs::write(
        cargo_config_dir.join("config.toml"),
        r#"[source.crates-io]
replace-with = "company"

[source.company]
registry = "https://cargo.company.example/index"
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
        "trusted repo-local Cargo registry rewrites should pass strict preflight: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_repo_local_cargo_config_alias_with_unsupported_source_definition() {
    let dir = unique_dir();
    let cargo_config_dir = dir.join(".cargo");
    let vendor = dir.join("vendor");
    std::fs::create_dir_all(&cargo_config_dir).unwrap();
    std::fs::create_dir_all(&vendor).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        cargo_config_dir.join("config.toml"),
        r#"[source.crates-io]
replace-with = "company"

[source.company]
directory = "../vendor"
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
    let err = detected_project_inputs_with_config(&dir, Some("cargo"), &config)
        .expect_err("repo-local source definitions must not be masked by allowlisted alias names");
    assert!(err.to_string().contains("unsupported directory source"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn host_local_cargo_config_rewrites_block_by_default() {
    let home = unique_dir();
    let cargo_home = home.join(".cargo");
    std::fs::create_dir_all(&cargo_home).unwrap();
    std::fs::write(cargo_home.join("config.toml"), r#"paths = ["../shared"]"#).unwrap();

    let err = cargo_host_local_config_rewrites_for_test(&home, &config::SloppyJoeConfig::default())
        .expect_err("host-local Cargo config must block by default");
    assert!(err.to_string().contains("host-local"));

    let _ = std::fs::remove_dir_all(&home);
}
