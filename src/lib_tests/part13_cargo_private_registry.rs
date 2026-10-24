use super::*;

#[tokio::test]
async fn cargo_private_registry_dependency_scans_with_trusted_lockfile_source() {
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

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("cargo"),
        config,
        &FakeRegistry {
            existing: vec!["internal-crate".to_string()],
        },
        &FakeOsvClient,
        &ScanOptions::default(),
    )
    .await
    .expect("trusted Cargo private registries should survive the full scan path");

    assert_eq!(report.packages_checked, 1);
    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.check.starts_with("resolution/")),
        "trusted Cargo private registry dependency should not degrade into a resolution failure: {:?}",
        report.issues
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_warns_for_cargo_allowlisted_pinned_git_dependency() {
    let dir = unique_dir();
    let rev = "0123456789abcdef0123456789abcdef01234567";
    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
shared = {{ git = "https://github.com/yourorg/shared-crate", rev = "{rev}" }}
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
source = "git+https://github.com/yourorg/shared-crate?rev={rev}#{rev}"
"#
        ),
    )
    .unwrap();

    let config = config::SloppyJoeConfig {
        cargo_git_policy: config::CargoGitPolicy::WarnPinned,
        trusted_git_sources: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec!["https://github.com/yourorg/shared-crate".to_string()],
        )]),
        ..Default::default()
    };
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let warnings = preflight_project_inputs(&dir, &specs, &config)
        .expect("allowlisted pinned Cargo git deps should continue in reduced-confidence mode");
    assert!(warnings.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_REDUCED_CONFIDENCE_GIT
            && issue.package == "shared"
            && issue.severity == Severity::Warning
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_trusted_cargo_patch_rewrite_to_local_path() {
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

[patch.crates-io]
serde = { path = "patched-serde" }
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
        "trusted repo-visible Cargo patch rewrites to local crates should pass strict preflight: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_workspace_root_cargo_patch_rewrite_for_member() {
    let dir = unique_dir();
    let app = dir.join("app");
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::create_dir_all(&patched).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[workspace]
members = ["app", "patched-serde"]

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
serde = "=1.0.228"
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

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "workspace-root Cargo patch rewrites must apply to member crates: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_ignores_member_local_cargo_patch_rewrites() {
    let dir = unique_dir();
    let app = dir.join("app");
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::create_dir_all(&patched).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[workspace]
members = ["app", "patched-serde"]
"#,
    )
    .unwrap();
    std::fs::write(
        app.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"

[patch.crates-io]
serde = { path = "../patched-serde" }
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

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let err = preflight_project_inputs(&dir, &specs, &config)
        .expect_err("member-local Cargo [patch] should be ignored like Cargo itself");
    assert!(err.to_string().contains("Cargo.lock"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn detected_project_inputs_include_workspace_root_cargo_patch_local_crate() {
    let dir = unique_dir();
    let app = dir.join("app");
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::create_dir_all(&patched).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[workspace]
members = ["app", "patched-serde"]

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
serde = "=1.0.228"
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
        "workspace-root Cargo patch targets must be discovered as first-class Cargo projects"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_repo_local_cargo_config_named_source_chain_to_trusted_registry() {
    let dir = unique_dir();
    let cargo_config_dir = dir.join(".cargo");
    std::fs::create_dir_all(&cargo_config_dir).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = { version = "=1.0.228", registry = "company" }
"#,
    )
    .unwrap();
    std::fs::write(
        cargo_config_dir.join("config.toml"),
        r#"[source.company]
replace-with = "mirror"

[source.mirror]
registry = "https://cargo.company.mirror/index"
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://cargo.company.mirror/index"
checksum = "abababababababababababababababababababababababababababababababab"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig {
        trusted_registries: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec![
                config::TrustedRegistry {
                    name: "company".to_string(),
                    source: "registry+https://cargo.company.example/index".to_string(),
                },
                config::TrustedRegistry {
                    name: "mirror".to_string(),
                    source: "registry+https://cargo.company.mirror/index".to_string(),
                },
            ],
        )]),
        ..Default::default()
    };
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let result = preflight_project_inputs(&dir, &specs, &config);
    assert!(
        result.is_ok(),
        "trusted Cargo named-source replacement chains must pass strict preflight: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_repo_local_cargo_config_directory_source_rewrite() {
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
    std::fs::write(
        cargo_config_dir.join("config.toml"),
        r#"[source.crates-io]
replace-with = "vendored"

[source.vendored]
directory = "../vendor"
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let err = detected_project_inputs_with_config(&dir, Some("cargo"), &config)
        .expect_err("unsupported Cargo directory source rewrites must block");
    assert!(err.to_string().contains("unsupported directory source"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_repo_local_cargo_config_patch_rewrite_to_trusted_local_crate() {
    let dir = unique_dir();
    let cargo_config_dir = dir.join(".cargo");
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&cargo_config_dir).unwrap();
    std::fs::create_dir_all(&patched).unwrap();

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
        r#"[patch.crates-io]
serde = { path = "../patched-serde" }
"#,
    )
    .unwrap();
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
        "repo-local Cargo config patch rewrites to trusted local crates must pass strict preflight: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn detected_project_inputs_include_repo_local_cargo_config_patch_local_crate() {
    let dir = unique_dir();
    let cargo_config_dir = dir.join(".cargo");
    let patched = dir.join("patched-serde");
    std::fs::create_dir_all(&cargo_config_dir).unwrap();
    std::fs::create_dir_all(&patched).unwrap();

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
        r#"[patch.crates-io]
serde = { path = "../patched-serde" }
"#,
    )
    .unwrap();
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
        "repo-local Cargo config patch targets must be discovered as first-class Cargo projects"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_conflicting_cargo_patch_rewrites_for_same_scope() {
    let dir = unique_dir();
    let cargo_config_dir = dir.join(".cargo");
    let patched_a = dir.join("patched-serde-a");
    let patched_b = dir.join("patched-serde-b");
    std::fs::create_dir_all(&cargo_config_dir).unwrap();
    std::fs::create_dir_all(&patched_a).unwrap();
    std::fs::create_dir_all(&patched_b).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"

[patch.crates-io]
serde = { path = "patched-serde-a" }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        cargo_config_dir.join("config.toml"),
        r#"[patch.crates-io]
serde = { path = "../patched-serde-b" }
"#,
    )
    .unwrap();
    std::fs::write(
        patched_a.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(
        patched_b.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "1.0.228"
"#,
    )
    .unwrap();

    let err = detected_project_inputs_with_config(
        &dir,
        Some("cargo"),
        &config::SloppyJoeConfig::default(),
    )
    .expect_err("conflicting Cargo rewrites for the same package/scope must fail closed");
    assert!(err.to_string().contains("Conflicting Cargo rewrite"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_cargo_replace_rewrite_with_package_id_spec() {
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
"serde:1.0.228" = { path = "patched-serde" }
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
        "Cargo [replace] entries with package ID specs must resolve through the trusted local rewrite model: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_cargo_replace_target_with_mismatched_package_id_version() {
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
"serde:1.0.228" = { path = "patched-serde" }
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        patched.join("Cargo.toml"),
        r#"[package]
name = "serde"
version = "9.9.9"
"#,
    )
    .unwrap();
    std::fs::write(patched.join("Cargo.lock"), "version = 4\n").unwrap();

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("cargo"), &config).unwrap();
    let err = preflight_project_inputs(&dir, &specs, &config)
        .expect_err("Cargo [replace] targets must match the exact replaced package ID version");
    assert!(err.to_string().contains("declares version"));

    let _ = std::fs::remove_dir_all(&dir);
}

fn cargo_project_with_lock(lock_tail: &str, config: Option<&str>) -> std::path::PathBuf {
    let dir = unique_dir();
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"=1.0.200\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        format!("version = 3\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"serde\"]\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n{lock_tail}"),
    )
    .unwrap();
    if let Some(config) = config {
        std::fs::create_dir_all(dir.join(".cargo")).unwrap();
        std::fs::write(dir.join(".cargo/config.toml"), config).unwrap();
    }
    dir
}

#[test]
fn a_registry_crate_without_a_lockfile_checksum_blocks() {
    let checksum = format!("checksum = \"{}\"\n", "ab".repeat(32));
    let dir = cargo_project_with_lock(&checksum, None);
    preflight_scan_inputs(&dir, Some("cargo")).unwrap();
    let dir_missing = cargo_project_with_lock("", None);
    let err = preflight_scan_inputs(&dir_missing, Some("cargo"))
        .expect_err("a registry crate without a checksum is unverified");
    let msg = err.to_string();
    assert!(
        msg.contains("without a checksum") && msg.contains("serde 1.0.200"),
        "{msg}"
    );
    // Lockfile v1 records checksums in [metadata] instead.
    let legacy = cargo_project_with_lock(
        &format!(
            "\n[metadata]\n\"checksum serde 1.0.200 (registry+https://github.com/rust-lang/crates.io-index)\" = \"{}\"\n",
            "ab".repeat(32)
        ),
        None,
    );
    preflight_scan_inputs(&legacy, Some("cargo")).unwrap();
    for d in [dir, dir_missing, legacy] {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[test]
fn cargo_config_network_and_build_settings_block() {
    let checksum = format!("checksum = \"{}\"\n", "ab".repeat(32));
    for setting in [
        "[http]\nproxy = \"http://evil.example:8080\"\n",
        "[http]\ncainfo = \"certs/evil.pem\"\n",
        "[net]\ngit-fetch-with-cli = true\n",
        "[build]\nrustc-wrapper = \"./wrap.sh\"\n",
        "[registry]\ncredential-provider = \"cargo:token\"\n",
        "include = \"extra.toml\"\n",
        "include = [{ path = \"extra.toml\", optional = true }]\n",
        "[build]\nrustc = \"./fake-rustc\"\n",
        "[build]\nrustflags = [\"-C\", \"linker=./evil.sh\"]\n",
        "[build]\nrustflags = [\"-Clink-arg=-fuse-ld=evil\"]\n",
        "[target.x86_64-unknown-linux-gnu]\nlinker = \"./evil.sh\"\n",
        "[target.'cfg(unix)']\nrunner = \"./evil.sh\"\n",
        "[target.'cfg(unix)']\nrustflags = \"-C linker=./evil.sh\"\n",
        "[env]\nRUSTC_WRAPPER = \"./wrap.sh\"\n",
        "[env]\nCARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER = \"./evil.sh\"\n",
    ] {
        let dir = cargo_project_with_lock(&checksum, Some(setting));
        let err = preflight_scan_inputs(&dir, Some("cargo"))
            .expect_err("a setting the scan cannot verify must block");
        assert!(
            err.to_string().contains("cannot verify"),
            "{setting}: {err}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
    let benign = cargo_project_with_lock(
        &checksum,
        Some(
            "[term]\ncolor = \"never\"\n[env]\nRUST_BACKTRACE = \"1\"\n[build]\nrustflags = [\"-C\", \"target-cpu=native\"]\n",
        ),
    );
    preflight_scan_inputs(&benign, Some("cargo")).unwrap();
    let _ = std::fs::remove_dir_all(benign);
}
