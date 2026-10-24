use super::*;

#[test]
fn scan_hash_changes_with_lockfile() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let id = CTR.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-hash-test-{}-{}", std::process::id(), id));
    std::fs::create_dir_all(&dir).unwrap();

    let deps = vec![Dependency {
        name: "react".to_string(),
        version: Some("^18.0".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }];

    // Hash without lockfile
    let hash_no_lock = scan_hash(&dir, &deps).unwrap();

    // Write a lockfile
    std::fs::write(dir.join("package-lock.json"), r#"{"lockfileVersion":3}"#).unwrap();
    let hash_with_lock = scan_hash(&dir, &deps).unwrap();

    // Change lockfile content
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"node_modules/react":{"version":"18.999.0"}}}"#,
    )
    .unwrap();
    let hash_changed_lock = scan_hash(&dir, &deps).unwrap();

    assert_ne!(
        hash_no_lock, hash_with_lock,
        "Adding lockfile should change hash"
    );
    assert_ne!(
        hash_with_lock, hash_changed_lock,
        "Changing lockfile content should change hash"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scan_hash_for_projects_changes_when_policy_changes() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let specs =
        detected_project_inputs_with_config(&dir, Some("npm"), &config::SloppyJoeConfig::default())
            .unwrap();
    let projects = parse_project_inputs(&dir, &specs, &config::SloppyJoeConfig::default()).unwrap();

    let default_hash = scan_hash_for_projects_with_policy(
        &projects,
        &config::SloppyJoeConfig::default(),
        &ScanOptions::default(),
    )
    .unwrap();
    let allowed_hash = scan_hash_for_projects_with_policy(
        &projects,
        &config::SloppyJoeConfig {
            allowed: std::collections::HashMap::from([(
                "npm".to_string(),
                vec!["react".to_string()],
            )]),
            ..Default::default()
        },
        &ScanOptions::default(),
    )
    .unwrap();

    assert_ne!(
        default_hash, allowed_hash,
        "policy changes must invalidate the dependency-hash shortcut"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scan_hash_for_projects_changes_when_result_shaping_options_change() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let specs =
        detected_project_inputs_with_config(&dir, Some("npm"), &config::SloppyJoeConfig::default())
            .unwrap();
    let projects = parse_project_inputs(&dir, &specs, &config::SloppyJoeConfig::default()).unwrap();

    let default_hash = scan_hash_for_projects_with_policy(
        &projects,
        &config::SloppyJoeConfig::default(),
        &ScanOptions::default(),
    )
    .unwrap();
    let deep_hash = scan_hash_for_projects_with_policy(
        &projects,
        &config::SloppyJoeConfig::default(),
        &ScanOptions {
            deep: true,
            ..Default::default()
        },
    )
    .unwrap();
    let review_hash = scan_hash_for_projects_with_policy(
        &projects,
        &config::SloppyJoeConfig::default(),
        &ScanOptions {
            review_exceptions: true,
            ..Default::default()
        },
    )
    .unwrap();

    assert_ne!(
        default_hash, deep_hash,
        "--deep must invalidate the dependency-hash shortcut"
    );
    assert_ne!(
        default_hash, review_hash,
        "--review-exceptions must invalidate the dependency-hash shortcut"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scan_hash_ignores_shadowed_package_lock_when_shrinkwrap_exists() {
    let dir = unique_dir();
    let deps = vec![Dependency {
        name: "react".to_string(),
        version: Some("^18.0".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }];

    std::fs::write(
        dir.join("npm-shrinkwrap.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"18.3.1"}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"18.3.1"}}}"#,
    )
    .unwrap();

    let hash_before = scan_hash(&dir, &deps).unwrap();

    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"99.0.0"}}}"#,
    )
    .unwrap();

    let hash_after = scan_hash(&dir, &deps).unwrap();
    assert_eq!(
        hash_before, hash_after,
        "shadowed package-lock.json must not affect the hash when npm-shrinkwrap.json is authoritative"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cargo_lockfile_trusts_non_exact_direct_deps_only_when_the_locked_version_satisfies_them() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1.0"
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

    let deps = parsers::cargo_toml::parse(&dir).unwrap();
    let data = lockfiles::LockfileData::parse(&dir, &deps).unwrap();

    assert_eq!(
        data.resolution.exact_version(&deps[0]),
        Some("1.0.228"),
        "the one locked version satisfies serde = \"1.0\", so Cargo.lock decides it"
    );
    assert!(data.resolution.issues.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn composer_lockfile_trust_requires_proven_sync_for_non_exact_direct_deps() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("composer.json"),
        r#"{"require":{"laravel/framework":"^10.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("composer.lock"),
        r#"{"packages":[{"name":"laravel/framework","version":"10.48.29"}]}"#,
    )
    .unwrap();

    let deps = parsers::composer_json::parse(&dir).unwrap();
    let data = lockfiles::LockfileData::parse(&dir, &deps).unwrap();

    assert!(
        data.resolution.exact_version(&deps[0]).is_none(),
        "non-exact Composer direct deps must not be trusted from composer.lock without sync proof"
    );
    assert!(data.resolution.issues.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE_SYNC
            && issue.package == "laravel/framework"
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ruby_lockfile_trust_requires_proven_sync_for_non_exact_direct_deps() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("Gemfile"),
        "source 'https://rubygems.org'\ngem 'rails', '~> 7.0'\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("Gemfile.lock"),
        r#"GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.4)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 7.0)
"#,
    )
    .unwrap();

    let deps = parsers::gemfile::parse(&dir).unwrap();
    let data = lockfiles::LockfileData::parse(&dir, &deps).unwrap();

    assert!(
        data.resolution.exact_version(&deps[0]).is_none(),
        "non-exact Gemfile deps must not be trusted from Gemfile.lock without sync proof"
    );
    assert!(data.resolution.issues.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE_SYNC
            && issue.package == "rails"
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn gradle_lockfile_trust_requires_proven_sync_for_non_exact_direct_deps() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("build.gradle"),
        "repositories {\n  mavenCentral()\n}\ndependencies {\n  implementation 'com.google.guava:guava:[31.0,32.0)'\n}\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("gradle.lockfile"),
        "com.google.guava:guava:31.1-jre=runtimeClasspath\n",
    )
    .unwrap();

    let deps = parsers::jvm::parse_manifest(&dir.join("build.gradle")).unwrap();
    let data = lockfiles::LockfileData::parse_for_kind(&dir, Some(ProjectInputKind::Gradle), &deps)
        .unwrap();

    assert!(
        data.resolution.exact_version(&deps[0]).is_none(),
        "non-exact Gradle direct deps must not be trusted from gradle.lockfile without sync proof"
    );
    assert!(data.resolution.issues.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE_SYNC
            && issue.package == "com.google.guava:guava"
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dotnet_lockfile_trust_requires_proven_sync_for_non_exact_direct_deps() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("app.csproj"),
        r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="[13.0.0,14.0.0)" /></ItemGroup></Project>"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages.lock.json"),
        r#"{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","requested":"[13.0.0,14.0.0)","resolved":"13.0.1"}}}}"#,
    )
    .unwrap();

    let deps = parsers::csproj::parse_file(&dir.join("app.csproj")).unwrap();
    let data = lockfiles::LockfileData::parse_for_kind(&dir, Some(ProjectInputKind::Dotnet), &deps)
        .unwrap();

    assert!(
        data.resolution.exact_version(&deps[0]).is_none(),
        "non-exact .NET direct deps must not be trusted from packages.lock.json without sync proof"
    );
    assert!(data.resolution.issues.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE_SYNC
            && issue.package == "Newtonsoft.Json"
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn poetry_lockfile_trust_requires_proven_sync_for_non_exact_direct_deps() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31.0"
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("poetry.lock"),
        r#"[[package]]
name = "requests"
version = "2.31.0"

[metadata]
lock-version = "2.0"
"#,
    )
    .unwrap();

    let deps = parsers::pyproject_toml::parse_poetry(&dir).unwrap();
    let data = lockfiles::LockfileData::parse_for_kind(
        &dir,
        Some(ProjectInputKind::PyProjectPoetry),
        &deps,
    )
    .unwrap();

    assert!(
        data.resolution.exact_version(&deps[0]).is_none(),
        "non-exact Poetry direct deps must not be trusted from poetry.lock without sync proof"
    );
    assert!(data.resolution.issues.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE_SYNC
            && issue.package == "requests"
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_poetry_lock_missing_artifact_identity_when_policy_is_strict() {
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
files = []

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
        .expect_err("strict Poetry lock policy must fail on missing artifact identity");
    assert!(err.to_string().contains("artifact identity"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_warns_when_poetry_lock_missing_artifact_identity_in_warn_mode() {
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
files = []

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
content-hash = "a2bc317d8861d66a7774092d6797ba6ee5daaddd501c46bf86524f04aa57d234"
"#,
    )
    .unwrap();

    let config = python_config_with_poetry_policy(
        config::PythonEnforcement::PreferPoetry,
        config::PoetryLockPolicy::WarnMissingProofs,
    );
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config)
        .expect("fixture should detect cleanly");
    let warnings = preflight_project_inputs(&dir, &specs, &config)
        .expect("warn policy should downgrade missing artifact identity");
    assert!(warnings.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE
            && issue.message.contains("artifact identity")
    }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn warn_mode_poetry_missing_proof_drops_trusted_transitive_coverage() {
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
optional = false
python-versions = ">=3.8"
files = []

[package.dependencies]
urllib3 = ">=2.0"

[[package]]
name = "urllib3"
version = "2.1.0"
optional = false
python-versions = ">=3.8"
files = []

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
content-hash = "a2bc317d8861d66a7774092d6797ba6ee5daaddd501c46bf86524f04aa57d234"
"#,
    )
    .unwrap();

    let registry = FakeRegistry {
        existing: vec!["requests".to_string(), "urllib3".to_string()],
    };
    let osv = VulnOsvClient {
        vulnerable: vec!["urllib3".to_string()],
    };
    let deps = parsers::pyproject_toml::parse_poetry(&dir).unwrap();
    let report = scan_with_services_inner_for_kind(
        Some(ProjectInputKind::PyProjectPoetry),
        &dir,
        python_config_with_poetry_policy(
            config::PythonEnforcement::PreferPoetry,
            config::PoetryLockPolicy::WarnMissingProofs,
        ),
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
        report.issues.iter().any(|issue| issue.check
            == checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE
            && issue.message.contains("artifact identity")),
        "warn mode should surface reduced-confidence Poetry proof warnings: {:?}",
        report.issues
    );
    assert!(
        !report.issues.iter().any(
            |issue| issue.package == "urllib3" && issue.source.as_deref() == Some("transitive")
        ),
        "warn mode Poetry must not use transitive lock coverage without full proof: {:?}",
        report.issues
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_stale_poetry_content_hash_even_in_warn_mode() {
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
files = [{ file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }]

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
content-hash = "deadbeef"
"#,
    )
    .unwrap();

    let config = python_config_with_poetry_policy(
        config::PythonEnforcement::PreferPoetry,
        config::PoetryLockPolicy::WarnMissingProofs,
    );
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config)
        .expect("fixture should detect cleanly");
    let err = preflight_project_inputs(&dir, &specs, &config)
        .expect_err("stale content hashes are contradictions and must always block");
    assert!(err.to_string().contains("content-hash"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn strict_poetry_rejects_name_only_metadata_hashes_as_artifact_identity() {
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

[metadata.hashes]
requests = ["sha256:1111111111111111111111111111111111111111111111111111111111111111"]
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
        .expect_err("name-only metadata.hashes should not count as exact artifact identity");
    assert!(err.to_string().contains("artifact identity"));

    let _ = std::fs::remove_dir_all(&dir);
}
