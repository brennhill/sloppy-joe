use super::*;

use std::sync::atomic::{AtomicU64, Ordering};
static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir() -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-lockfiles-{}-{}", std::process::id(), id));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn npm_dep(name: &str, version: &str) -> Dependency {
    Dependency {
        name: name.to_string(),
        version: Some(version.to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }
}

fn cargo_dep(name: &str, version: &str) -> Dependency {
    Dependency {
        name: name.to_string(),
        version: Some(version.to_string()),
        ecosystem: Ecosystem::Cargo,
        actual_name: None,
    }
}

// -- Resolution tests (unchanged, exercising the same public API) --

#[test]
fn uses_manifest_exact_when_no_supported_lockfile_exists() {
    let dir = unique_dir();
    let deps = vec![npm_dep("react", "18.3.1")];
    let result = resolve_versions(&dir, &deps).unwrap();
    let resolved = result.resolved_version(&deps[0]).unwrap();
    assert_eq!(resolved.version, "18.3.1");
    assert_eq!(resolved.source, ResolutionSource::ManifestExact);
    assert!(result.issues.is_empty());
}

#[test]
fn npm_package_lock_v3_resolves_direct_dependency() {
    let dir = unique_dir();
    std::fs::write(dir.join("package-lock.json"), r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.2.0"}},"node_modules/react":{"version":"18.3.1"}}}"#).unwrap();
    let deps = vec![npm_dep("react", "^18.2.0")];
    let result = resolve_versions(&dir, &deps).unwrap();
    let resolved = result.resolved_version(&deps[0]).unwrap();
    assert_eq!(resolved.version, "18.3.1");
    assert_eq!(resolved.source, ResolutionSource::Lockfile);
    assert!(result.issues.is_empty());
}

#[test]
fn npm_package_lock_v1_resolves_direct_dependency() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":1,"dependencies":{"react":{"version":"18.3.1"}}}"#,
    )
    .unwrap();
    let deps = vec![npm_dep("react", "^18.2.0")];
    let result = resolve_versions(&dir, &deps).unwrap();
    assert_eq!(result.resolved_version(&deps[0]).unwrap().version, "18.3.1");
}

#[test]
fn npm_shrinkwrap_takes_precedence_over_package_lock() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.2.0"}},"node_modules/react":{"version":"18.3.1"}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("npm-shrinkwrap.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.2.0"}},"node_modules/react":{"version":"18.2.9"}}}"#,
    )
    .unwrap();
    let deps = vec![npm_dep("react", "^18.2.0")];
    let result = resolve_versions(&dir, &deps).unwrap();
    assert_eq!(result.resolved_version(&deps[0]).unwrap().version, "18.2.9");
}

#[test]
fn npm_alias_resolves_against_alias_path_but_real_package_identity() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"lodash":"npm:evil-pkg@1.2.3"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"lodash":"npm:evil-pkg@1.2.3"}},"node_modules/lodash":{"name":"evil-pkg","version":"1.2.3"}}}"#,
    )
    .unwrap();

    let deps = crate::parsers::package_json::parse(&dir).unwrap();
    let data = LockfileData::parse(&dir, &deps).unwrap();

    assert_eq!(data.resolution.exact_version(&deps[0]), Some("1.2.3"));
    assert!(
        data.transitive_deps.is_empty(),
        "direct alias target must not be reintroduced as transitive"
    );
}

#[test]
fn npm_parse_retains_nested_versions_of_direct_package_names() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1"},"node_modules/other":{"version":"1.0.0"},"node_modules/other/node_modules/react":{"version":"17.0.2"}}}"#,
    )
    .unwrap();

    let direct = vec![npm_dep("react", "18.3.1")];
    let data = LockfileData::parse(&dir, &direct).expect(
        "nested locked versions of a direct package must still be scanned as transitive deps",
    );

    assert!(
        data.transitive_deps
            .iter()
            .any(|dep| dep.name == "react" && dep.version.as_deref() == Some("17.0.2")),
        "nested direct-name versions must remain visible as transitive deps"
    );
}

#[test]
fn npm_parse_skips_linked_workspace_entries() {
    let lockfile = r#"{
        "packages": {
            "": { "name": "demo" },
            "packages/local-lib": { "name": "local-lib", "version": "1.0.0" },
            "node_modules/local-lib": { "resolved": "packages/local-lib", "link": true },
            "node_modules/react": { "version": "18.3.1" }
        }
    }"#;
    let deps =
        npm::parse_all(lockfile).expect("lockfile parsing should ignore linked local entries");
    let names: Vec<&str> = deps.iter().map(|dep| dep.name.as_str()).collect();
    assert_eq!(names, vec!["react"]);
}

#[test]
fn npm_v1_lockfile_data_disables_transitive_extraction() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":1,"dependencies":{"react":{"version":"18.3.1","dependencies":{"loose-envify":{"version":"1.4.0"}}}}}"#,
    )
    .unwrap();

    let direct = vec![npm_dep("react", "18.3.1")];
    let data = LockfileData::parse(&dir, &direct)
        .expect("legacy npm lockfiles should still parse for reduced-trust direct resolution");

    assert!(
        data.transitive_deps.is_empty(),
        "legacy npm v1 lockfiles must not claim trusted transitive coverage"
    );
}

#[test]
fn npm_exact_pin_out_of_sync_emits_resolution_issue() {
    let dir = unique_dir();
    std::fs::write(dir.join("package-lock.json"), r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.2.0"}},"node_modules/react":{"version":"18.3.1"}}}"#).unwrap();
    let deps = vec![npm_dep("react", "18.2.0")];
    let result = resolve_versions(&dir, &deps).unwrap();
    assert_eq!(
        result.resolved_version(&deps[0]).unwrap().source,
        ResolutionSource::ManifestExact
    );
    assert!(
        result
            .issues
            .iter()
            .any(|i| i.check == crate::names::RESOLUTION_LOCKFILE_OUT_OF_SYNC)
    );
}

#[test]
fn npm_missing_direct_dependency_emits_resolution_issue() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo"}}}"#,
    )
    .unwrap();
    let deps = vec![npm_dep("react", "^18.2.0")];
    let result = resolve_versions(&dir, &deps).unwrap();
    assert!(result.resolved_version(&deps[0]).is_none());
    assert!(
        result
            .issues
            .iter()
            .any(|i| i.check == crate::names::RESOLUTION_MISSING_LOCKFILE_ENTRY)
    );
}

#[test]
fn npm_malformed_lockfile_emits_parse_failed_issue() {
    let dir = unique_dir();
    std::fs::write(dir.join("package-lock.json"), "{not json").unwrap();
    let deps = vec![npm_dep("react", "18.2.0")];
    let result = resolve_versions(&dir, &deps).unwrap();
    assert_eq!(
        result.resolved_version(&deps[0]).unwrap().source,
        ResolutionSource::ManifestExact
    );
    assert!(
        result
            .issues
            .iter()
            .any(|i| i.check == crate::names::RESOLUTION_PARSE_FAILED)
    );
}

#[test]
fn lockfile_data_parse_npm_malformed_lockfile_errors() {
    let dir = unique_dir();
    std::fs::write(dir.join("package-lock.json"), "{not json").unwrap();
    let deps = vec![npm_dep("react", "^18.2.0")];

    let err = match LockfileData::parse(&dir, &deps) {
        Ok(_) => panic!("malformed npm lockfiles must block scanning"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("package-lock.json"));
}

#[test]
fn cargo_lock_resolves_single_locked_version() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("Cargo.lock"),
        "[[package]]\nname = \"serde\"\nversion = \"1.0.203\"\n",
    )
    .unwrap();
    let deps = vec![cargo_dep("serde", "=1.0.203")];
    let result = resolve_versions(&dir, &deps).unwrap();
    assert_eq!(
        result.resolved_version(&deps[0]).unwrap().version,
        "1.0.203"
    );
    assert_eq!(
        result.resolved_version(&deps[0]).unwrap().source,
        ResolutionSource::Lockfile
    );
}

#[test]
fn cargo_lock_uses_exact_manifest_match_when_multiple_versions_exist() {
    let dir = unique_dir();
    std::fs::write(dir.join("Cargo.lock"), "[[package]]\nname = \"serde\"\nversion = \"1.0.201\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.203\"\n").unwrap();
    let deps = vec![cargo_dep("serde", "=1.0.203")];
    let result = resolve_versions(&dir, &deps).unwrap();
    assert_eq!(
        result.resolved_version(&deps[0]).unwrap().version,
        "1.0.203"
    );
}

#[test]
fn cargo_lock_resolves_lockfile_extracted_version_against_multiple() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("Cargo.lock"),
        "[[package]]\nname = \"serde\"\nversion = \"1.0.203\"\n\n[[package]]\nname = \"windows-sys\"\nversion = \"0.52.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"windows-sys\"\nversion = \"0.59.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
    ).unwrap();
    let direct = vec![cargo_dep("serde", "=1.0.203")];
    let data = LockfileData::parse(&dir, &direct).unwrap();
    let deps = vec![cargo_dep("windows-sys", "0.52.0")];
    let result = data.resolve_transitive(&deps).unwrap();
    assert_eq!(
        result.resolved_version(&deps[0]).unwrap().version,
        "0.52.0",
        "Lockfile-extracted version should resolve against multiple versions"
    );
    assert!(
        !result
            .issues
            .iter()
            .any(|i| i.check == crate::names::RESOLUTION_AMBIGUOUS),
        "Should not emit ambiguous issue when version matches"
    );
}

#[test]
fn cargo_lock_ambiguous_versions_emit_resolution_issue() {
    let dir = unique_dir();
    std::fs::write(dir.join("Cargo.lock"), "[[package]]\nname = \"serde\"\nversion = \"1.0.201\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.203\"\n").unwrap();
    let deps = vec![cargo_dep("serde", "1")];
    let result = resolve_versions(&dir, &deps).unwrap();
    assert!(result.resolved_version(&deps[0]).is_none());
    assert!(
        result
            .issues
            .iter()
            .any(|i| i.check == crate::names::RESOLUTION_AMBIGUOUS)
    );
}

#[test]
fn cargo_lock_missing_direct_dependency_emits_resolution_issue() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("Cargo.lock"),
        "[[package]]\nname = \"tokio\"\nversion = \"1.42.0\"\n",
    )
    .unwrap();
    let deps = vec![cargo_dep("serde", "1")];
    let result = resolve_versions(&dir, &deps).unwrap();
    assert!(result.resolved_version(&deps[0]).is_none());
    assert!(
        result
            .issues
            .iter()
            .any(|i| i.check == crate::names::RESOLUTION_MISSING_LOCKFILE_ENTRY)
    );
}

#[test]
fn parse_all_npm_fails_on_malformed_json() {
    let result = npm::parse_all("{not valid json");
    assert!(result.is_err());
}

#[test]
fn parse_all_npm_succeeds_on_valid_lockfile() {
    let content = r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo"},"node_modules/react":{"version":"18.3.1"},"node_modules/lodash":{"version":"4.17.21"}}}"#;
    let deps = npm::parse_all(content).unwrap();
    assert_eq!(deps.len(), 2);
    assert!(deps.iter().any(|d| d.name == "react"));
    assert!(deps.iter().any(|d| d.name == "lodash"));
}

#[test]
fn parse_all_cargo_fails_on_malformed_toml() {
    let result = cargo::parse_all("[[package]");
    assert!(result.is_err());
}

#[test]
fn parse_all_cargo_succeeds_on_valid_lockfile() {
    let content = "[[package]]\nname = \"serde\"\nversion = \"1.0.203\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"tokio\"\nversion = \"1.42.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
    let deps = cargo::parse_all(content).unwrap();
    assert_eq!(deps.len(), 2);
    assert!(deps.iter().any(|d| d.name == "serde"));
    assert!(deps.iter().any(|d| d.name == "tokio"));
}

#[test]
fn cargo_lock_rejects_path_traversal() {
    let dir = unique_dir();
    std::fs::write(dir.join("Cargo.lock"), "[[package]]\nname = \"../malicious\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"safe-pkg\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"foo\\u0000bar\"\nversion = \"1.0.0\"\n").unwrap();
    let deps = vec![
        cargo_dep("../malicious", "=1.0.0"),
        cargo_dep("safe-pkg", "=1.0.0"),
    ];
    let result = resolve_versions(&dir, &deps).unwrap();
    assert!(
        result
            .resolved_version(&deps[0])
            .is_none_or(|resolved| resolved.source == ResolutionSource::ManifestExact)
    );
    assert_eq!(result.resolved_version(&deps[1]).unwrap().version, "1.0.0");
}

#[test]
fn cargo_lock_malformed_lockfile_emits_parse_failed_issue() {
    let dir = unique_dir();
    std::fs::write(dir.join("Cargo.lock"), "[[package]").unwrap();
    let deps = vec![cargo_dep("serde", "1")];
    let result = resolve_versions(&dir, &deps).unwrap();
    assert!(result.resolved_version(&deps[0]).is_none());
    assert!(
        result
            .issues
            .iter()
            .any(|i| i.check == crate::names::RESOLUTION_PARSE_FAILED)
    );
}

#[test]
fn lockfile_data_parse_provides_resolution_and_transitive() {
    let dir = unique_dir();
    std::fs::write(dir.join("package-lock.json"), r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.2.0"}},"node_modules/react":{"version":"18.3.1"},"node_modules/loose-envify":{"version":"1.4.0"}}}"#).unwrap();
    let direct = vec![npm_dep("react", "^18.2.0")];
    let data = LockfileData::parse(&dir, &direct).unwrap();
    assert_eq!(data.resolution.exact_version(&direct[0]), Some("18.3.1"));
    assert_eq!(data.transitive_deps.len(), 1);
    assert_eq!(data.transitive_deps[0].name, "loose-envify");
}

#[test]
fn lockfile_data_parse_keeps_transitive_coverage_when_one_direct_dep_lacks_trusted_sync() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("Cargo.lock"),
        r#"version = 4

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "rand"
version = "0.8.5"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "libc"
version = "0.2.170"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
    )
    .unwrap();
    let direct = vec![
        cargo_dep("serde", "1.0.228"),
        Dependency {
            name: "rand".to_string(),
            version: Some("0.8 || 0.9".to_string()),
            ecosystem: Ecosystem::Cargo,
            actual_name: None,
        },
    ];
    let data = LockfileData::parse(&dir, &direct).unwrap();

    assert!(data.resolution.issues.iter().any(|issue| issue.check
        == crate::names::RESOLUTION_NO_TRUSTED_LOCKFILE_SYNC
        && issue.package == "rand"));
    assert!(
        data.transitive_deps.iter().any(|dep| dep.name == "libc"),
        "transitive lockfile coverage should remain available for the rest of the graph even when one direct dependency lacks trusted lockfile sync"
    );
}

// ── Ruby lockfile path tests ──

fn ruby_dep(name: &str, version: &str) -> Dependency {
    Dependency {
        name: name.to_string(),
        version: Some(version.to_string()),
        ecosystem: Ecosystem::Ruby,
        actual_name: None,
    }
}

fn pypi_dep(name: &str, version: &str) -> Dependency {
    Dependency {
        name: name.to_string(),
        version: Some(version.to_string()),
        ecosystem: Ecosystem::PyPI,
        actual_name: None,
    }
}

fn go_dep(name: &str, version: &str) -> Dependency {
    Dependency {
        name: name.to_string(),
        version: Some(version.to_string()),
        ecosystem: Ecosystem::Go,
        actual_name: None,
    }
}

fn php_dep(name: &str, version: Option<&str>) -> Dependency {
    Dependency {
        name: name.to_string(),
        version: version.map(str::to_string),
        ecosystem: Ecosystem::Php,
        actual_name: None,
    }
}

fn jvm_dep(name: &str, version: Option<&str>) -> Dependency {
    Dependency {
        name: name.to_string(),
        version: version.map(str::to_string),
        ecosystem: Ecosystem::Jvm,
        actual_name: None,
    }
}

fn dotnet_dep(name: &str, version: Option<&str>) -> Dependency {
    Dependency {
        name: name.to_string(),
        version: version.map(str::to_string),
        ecosystem: Ecosystem::Dotnet,
        actual_name: None,
    }
}

#[test]
fn ruby_lockfile_resolves_versions() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("Gemfile.lock"),
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n    pg (1.4.5)\n\nPLATFORMS\n  ruby\n",
    )
    .unwrap();
    let deps = vec![ruby_dep("rails", "7.0.4"), ruby_dep("pg", "1.4.5")];
    let result = resolve_versions(&dir, &deps).unwrap();
    assert_eq!(result.resolved_version(&deps[0]).unwrap().version, "7.0.4");
    assert_eq!(result.resolved_version(&deps[1]).unwrap().version, "1.4.5");
}

#[test]
fn ruby_no_lockfile_uses_manifest_fallback() {
    let dir = unique_dir();
    // No Gemfile.lock — should fall back to manifest exact
    let deps = vec![ruby_dep("rails", "7.0.4")];
    let result = resolve_versions(&dir, &deps).unwrap();
    // "7.0.4" is exact for Ruby ecosystem
    assert_eq!(
        result.resolved_version(&deps[0]).unwrap().source,
        ResolutionSource::ManifestExact
    );
}

#[test]
fn python_poetry_projects_use_poetry_lock() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("poetry.lock"),
        "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[metadata]\nlock-version = \"2.0\"\npython-versions = \"^3.8\"\n",
    )
    .unwrap();
    let deps = vec![pypi_dep("requests", "==2.31.0")];
    let result = LockfileData::parse_for_kind(&dir, Some(LockfileKind::PYPI), &deps)
        .unwrap()
        .resolution;
    assert_eq!(
        result.resolved_version(&deps[0]).unwrap().source,
        ResolutionSource::Lockfile
    );
}

#[test]
fn python_uv_projects_use_uv_lock() {
    let dir = unique_dir();
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
    let deps = vec![pypi_dep("requests", "==2.32.3")];
    let result = LockfileData::parse_for_kind(&dir, Some(LockfileKind::UV), &deps)
        .unwrap()
        .resolution;
    assert_eq!(
        result.resolved_version(&deps[0]).unwrap().source,
        ResolutionSource::Lockfile
    );
}

#[test]
fn legacy_python_projects_do_not_use_poetry_lock() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("poetry.lock"),
        "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[metadata]\nlock-version = \"2.0\"\npython-versions = \"^3.8\"\n",
    )
    .unwrap();
    let deps = vec![pypi_dep("requests", "==2.31.0")];
    let result = LockfileData::parse_for_kind(&dir, Some(LockfileKind::ABSENT), &deps)
        .unwrap()
        .resolution;
    assert_eq!(
        result.resolved_version(&deps[0]).unwrap().source,
        ResolutionSource::ManifestExact
    );
}

#[test]
fn python_no_lockfile_uses_manifest_fallback() {
    let dir = unique_dir();
    let deps = vec![pypi_dep("requests", "==2.31.0")];
    let result = resolve_versions(&dir, &deps).unwrap();
    assert_eq!(
        result.resolved_version(&deps[0]).unwrap().source,
        ResolutionSource::ManifestExact
    );
}

#[test]
fn lockfile_data_parse_python_rejects_malformed_poetry_lockfiles() {
    let dir = unique_dir();
    std::fs::write(dir.join("poetry.lock"), "not = [valid").unwrap();
    let deps = vec![pypi_dep("requests", "==2.31.0")];

    let err = match LockfileData::parse(&dir, &deps) {
        Ok(_) => panic!("trusted Python lockfiles must fail closed on parse errors"),
        Err(err) => err,
    };
    assert!(err.to_string().contains("poetry.lock"));
}

#[test]
fn maven_projects_do_not_read_gradle_lockfiles() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("gradle.lockfile"),
        "com.google.guava:guava:31.1-jre=compileClasspath\n",
    )
    .unwrap();
    let deps = vec![jvm_dep("com.google.guava:guava", Some("31.1-jre"))];

    let data = LockfileData::parse_for_kind(&dir, Some(LockfileKind::ABSENT), &deps)
        .expect("Maven projects must not consume gradle.lockfile");

    assert_eq!(
        data.resolution.resolved_version(&deps[0]).unwrap().source,
        ResolutionSource::ManifestExact
    );
    assert!(data.transitive_deps.is_empty());
}

#[test]
fn go_no_lockfile_uses_manifest_fallback() {
    let dir = unique_dir();
    let deps = vec![go_dep("github.com/gin-gonic/gin", "v1.9.0")];
    let result = resolve_versions(&dir, &deps).unwrap();
    // Go ecosystem uses the "other" fallback path
    assert_eq!(
        result.resolved_version(&deps[0]).unwrap().source,
        ResolutionSource::ManifestExact
    );
}

#[test]
fn lockfile_data_parse_ruby_with_transitive() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("Gemfile.lock"),
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n    actioncable (7.0.4)\n    pg (1.4.5)\n\nPLATFORMS\n  ruby\n",
    )
    .unwrap();
    let direct = vec![ruby_dep("rails", "7.0.4")];
    let data = LockfileData::parse(&dir, &direct).unwrap();
    assert_eq!(data.resolution.exact_version(&direct[0]), Some("7.0.4"));
    // actioncable and pg are transitive
    assert!(data.transitive_deps.len() >= 2);
    let names: Vec<&str> = data
        .transitive_deps
        .iter()
        .map(|d| d.name.as_str())
        .collect();
    assert!(names.contains(&"actioncable"));
    assert!(names.contains(&"pg"));
}

#[test]
fn lockfile_data_parse_python_exposes_transitive_dependencies_from_trusted_lockfile() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("poetry.lock"),
        "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[package.dependencies]\nurllib3 = \">=2.0\"\n\n[[package]]\nname = \"urllib3\"\nversion = \"2.1.0\"\n\n[metadata]\nlock-version = \"2.0\"\npython-versions = \"^3.8\"\n",
    )
    .unwrap();
    let direct = vec![pypi_dep("requests", "==2.31.0")];
    let data = LockfileData::parse(&dir, &direct).unwrap();
    assert_eq!(data.resolution.exact_version(&direct[0]), Some("2.31.0"));
    assert!(
        data.transitive_deps
            .iter()
            .any(|dep| dep.name == "urllib3" && dep.version.as_deref() == Some("2.1.0"))
    );
}

#[test]
fn lockfile_data_parse_php_with_transitive() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("composer.lock"),
        r#"{
  "packages": [
{"name": "laravel/framework", "version": "v10.0.0"},
{"name": "symfony/console", "version": "v6.4.0"}
  ],
  "packages-dev": []
}"#,
    )
    .unwrap();
    let direct = vec![php_dep("laravel/framework", Some("v10.0.0"))];
    let data = LockfileData::parse(&dir, &direct).unwrap();
    let resolved = data.resolution.resolved_version(&direct[0]).unwrap();
    assert_eq!(resolved.version, "v10.0.0");
    assert_eq!(resolved.source, ResolutionSource::Lockfile);
    assert_eq!(data.transitive_deps.len(), 1);
    assert_eq!(data.transitive_deps[0].name, "symfony/console");
}

#[test]
fn lockfile_data_parse_gradle_with_transitive() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("gradle.lockfile"),
        "\
org.slf4j:slf4j-api:2.0.9=compileClasspath,runtimeClasspath\n\
ch.qos.logback:logback-core:1.4.14=runtimeClasspath\n\
empty=annotationProcessor\n",
    )
    .unwrap();
    let direct = vec![jvm_dep("org.slf4j:slf4j-api", None)];
    let data = LockfileData::parse(&dir, &direct).unwrap();
    let resolved = data.resolution.resolved_version(&direct[0]).unwrap();
    assert_eq!(resolved.version, "2.0.9");
    assert_eq!(resolved.source, ResolutionSource::Lockfile);
    assert_eq!(data.transitive_deps.len(), 1);
    assert_eq!(data.transitive_deps[0].name, "ch.qos.logback:logback-core");
}

#[test]
fn lockfile_data_parse_dotnet_with_transitive() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("packages.lock.json"),
        r#"{
  "version": 1,
  "dependencies": {
".NETCoreApp,Version=v8.0": {
  "Newtonsoft.Json": {
    "type": "Direct",
    "requested": "13.0.1",
    "resolved": "13.0.1",
    "dependencies": {
      "System.Runtime.CompilerServices.Unsafe": "6.0.0"
    }
  },
  "System.Runtime.CompilerServices.Unsafe": {
    "type": "Transitive",
    "resolved": "6.0.0"
  }
}
  }
}"#,
    )
    .unwrap();
    let direct = vec![dotnet_dep("Newtonsoft.Json", Some("13.0.1"))];
    let data = LockfileData::parse(&dir, &direct).unwrap();
    let resolved = data.resolution.resolved_version(&direct[0]).unwrap();
    assert_eq!(resolved.version, "13.0.1");
    assert_eq!(resolved.source, ResolutionSource::Lockfile);
    assert_eq!(data.transitive_deps.len(), 1);
    assert_eq!(
        data.transitive_deps[0].name,
        "System.Runtime.CompilerServices.Unsafe"
    );
}

#[test]
fn lockfile_data_parse_no_lockfile_returns_empty_transitive() {
    let dir = unique_dir();
    let direct = vec![npm_dep("react", "18.3.1")];
    let data = LockfileData::parse(&dir, &direct).unwrap();
    assert!(data.transitive_deps.is_empty());
}

#[test]
fn resolve_versions_empty_deps_returns_default() {
    let dir = unique_dir();
    let deps: Vec<Dependency> = vec![];
    let result = resolve_versions(&dir, &deps).unwrap();
    assert!(result.exact_versions.is_empty());
    assert!(result.issues.is_empty());
}
