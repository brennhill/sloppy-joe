use super::*;
use crate::parsers::pyproject_toml::PythonDependencySourceIntent;

const UV_LOCK: &str = r#"version = 1
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
dependencies = [{ name = "requests" }]

[package.metadata]
requires-dist = [{ name = "requests", specifier = "==2.32.3" }]
"#;

fn dep(name: &str, version: Option<&str>) -> Dependency {
    crate::test_helpers::dep_with(name, version, crate::Ecosystem::PyPI)
}

fn trusted_python_index_config(urls: &[&str]) -> crate::config::SloppyJoeConfig {
    let mut config = crate::config::SloppyJoeConfig::default();
    config.trusted_indexes.insert(
        "pypi".to_string(),
        urls.iter()
            .map(|url| crate::config::normalize_python_index_url(url))
            .collect(),
    );
    config
}

#[test]
fn resolve_finds_uv_locked_version() {
    let parsed: toml::Value = toml::from_str(UV_LOCK).unwrap();
    let deps = vec![dep("requests", Some("==2.32.3"))];
    let result = resolve_from_value_with_mode(&parsed, &deps, ResolutionMode::Direct).unwrap();
    assert_eq!(result.exact_version(&deps[0]), Some("2.32.3"));
    assert!(result.issues.is_empty());
}

#[test]
fn resolve_uses_profile_selected_uv_root_specifier_for_exact_deps() {
    let parsed: toml::Value = toml::from_str(
        r#"version = 1
requires-python = ">=3.12"

[[package]]
name = "widget"
version = "1.1.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/example/widget-1.1.0.tar.gz", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", size = 1 }

[[package]]
name = "widget"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/example/widget-2.0.0.tar.gz", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222", size = 1 }

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
{ name = "widget", version = "2.0.0", marker = "sys_platform == 'linux'" },
{ name = "widget", version = "1.1.0", marker = "sys_platform == 'win32'" },
]

[package.metadata]
requires-dist = [
{ name = "widget", specifier = "==2.0.0", marker = "sys_platform == 'linux'" },
{ name = "widget", specifier = "==1.1.0", marker = "sys_platform == 'win32'" },
]
"#,
    )
    .unwrap();
    let deps = vec![dep("widget", Some("==2.0.0"))];
    let lock_profile = PythonLockfileProfile {
        environment: crate::parsers::python_scope::PythonProfile::for_target("linux", "3.12"),
        root_extras: Default::default(),
    };
    let result = resolve_from_value_with_mode_and_profile(
        &parsed,
        &deps,
        ResolutionMode::Direct,
        Some(&lock_profile),
    )
    .expect("profile-selected uv root entries should drive exact direct resolution");
    assert_eq!(result.exact_version(&deps[0]), Some("2.0.0"));
    assert!(result.issues.is_empty());
}

#[test]
fn parse_all_skips_virtual_root_package() {
    let parsed: toml::Value = toml::from_str(UV_LOCK).unwrap();
    let all = parse_all_from_value(&parsed).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].name, "requests");
}

#[test]
fn validate_manifest_consistency_uses_root_dependency_versions_to_disambiguate() {
    let parsed: toml::Value = toml::from_str(
        r#"version = 1
requires-python = ">=3.11"

[[package]]
name = "widget"
version = "1.1.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/example/widget-1.1.0.tar.gz", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", size = 1 }

[[package]]
name = "widget"
version = "2.0.0"
source = { registry = "https://packages.example.com/simple" }
sdist = { url = "https://packages.example.com/files/widget-2.0.0.tar.gz", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222", size = 1 }

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "widget", version = "1.1.0" }]

[package.metadata]
requires-dist = [{ name = "widget", specifier = "^1.0.0" }]
"#,
    )
    .unwrap();
    let deps = vec![dep("widget", Some("^1.0.0"))];
    validate_manifest_consistency(&parsed, &deps, Path::new("uv.lock"), None)
        .expect("root dependency version should disambiguate multiple same-name candidates");
}

#[test]
fn reachable_package_identities_uses_root_dependency_versions_to_disambiguate() {
    let parsed: toml::Value = toml::from_str(
        r#"version = 1
requires-python = ">=3.11"

[[package]]
name = "widget"
version = "1.1.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/example/widget-1.1.0.tar.gz", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", size = 1 }

[[package]]
name = "widget"
version = "2.0.0"
source = { registry = "https://packages.example.com/simple" }
sdist = { url = "https://packages.example.com/files/widget-2.0.0.tar.gz", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222", size = 1 }

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "widget", version = "1.1.0" }]

[package.metadata]
requires-dist = [{ name = "widget", specifier = "^1.0.0" }]
"#,
    )
    .unwrap();
    let deps = vec![dep("widget", Some("^1.0.0"))];
    let reachable = reachable_package_identities(&parsed, &deps, None)
        .expect("root dependency version should select a single reachable candidate");
    assert_eq!(
        reachable,
        [PythonPackageIdentity {
            normalized_name: "widget".to_string(),
            version: "1.1.0".to_string(),
        }]
        .into_iter()
        .collect()
    );
}

#[test]
fn reachable_package_identities_fail_closed_for_ambiguous_non_exact_root() {
    let parsed: toml::Value = toml::from_str(
        r#"version = 1
requires-python = ">=3.11"

[[package]]
name = "widget"
version = "1.1.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/example/widget-1.1.0.tar.gz", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", size = 1 }

[[package]]
name = "widget"
version = "2.0.0"
source = { registry = "https://packages.example.com/simple" }
sdist = { url = "https://packages.example.com/files/widget-2.0.0.tar.gz", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222", size = 1 }
"#,
    )
    .unwrap();
    let deps = vec![dep("widget", Some("^1.0.0"))];
    let err = reachable_package_identities(&parsed, &deps, None)
        .expect_err("ambiguous non-exact uv roots must fail closed");
    assert!(err.to_string().contains("ambiguous"));
}

#[test]
fn reachable_package_identities_respects_marker_scoped_duplicate_root_entries() {
    let parsed: toml::Value = toml::from_str(
        r#"version = 1
requires-python = ">=3.11"

[[package]]
name = "widget"
version = "1.1.0"
source = { registry = "https://packages.example.com/simple" }
sdist = { url = "https://packages.example.com/files/widget-1.1.0.tar.gz", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", size = 1 }

[[package]]
name = "widget"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/example/widget-2.0.0.tar.gz", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222", size = 1 }

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
{ name = "widget", version = "2.0.0", marker = "sys_platform == 'linux'" },
{ name = "widget", version = "1.1.0", marker = "sys_platform == 'win32'" },
]

[package.metadata]
requires-dist = [
{ name = "widget", specifier = ">=2.0.0,<3.0.0", marker = "sys_platform == 'linux'" },
{ name = "widget", specifier = ">=1.0.0,<2.0.0", marker = "sys_platform == 'win32'" },
]
"#,
    )
    .unwrap();
    let deps = vec![dep("widget", Some(">=2.0.0,<3.0.0"))];
    let lock_profile = PythonLockfileProfile {
        environment: crate::parsers::python_scope::PythonProfile::for_target("linux", "3.12"),
        root_extras: Default::default(),
    };
    let reachable = reachable_package_identities(&parsed, &deps, Some(&lock_profile))
        .expect("marker-scoped root entries should select the in-scope root version");
    assert_eq!(
        reachable,
        [PythonPackageIdentity {
            normalized_name: "widget".to_string(),
            version: "2.0.0".to_string(),
        }]
        .into_iter()
        .collect()
    );
}

#[test]
fn validate_manifest_consistency_rejects_root_version_that_contradicts_specifier() {
    let parsed: toml::Value = toml::from_str(
        r#"version = 1
requires-python = ">=3.11"

[[package]]
name = "widget"
version = "1.1.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/example/widget-1.1.0.tar.gz", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", size = 1 }

[[package]]
name = "widget"
version = "2.0.0"
source = { registry = "https://packages.example.com/simple" }
sdist = { url = "https://packages.example.com/files/widget-2.0.0.tar.gz", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222", size = 1 }

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "widget", version = "2.0.0" }]

[package.metadata]
requires-dist = [{ name = "widget", specifier = ">=1.0.0,<2.0.0" }]
"#,
    )
    .unwrap();
    let deps = vec![dep("widget", Some(">=1.0.0,<2.0.0"))];
    let err = validate_manifest_consistency(&parsed, &deps, Path::new("uv.lock"), None)
        .expect_err("root-selected version must still satisfy the matching requires-dist");
    assert!(err.to_string().contains("out of sync"));
}

#[test]
fn source_policy_blocks_when_declared_source_has_no_resolved_package() {
    let parsed: toml::Value = toml::from_str(UV_LOCK).unwrap();
    let declared_sources = vec![crate::parsers::pyproject_toml::PythonSourceDecl {
        name: "pytorch".to_string(),
        normalized_url: "https://download.pytorch.org/whl/cu124/".to_string(),
    }];
    let intents = vec![PythonDependencySourceIntent {
        package: "torch".to_string(),
        source_name: "pytorch".to_string(),
        normalized_url: "https://download.pytorch.org/whl/cu124/".to_string(),
    }];
    let config = trusted_python_index_config(&["https://download.pytorch.org/whl/cu124"]);
    let err = validate_source_policy(
        &parsed,
        &declared_sources,
        &intents,
        &config,
        Path::new("uv.lock"),
        None,
        None,
    )
    .expect_err("missing resolved package must fail closed");
    assert!(err.to_string().contains("missing a resolved package entry"));
}

#[test]
fn source_policy_blocks_when_same_package_resolves_from_multiple_sources() {
    let parsed: toml::Value = toml::from_str(
        r#"version = 1
requires-python = ">=3.11"

[[package]]
name = "torch"
version = "2.6.0"
source = { registry = "https://download.pytorch.org/whl/cu124" }
sdist = { url = "https://download.pytorch.org/packages/torch-2.6.0.tar.gz", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", size = 1 }

[[package]]
name = "torch"
version = "2.6.0"
source = { registry = "https://packages.example.com/simple" }
sdist = { url = "https://packages.example.com/files/torch-2.6.0.tar.gz", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222", size = 1 }
"#,
    )
    .unwrap();
    let declared_sources = vec![
        crate::parsers::pyproject_toml::PythonSourceDecl {
            name: "pytorch".to_string(),
            normalized_url: "https://download.pytorch.org/whl/cu124/".to_string(),
        },
        crate::parsers::pyproject_toml::PythonSourceDecl {
            name: "mirror".to_string(),
            normalized_url: "https://packages.example.com/simple/".to_string(),
        },
    ];
    let intents = vec![PythonDependencySourceIntent {
        package: "torch".to_string(),
        source_name: "pytorch".to_string(),
        normalized_url: "https://download.pytorch.org/whl/cu124/".to_string(),
    }];
    let config = trusted_python_index_config(&[
        "https://download.pytorch.org/whl/cu124",
        "https://packages.example.com/simple",
    ]);
    let err = validate_source_policy(
        &parsed,
        &declared_sources,
        &intents,
        &config,
        Path::new("uv.lock"),
        None,
        None,
    )
    .expect_err("ambiguous source resolution must fail closed");
    assert!(err.to_string().contains("resolves from multiple sources"));
}

#[test]
fn source_policy_rejects_reachable_duplicate_same_version_across_sources() {
    let parsed: toml::Value = toml::from_str(
        r#"version = 1
requires-python = ">=3.11"

[[package]]
name = "torch"
version = "2.6.0"
source = { registry = "https://download.pytorch.org/whl/cu124" }
sdist = { url = "https://download.pytorch.org/packages/torch-2.6.0.tar.gz", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", size = 1 }

[[package]]
name = "torch"
version = "2.6.0"
source = { registry = "https://packages.example.com/simple" }
sdist = { url = "https://packages.example.com/files/torch-2.6.0.tar.gz", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222", size = 1 }
"#,
    )
    .unwrap();
    let declared_sources = vec![
        crate::parsers::pyproject_toml::PythonSourceDecl {
            name: "pytorch".to_string(),
            normalized_url: "https://download.pytorch.org/whl/cu124/".to_string(),
        },
        crate::parsers::pyproject_toml::PythonSourceDecl {
            name: "mirror".to_string(),
            normalized_url: "https://packages.example.com/simple/".to_string(),
        },
    ];
    let config = trusted_python_index_config(&[
        "https://download.pytorch.org/whl/cu124",
        "https://packages.example.com/simple",
    ]);
    let reachable = [PythonPackageIdentity {
        normalized_name: "torch".to_string(),
        version: "2.6.0".to_string(),
    }]
    .into_iter()
    .collect();

    let err = validate_source_policy(
        &parsed,
        &declared_sources,
        &[],
        &config,
        Path::new("uv.lock"),
        Some(&reachable),
        None,
    )
    .expect_err("duplicate same-version packages across sources must fail closed");
    assert!(err.to_string().contains("multiple sources"));
}

#[test]
fn source_policy_blocks_when_non_pypi_lock_source_is_not_declared() {
    let parsed: toml::Value = toml::from_str(
        r#"version = 1
requires-python = ">=3.11"

[[package]]
name = "torch"
version = "2.6.0"
source = { registry = "https://download.pytorch.org/whl/cu124" }
sdist = { url = "https://download.pytorch.org/packages/torch-2.6.0.tar.gz", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", size = 1 }
"#,
    )
    .unwrap();
    let declared_sources = Vec::new();
    let intents = Vec::new();
    let config = trusted_python_index_config(&["https://download.pytorch.org/whl/cu124"]);
    let err = validate_source_policy(
        &parsed,
        &declared_sources,
        &intents,
        &config,
        Path::new("uv.lock"),
        None,
        None,
    )
    .expect_err("undeclared non-PyPI lock source must fail closed");
    assert!(err.to_string().contains("not declared"));
}

#[test]
fn artifact_urls_must_come_from_where_the_registry_serves_files() {
    let path = Path::new("uv.lock");
    let parsed: toml::Value = toml::from_str(UV_LOCK).unwrap();
    validate_provenance(&parsed, path).unwrap();

    // Registry says PyPI but the sdist and wheel point at an attacker's host.
    let evil = UV_LOCK.replace("files.pythonhosted.org", "evil.example");
    let parsed: toml::Value = toml::from_str(&evil).unwrap();
    let err = validate_provenance(&parsed, path).unwrap_err().to_string();
    assert!(err.contains("evil.example"), "{err}");

    // Only the wheel is redirected.
    let wheel_only = UV_LOCK.replace(
        "{ url = \"https://files.pythonhosted.org/packages/example/requests-2.32.3-py3-none-any.whl\"",
        "{ url = \"https://evil.example/requests-2.32.3-py3-none-any.whl\"",
    );
    let parsed: toml::Value = toml::from_str(&wheel_only).unwrap();
    assert!(validate_provenance(&parsed, path).is_err());

    // PyPI files over plain http are not accepted either.
    let http = UV_LOCK.replace(
        "https://files.pythonhosted.org",
        "http://files.pythonhosted.org",
    );
    let parsed: toml::Value = toml::from_str(&http).unwrap();
    assert!(validate_provenance(&parsed, path).is_err());
}

#[test]
fn a_private_registry_may_serve_its_own_artifacts() {
    let path = Path::new("uv.lock");
    let private = UV_LOCK
        .replace("https://pypi.org/simple", "https://pkgs.example.com/simple")
        .replace(
            "https://files.pythonhosted.org/packages",
            "https://pkgs.example.com/files",
        );
    let parsed: toml::Value = toml::from_str(&private).unwrap();
    validate_provenance(&parsed, path).unwrap();

    let elsewhere = private.replace(
        "https://pkgs.example.com/files",
        "https://cdn.example.net/files",
    );
    let parsed: toml::Value = toml::from_str(&elsewhere).unwrap();
    assert!(validate_provenance(&parsed, path).is_err());
}
