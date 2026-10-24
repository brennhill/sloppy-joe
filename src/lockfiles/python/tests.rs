use super::*;

#[test]
fn filename_matching_accepts_original_project_name_punctuation() {
    // The lock names the project `jaraco-classes`; PyPI files keep the dot.
    assert!(poetry_filename_matches_package_version(
        "jaraco-classes",
        "3.4.0",
        "jaraco.classes-3.4.0-py3-none-any.whl"
    ));
    assert!(poetry_filename_matches_package_version(
        "jaraco-classes",
        "3.4.0",
        "jaraco.classes-3.4.0.tar.gz"
    ));
    assert!(poetry_filename_matches_package_version(
        "zope-interface",
        "7.0",
        "zope.interface-7.0-cp312-cp312-manylinux_2_17_x86_64.whl"
    ));
    assert!(poetry_filename_matches_package_version(
        "Typing_Extensions",
        "4.12.2",
        "typing_extensions-4.12.2-py3-none-any.whl"
    ));
}

#[test]
fn filename_matching_rejects_other_packages_and_versions() {
    assert!(!poetry_filename_matches_package_version(
        "requests",
        "2.32.3",
        "requests_toolbelt-2.32.3-py3-none-any.whl"
    ));
    assert!(!poetry_filename_matches_package_version(
        "requests",
        "2.32.3",
        "requests-2.32.30-py3-none-any.whl"
    ));
    assert!(!poetry_filename_matches_package_version(
        "requests",
        "1.0",
        "requests-1.0.1.tar.gz"
    ));
    assert!(!poetry_filename_matches_package_version(
        "requests",
        "1.0",
        "requests-1.0.1-py3-none-any.whl"
    ));
}

use crate::parsers::pyproject_toml::PythonDependencySourceIntent;

const POETRY_LOCK: &str = r#"
[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."

[[package]]
name = "urllib3"
version = "2.1.0"
description = "HTTP library with thread-safe connection pooling"

[[package]]
name = "certifi"
version = "2023.11.17"
description = "Python package for providing Mozilla's CA Bundle."

[metadata]
lock-version = "2.0"
python-versions = "^3.8"
"#;

const POETRY_LOCK_ALT_SOURCE: &str = r#"
[[package]]
name = "torch"
version = "2.6.0"

[package.source]
type = "explicit"
url = "https://download.pytorch.org/whl/cu124"
reference = "pytorch"

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
"#;

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

fn dep(name: &str, version: Option<&str>) -> Dependency {
    crate::test_helpers::dep_with(name, version, crate::Ecosystem::PyPI)
}

#[test]
fn extract_packages_works() {
    let parsed: toml::Value = toml::from_str(POETRY_LOCK).unwrap();
    let packages = extract_packages(&parsed);
    assert_eq!(packages.len(), 3);
    assert!(
        packages
            .iter()
            .any(|(n, v)| n == "requests" && v == "2.31.0")
    );
    assert!(packages.iter().any(|(n, v)| n == "urllib3" && v == "2.1.0"));
    assert!(
        packages
            .iter()
            .any(|(n, v)| n == "certifi" && v == "2023.11.17")
    );
}

#[test]
fn resolve_finds_version() {
    let parsed: toml::Value = toml::from_str(POETRY_LOCK).unwrap();
    let deps = vec![dep("requests", Some("==2.31.0")), dep("urllib3", None)];
    let result = resolve_from_value(&parsed, &deps).unwrap();
    assert_eq!(result.exact_version(&deps[0]), Some("2.31.0"));
    assert_eq!(result.exact_version(&deps[1]), Some("2.1.0"));
    assert!(result.issues.is_empty());
}

#[test]
fn resolve_pep503_normalized() {
    // poetry.lock has "requests" but dep might be "Requests" or "requests_lib"
    let parsed: toml::Value = toml::from_str(POETRY_LOCK).unwrap();
    let deps = vec![dep("Requests", None)];
    let result = resolve_from_value(&parsed, &deps).unwrap();
    assert_eq!(result.exact_version(&deps[0]), Some("2.31.0"));
}

#[test]
fn resolve_chooses_exact_poetry_version_when_multiple_same_name_packages_exist() {
    let parsed: toml::Value = toml::from_str(
        r#"[[package]]
name = "widget"
version = "1.0.0"

[[package]]
name = "widget"
version = "2.0.0"

[metadata]
lock-version = "2.0"
"#,
    )
    .unwrap();
    let deps = vec![dep("widget", Some("==2.0.0"))];
    let result =
        resolve_from_value_with_mode_and_profile(&parsed, &deps, ResolutionMode::Direct, None)
            .expect("exact Poetry direct deps should match the requested exact version");
    assert_eq!(result.exact_version(&deps[0]), Some("2.0.0"));
    assert!(result.issues.is_empty());
}

#[test]
fn resolve_missing_dep_reports_issue() {
    let parsed: toml::Value = toml::from_str(POETRY_LOCK).unwrap();
    let deps = vec![dep("nonexistent-pkg", None)];
    let result = resolve_from_value(&parsed, &deps).unwrap();
    assert!(result.exact_version(&deps[0]).is_none());
    assert!(!result.issues.is_empty());
    assert!(result.issues[0].check.contains("missing"));
}

#[test]
fn parse_all_extracts_transitive() {
    let parsed: toml::Value = toml::from_str(POETRY_LOCK).unwrap();
    let all = parse_all_from_value(&parsed).unwrap();
    assert_eq!(all.len(), 3);
    let names: Vec<&str> = all.iter().map(|d| d.name.as_str()).collect();
    assert!(names.contains(&"requests"));
    assert!(names.contains(&"urllib3"));
    assert!(names.contains(&"certifi"));
}

#[test]
fn normalize_name_pep503() {
    assert_eq!(normalize_name("Requests"), "requests");
    assert_eq!(normalize_name("my_package"), "my-package");
    assert_eq!(normalize_name("my.package"), "my-package");
    assert_eq!(normalize_name("My__Package"), "my-package");
}

#[test]
fn source_policy_blocks_when_declared_source_has_no_resolved_package() {
    let parsed: toml::Value = toml::from_str(POETRY_LOCK_ALT_SOURCE).unwrap();
    let declared_sources = vec![crate::parsers::pyproject_toml::PythonSourceDecl {
        name: "pytorch".to_string(),
        normalized_url: "https://download.pytorch.org/whl/cu124/".to_string(),
    }];
    let intents = vec![PythonDependencySourceIntent {
        package: "private-lib".to_string(),
        source_name: "pytorch".to_string(),
        normalized_url: "https://download.pytorch.org/whl/cu124/".to_string(),
    }];
    let config = trusted_python_index_config(&["https://download.pytorch.org/whl/cu124"]);
    let err = validate_source_policy(
        &parsed,
        &declared_sources,
        &intents,
        &config,
        Path::new("poetry.lock"),
        None,
        None,
    )
    .expect_err("missing resolved package must fail closed");
    assert!(err.to_string().contains("missing a resolved package entry"));
}

#[test]
fn source_policy_blocks_when_same_package_resolves_from_multiple_sources() {
    let parsed: toml::Value = toml::from_str(
        r#"
[[package]]
name = "torch"
version = "2.6.0"
[package.source]
type = "explicit"
url = "https://download.pytorch.org/whl/cu124"
reference = "pytorch"

[[package]]
name = "torch"
version = "2.6.0"
[package.source]
type = "explicit"
url = "https://packages.example.com/simple"
reference = "mirror"
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
        Path::new("poetry.lock"),
        None,
        None,
    )
    .expect_err("ambiguous source resolution must fail closed");
    assert!(err.to_string().contains("resolves from multiple sources"));
}

#[test]
fn source_policy_rejects_reachable_duplicate_same_version_across_sources() {
    let parsed: toml::Value = toml::from_str(
        r#"
[[package]]
name = "torch"
version = "2.6.0"
[package.source]
type = "explicit"
url = "https://download.pytorch.org/whl/cu124"
reference = "pytorch"

[[package]]
name = "torch"
version = "2.6.0"
[package.source]
type = "explicit"
url = "https://packages.example.com/simple"
reference = "mirror"
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
        Path::new("poetry.lock"),
        Some(&reachable),
        None,
    )
    .expect_err("duplicate same-version packages across sources must fail closed");
    assert!(err.to_string().contains("multiple sources"));
}

#[test]
fn source_policy_blocks_when_non_pypi_lock_source_is_not_declared() {
    let parsed: toml::Value = toml::from_str(POETRY_LOCK_ALT_SOURCE).unwrap();
    let declared_sources = Vec::new();
    let intents = Vec::new();
    let config = trusted_python_index_config(&["https://download.pytorch.org/whl/cu124"]);
    let err = validate_source_policy(
        &parsed,
        &declared_sources,
        &intents,
        &config,
        Path::new("poetry.lock"),
        None,
        None,
    )
    .expect_err("undeclared non-PyPI lock source must fail closed");
    assert!(err.to_string().contains("not declared"));
}
