use super::{
    ResolutionKey, ResolutionMode, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, missing_entry_issue, no_trusted_lockfile_sync_issue,
    out_of_sync_issue,
};
use crate::{Dependency, parsers::pyproject_toml::PythonDependencySourceIntent};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[cfg(test)]
use super::add_manifest_exact_fallbacks;

/// Resolve versions from a pre-parsed poetry.lock TOML value.
#[cfg(test)]
pub(super) fn resolve_from_value(
    parsed: &toml::Value,
    deps: &[Dependency],
) -> Result<ResolutionResult> {
    resolve_from_value_with_mode(parsed, deps, ResolutionMode::Direct)
}

pub(super) fn resolve_from_value_with_mode(
    parsed: &toml::Value,
    deps: &[Dependency],
    mode: ResolutionMode,
) -> Result<ResolutionResult> {
    let packages = extract_packages(parsed);
    let mut result = ResolutionResult::default();

    for dep in deps {
        // PEP 503 normalize: lowercase, replace [-_.] with -
        let normalized = normalize_name(&dep.name);
        match packages
            .iter()
            .find(|(n, _)| normalize_name(n) == normalized)
        {
            Some((_, version)) => {
                if let Some(exact_manifest) = dep.exact_version()
                    && exact_manifest != *version
                {
                    result.push_issue_for(dep, out_of_sync_issue(dep, version));
                    add_manifest_exact_fallback(&mut result, dep);
                    continue;
                }
                if mode == ResolutionMode::Direct
                    && dep.version.is_some()
                    && dep.exact_version().is_none()
                {
                    result.push_issue_for(dep, no_trusted_lockfile_sync_issue(dep, "poetry.lock"));
                    continue;
                }
                result.exact_versions.insert(
                    ResolutionKey::from(dep),
                    ResolvedVersion {
                        version: version.clone(),
                        source: ResolutionSource::Lockfile,
                    },
                );
            }
            None => {
                result.push_issue_for(dep, missing_entry_issue(dep, "poetry.lock"));
                add_manifest_exact_fallback(&mut result, dep);
            }
        }
    }

    Ok(result)
}

/// Parse all packages from a pre-parsed poetry.lock TOML value.
pub(super) fn parse_all_from_value(parsed: &toml::Value) -> Result<Vec<Dependency>> {
    Ok(extract_packages(parsed)
        .into_iter()
        .map(|(name, version)| Dependency {
            name,
            version: Some(version),
            ecosystem: crate::Ecosystem::PyPI,
            actual_name: None,
        })
        .collect())
}

pub(super) fn read_lockfile(project_dir: &Path) -> Result<Option<toml::Value>> {
    let path = project_dir.join("poetry.lock");
    if !crate::parsers::path_detected(&path)? {
        return Ok(None);
    }
    let content = crate::parsers::read_file_limited(&path, crate::parsers::MAX_MANIFEST_BYTES)?;
    let parsed = toml::from_str(&content)
        .map_err(|err| anyhow::anyhow!("Failed to parse {}: {}", path.display(), err))?;
    Ok(Some(parsed))
}

pub(crate) fn validate_source_policy(
    parsed: &toml::Value,
    declared_sources: &[crate::parsers::pyproject_toml::PythonSourceDecl],
    source_intents: &[PythonDependencySourceIntent],
    config: &crate::config::SloppyJoeConfig,
    source_path: &Path,
) -> Result<(HashSet<String>, HashSet<String>)> {
    let mut used_source_urls = HashSet::new();
    let mut used_source_names = HashSet::new();
    let mut package_sources: HashMap<String, HashSet<String>> = HashMap::new();
    let declared_source_names: HashMap<String, String> = declared_sources
        .iter()
        .map(|source| (source.name.to_lowercase(), source.normalized_url.clone()))
        .collect();
    let declared_source_urls: HashSet<String> = declared_sources
        .iter()
        .map(|source| source.normalized_url.clone())
        .collect();

    let Some(packages) = parsed.get("package").and_then(|value| value.as_array()) else {
        return Ok((used_source_urls, used_source_names));
    };

    for pkg in packages {
        let table = pkg.as_table().ok_or_else(|| {
            anyhow::anyhow!(
                "Broken lockfile '{}': package entry must be a table",
                source_path.display()
            )
        })?;
        let name = table
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Broken lockfile '{}': package entry missing name",
                    source_path.display()
                )
            })?;
        let normalized_name = normalize_name(name);
        let (source_url, source_name) = poetry_package_source(table, source_path, name)?;
        if !config.is_trusted_index("pypi", &source_url) {
            anyhow::bail!(
                "Broken lockfile '{}': package '{}' resolves from untrusted Python index '{}'",
                source_path.display(),
                crate::report::sanitize_for_terminal(name),
                source_url
            );
        }
        if source_url != crate::config::normalized_default_pypi_index() {
            match source_name.as_deref() {
                Some(source_name) => {
                    let Some(declared_url) = declared_source_names.get(&source_name.to_lowercase())
                    else {
                        anyhow::bail!(
                            "Broken lockfile '{}': package '{}' resolves from source '{}' that is not declared in '{}'",
                            source_path.display(),
                            crate::report::sanitize_for_terminal(name),
                            crate::report::sanitize_for_terminal(source_name),
                            source_path
                                .parent()
                                .unwrap_or_else(|| Path::new("."))
                                .join("pyproject.toml")
                                .display()
                        );
                    };
                    if declared_url != &source_url {
                        anyhow::bail!(
                            "Broken lockfile '{}': package '{}' resolves from source '{}' ({}) but pyproject.toml declares that source as {}",
                            source_path.display(),
                            crate::report::sanitize_for_terminal(name),
                            crate::report::sanitize_for_terminal(source_name),
                            source_url,
                            declared_url
                        );
                    }
                }
                None if !declared_source_urls.contains(&source_url) => {
                    anyhow::bail!(
                        "Broken lockfile '{}': package '{}' resolves from non-PyPI source '{}' that is not declared in '{}'",
                        source_path.display(),
                        crate::report::sanitize_for_terminal(name),
                        source_url,
                        source_path
                            .parent()
                            .unwrap_or_else(|| Path::new("."))
                            .join("pyproject.toml")
                            .display()
                    );
                }
                None => {}
            }
        }
        used_source_urls.insert(source_url.clone());
        if let Some(source_name) = source_name {
            used_source_names.insert(source_name.to_lowercase());
        }
        package_sources
            .entry(normalized_name)
            .or_default()
            .insert(source_url);
    }

    for intent in source_intents {
        let Some(resolved_sources) = package_sources.get(&intent.package) else {
            anyhow::bail!(
                "Broken lockfile '{}': dependency '{}' is missing a resolved package entry for declared source '{}'",
                source_path.display(),
                crate::report::sanitize_for_terminal(&intent.package),
                crate::report::sanitize_for_terminal(&intent.source_name)
            );
        };
        if resolved_sources.len() != 1 {
            anyhow::bail!(
                "Broken lockfile '{}': dependency '{}' resolves from multiple sources and cannot be trusted exactly",
                source_path.display(),
                crate::report::sanitize_for_terminal(&intent.package)
            );
        }
        let resolved_source = resolved_sources
            .iter()
            .next()
            .expect("non-empty set should have one element");
        if resolved_source != &intent.normalized_url {
            anyhow::bail!(
                "Broken lockfile '{}': dependency '{}' declares source '{}' ({}) but poetry.lock resolves it from {}",
                source_path.display(),
                crate::report::sanitize_for_terminal(&intent.package),
                crate::report::sanitize_for_terminal(&intent.source_name),
                intent.normalized_url,
                resolved_source
            );
        }
        used_source_names.insert(intent.source_name.to_lowercase());
    }

    Ok((used_source_urls, used_source_names))
}

#[cfg(test)]
pub(super) fn resolve(project_dir: &Path, deps: &[Dependency]) -> Result<ResolutionResult> {
    let Some(parsed) = read_lockfile(project_dir)? else {
        let mut result = ResolutionResult::default();
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };
    resolve_from_value(&parsed, deps)
}

/// PEP 503 normalization: lowercase, replace [-_.] with single hyphen.
fn normalize_name(name: &str) -> String {
    let lower = name.to_lowercase();
    let mut result = String::with_capacity(lower.len());
    let mut last_was_sep = false;
    for ch in lower.chars() {
        if ch == '-' || ch == '_' || ch == '.' {
            if !last_was_sep {
                result.push('-');
                last_was_sep = true;
            }
        } else {
            result.push(ch);
            last_was_sep = false;
        }
    }
    result
}

/// Extract (name, version) pairs from poetry.lock TOML.
/// Format: `[[package]]` array of tables with `name` and `version` keys.
fn extract_packages(parsed: &toml::Value) -> Vec<(String, String)> {
    let Some(packages) = parsed.get("package").and_then(|v| v.as_array()) else {
        return vec![];
    };

    packages
        .iter()
        .filter_map(|pkg| {
            let name = pkg.get("name")?.as_str()?;
            let version = pkg.get("version")?.as_str()?;
            Some((name.to_string(), version.to_string()))
        })
        .collect()
}

fn poetry_package_source(
    pkg: &toml::value::Table,
    source_path: &Path,
    package_name: &str,
) -> Result<(String, Option<String>)> {
    let Some(source) = pkg.get("source") else {
        return Ok((
            crate::config::normalized_default_pypi_index().to_string(),
            None,
        ));
    };
    let table = source.as_table().ok_or_else(|| {
        anyhow::anyhow!(
            "Broken lockfile '{}': package '{}' has malformed source metadata",
            source_path.display(),
            crate::report::sanitize_for_terminal(package_name)
        )
    })?;
    let source_type = table
        .get("type")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Broken lockfile '{}': package '{}' source metadata is missing type",
                source_path.display(),
                crate::report::sanitize_for_terminal(package_name)
            )
        })?;
    let url = table
        .get("url")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Broken lockfile '{}': package '{}' source metadata is missing URL",
                source_path.display(),
                crate::report::sanitize_for_terminal(package_name)
            )
        })?;
    match source_type {
        "legacy" | "explicit" | "supplemental" | "primary" => Ok((
            crate::config::normalize_python_index_url(url),
            table
                .get("reference")
                .and_then(|value| value.as_str())
                .map(str::to_string),
        )),
        other => anyhow::bail!(
            "Broken lockfile '{}': package '{}' uses unsupported Poetry source provenance '{}'",
            source_path.display(),
            crate::report::sanitize_for_terminal(package_name),
            crate::report::sanitize_for_terminal(other)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        )
        .expect_err("ambiguous source resolution must fail closed");
        assert!(err.to_string().contains("resolves from multiple sources"));
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
        )
        .expect_err("undeclared non-PyPI lock source must fail closed");
        assert!(err.to_string().contains("not declared"));
    }
}
