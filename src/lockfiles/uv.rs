use super::{
    ResolutionKey, ResolutionMode, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, ambiguous_issue, missing_entry_issue,
    no_trusted_lockfile_sync_issue, out_of_sync_issue,
};
use crate::{Dependency, parsers::pyproject_toml::PythonDependencySourceIntent};
use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub(super) fn read_lockfile(project_dir: &Path) -> Result<Option<toml::Value>> {
    let path = project_dir.join("uv.lock");
    if !crate::parsers::path_detected(&path)? {
        return Ok(None);
    }
    let content = crate::parsers::read_file_limited(&path, crate::parsers::MAX_MANIFEST_BYTES)?;
    let parsed = toml::from_str(&content)
        .map_err(|err| anyhow::anyhow!("Failed to parse {}: {}", path.display(), err))?;
    Ok(Some(parsed))
}

pub(crate) fn validate_schema(parsed: &toml::Value, source_path: &Path) -> Result<()> {
    let version = parsed.get("version").and_then(|value| value.as_integer());
    if version != Some(1) {
        bail!(
            "Unsupported uv.lock schema in {}: expected version = 1",
            source_path.display()
        );
    }
    if parsed
        .get("requires-python")
        .and_then(|value| value.as_str())
        .is_none()
    {
        bail!(
            "Broken lockfile '{}': missing requires-python",
            source_path.display()
        );
    }
    Ok(())
}

pub(crate) fn validate_manifest_consistency(
    parsed: &toml::Value,
    deps: &[Dependency],
    source_path: &Path,
) -> Result<()> {
    let root_requires = extract_root_requires(parsed).ok_or_else(|| {
        anyhow::anyhow!(
            "Broken lockfile '{}': missing root package metadata.requires-dist",
            source_path.display()
        )
    })?;
    let packages = package_entries(parsed);

    for dep in deps {
        let normalized = normalize_name(&dep.name);
        let Some(specifier) = root_requires.get(&normalized) else {
            bail!(
                "Broken lockfile '{}': '{}' is missing from root requires-dist metadata",
                source_path.display(),
                dep.name
            );
        };
        if dep.version.as_deref() != specifier.as_deref() {
            bail!(
                "Broken lockfile '{}': '{}' is out of sync with pyproject.toml",
                source_path.display(),
                dep.name
            );
        }

        let candidates: Vec<&toml::value::Table> = packages
            .iter()
            .copied()
            .filter(|pkg| {
                pkg.get("name")
                    .and_then(|value| value.as_str())
                    .is_some_and(|name| normalize_name(name) == normalized)
                    && !is_virtual_package(pkg)
            })
            .collect();

        if candidates.is_empty() {
            bail!(
                "Broken lockfile '{}': '{}' is missing a resolved package entry",
                source_path.display(),
                dep.name
            );
        }

        if let Some(exact) = dep.exact_version() {
            if !candidates.iter().any(|pkg| {
                pkg.get("version")
                    .and_then(|value| value.as_str())
                    .is_some_and(|version| version == exact)
            }) {
                bail!(
                    "Broken lockfile '{}': '{}' is out of sync with pyproject.toml",
                    source_path.display(),
                    dep.name
                );
            }
        } else if candidates.len() > 1 {
            bail!(
                "Broken lockfile '{}': '{}' resolves ambiguously and cannot be trusted exactly",
                source_path.display(),
                dep.name
            );
        }
    }

    Ok(())
}

pub(crate) fn validate_provenance(parsed: &toml::Value, source_path: &Path) -> Result<()> {
    for pkg in package_entries(parsed) {
        let name = pkg
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Broken lockfile '{}': package entry missing name",
                    source_path.display()
                )
            })?;
        let _version = pkg
            .get("version")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Broken lockfile '{}': package '{}' is missing version",
                    source_path.display(),
                    name
                )
            })?;

        if is_virtual_package(pkg) {
            continue;
        }

        let source = pkg
            .get("source")
            .and_then(|value| value.as_table())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Broken lockfile '{}': package '{}' is missing source metadata",
                    source_path.display(),
                    name
                )
            })?;

        if source
            .get("registry")
            .and_then(|value| value.as_str())
            .is_none()
        {
            bail!(
                "Broken lockfile '{}': package '{}' uses unsupported uv source provenance",
                source_path.display(),
                name
            );
        }

        if !has_artifact_identity(pkg) {
            bail!(
                "Broken lockfile '{}': package '{}' is missing trusted artifact identity",
                source_path.display(),
                name
            );
        }
    }

    Ok(())
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
    let declared_source_urls: HashSet<String> = declared_sources
        .iter()
        .map(|source| source.normalized_url.clone())
        .collect();

    for pkg in package_entries(parsed) {
        if is_virtual_package(pkg) {
            continue;
        }

        let name = pkg
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Broken lockfile '{}': package entry missing name",
                    source_path.display()
                )
            })?;
        let registry = pkg
            .get("source")
            .and_then(|value| value.as_table())
            .and_then(|source| source.get("registry"))
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Broken lockfile '{}': package '{}' is missing registry source metadata",
                    source_path.display(),
                    crate::report::sanitize_for_terminal(name)
                )
            })?;
        let normalized_url = crate::config::normalize_python_index_url(registry);
        if !config.is_trusted_index("pypi", &normalized_url) {
            bail!(
                "Broken lockfile '{}': package '{}' resolves from untrusted Python index '{}'",
                source_path.display(),
                crate::report::sanitize_for_terminal(name),
                normalized_url
            );
        }
        if normalized_url != crate::config::normalized_default_pypi_index()
            && !declared_source_urls.contains(&normalized_url)
        {
            bail!(
                "Broken lockfile '{}': package '{}' resolves from non-PyPI source '{}' that is not declared in '{}'",
                source_path.display(),
                crate::report::sanitize_for_terminal(name),
                normalized_url,
                source_path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .join("pyproject.toml")
                    .display()
            );
        }
        used_source_urls.insert(normalized_url.clone());
        package_sources
            .entry(normalize_name(name))
            .or_default()
            .insert(normalized_url);
    }

    for intent in source_intents {
        let Some(resolved_sources) = package_sources.get(&intent.package) else {
            bail!(
                "Broken lockfile '{}': dependency '{}' is missing a resolved package entry for declared source '{}'",
                source_path.display(),
                crate::report::sanitize_for_terminal(&intent.package),
                crate::report::sanitize_for_terminal(&intent.source_name)
            );
        };
        if resolved_sources.len() != 1 {
            bail!(
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
            bail!(
                "Broken lockfile '{}': dependency '{}' declares source '{}' ({}) but uv.lock resolves it from {}",
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

pub(super) fn resolve_from_value_with_mode(
    parsed: &toml::Value,
    deps: &[Dependency],
    mode: ResolutionMode,
) -> Result<ResolutionResult> {
    let packages = extract_packages(parsed);
    let root_requires = extract_root_requires(parsed).unwrap_or_default();
    let mut result = ResolutionResult::default();

    for dep in deps {
        let normalized = normalize_name(&dep.name);
        match root_requires.get(&normalized) {
            Some(specifier) if dep.version.as_deref() != specifier.as_deref() => {
                result.push_issue_for(
                    dep,
                    out_of_sync_issue(dep, specifier.as_deref().unwrap_or("")),
                );
                add_manifest_exact_fallback(&mut result, dep);
                continue;
            }
            None if mode == ResolutionMode::Direct => {
                result.push_issue_for(dep, missing_entry_issue(dep, "uv.lock"));
                add_manifest_exact_fallback(&mut result, dep);
                continue;
            }
            _ => {}
        }

        let candidates: Vec<&String> = packages
            .iter()
            .filter(|(name, _)| normalize_name(name) == normalized)
            .map(|(_, version)| version)
            .collect();

        if let Some(exact_manifest) = dep.exact_version() {
            match candidates
                .iter()
                .find(|version| version.as_str() == exact_manifest)
            {
                Some(version) => {
                    result.exact_versions.insert(
                        ResolutionKey::from(dep),
                        ResolvedVersion {
                            version: (*version).clone(),
                            source: ResolutionSource::Lockfile,
                        },
                    );
                }
                None => {
                    if let Some(version) = candidates.first() {
                        result.push_issue_for(dep, out_of_sync_issue(dep, version));
                    } else {
                        result.push_issue_for(dep, missing_entry_issue(dep, "uv.lock"));
                    }
                    add_manifest_exact_fallback(&mut result, dep);
                }
            }
            continue;
        }

        if mode == ResolutionMode::Direct && dep.version.is_some() {
            result.push_issue_for(dep, no_trusted_lockfile_sync_issue(dep, "uv.lock"));
            continue;
        }

        match candidates.as_slice() {
            [version] => {
                result.exact_versions.insert(
                    ResolutionKey::from(dep),
                    ResolvedVersion {
                        version: (*version).clone(),
                        source: ResolutionSource::Lockfile,
                    },
                );
            }
            [] => {
                result.push_issue_for(dep, missing_entry_issue(dep, "uv.lock"));
                add_manifest_exact_fallback(&mut result, dep);
            }
            _ => result.push_issue_for(dep, ambiguous_issue(dep)),
        }
    }

    Ok(result)
}

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

fn extract_packages(parsed: &toml::Value) -> Vec<(String, String)> {
    package_entries(parsed)
        .into_iter()
        .filter(|pkg| !is_virtual_package(pkg))
        .filter_map(|pkg| {
            let name = pkg.get("name")?.as_str()?;
            let version = pkg.get("version")?.as_str()?;
            Some((name.to_string(), version.to_string()))
        })
        .collect()
}

fn package_entries(parsed: &toml::Value) -> Vec<&toml::value::Table> {
    parsed
        .get("package")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_table())
        .collect()
}

fn extract_root_requires(parsed: &toml::Value) -> Option<HashMap<String, Option<String>>> {
    let root = package_entries(parsed)
        .into_iter()
        .find(|pkg| is_virtual_package(pkg))?;
    let requires = root
        .get("metadata")
        .and_then(|value| value.as_table())?
        .get("requires-dist")
        .and_then(|value| value.as_array())?;
    let mut map = HashMap::new();
    for entry in requires {
        let table = entry.as_table()?;
        let name = normalize_name(table.get("name")?.as_str()?);
        let specifier = table
            .get("specifier")
            .and_then(|value| value.as_str())
            .map(str::to_string);
        map.insert(name, specifier);
    }
    Some(map)
}

fn is_virtual_package(pkg: &toml::value::Table) -> bool {
    pkg.get("source")
        .and_then(|value| value.as_table())
        .and_then(|source| source.get("virtual"))
        .and_then(|value| value.as_str())
        .is_some()
}

fn has_artifact_identity(pkg: &toml::value::Table) -> bool {
    let has_sdist = pkg
        .get("sdist")
        .and_then(|value| value.as_table())
        .is_some_and(has_url_and_hash);
    let has_wheel = pkg
        .get("wheels")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_table())
        .any(has_url_and_hash);
    has_sdist || has_wheel
}

fn has_url_and_hash(table: &toml::value::Table) -> bool {
    table.get("url").and_then(|value| value.as_str()).is_some()
        && table.get("hash").and_then(|value| value.as_str()).is_some()
}

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

#[cfg(test)]
mod tests {
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
    fn parse_all_skips_virtual_root_package() {
        let parsed: toml::Value = toml::from_str(UV_LOCK).unwrap();
        let all = parse_all_from_value(&parsed).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "requests");
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
        )
        .expect_err("ambiguous source resolution must fail closed");
        assert!(err.to_string().contains("resolves from multiple sources"));
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
        )
        .expect_err("undeclared non-PyPI lock source must fail closed");
        assert!(err.to_string().contains("not declared"));
    }
}
