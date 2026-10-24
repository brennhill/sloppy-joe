mod source_policy;
pub(crate) use source_policy::*;
mod root;
pub(crate) use root::*;
mod graph;
use super::{
    ResolutionKey, ResolutionMode, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, ambiguous_issue, missing_entry_issue, out_of_sync_issue,
};
use crate::{
    Dependency,
    lockfiles::{PythonLockfileProfile, PythonPackageIdentity},
    parsers::{
        pyproject_toml::PythonDependencySourceIntent,
        python_scope::{
            PythonPackageRequest, PythonProfile, evaluate_marker_for_extras,
            evaluate_marker_for_profile_extras,
        },
    },
};
use anyhow::{Result, bail};
pub(crate) use graph::*;
use std::collections::{BTreeSet, HashMap, HashSet};
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

#[cfg(test)]
pub(super) fn resolve_from_value_with_mode(
    parsed: &toml::Value,
    deps: &[Dependency],
    mode: ResolutionMode,
) -> Result<ResolutionResult> {
    resolve_from_value_with_mode_and_profile(parsed, deps, mode, None)
}

pub(super) fn resolve_from_value_with_mode_and_profile(
    parsed: &toml::Value,
    deps: &[Dependency],
    mode: ResolutionMode,
    lock_profile: Option<&PythonLockfileProfile>,
) -> Result<ResolutionResult> {
    let packages = extract_packages(parsed);
    let profile = effective_python_profile(lock_profile);
    let root_requires_entries = extract_root_requires_entries(parsed)?.unwrap_or_default();
    let root_dependencies = extract_root_dependency_entries(parsed)?.unwrap_or_default();
    let mut result = ResolutionResult::default();

    for dep in deps {
        let normalized = normalize_name(&dep.name);
        match match_root_specifier(
            &root_requires_entries,
            &normalized,
            &profile,
            dep.version.as_deref(),
        )? {
            UvRootSpecifierMatch::Mismatch(specifier) => {
                result.push_issue_for(
                    dep,
                    out_of_sync_issue(dep, specifier.as_deref().unwrap_or("")),
                );
                add_manifest_exact_fallback(&mut result, dep);
                continue;
            }
            UvRootSpecifierMatch::Missing if mode == ResolutionMode::Direct => {
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
        let selected_root_version = if lock_profile.is_some() {
            select_root_dependency(&root_dependencies, &normalized, &profile)?
                .and_then(|selection| selection.version)
        } else {
            None
        };

        if let Some(exact_manifest) = dep.exact_version() {
            let expected_version = selected_root_version
                .as_deref()
                .unwrap_or(exact_manifest.as_str());
            match candidates
                .iter()
                .find(|version| version.as_str() == expected_version)
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
            let selected = selected_root_version
                .as_ref()
                .or_else(|| (candidates.len() == 1).then(|| candidates[0]));
            match selected {
                Some(version) if version_matches_uv_specifier(version, dep.version.as_deref())? => {
                    result.exact_versions.insert(
                        ResolutionKey::from(dep),
                        ResolvedVersion {
                            version: version.clone(),
                            source: ResolutionSource::Lockfile,
                        },
                    );
                }
                Some(version) => result.push_issue_for(dep, out_of_sync_issue(dep, version)),
                None => result.push_issue_for(dep, ambiguous_issue(dep)),
            }
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

pub(super) fn parse_all_from_value_for_roots(
    parsed: &toml::Value,
    direct_deps: &[Dependency],
    lock_profile: Option<&PythonLockfileProfile>,
) -> Result<Vec<Dependency>> {
    let nodes = uv_package_nodes(parsed)?;
    let root_dependencies = extract_root_dependency_entries(parsed)?.unwrap_or_default();
    let reachable = reachable_package_identities_from_nodes(
        &nodes,
        direct_deps,
        lock_profile,
        &root_dependencies,
    )?;
    let profile = effective_python_profile(lock_profile);
    let root_packages = resolved_root_identities(
        direct_deps,
        lock_profile,
        &profile,
        &nodes,
        &root_dependencies,
    )?;
    Ok(package_entries(parsed)
        .into_iter()
        .filter(|pkg| !is_local_root_package(pkg))
        .filter_map(|pkg| {
            let name = pkg.get("name")?.as_str()?;
            let version = pkg.get("version")?.as_str()?;
            let normalized_name = normalize_name(name);
            let identity = PythonPackageIdentity {
                normalized_name: normalized_name.clone(),
                version: version.to_string(),
            };
            if !reachable.contains(&identity) || root_packages.contains(&identity) {
                return None;
            }
            Some(Dependency {
                name: name.to_string(),
                version: Some(version.to_string()),
                ecosystem: crate::Ecosystem::PyPI,
                actual_name: None,
            })
        })
        .collect())
}

fn extract_packages(parsed: &toml::Value) -> Vec<(String, String)> {
    package_entries(parsed)
        .into_iter()
        .filter(|pkg| !is_local_root_package(pkg))
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

fn is_local_root_package(pkg: &toml::value::Table) -> bool {
    pkg.get("source")
        .and_then(|value| value.as_table())
        .and_then(|source| source.get("virtual").or_else(|| source.get("editable")))
        .and_then(|value| value.as_str())
        == Some(".")
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

pub(crate) use crate::parsers::python_version::version_matches_uv_specifier;

#[cfg(test)]
mod tests;
