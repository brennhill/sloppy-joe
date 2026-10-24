mod source_policy;
pub(crate) use source_policy::*;
mod poetry_hash;
pub(crate) use poetry_hash::*;
mod graph;
use super::{
    ResolutionKey, ResolutionMode, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, missing_entry_issue, no_trusted_lockfile_sync_issue,
    out_of_sync_issue,
};
use crate::{
    Dependency,
    config::PoetryLockPolicy,
    lockfiles::{PythonLockfileProfile, PythonPackageIdentity},
    parsers::{
        pyproject_toml::PythonDependencySourceIntent,
        python_scope::{PythonPackageRequest, PythonProfile, evaluate_marker_for_extras},
    },
    report::{Issue, Severity},
};
use anyhow::{Result, bail};
pub(crate) use graph::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

#[cfg(test)]
use super::add_manifest_exact_fallbacks;

pub(crate) struct PoetryLockValidation {
    pub(crate) warnings: Vec<Issue>,
    pub(crate) fully_trusted: bool,
}

/// Resolve versions from a pre-parsed poetry.lock TOML value.
#[cfg(test)]
pub(super) fn resolve_from_value(
    parsed: &toml::Value,
    deps: &[Dependency],
) -> Result<ResolutionResult> {
    resolve_from_value_with_mode(parsed, deps, ResolutionMode::Direct)
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
    _lock_profile: Option<&super::PythonLockfileProfile>,
) -> Result<ResolutionResult> {
    let packages = extract_packages(parsed);
    let mut result = ResolutionResult::default();

    for dep in deps {
        // PEP 503 normalize: lowercase, replace [-_.] with -
        let normalized = normalize_name(&dep.name);
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
                        result.push_issue_for(dep, missing_entry_issue(dep, "poetry.lock"));
                    }
                    add_manifest_exact_fallback(&mut result, dep);
                }
            }
            continue;
        }

        match candidates.first() {
            Some(version) => {
                if mode == ResolutionMode::Direct && dep.version.is_some() {
                    result.push_issue_for(dep, no_trusted_lockfile_sync_issue(dep, "poetry.lock"));
                    continue;
                }
                result.exact_versions.insert(
                    ResolutionKey::from(dep),
                    ResolvedVersion {
                        version: (*version).clone(),
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

pub(super) fn parse_all_from_value_for_roots(
    parsed: &toml::Value,
    direct_deps: &[Dependency],
    lock_profile: Option<&PythonLockfileProfile>,
) -> Result<Vec<Dependency>> {
    let nodes = poetry_package_nodes(parsed)?;
    let reachable = reachable_package_identities_from_nodes(&nodes, direct_deps, lock_profile)?;
    let root_packages = resolved_root_identities(direct_deps, lock_profile, &nodes)?;
    let packages = package_entries(parsed);

    Ok(packages
        .into_iter()
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

pub(crate) fn validate_trusted_poetry_lockfile(
    parsed: &toml::Value,
    lockfile_content: &str,
    pyproject: &toml::Value,
    deps: &[Dependency],
    source_path: &Path,
    reachable_packages: &HashSet<PythonPackageIdentity>,
    policy: PoetryLockPolicy,
) -> Result<PoetryLockValidation> {
    let mut warnings = Vec::new();
    let mut fully_trusted = true;
    let Some(metadata) = parsed.get("metadata").and_then(|value| value.as_table()) else {
        handle_poetry_missing_proof(
            &mut warnings,
            &mut fully_trusted,
            policy,
            source_path,
            "metadata section is missing",
            "Regenerate poetry.lock with `poetry lock` and commit the fresh lockfile.",
        )?;
        return Ok(PoetryLockValidation {
            warnings,
            fully_trusted,
        });
    };

    let Some(lock_version) = metadata
        .get("lock-version")
        .and_then(|value| value.as_str())
    else {
        handle_poetry_missing_proof(
            &mut warnings,
            &mut fully_trusted,
            policy,
            source_path,
            "lock-version metadata is missing",
            "Regenerate poetry.lock with a current Poetry and commit the updated lockfile.",
        )?;
        return Ok(PoetryLockValidation {
            warnings,
            fully_trusted,
        });
    };
    if !poetry_lock_version_supported(lock_version) {
        handle_poetry_missing_proof(
            &mut warnings,
            &mut fully_trusted,
            policy,
            source_path,
            &format!(
                "lock-version '{}' is outside the supported Poetry trust range",
                lock_version
            ),
            "Upgrade Poetry if needed, regenerate poetry.lock, and commit the updated lockfile.",
        )?;
    }

    match metadata
        .get("content-hash")
        .and_then(|value| value.as_str())
    {
        Some(content_hash) => {
            let expected = poetry_content_hash(pyproject, true)?;
            let legacy_expected = generated_poetry_version(lockfile_content)
                .is_some_and(|version| version < (2, 3, 0))
                .then(|| poetry_content_hash(pyproject, false))
                .transpose()?;
            if content_hash != expected
                && legacy_expected
                    .as_deref()
                    .is_none_or(|legacy| content_hash != legacy)
            {
                bail!(
                    "Broken lockfile '{}': poetry.lock content-hash is stale or contradictory to pyproject.toml",
                    source_path.display()
                );
            }
        }
        None => handle_poetry_missing_proof(
            &mut warnings,
            &mut fully_trusted,
            policy,
            source_path,
            "content-hash metadata is missing",
            "Regenerate poetry.lock with `poetry lock` and commit the fresh lockfile.",
        )?,
    }

    validate_manifest_consistency(parsed, deps, source_path)?;
    validate_provenance(
        parsed,
        source_path,
        reachable_packages,
        policy,
        &mut warnings,
        &mut fully_trusted,
    )?;

    Ok(PoetryLockValidation {
        warnings,
        fully_trusted,
    })
}

fn handle_poetry_missing_proof(
    warnings: &mut Vec<Issue>,
    fully_trusted: &mut bool,
    policy: PoetryLockPolicy,
    source_path: &Path,
    detail: &str,
    fix: &str,
) -> Result<()> {
    *fully_trusted = false;
    match policy {
        PoetryLockPolicy::Strict => bail!(
            "Broken lockfile '{}': trusted Poetry mode requires stronger proof because {}",
            source_path.display(),
            detail
        ),
        PoetryLockPolicy::WarnMissingProofs => {
            warnings.push(
                Issue::new(
                    "<lockfile>",
                    crate::names::RESOLUTION_NO_TRUSTED_LOCKFILE,
                    Severity::Warning,
                )
                .message(format!(
                    "Poetry lockfile '{}' is being used in reduced-confidence mode because {}.",
                    source_path.display(),
                    detail
                ))
                .fix(fix.to_string()),
            );
            Ok(())
        }
    }
}

fn validate_manifest_consistency(
    parsed: &toml::Value,
    deps: &[Dependency],
    source_path: &Path,
) -> Result<()> {
    let packages = extract_packages(parsed);
    for dep in deps {
        let normalized = normalize_name(dep.package_name());
        let candidates: Vec<&String> = packages
            .iter()
            .filter(|(name, _)| normalize_name(name) == normalized)
            .map(|(_, version)| version)
            .collect();
        if candidates.is_empty() {
            bail!(
                "Broken lockfile '{}': '{}' is missing a resolved package entry",
                source_path.display(),
                crate::report::sanitize_for_terminal(dep.package_name())
            );
        }

        if let Some(exact_manifest) = dep.exact_version() {
            if !candidates
                .iter()
                .any(|version| version.as_str() == exact_manifest)
            {
                bail!(
                    "Broken lockfile '{}': '{}' is out of sync with pyproject.toml",
                    source_path.display(),
                    crate::report::sanitize_for_terminal(dep.package_name())
                );
            }
            continue;
        }

        if let Some(specifier) = dep.version.as_deref()
            && !candidates.iter().any(|version| {
                crate::lockfiles::uv::version_matches_uv_specifier(version, Some(specifier))
                    .unwrap_or(false)
            })
        {
            bail!(
                "Broken lockfile '{}': '{}' is out of sync with pyproject.toml",
                source_path.display(),
                crate::report::sanitize_for_terminal(dep.package_name())
            );
        }
    }
    Ok(())
}

fn validate_provenance(
    parsed: &toml::Value,
    source_path: &Path,
    reachable_packages: &HashSet<PythonPackageIdentity>,
    policy: PoetryLockPolicy,
    warnings: &mut Vec<Issue>,
    fully_trusted: &mut bool,
) -> Result<()> {
    let metadata = parsed.get("metadata").and_then(|value| value.as_table());
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
        let version = pkg
            .get("version")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Broken lockfile '{}': package '{}' entry missing version",
                    source_path.display(),
                    crate::report::sanitize_for_terminal(name)
                )
            })?;
        let identity = PythonPackageIdentity {
            normalized_name: normalize_name(name),
            version: version.to_string(),
        };
        if !reachable_packages.contains(&identity) {
            continue;
        }
        if !poetry_package_has_artifact_identity(pkg, metadata, name, version) {
            handle_poetry_missing_proof(
                warnings,
                fully_trusted,
                policy,
                source_path,
                &format!(
                    "package '{}' is missing trusted artifact identity",
                    crate::report::sanitize_for_terminal(name)
                ),
                "Regenerate poetry.lock with artifact hashes present and commit the refreshed lockfile.",
            )?;
        }
    }
    Ok(())
}

fn poetry_package_has_artifact_identity(
    pkg: &toml::value::Table,
    metadata: Option<&toml::value::Table>,
    package_name: &str,
    version: &str,
) -> bool {
    if let Some(files) = pkg.get("files").and_then(|value| value.as_array()) {
        return files
            .iter()
            .any(|value| poetry_metadata_file_entry_matches_version(value, package_name, version));
    }
    metadata
        .and_then(|metadata| metadata.get("files"))
        .and_then(|value| value.as_table())
        .and_then(|table| table.get(package_name))
        .and_then(|value| value.as_array())
        .is_some_and(|files| {
            files.iter().any(|value| {
                poetry_metadata_file_entry_matches_version(value, package_name, version)
            })
        })
}

fn poetry_file_entry_has_identity(value: &toml::Value) -> bool {
    let Some(table) = value.as_table() else {
        return false;
    };
    table
        .get("hash")
        .and_then(|value| value.as_str())
        .is_some_and(|hash| !hash.trim().is_empty())
        && table
            .get("file")
            .and_then(|value| value.as_str())
            .is_some_and(|file| !file.trim().is_empty())
}

fn poetry_metadata_file_entry_matches_version(
    value: &toml::Value,
    package_name: &str,
    version: &str,
) -> bool {
    let Some(table) = value.as_table() else {
        return false;
    };
    if !poetry_file_entry_has_identity(value) {
        return false;
    }
    let Some(file_name) = table.get("file").and_then(|value| value.as_str()) else {
        return false;
    };
    poetry_filename_matches_package_version(package_name, version, file_name)
}

fn poetry_filename_matches_package_version(
    package_name: &str,
    version: &str,
    file_name: &str,
) -> bool {
    const SDIST_EXTENSIONS: [&str; 6] = [".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".egg"];
    let normalized = normalize_name(package_name);
    let file_name = file_name.to_ascii_lowercase();
    let version_marker = format!("-{}", version.to_ascii_lowercase());
    // The project name may keep punctuation the lock normalizes away
    // (`jaraco.classes-3.4.0-...` for `jaraco-classes`), and the version must end
    // exactly where the wheel tag or sdist extension begins.
    file_name.match_indices(&version_marker).any(|(index, _)| {
        let remainder = &file_name[index + version_marker.len()..];
        normalize_name(&file_name[..index]) == normalized
            && (remainder.starts_with('-') || SDIST_EXTENSIONS.contains(&remainder))
    })
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
    package_entries(parsed)
        .iter()
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

#[cfg(test)]
mod tests;
