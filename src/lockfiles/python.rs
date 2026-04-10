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

pub(crate) fn reachable_package_identities(
    parsed: &toml::Value,
    direct_deps: &[Dependency],
    lock_profile: Option<&PythonLockfileProfile>,
) -> Result<HashSet<PythonPackageIdentity>> {
    if direct_deps.is_empty() {
        return Ok(HashSet::new());
    }

    let nodes = poetry_package_nodes(parsed)?;
    reachable_package_identities_from_nodes(&nodes, direct_deps, lock_profile)
}

fn reachable_package_identities_from_nodes(
    nodes: &[PoetryPackageNode],
    direct_deps: &[Dependency],
    lock_profile: Option<&PythonLockfileProfile>,
) -> Result<HashSet<PythonPackageIdentity>> {
    let runtime_profile;
    let profile = if let Some(lock_profile) = lock_profile {
        &lock_profile.environment
    } else {
        runtime_profile = PythonProfile::runtime_for_current_host();
        &runtime_profile
    };

    let mut pending = resolved_root_requests(direct_deps, lock_profile, nodes)?;
    let mut visited_states = HashSet::new();
    let mut visited_packages = HashSet::new();

    while let Some(request) = pending.pop() {
        for node in nodes.iter().filter(|node| {
            node.normalized_name == request.normalized_name
                && request
                    .version
                    .as_ref()
                    .is_none_or(|version| node.version == *version)
        }) {
            if !visited_states.insert((
                node.normalized_name.clone(),
                node.version.clone(),
                request.normalized_extras_key(),
            )) {
                continue;
            }
            visited_packages.insert(PythonPackageIdentity {
                normalized_name: node.normalized_name.clone(),
                version: node.version.clone(),
            });
            for edge in &node.dependencies {
                if edge.is_in_scope(profile, &request.requested_extras)? {
                    pending.push(edge.request.clone());
                }
            }
        }
    }

    Ok(visited_packages)
}

fn poetry_package_nodes(parsed: &toml::Value) -> Result<Vec<PoetryPackageNode>> {
    package_entries(parsed)
        .iter()
        .map(|pkg| {
            let name = pkg
                .get("name")
                .and_then(|value| value.as_str())
                .ok_or_else(|| anyhow::anyhow!("Broken poetry.lock: package entry missing name"))?;
            let version = pkg
                .get("version")
                .and_then(|value| value.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Broken poetry.lock: package '{}' entry missing version",
                        crate::report::sanitize_for_terminal(name)
                    )
                })?;
            Ok(PoetryPackageNode {
                normalized_name: normalize_name(name),
                version: version.to_string(),
                dependencies: poetry_dependency_edges(pkg)?,
            })
        })
        .collect()
}

fn resolved_root_requests(
    direct_deps: &[Dependency],
    lock_profile: Option<&PythonLockfileProfile>,
    nodes: &[PoetryPackageNode],
) -> Result<Vec<PythonPackageRequest>> {
    direct_deps
        .iter()
        .map(|dep| {
            let normalized_name = normalize_name(dep.package_name());
            let requested_extras = lock_profile
                .and_then(|lock_profile| lock_profile.root_extras.get(&normalized_name))
                .cloned()
                .unwrap_or_default();
            let version = resolve_root_request_version(dep, &normalized_name, nodes)?;
            Ok(PythonPackageRequest::with_requested_extras(
                normalized_name,
                version,
                requested_extras,
            ))
        })
        .collect()
}

fn resolved_root_identities(
    direct_deps: &[Dependency],
    lock_profile: Option<&PythonLockfileProfile>,
    nodes: &[PoetryPackageNode],
) -> Result<HashSet<PythonPackageIdentity>> {
    Ok(resolved_root_requests(direct_deps, lock_profile, nodes)?
        .into_iter()
        .filter_map(|request| {
            request.version.map(|version| PythonPackageIdentity {
                normalized_name: request.normalized_name,
                version,
            })
        })
        .collect())
}

fn resolve_root_request_version(
    dep: &Dependency,
    normalized_name: &str,
    nodes: &[PoetryPackageNode],
) -> Result<Option<String>> {
    if let Some(version) = dep.exact_version() {
        return Ok(Some(version.to_string()));
    }

    let mut matching_versions = nodes
        .iter()
        .filter(|node| node.normalized_name == normalized_name)
        .map(|node| node.version.clone())
        .collect::<Vec<_>>();
    matching_versions.sort();
    matching_versions.dedup();

    match matching_versions.as_slice() {
        [] => Ok(None),
        [version] => Ok(Some(version.clone())),
        _ => bail!(
            "Dependency '{}' resolves ambiguously in poetry.lock and cannot be trusted exactly",
            crate::report::sanitize_for_terminal(dep.package_name())
        ),
    }
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
                    crate::checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE,
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
    let normalized = normalize_name(package_name);
    let version_suffix = format!("-{version}");
    [
        normalized.clone(),
        normalized.replace('-', "_"),
        package_name.to_ascii_lowercase(),
        package_name.to_ascii_lowercase().replace('-', "_"),
        package_name.to_ascii_lowercase().replace('_', "-"),
    ]
    .into_iter()
    .any(|candidate| {
        file_name
            .to_ascii_lowercase()
            .starts_with(&(candidate + &version_suffix))
    })
}

pub(crate) fn authorized_source_urls_for_reachable_packages(
    parsed: &toml::Value,
    direct_deps: &[Dependency],
    source_intents: &[PythonDependencySourceIntent],
    lock_profile: Option<&PythonLockfileProfile>,
    source_path: &Path,
) -> Result<HashMap<PythonPackageIdentity, HashSet<String>>> {
    if direct_deps.is_empty() {
        return Ok(HashMap::new());
    }

    let nodes = poetry_package_nodes(parsed)?;
    let actual_sources = poetry_source_urls_by_identity(parsed, source_path)?;
    let runtime_profile;
    let profile = if let Some(lock_profile) = lock_profile {
        &lock_profile.environment
    } else {
        runtime_profile = PythonProfile::runtime_for_current_host();
        &runtime_profile
    };
    let root_requests = resolved_root_requests(direct_deps, lock_profile, &nodes)?;
    let explicit_sources = source_intent_urls_by_package(source_intents);
    let default_pypi = crate::config::normalized_default_pypi_index().to_string();

    let mut pending: Vec<(PythonPackageRequest, HashSet<String>)> = root_requests
        .into_iter()
        .map(|request| {
            let mut authorized = HashSet::from([default_pypi.clone()]);
            if let Some(urls) = explicit_sources.get(&request.normalized_name) {
                authorized.extend(urls.iter().cloned());
            }
            for node in nodes.iter().filter(|node| {
                node.normalized_name == request.normalized_name
                    && request
                        .version
                        .as_ref()
                        .is_none_or(|version| node.version == *version)
            }) {
                let identity = PythonPackageIdentity {
                    normalized_name: node.normalized_name.clone(),
                    version: node.version.clone(),
                };
                if let Some(actual_source) = actual_sources.get(&identity) {
                    authorized.insert(actual_source.clone());
                }
            }
            (request, authorized)
        })
        .collect();

    let mut visited_states: HashMap<(String, String, String), HashSet<String>> = HashMap::new();
    let mut authorized_by_identity: HashMap<PythonPackageIdentity, HashSet<String>> =
        HashMap::new();

    while let Some((request, authorized_sources)) = pending.pop() {
        for node in nodes.iter().filter(|node| {
            node.normalized_name == request.normalized_name
                && request
                    .version
                    .as_ref()
                    .is_none_or(|version| node.version == *version)
        }) {
            let identity = PythonPackageIdentity {
                normalized_name: node.normalized_name.clone(),
                version: node.version.clone(),
            };
            let Some(actual_source) = actual_sources.get(&identity) else {
                continue;
            };
            if !authorized_sources.contains(actual_source) {
                continue;
            }
            let state_key = (
                node.normalized_name.clone(),
                node.version.clone(),
                request.normalized_extras_key(),
            );
            let state_sources = visited_states.entry(state_key).or_default();
            let grew = authorized_sources
                .iter()
                .any(|source| !state_sources.contains(source));
            if !grew {
                continue;
            }
            state_sources.extend(authorized_sources.iter().cloned());
            authorized_by_identity
                .entry(identity)
                .or_default()
                .extend(authorized_sources.iter().cloned());
            for edge in &node.dependencies {
                if edge.is_in_scope(profile, &request.requested_extras)? {
                    pending.push((edge.request.clone(), authorized_sources.clone()));
                }
            }
        }
    }

    Ok(authorized_by_identity)
}

fn source_intent_urls_by_package(
    source_intents: &[PythonDependencySourceIntent],
) -> HashMap<String, HashSet<String>> {
    let mut by_package = HashMap::new();
    for intent in source_intents {
        by_package
            .entry(intent.package.clone())
            .or_insert_with(HashSet::new)
            .insert(intent.normalized_url.clone());
    }
    by_package
}

fn poetry_source_urls_by_identity(
    parsed: &toml::Value,
    source_path: &Path,
) -> Result<HashMap<PythonPackageIdentity, String>> {
    let mut sources = HashMap::new();
    for table in package_entries(parsed) {
        let Some(name) = table.get("name").and_then(|value| value.as_str()) else {
            continue;
        };
        let Some(version) = table.get("version").and_then(|value| value.as_str()) else {
            continue;
        };
        let (source_url, _) = poetry_package_source(table, source_path, name)?;
        let identity = PythonPackageIdentity {
            normalized_name: normalize_name(name),
            version: version.to_string(),
        };
        match sources.insert(identity.clone(), source_url.clone()) {
            Some(previous) if previous != source_url => {
                bail!(
                    "Broken lockfile '{}': package '{}' version '{}' resolves from multiple sources and cannot be trusted exactly",
                    source_path.display(),
                    crate::report::sanitize_for_terminal(name),
                    version
                );
            }
            _ => {}
        }
    }
    Ok(sources)
}

fn poetry_lock_version_supported(lock_version: &str) -> bool {
    let Ok((major, _minor)) = parse_simple_version(lock_version) else {
        return false;
    };
    (1..3).contains(&major)
}

fn generated_poetry_version(lockfile_content: &str) -> Option<(u64, u64, u64)> {
    let first_line = lockfile_content.lines().next()?;
    let (_, version) = first_line.split_once("Poetry ")?;
    let token = version.split_whitespace().next()?;
    parse_semver_like(token).ok()
}

fn parse_simple_version(value: &str) -> Result<(u64, u64)> {
    let mut parts = value.trim().split('.');
    let major = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing major version"))?
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid major version"))?;
    let minor = parts
        .next()
        .unwrap_or("0")
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid minor version"))?;
    Ok((major, minor))
}

fn parse_semver_like(value: &str) -> Result<(u64, u64, u64)> {
    let token = value
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == '.')
        .collect::<String>();
    let mut parts = token.split('.');
    let major = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing major version"))?
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid major version"))?;
    let minor = parts
        .next()
        .unwrap_or("0")
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid minor version"))?;
    let patch = parts
        .next()
        .unwrap_or("0")
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid patch version"))?;
    Ok((major, minor, patch))
}

fn poetry_content_hash(pyproject: &toml::Value, with_dependency_groups: bool) -> Result<String> {
    let project = pyproject.get("project").and_then(|value| value.as_table());
    let dependency_groups = with_dependency_groups
        .then(|| {
            pyproject
                .get("dependency-groups")
                .and_then(|value| value.as_table())
        })
        .flatten();
    let tool_poetry = pyproject
        .get("tool")
        .and_then(|tool| tool.get("poetry"))
        .and_then(|value| value.as_table());

    let mut relevant_project = toml::value::Table::new();
    for key in ["requires-python", "dependencies", "optional-dependencies"] {
        if let Some(value) = project.and_then(|table| table.get(key)).cloned() {
            relevant_project.insert(key.to_string(), value);
        }
    }

    let mut relevant_poetry = toml::value::Table::new();
    for key in [
        "dependencies",
        "source",
        "extras",
        "dev-dependencies",
        "group",
    ] {
        let value = tool_poetry.and_then(|table| table.get(key)).cloned();
        let is_legacy = matches!(
            key,
            "dependencies" | "source" | "extras" | "dev-dependencies"
        );
        if value.is_none()
            && (!is_legacy || !relevant_project.is_empty() || dependency_groups.is_some())
        {
            continue;
        }
        if let Some(value) = value {
            relevant_poetry.insert(key.to_string(), value);
        }
    }

    let relevant = if !relevant_project.is_empty() || dependency_groups.is_some() {
        let mut top = toml::value::Table::new();
        if !relevant_project.is_empty() {
            top.insert("project".to_string(), toml::Value::Table(relevant_project));
        }
        if let Some(groups) = dependency_groups
            && !groups.is_empty()
        {
            top.insert(
                "dependency-groups".to_string(),
                toml::Value::Table(groups.clone()),
            );
        }
        let mut tool = toml::value::Table::new();
        tool.insert("poetry".to_string(), toml::Value::Table(relevant_poetry));
        top.insert("tool".to_string(), toml::Value::Table(tool));
        toml::Value::Table(top)
    } else {
        toml::Value::Table(relevant_poetry)
    };

    let mut hasher = Sha256::new();
    hasher.update(canonical_json_from_toml(&relevant)?.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
pub(crate) fn poetry_content_hash_for_test(pyproject: &str) -> Result<String> {
    let parsed = toml::from_str::<toml::Value>(pyproject)?;
    poetry_content_hash(&parsed, true)
}

fn canonical_json_from_toml(value: &toml::Value) -> Result<String> {
    match value {
        toml::Value::String(text) => serde_json::to_string(text).map_err(Into::into),
        toml::Value::Integer(value) => Ok(value.to_string()),
        toml::Value::Float(value) => serde_json::to_string(value).map_err(Into::into),
        toml::Value::Boolean(value) => Ok(value.to_string()),
        toml::Value::Datetime(value) => {
            serde_json::to_string(&value.to_string()).map_err(Into::into)
        }
        toml::Value::Array(values) => {
            let parts = values
                .iter()
                .map(canonical_json_from_toml)
                .collect::<Result<Vec<_>>>()?;
            Ok(format!("[{}]", parts.join(", ")))
        }
        toml::Value::Table(table) => {
            let mut keys = table.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let mut parts = Vec::with_capacity(keys.len());
            for key in keys {
                let key_json = serde_json::to_string(&key)?;
                let value_json = canonical_json_from_toml(
                    table
                        .get(&key)
                        .expect("sorted key list must resolve back into table"),
                )?;
                parts.push(format!("{key_json}: {value_json}"));
            }
            Ok(format!("{{{}}}", parts.join(", ")))
        }
    }
}

pub(crate) fn validate_source_policy(
    parsed: &toml::Value,
    declared_sources: &[crate::parsers::pyproject_toml::PythonSourceDecl],
    source_intents: &[PythonDependencySourceIntent],
    config: &crate::config::SloppyJoeConfig,
    source_path: &Path,
    reachable_packages: Option<&HashSet<PythonPackageIdentity>>,
    authorized_sources: Option<&HashMap<PythonPackageIdentity, HashSet<String>>>,
) -> Result<(HashSet<String>, HashSet<String>)> {
    let mut used_source_urls = HashSet::new();
    let mut used_source_names = HashSet::new();
    let mut package_sources: HashMap<String, HashSet<String>> = HashMap::new();
    let mut identity_sources: HashMap<PythonPackageIdentity, HashSet<String>> = HashMap::new();
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
        let version = table
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
            normalized_name: normalized_name.clone(),
            version: version.to_string(),
        };
        if reachable_packages.is_some_and(|reachable| !reachable.contains(&identity)) {
            continue;
        }
        let (source_url, source_name) = poetry_package_source(table, source_path, name)?;
        let sources_for_identity = identity_sources.entry(identity.clone()).or_default();
        sources_for_identity.insert(source_url.clone());
        if sources_for_identity.len() > 1 {
            anyhow::bail!(
                "Broken lockfile '{}': package '{}' version '{}' resolves from multiple sources and cannot be trusted exactly",
                source_path.display(),
                crate::report::sanitize_for_terminal(name),
                version
            );
        }
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
        if let Some(authorized_sources) = authorized_sources {
            let authorized = authorized_sources.get(&identity);
            if authorized.is_none_or(|allowed| !allowed.contains(&source_url)) {
                anyhow::bail!(
                    "Broken lockfile '{}': package '{}' resolves from source '{}' but that source is not authorized by the in-scope root dependency graph",
                    source_path.display(),
                    crate::report::sanitize_for_terminal(name),
                    source_url
                );
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

struct PoetryPackageNode {
    normalized_name: String,
    version: String,
    dependencies: Vec<PoetryDependencyEdge>,
}

#[derive(Clone)]
struct PoetryDependencyEdge {
    request: PythonPackageRequest,
    marker: Option<String>,
    optional: bool,
}

impl PoetryDependencyEdge {
    fn is_in_scope(
        &self,
        profile: &PythonProfile,
        active_extras: &BTreeSet<String>,
    ) -> Result<bool> {
        if let Some(marker) = &self.marker {
            return evaluate_marker_for_extras(marker, profile, active_extras);
        }
        Ok(!self.optional)
    }
}

fn poetry_dependency_edges(pkg: &toml::value::Table) -> Result<Vec<PoetryDependencyEdge>> {
    let Some(value) = pkg.get("dependencies") else {
        return Ok(Vec::new());
    };
    match value {
        toml::Value::Table(table) => {
            let mut deps = Vec::new();
            for (name, spec) in table {
                if name == "python" {
                    continue;
                }
                deps.push(poetry_dependency_edge(name, spec)?);
            }
            Ok(deps)
        }
        toml::Value::Array(entries) => {
            let mut deps = Vec::new();
            for entry in entries {
                let Some(table) = entry.as_table() else {
                    continue;
                };
                let Some(name) = table.get("name").and_then(|value| value.as_str()) else {
                    continue;
                };
                deps.push(poetry_dependency_edge(
                    name,
                    &toml::Value::Table(table.clone()),
                )?);
            }
            Ok(deps)
        }
        _ => Ok(Vec::new()),
    }
}

fn poetry_dependency_edge(name: &str, value: &toml::Value) -> Result<PoetryDependencyEdge> {
    match value {
        toml::Value::String(_) => Ok(PoetryDependencyEdge {
            request: PythonPackageRequest::new(normalize_name(name)),
            marker: None,
            optional: false,
        }),
        toml::Value::Table(table) => {
            let mut request = PythonPackageRequest::new(normalize_name(name));
            request
                .requested_extras
                .extend(python_lock_dependency_extras(table)?);
            Ok(PoetryDependencyEdge {
                request,
                marker: table
                    .get("markers")
                    .or_else(|| table.get("marker"))
                    .and_then(|value| value.as_str())
                    .map(str::to_string),
                optional: table.get("optional").and_then(|value| value.as_bool()) == Some(true),
            })
        }
        _ => Ok(PoetryDependencyEdge {
            request: PythonPackageRequest::new(normalize_name(name)),
            marker: None,
            optional: false,
        }),
    }
}

fn python_lock_dependency_extras(table: &toml::value::Table) -> Result<BTreeSet<String>> {
    let Some(value) = table.get("extras").or_else(|| table.get("extra")) else {
        return Ok(BTreeSet::new());
    };
    match value {
        toml::Value::Array(values) => values
            .iter()
            .map(|value| {
                let extra = value.as_str().ok_or_else(|| {
                    anyhow::anyhow!("Broken poetry.lock: dependency extra entries must be strings")
                })?;
                Ok(crate::parsers::requirements::normalize_distribution_name(
                    extra,
                ))
            })
            .collect(),
        toml::Value::String(value) => {
            Ok([crate::parsers::requirements::normalize_distribution_name(
                value,
            )]
            .into_iter()
            .filter(|extra| !extra.is_empty())
            .collect())
        }
        other => {
            bail!("Broken poetry.lock: dependency extras must be a string or array, got {other:?}")
        }
    }
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
}
