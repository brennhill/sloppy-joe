use super::{
    ResolutionKey, ResolutionMode, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, ambiguous_issue, missing_entry_issue,
    no_trusted_lockfile_sync_issue, out_of_sync_issue,
};
use crate::{
    Dependency,
    lockfiles::{PythonLockfileProfile, PythonPackageIdentity},
    parsers::{
        pyproject_toml::PythonDependencySourceIntent,
        python_scope::{PythonPackageRequest, PythonProfile, evaluate_marker_for_extras},
    },
};
use anyhow::{Result, bail};
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

#[derive(Clone, Debug)]
struct UvRootRequiresEntry {
    normalized_name: String,
    specifier: Option<String>,
    marker: Option<String>,
}

#[derive(Clone, Debug)]
struct UvRootDependencyEntry {
    normalized_name: String,
    version: Option<String>,
    requested_extras: BTreeSet<String>,
    marker: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct UvSelectedRootDependency {
    version: Option<String>,
    requested_extras: BTreeSet<String>,
}

pub(crate) fn validate_manifest_consistency(
    parsed: &toml::Value,
    deps: &[Dependency],
    source_path: &Path,
    lock_profile: Option<&PythonLockfileProfile>,
) -> Result<()> {
    let root_requires = extract_root_requires_entries(parsed)?.ok_or_else(|| {
        anyhow::anyhow!(
            "Broken lockfile '{}': missing root package metadata.requires-dist",
            source_path.display()
        )
    })?;
    let root_dependencies = extract_root_dependency_entries(parsed)?.unwrap_or_default();
    let profile = effective_python_profile(lock_profile);
    let packages = package_entries(parsed);

    for dep in deps {
        let normalized = normalize_name(&dep.name);
        let Some(specifier) = select_root_specifier(&root_requires, &normalized, &profile)? else {
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

        let selected_root = select_root_dependency(&root_dependencies, &normalized, &profile)?;
        if let Some(root_version) = selected_root
            .as_ref()
            .and_then(|selection| selection.version.as_deref())
            && !version_matches_uv_specifier(root_version, specifier.as_deref())?
        {
            bail!(
                "Broken lockfile '{}': '{}' is out of sync with requires-dist because root-selected version '{}' contradicts '{}'",
                source_path.display(),
                dep.name,
                root_version,
                specifier.as_deref().unwrap_or("")
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

        let expected_version = selected_root
            .and_then(|selection| selection.version)
            .or_else(|| dep.exact_version());
        if let Some(expected_version) = expected_version.as_deref() {
            if !candidates.iter().any(|pkg| {
                pkg.get("version")
                    .and_then(|value| value.as_str())
                    .is_some_and(|version| version == expected_version)
            }) {
                bail!(
                    "Broken lockfile '{}': '{}' is missing the root-selected resolved package entry '{}'",
                    source_path.display(),
                    dep.name,
                    expected_version
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
    reachable_packages: Option<&HashSet<PythonPackageIdentity>>,
    authorized_sources: Option<&HashMap<PythonPackageIdentity, HashSet<String>>>,
) -> Result<(HashSet<String>, HashSet<String>)> {
    let mut used_source_urls = HashSet::new();
    let mut used_source_names = HashSet::new();
    let mut package_sources: HashMap<String, HashSet<String>> = HashMap::new();
    let mut identity_sources: HashMap<PythonPackageIdentity, HashSet<String>> = HashMap::new();
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
        let normalized_name = normalize_name(name);
        let version = pkg
            .get("version")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Broken lockfile '{}': package '{}' is missing version",
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
        let sources_for_identity = identity_sources.entry(identity.clone()).or_default();
        sources_for_identity.insert(normalized_url.clone());
        if sources_for_identity.len() > 1 {
            bail!(
                "Broken lockfile '{}': package '{}' version '{}' resolves from multiple sources and cannot be trusted exactly",
                source_path.display(),
                crate::report::sanitize_for_terminal(name),
                version
            );
        }
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
        if let Some(authorized_sources) = authorized_sources {
            let authorized = authorized_sources.get(&identity);
            if authorized.is_none_or(|allowed| !allowed.contains(&normalized_url)) {
                bail!(
                    "Broken lockfile '{}': package '{}' resolves from source '{}' but that source is not authorized by the in-scope root dependency graph",
                    source_path.display(),
                    crate::report::sanitize_for_terminal(name),
                    normalized_url
                );
            }
        }
        used_source_urls.insert(normalized_url.clone());
        package_sources
            .entry(normalized_name)
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

    let nodes = uv_package_nodes(parsed)?;
    let root_dependencies = extract_root_dependency_entries(parsed)?.unwrap_or_default();
    let profile = effective_python_profile(lock_profile);
    let root_requests = resolved_root_requests(
        direct_deps,
        lock_profile,
        &profile,
        &nodes,
        &root_dependencies,
    )?;
    let actual_sources = uv_source_urls_by_identity(parsed, source_path)?;
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
                if edge.is_in_scope(&profile, &request.requested_extras)? {
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

fn uv_source_urls_by_identity(
    parsed: &toml::Value,
    source_path: &Path,
) -> Result<HashMap<PythonPackageIdentity, String>> {
    let mut sources = HashMap::new();
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
        let version = pkg
            .get("version")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Broken lockfile '{}': package '{}' is missing version",
                    source_path.display(),
                    crate::report::sanitize_for_terminal(name)
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
        let identity = PythonPackageIdentity {
            normalized_name: normalize_name(name),
            version: version.to_string(),
        };
        let normalized_registry = crate::config::normalize_python_index_url(registry);
        match sources.insert(identity.clone(), normalized_registry.clone()) {
            Some(previous) if previous != normalized_registry => {
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
    let root_requires = extract_root_requires(parsed).unwrap_or_default();
    let root_requires_entries = extract_root_requires_entries(parsed)?.unwrap_or_default();
    let root_dependencies = extract_root_dependency_entries(parsed)?.unwrap_or_default();
    let mut result = ResolutionResult::default();

    for dep in deps {
        let normalized = normalize_name(&dep.name);
        let profile_specifier = if lock_profile.is_some() {
            select_root_specifier(&root_requires_entries, &normalized, &profile)?
        } else {
            root_requires.get(&normalized).cloned()
        };
        match profile_specifier {
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
        .filter(|pkg| !is_virtual_package(pkg))
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

    let nodes = uv_package_nodes(parsed)?;
    let root_dependencies = extract_root_dependency_entries(parsed)?.unwrap_or_default();
    reachable_package_identities_from_nodes(&nodes, direct_deps, lock_profile, &root_dependencies)
}

fn reachable_package_identities_from_nodes(
    nodes: &[UvPackageNode],
    direct_deps: &[Dependency],
    lock_profile: Option<&PythonLockfileProfile>,
    root_dependencies: &[UvRootDependencyEntry],
) -> Result<HashSet<PythonPackageIdentity>> {
    let profile = effective_python_profile(lock_profile);

    let mut pending = resolved_root_requests(
        direct_deps,
        lock_profile,
        &profile,
        nodes,
        root_dependencies,
    )?;
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
                if edge.is_in_scope(&profile, &request.requested_extras)? {
                    pending.push(edge.request.clone());
                }
            }
        }
    }

    Ok(visited_packages)
}

fn uv_package_nodes(parsed: &toml::Value) -> Result<Vec<UvPackageNode>> {
    package_entries(parsed)
        .into_iter()
        .filter(|pkg| !is_virtual_package(pkg))
        .map(|pkg| {
            let name = pkg
                .get("name")
                .and_then(|value| value.as_str())
                .ok_or_else(|| anyhow::anyhow!("Broken uv.lock: package entry missing name"))?;
            let version = pkg
                .get("version")
                .and_then(|value| value.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Broken uv.lock: package '{}' entry missing version",
                        crate::report::sanitize_for_terminal(name)
                    )
                })?;
            Ok(UvPackageNode {
                normalized_name: normalize_name(name),
                version: version.to_string(),
                dependencies: uv_dependency_edges(pkg)?,
            })
        })
        .collect()
}

fn resolved_root_requests(
    direct_deps: &[Dependency],
    lock_profile: Option<&PythonLockfileProfile>,
    profile: &PythonProfile,
    nodes: &[UvPackageNode],
    root_dependencies: &[UvRootDependencyEntry],
) -> Result<Vec<PythonPackageRequest>> {
    direct_deps
        .iter()
        .map(|dep| {
            let normalized_name = normalize_name(dep.package_name());
            let mut requested_extras = lock_profile
                .and_then(|lock_profile| lock_profile.root_extras.get(&normalized_name))
                .cloned()
                .unwrap_or_default();
            if let Some(selection) =
                select_root_dependency(root_dependencies, &normalized_name, profile)?
            {
                requested_extras.extend(selection.requested_extras);
            }
            let version = resolve_root_request_version(
                dep,
                &normalized_name,
                profile,
                nodes,
                root_dependencies,
            )?;
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
    profile: &PythonProfile,
    nodes: &[UvPackageNode],
    root_dependencies: &[UvRootDependencyEntry],
) -> Result<HashSet<PythonPackageIdentity>> {
    Ok(
        resolved_root_requests(direct_deps, lock_profile, profile, nodes, root_dependencies)?
            .into_iter()
            .filter_map(|request| {
                request.version.map(|version| PythonPackageIdentity {
                    normalized_name: request.normalized_name,
                    version,
                })
            })
            .collect(),
    )
}

fn resolve_root_request_version(
    dep: &Dependency,
    normalized_name: &str,
    profile: &PythonProfile,
    nodes: &[UvPackageNode],
    root_dependencies: &[UvRootDependencyEntry],
) -> Result<Option<String>> {
    if let Some(version) = dep.exact_version() {
        return Ok(Some(version.to_string()));
    }

    if let Some(selection) = select_root_dependency(root_dependencies, normalized_name, profile)?
        && let Some(version) = selection.version
    {
        return Ok(Some(version));
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
            "Dependency '{}' resolves ambiguously in uv.lock and cannot be trusted exactly",
            crate::report::sanitize_for_terminal(dep.package_name())
        ),
    }
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

struct UvPackageNode {
    normalized_name: String,
    version: String,
    dependencies: Vec<UvDependencyEdge>,
}

#[derive(Clone)]
struct UvDependencyEdge {
    request: PythonPackageRequest,
    marker: Option<String>,
}

impl UvDependencyEdge {
    fn is_in_scope(
        &self,
        profile: &PythonProfile,
        active_extras: &BTreeSet<String>,
    ) -> Result<bool> {
        match &self.marker {
            Some(marker) => evaluate_marker_for_extras(marker, profile, active_extras),
            None => Ok(true),
        }
    }
}

fn uv_dependency_edges(pkg: &toml::value::Table) -> Result<Vec<UvDependencyEdge>> {
    let Some(entries) = pkg.get("dependencies").and_then(|value| value.as_array()) else {
        return Ok(Vec::new());
    };
    let mut deps = Vec::new();
    for entry in entries {
        let Some(table) = entry.as_table() else {
            continue;
        };
        let Some(name) = table.get("name").and_then(|value| value.as_str()) else {
            continue;
        };
        let mut request = PythonPackageRequest::new(normalize_name(name));
        request.version = table
            .get("version")
            .and_then(|value| value.as_str())
            .map(str::to_string);
        request
            .requested_extras
            .extend(python_lock_dependency_extras(table)?);
        deps.push(UvDependencyEdge {
            request,
            marker: table
                .get("marker")
                .and_then(|value| value.as_str())
                .map(str::to_string),
        });
    }
    Ok(deps)
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
                    anyhow::anyhow!("Broken uv.lock: dependency extra entries must be strings")
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
            bail!("Broken uv.lock: dependency extras must be a string or array, got {other:?}")
        }
    }
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

fn effective_python_profile(lock_profile: Option<&PythonLockfileProfile>) -> PythonProfile {
    lock_profile
        .map(|lock_profile| lock_profile.environment.clone())
        .unwrap_or_else(PythonProfile::runtime_for_current_host)
}

fn root_marker_matches_profile(marker: Option<&str>, profile: &PythonProfile) -> Result<bool> {
    match marker {
        Some(marker) => evaluate_marker_for_extras(marker, profile, &profile.selected_extras),
        None => Ok(true),
    }
}

fn merge_selected_scalar(
    current: &mut Option<String>,
    next: Option<&str>,
    package_name: &str,
    field: &str,
) -> Result<()> {
    let Some(next) = next.filter(|value| !value.trim().is_empty()) else {
        return Ok(());
    };
    match current {
        Some(current) if current != next => bail!(
            "Dependency '{}' has multiple in-scope uv root {} entries and cannot be trusted exactly",
            crate::report::sanitize_for_terminal(package_name),
            field
        ),
        Some(_) => Ok(()),
        None => {
            *current = Some(next.to_string());
            Ok(())
        }
    }
}

fn select_root_specifier(
    entries: &[UvRootRequiresEntry],
    normalized_name: &str,
    profile: &PythonProfile,
) -> Result<Option<Option<String>>> {
    let mut selected = false;
    let mut specifier = None;
    for entry in entries {
        if entry.normalized_name != normalized_name
            || !root_marker_matches_profile(entry.marker.as_deref(), profile)?
        {
            continue;
        }
        selected = true;
        merge_selected_scalar(
            &mut specifier,
            entry.specifier.as_deref(),
            normalized_name,
            "requires-dist",
        )?;
    }
    Ok(selected.then_some(specifier))
}

fn select_root_dependency(
    entries: &[UvRootDependencyEntry],
    normalized_name: &str,
    profile: &PythonProfile,
) -> Result<Option<UvSelectedRootDependency>> {
    let mut selected = false;
    let mut version = None;
    let mut requested_extras = BTreeSet::new();
    for entry in entries {
        if entry.normalized_name != normalized_name
            || !root_marker_matches_profile(entry.marker.as_deref(), profile)?
        {
            continue;
        }
        selected = true;
        merge_selected_scalar(
            &mut version,
            entry.version.as_deref(),
            normalized_name,
            "dependency version",
        )?;
        requested_extras.extend(entry.requested_extras.iter().cloned());
    }
    Ok(selected.then_some(UvSelectedRootDependency {
        version,
        requested_extras,
    }))
}

fn extract_root_requires_entries(parsed: &toml::Value) -> Result<Option<Vec<UvRootRequiresEntry>>> {
    let Some(root) = package_entries(parsed)
        .into_iter()
        .find(|pkg| is_virtual_package(pkg))
    else {
        return Ok(None);
    };
    let Some(requires) = root
        .get("metadata")
        .and_then(|value| value.as_table())
        .and_then(|table| table.get("requires-dist"))
        .and_then(|value| value.as_array())
    else {
        return Ok(None);
    };
    let mut entries = Vec::new();
    for entry in requires {
        let table = entry.as_table().ok_or_else(|| {
            anyhow::anyhow!("Broken uv.lock: root requires-dist entries must be tables")
        })?;
        let name = table
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!("Broken uv.lock: root requires-dist entry missing name")
            })?;
        entries.push(UvRootRequiresEntry {
            normalized_name: normalize_name(name),
            specifier: table
                .get("specifier")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            marker: table
                .get("marker")
                .and_then(|value| value.as_str())
                .map(str::to_string),
        });
    }
    Ok(Some(entries))
}

fn extract_root_dependency_entries(
    parsed: &toml::Value,
) -> Result<Option<Vec<UvRootDependencyEntry>>> {
    let Some(root) = package_entries(parsed)
        .into_iter()
        .find(|pkg| is_virtual_package(pkg))
    else {
        return Ok(None);
    };
    let Some(dependencies) = root.get("dependencies").and_then(|value| value.as_array()) else {
        return Ok(None);
    };
    let mut entries = Vec::new();
    for dependency in dependencies {
        let table = dependency.as_table().ok_or_else(|| {
            anyhow::anyhow!("Broken uv.lock: root dependency entries must be tables")
        })?;
        let name = table
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow::anyhow!("Broken uv.lock: root dependency entry missing name"))?;
        entries.push(UvRootDependencyEntry {
            normalized_name: normalize_name(name),
            version: table
                .get("version")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            requested_extras: python_lock_dependency_extras(table)?,
            marker: table
                .get("marker")
                .and_then(|value| value.as_str())
                .map(str::to_string),
        });
    }
    Ok(Some(entries))
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

pub(crate) fn version_matches_uv_specifier(version: &str, specifier: Option<&str>) -> Result<bool> {
    let Some(specifier) = specifier
        .map(str::trim)
        .filter(|specifier| !specifier.is_empty())
    else {
        return Ok(true);
    };
    for clause in specifier
        .split(',')
        .map(str::trim)
        .filter(|clause| !clause.is_empty())
    {
        if let Some(exact) = clause.strip_prefix("==") {
            if let Some(prefix) = exact.strip_suffix(".*") {
                if !version
                    .split('.')
                    .map(str::trim)
                    .zip(prefix.split('.').map(str::trim))
                    .all(|(actual, expected)| actual == expected)
                {
                    return Ok(false);
                }
                continue;
            }
            if version != exact.trim() {
                return Ok(false);
            }
            continue;
        }
        if let Some(not_equal) = clause.strip_prefix("!=") {
            if version == not_equal.trim() {
                return Ok(false);
            }
            continue;
        }
        if let Some(lower) = clause.strip_prefix(">=") {
            if compare_numeric_release_versions(version, lower.trim())? == std::cmp::Ordering::Less
            {
                return Ok(false);
            }
            continue;
        }
        if let Some(lower) = clause.strip_prefix('>') {
            if compare_numeric_release_versions(version, lower.trim())?
                != std::cmp::Ordering::Greater
            {
                return Ok(false);
            }
            continue;
        }
        if let Some(upper) = clause.strip_prefix("<=") {
            if compare_numeric_release_versions(version, upper.trim())?
                == std::cmp::Ordering::Greater
            {
                return Ok(false);
            }
            continue;
        }
        if let Some(upper) = clause.strip_prefix('<') {
            if compare_numeric_release_versions(version, upper.trim())? != std::cmp::Ordering::Less
            {
                return Ok(false);
            }
            continue;
        }
        if let Some(requirement) = clause.strip_prefix("^") {
            let lower = requirement.trim();
            let upper = caret_upper_bound(lower)?;
            if compare_numeric_release_versions(version, lower)? == std::cmp::Ordering::Less
                || compare_numeric_release_versions(version, &upper)? != std::cmp::Ordering::Less
            {
                return Ok(false);
            }
            continue;
        }
        if let Some(requirement) = clause.strip_prefix("~=") {
            let lower = requirement.trim();
            let upper = compatible_release_upper_bound(lower)?;
            if compare_numeric_release_versions(version, lower)? == std::cmp::Ordering::Less
                || compare_numeric_release_versions(version, &upper)? != std::cmp::Ordering::Less
            {
                return Ok(false);
            }
            continue;
        }
        if let Some(requirement) = clause.strip_prefix('~') {
            let lower = requirement.trim();
            let upper = tilde_upper_bound(lower)?;
            if compare_numeric_release_versions(version, lower)? == std::cmp::Ordering::Less
                || compare_numeric_release_versions(version, &upper)? != std::cmp::Ordering::Less
            {
                return Ok(false);
            }
            continue;
        }
        if version != clause {
            return Ok(false);
        }
    }
    Ok(true)
}

fn compare_numeric_release_versions(left: &str, right: &str) -> Result<std::cmp::Ordering> {
    let left = parse_numeric_release(left)?;
    let right = parse_numeric_release(right)?;
    let max_len = left.len().max(right.len());
    for index in 0..max_len {
        match left
            .get(index)
            .copied()
            .unwrap_or_default()
            .cmp(&right.get(index).copied().unwrap_or_default())
        {
            std::cmp::Ordering::Equal => {}
            ordering => return Ok(ordering),
        }
    }
    Ok(std::cmp::Ordering::Equal)
}

fn parse_numeric_release(value: &str) -> Result<Vec<u64>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("Broken uv.lock: empty version specifier component cannot be trusted exactly");
    }
    trimmed
        .split('.')
        .map(|part| {
            part.trim().parse::<u64>().map_err(|_| {
                anyhow::anyhow!(
                    "Broken uv.lock: unsupported non-numeric uv version specifier component '{}'",
                    crate::report::sanitize_for_terminal(value)
                )
            })
        })
        .collect()
}

fn caret_upper_bound(value: &str) -> Result<String> {
    let mut parts = parse_numeric_release(value)?;
    let index = parts
        .iter()
        .position(|part| *part != 0)
        .unwrap_or(parts.len() - 1);
    parts[index] += 1;
    parts.truncate(index + 1);
    Ok(parts
        .into_iter()
        .map(|part| part.to_string())
        .collect::<Vec<_>>()
        .join("."))
}

fn compatible_release_upper_bound(value: &str) -> Result<String> {
    let mut parts = parse_numeric_release(value)?;
    let index = if parts.len() <= 1 { 0 } else { parts.len() - 2 };
    parts[index] += 1;
    parts.truncate(index + 1);
    Ok(parts
        .into_iter()
        .map(|part| part.to_string())
        .collect::<Vec<_>>()
        .join("."))
}

fn tilde_upper_bound(value: &str) -> Result<String> {
    let mut parts = parse_numeric_release(value)?;
    let index = if parts.len() <= 1 { 0 } else { 1 };
    parts[index] += 1;
    parts.truncate(index + 1);
    Ok(parts
        .into_iter()
        .map(|part| part.to_string())
        .collect::<Vec<_>>()
        .join("."))
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
}
