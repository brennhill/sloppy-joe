use super::*;

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

        if is_local_root_package(pkg) {
            continue;
        }
        reject_non_root_dev_dependencies(pkg, name).map_err(|err| {
            anyhow::anyhow!("Broken lockfile '{}': {}", source_path.display(), err)
        })?;

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
        let registry = source.get("registry").and_then(|value| value.as_str());
        validate_artifact_hosts(pkg, name, registry.unwrap_or_default(), source_path)?;
    }

    Ok(())
}

/// `uv sync` downloads the `url` of each locked sdist and wheel, not whatever the registry
/// serves. The artifact must come from where the registry's files live: `files.pythonhosted.org`
/// for PyPI, the registry's own host otherwise (and always over https for PyPI).
fn validate_artifact_hosts(
    pkg: &toml::value::Table,
    name: &str,
    registry: &str,
    source_path: &Path,
) -> Result<()> {
    let is_pypi = crate::config::normalize_python_index_url(registry)
        == crate::config::normalized_default_pypi_index();
    let registry_url = reqwest::Url::parse(registry).ok();
    let artifacts = pkg
        .get("sdist")
        .and_then(|value| value.as_table())
        .into_iter()
        .chain(
            pkg.get("wheels")
                .and_then(|value| value.as_array())
                .into_iter()
                .flatten()
                .filter_map(|value| value.as_table()),
        );
    for artifact in artifacts {
        let Some(url) = artifact.get("url").and_then(|value| value.as_str()) else {
            continue;
        };
        let trusted = reqwest::Url::parse(url).ok().is_some_and(|artifact| {
            artifact.username().is_empty()
                && artifact.password().is_none()
                && match (&registry_url, is_pypi) {
                    (_, true) => {
                        artifact.scheme() == "https"
                            && artifact.port().is_none()
                            && artifact.host_str().map(str::to_ascii_lowercase).as_deref()
                                == Some("files.pythonhosted.org")
                    }
                    (Some(registry), false) => {
                        artifact.host_str().map(str::to_ascii_lowercase)
                            == registry.host_str().map(str::to_ascii_lowercase)
                            && artifact.port_or_known_default() == registry.port_or_known_default()
                    }
                    (None, false) => false,
                }
        });
        if !trusted {
            bail!(
                "Broken lockfile '{}': package '{}' downloads an artifact from '{}', which is not where its registry '{}' serves files. uv sync fetches that URL, not the registry's copy.",
                source_path.display(),
                crate::report::sanitize_for_terminal(name),
                crate::report::sanitize_for_terminal(url),
                crate::report::sanitize_for_terminal(registry)
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
        if is_local_root_package(pkg) {
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

pub(crate) fn source_intent_urls_by_package(
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

pub(crate) fn uv_source_urls_by_identity(
    parsed: &toml::Value,
    source_path: &Path,
) -> Result<HashMap<PythonPackageIdentity, String>> {
    let mut sources = HashMap::new();
    for pkg in package_entries(parsed) {
        if is_local_root_package(pkg) {
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
