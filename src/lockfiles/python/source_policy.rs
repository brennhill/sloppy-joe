use super::*;

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

pub(crate) fn poetry_source_urls_by_identity(
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

pub(crate) fn poetry_package_source(
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
