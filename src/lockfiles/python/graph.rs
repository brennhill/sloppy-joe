use super::*;

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

pub(crate) fn reachable_package_identities_from_nodes(
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

pub(crate) fn poetry_package_nodes(parsed: &toml::Value) -> Result<Vec<PoetryPackageNode>> {
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
                has_explicit_source: pkg.get("source").is_some(),
            })
        })
        .collect()
}

pub(crate) fn resolved_root_requests(
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

pub(crate) fn resolved_root_identities(
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

pub(crate) fn resolve_root_request_version(
    dep: &Dependency,
    normalized_name: &str,
    nodes: &[PoetryPackageNode],
) -> Result<Option<String>> {
    if let Some(version) = dep.exact_version() {
        return Ok(Some(version.to_string()));
    }

    let candidates: Vec<&PoetryPackageNode> = nodes
        .iter()
        .filter(|node| node.normalized_name == normalized_name)
        .collect();
    let mut matching_versions = candidates
        .iter()
        .map(|node| node.version.clone())
        .collect::<Vec<_>>();
    matching_versions.sort();
    matching_versions.dedup();

    match matching_versions.as_slice() {
        [] => Ok(None),
        [version] => Ok(Some(version.clone())),
        // poetry.lock keeps one entry per Python-version split, so several
        // locked versions are normal and the interpreter picks one at install
        // time. Leave the version open so every candidate is reachable and
        // scanned. An open version also authorizes each candidate's own locked
        // source, so that is only safe when no candidate names a non-default
        // source; otherwise stay fail closed.
        _ if candidates.iter().any(|node| node.has_explicit_source) => bail!(
            "Dependency '{}' resolves ambiguously in poetry.lock and cannot be trusted exactly",
            crate::report::sanitize_for_terminal(dep.package_name())
        ),
        _ => Ok(None),
    }
}

pub(crate) struct PoetryPackageNode {
    pub(crate) normalized_name: String,
    pub(crate) version: String,
    pub(crate) dependencies: Vec<PoetryDependencyEdge>,
    /// The lock entry names a `[package.source]` (an index other than the default).
    pub(crate) has_explicit_source: bool,
}

#[derive(Clone)]
pub(crate) struct PoetryDependencyEdge {
    pub(crate) request: PythonPackageRequest,
    pub(crate) marker: Option<String>,
    pub(crate) optional: bool,
}

impl PoetryDependencyEdge {
    pub(crate) fn is_in_scope(
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

pub(crate) fn poetry_dependency_edges(
    pkg: &toml::value::Table,
) -> Result<Vec<PoetryDependencyEdge>> {
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

pub(crate) fn poetry_dependency_edge(
    name: &str,
    value: &toml::Value,
) -> Result<PoetryDependencyEdge> {
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

pub(crate) fn python_lock_dependency_extras(
    table: &toml::value::Table,
) -> Result<BTreeSet<String>> {
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
