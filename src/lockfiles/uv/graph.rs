use super::*;

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

pub(crate) fn reachable_package_identities_from_nodes(
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

pub(crate) fn uv_package_nodes(parsed: &toml::Value) -> Result<Vec<UvPackageNode>> {
    package_entries(parsed)
        .into_iter()
        .filter(|pkg| !is_local_root_package(pkg))
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
            reject_non_root_dev_dependencies(pkg, name)
                .map_err(|err| anyhow::anyhow!("Broken uv.lock: {err}"))?;
            Ok(UvPackageNode {
                normalized_name: normalize_name(name),
                version: version.to_string(),
                dependencies: uv_dependency_edges(pkg)?,
            })
        })
        .collect()
}

pub(crate) fn resolved_root_requests(
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

pub(crate) fn resolved_root_identities(
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

pub(crate) fn resolve_root_request_version(
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

pub(crate) struct UvPackageNode {
    pub(crate) normalized_name: String,
    pub(crate) version: String,
    pub(crate) dependencies: Vec<UvDependencyEdge>,
}

#[derive(Clone)]
pub(crate) struct UvDependencyEdge {
    pub(crate) request: PythonPackageRequest,
    pub(crate) marker: Option<String>,
    /// Set for edges from `[package.optional-dependencies.<extra>]`: the edge applies only when
    /// the package itself was requested with that (normalized) extra.
    pub(crate) extra: Option<String>,
}

impl UvDependencyEdge {
    pub(crate) fn is_in_scope(
        &self,
        profile: &PythonProfile,
        active_extras: &BTreeSet<String>,
    ) -> Result<bool> {
        if let Some(extra) = &self.extra
            && !active_extras.contains(extra)
        {
            return Ok(false);
        }
        match &self.marker {
            Some(marker) => evaluate_marker_for_extras(marker, profile, active_extras),
            None => Ok(true),
        }
    }
}

/// uv records dependency groups only for the project root (and workspace members, which are
/// unsupported). A registry package claiming dev-dependencies is not something uv writes, and
/// installing from it would hide packages from the root graph, so it fails closed.
pub(crate) fn reject_non_root_dev_dependencies(pkg: &toml::value::Table, name: &str) -> Result<()> {
    if pkg.contains_key("dev-dependencies") {
        bail!(
            "package '{}' declares dev-dependencies, which uv only records for the project root; the lockfile was modified",
            crate::report::sanitize_for_terminal(name)
        );
    }
    Ok(())
}

pub(crate) fn uv_dependency_edges(pkg: &toml::value::Table) -> Result<Vec<UvDependencyEdge>> {
    let mut edges = Vec::new();
    if let Some(entries) = pkg.get("dependencies") {
        for table in lock_dependency_tables(entries, "dependencies")? {
            edges.push(uv_dependency_edge(table, None)?);
        }
    }
    if let Some(optional) = pkg.get("optional-dependencies") {
        let optional = optional.as_table().ok_or_else(|| {
            anyhow::anyhow!("Broken uv.lock: optional-dependencies must be a table of extras")
        })?;
        for (extra, entries) in optional {
            let extra = normalize_name(extra);
            for table in lock_dependency_tables(entries, "optional-dependencies")? {
                edges.push(uv_dependency_edge(table, Some(extra.clone()))?);
            }
        }
    }
    Ok(edges)
}

pub(crate) fn uv_dependency_edge(
    table: &toml::value::Table,
    extra: Option<String>,
) -> Result<UvDependencyEdge> {
    let name = table
        .get("name")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow::anyhow!("Broken uv.lock: dependency entry missing name"))?;
    let mut request = PythonPackageRequest::new(normalize_name(name));
    request.version = table
        .get("version")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    request
        .requested_extras
        .extend(python_lock_dependency_extras(table)?);
    Ok(UvDependencyEdge {
        request,
        marker: table
            .get("marker")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        extra,
    })
}

/// A uv.lock dependency list: an array of inline tables. Anything else fails closed instead of
/// silently dropping edges.
pub(crate) fn lock_dependency_tables<'a>(
    value: &'a toml::Value,
    label: &str,
) -> Result<Vec<&'a toml::value::Table>> {
    let entries = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Broken uv.lock: {label} must be an array of tables"))?;
    entries
        .iter()
        .map(|entry| {
            entry
                .as_table()
                .ok_or_else(|| anyhow::anyhow!("Broken uv.lock: {label} entries must be tables"))
        })
        .collect()
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
