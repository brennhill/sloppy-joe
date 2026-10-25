use super::*;

pub(crate) fn parse_python_project_dependencies(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    opts: &ScanOptions<'_>,
) -> Result<ParsedInput> {
    let scoped = match spec.kind {
        ProjectInputKind::PyProjectPoetry => {
            parsers::pyproject_toml::parse_poetry_scoped_file(&spec.manifest_path)?
        }
        ProjectInputKind::PyProjectUv | ProjectInputKind::PyProjectLegacy => {
            parsers::pyproject_toml::parse_legacy_scoped_file(&spec.manifest_path)?
        }
        ProjectInputKind::PyRequirements | ProjectInputKind::PyRequirementsTrusted => {
            parsers::requirements::parse_scoped_file(&spec.manifest_path, scan_root)?
        }
        _ => {
            return Ok(ParsedInput {
                deps: ecosystems::for_kind(spec.kind).parse_manifest(scan_root, spec)?,
                ..ParsedInput::default()
            });
        }
    };

    let profile = active_python_profile(opts);
    let coverage = profile.for_every_environment();
    // Where a lockfile resolves the project, markers pick the target's versions and the
    // lockfile coverage graph still scans every environment. Without a lockfile markers decide
    // nothing: a dependency gated on another platform is installed there, so it is scanned.
    let lockfile_backed = lockfile_resolves_markers(spec.kind);
    let target = if lockfile_backed { &profile } else { &coverage };
    let mut warnings = Vec::new();
    if lockfile_backed
        && scoped
            .iter()
            .any(parsers::python_scope::PythonScopedDependency::has_environment_scope)
        && !profile.explicit_selection
    {
        warnings.push(implicit_runtime_profile_warning(spec));
    }
    warnings.extend(python_unscanned_scope_warning(spec, &scoped, &profile));

    let mut deps = Vec::new();
    let mut tool_env_deps = Vec::new();
    let mut root_extras: PythonRootExtras = PythonRootExtras::new();
    for dep in &scoped {
        if !dep.is_in_scope(&coverage)? {
            continue;
        }
        if dep.unlocked_tool_env {
            // Hatch/PDM environments are installable but never recorded in uv.lock or
            // poetry.lock: scan them as unlocked tooling instead of reporting lock drift.
            tool_env_deps.push(dep.dependency.clone());
            continue;
        }
        if !dep.requested_extras.is_empty() {
            root_extras
                .entry(parsers::requirements::normalize_distribution_name(
                    dep.dependency.package_name(),
                ))
                .or_default()
                .extend(dep.requested_extras.iter().cloned());
        }
        if dep.is_in_scope(target)? {
            deps.push(dep.dependency.clone());
        }
    }
    let mut seen = std::collections::HashSet::new();
    deps.retain(|dep| {
        seen.insert((
            dep.package_name().to_string(),
            dep.version.clone(),
            dep.actual_name.clone(),
        ))
    });
    let mut unlocked_tooling_deps = match spec.kind {
        ProjectInputKind::PyProjectPoetry
        | ProjectInputKind::PyProjectUv
        | ProjectInputKind::PyProjectLegacy => {
            parsers::pyproject_toml::parse_unlocked_tooling_file(&spec.manifest_path)?
        }
        _ => Vec::new(),
    };
    unlocked_tooling_deps.extend(tool_env_deps);
    let mut seen_tooling = std::collections::HashSet::new();
    unlocked_tooling_deps.retain(|dep| {
        seen_tooling.insert((
            dep.package_name().to_string(),
            dep.version.clone(),
            dep.actual_name.clone(),
        ))
    });
    Ok(ParsedInput {
        deps,
        warnings,
        python_root_extras: root_extras,
        unlocked_tooling_deps,
    })
}

/// Poetry and uv resolve environment markers through their lockfile.
fn lockfile_resolves_markers(kind: ProjectInputKind) -> bool {
    matches!(
        kind,
        ProjectInputKind::PyProjectPoetry | ProjectInputKind::PyProjectUv
    )
}

/// The manifest dependencies of a Poetry or uv project in every environment (groups and extras
/// still follow the selection): the roots its lockfile is walked from for source policy and for
/// the packages the scan checks, so a root whose marker is false for the target is not lost.
pub(crate) fn python_coverage_roots(
    spec: &ProjectInputSpec,
    opts: &ScanOptions<'_>,
) -> Result<Vec<Dependency>> {
    let scoped = match spec.kind {
        ProjectInputKind::PyProjectPoetry => {
            parsers::pyproject_toml::parse_poetry_scoped_file(&spec.manifest_path)?
        }
        ProjectInputKind::PyProjectUv => {
            parsers::pyproject_toml::parse_legacy_scoped_file(&spec.manifest_path)?
        }
        _ => return Ok(Vec::new()),
    };
    let coverage = active_python_profile(opts).for_every_environment();
    let mut roots = Vec::new();
    for dep in scoped {
        if !dep.unlocked_tool_env && dep.is_in_scope(&coverage)? {
            roots.push(dep.dependency);
        }
    }
    Ok(roots)
}

/// The lockfile profile for `spec`: the target environment, with the coverage roots filled in.
pub(crate) fn python_lockfile_profile_for(
    spec: &ProjectInputSpec,
    opts: &ScanOptions<'_>,
    root_extras: &PythonRootExtras,
) -> Result<lockfiles::PythonLockfileProfile> {
    let mut profile = active_python_lockfile_profile(opts, root_extras);
    profile.coverage_roots = python_coverage_roots(spec, opts)?;
    Ok(profile)
}
