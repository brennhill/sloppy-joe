use crate::*;

pub(crate) fn npm_dependency_entries(manifest: &serde_json::Value) -> Vec<(String, String)> {
    [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ]
    .into_iter()
    .flat_map(|section| {
        manifest
            .get(section)
            .and_then(|value| value.as_object())
            .into_iter()
            .flat_map(|section| section.iter())
            .filter_map(|(name, value)| value.as_str().map(|spec| (name.clone(), spec.to_string())))
    })
    .collect()
}

#[cfg(test)]
pub(crate) fn parse_project_inputs(
    scan_root: &std::path::Path,
    specs: &[ProjectInputSpec],
    config: &config::SloppyJoeConfig,
) -> Result<Vec<ParsedProject>> {
    parse_project_inputs_with_options(scan_root, specs, config, &ScanOptions::default())
}

pub(crate) fn parse_project_inputs_with_options(
    scan_root: &std::path::Path,
    specs: &[ProjectInputSpec],
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> Result<Vec<ParsedProject>> {
    let mut projects = Vec::new();
    for spec in specs {
        let parsed = parse_project_input_with_config(scan_root, spec, config, opts)?;
        projects.push(ParsedProject {
            spec: spec.clone(),
            deps: parsed.deps,
            python_root_extras: parsed.python_root_extras,
            unlocked_tooling: false,
        });
        let tooling_groups = ecosystems::tooling_groups(spec.kind, parsed.unlocked_tooling_deps);
        for tooling_deps in tooling_groups.into_iter().filter(|deps| !deps.is_empty()) {
            projects.push(ParsedProject {
                spec: spec.clone(),
                deps: tooling_deps,
                python_root_extras: PythonRootExtras::new(),
                unlocked_tooling: true,
            });
        }
    }
    Ok(projects)
}

pub(crate) fn parse_project_input_with_config(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> Result<ParsedInput> {
    let ctx = ecosystems::ScanCtx {
        scan_root,
        config,
        opts,
    };
    ecosystems::for_kind(spec.kind).parse(&ctx, spec)
}

pub(crate) fn parse_project_input(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
) -> Result<Vec<Dependency>> {
    ecosystems::for_kind(spec.kind).parse_manifest(scan_root, spec)
}

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
                deps: parse_project_input(scan_root, spec)?,
                ..ParsedInput::default()
            });
        }
    };

    let profile = active_python_profile(opts);
    let mut warnings = Vec::new();
    if scoped
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
        if dep.is_in_scope(&profile)? {
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

pub(crate) fn js_lockfile_help(spec: &ProjectInputSpec) -> String {
    match spec.js_binding.as_ref().map(|binding| binding.manager) {
        Some(JsPackageManager::Pnpm) => {
            "Run `pnpm install --lockfile-only` and commit pnpm-lock.yaml.".to_string()
        }
        Some(JsPackageManager::Yarn) => {
            "Commit the authoritative yarn.lock for this project.".to_string()
        }
        Some(JsPackageManager::Bun) => {
            "Commit the authoritative bun.lock or bun.lockb for this project.".to_string()
        }
        _ => spec
            .kind
            .missing_lockfile_help()
            .unwrap_or("Commit the authoritative lockfile for this project.")
            .to_string(),
    }
}

pub(crate) fn lockfile_paths_for_project(spec: &ProjectInputSpec) -> Vec<std::path::PathBuf> {
    selected_lockfile_path(spec).into_iter().collect()
}
