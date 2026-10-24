use crate::*;

pub(crate) fn prefer_trusted_python_project_inputs(specs: &mut Vec<ProjectInputSpec>) {
    let trusted_pyproject_dirs: std::collections::HashSet<std::path::PathBuf> = specs
        .iter()
        .filter(|spec| {
            matches!(
                spec.kind,
                ProjectInputKind::PyProjectPoetry | ProjectInputKind::PyProjectUv
            )
        })
        .map(|spec| spec.project_dir().to_path_buf())
        .collect();
    let legacy_pyproject_dirs: std::collections::HashSet<std::path::PathBuf> = specs
        .iter()
        .filter(|spec| spec.kind == ProjectInputKind::PyProjectLegacy)
        .map(|spec| spec.project_dir().to_path_buf())
        .collect();
    let trusted_requirements_dirs: std::collections::HashSet<std::path::PathBuf> = specs
        .iter()
        .filter(|spec| spec.kind == ProjectInputKind::PyRequirementsTrusted)
        .map(|spec| spec.project_dir().to_path_buf())
        .collect();

    specs.retain(|spec| {
        if !spec.kind.is_python() {
            return true;
        }
        // `requirements/*.txt` belongs to the project in the parent directory.
        let owner_dir = if parsers::requirements::is_in_requirements_directory(&spec.manifest_path)
        {
            spec.project_dir().parent().unwrap_or(spec.project_dir())
        } else {
            spec.project_dir()
        };
        if trusted_pyproject_dirs.contains(spec.project_dir())
            || trusted_pyproject_dirs.contains(owner_dir)
        {
            return matches!(
                spec.kind,
                ProjectInputKind::PyProjectPoetry | ProjectInputKind::PyProjectUv
            );
        }
        if trusted_requirements_dirs.contains(spec.project_dir()) {
            if legacy_pyproject_dirs.contains(spec.project_dir()) {
                return true;
            }
            return spec.kind == ProjectInputKind::PyRequirementsTrusted;
        }
        true
    });
}

pub(crate) fn reject_ambiguous_python_project_inputs(specs: &[ProjectInputSpec]) -> Result<()> {
    let mut trusted_requirements_dirs = std::collections::HashSet::new();
    let mut legacy_pyproject_dirs = std::collections::HashSet::new();

    for spec in specs {
        match spec.kind {
            ProjectInputKind::PyRequirementsTrusted => {
                trusted_requirements_dirs.insert(spec.project_dir().to_path_buf());
            }
            ProjectInputKind::PyProjectLegacy => {
                legacy_pyproject_dirs.insert(spec.project_dir().to_path_buf());
            }
            _ => {}
        }
    }

    let ambiguous_dirs: Vec<_> = trusted_requirements_dirs
        .intersection(&legacy_pyproject_dirs)
        .cloned()
        .collect();
    if let Some(dir) = ambiguous_dirs.into_iter().min() {
        anyhow::bail!(
            "Ambiguous trusted Python roots in '{}': found both a legacy pyproject.toml and a fully hash-locked requirements file. sloppy-joe refuses to guess which manifest is authoritative. Fix: remove the weaker manifest from this directory, or split the trusted requirements into a separate standalone root.",
            dir.display()
        );
    }

    Ok(())
}

pub(crate) fn has_npm_lockfile(project_dir: &std::path::Path) -> bool {
    ["npm-shrinkwrap.json", "package-lock.json"]
        .iter()
        .any(|name| parsers::path_detected(&project_dir.join(name)).unwrap_or(false))
}

pub(crate) fn promote_trusted_pip_tools_specs(
    scan_root: &std::path::Path,
    specs: &mut [ProjectInputSpec],
) -> Result<()> {
    for spec in specs.iter_mut() {
        if spec.kind != ProjectInputKind::PyRequirements {
            continue;
        }
        if parsers::requirements::is_hash_locked_requirements_file(&spec.manifest_path, scan_root)?
        {
            spec.kind = ProjectInputKind::PyRequirementsTrusted;
        }
    }
    Ok(())
}

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

pub(crate) fn prune_included_requirement_specs(
    scan_root: &std::path::Path,
    specs: &mut Vec<ProjectInputSpec>,
) -> Result<()> {
    let mut included = std::collections::HashSet::new();

    for spec in specs.iter().filter(|spec| {
        matches!(
            spec.kind,
            ProjectInputKind::PyRequirements | ProjectInputKind::PyRequirementsTrusted
        )
    }) {
        for include in parsers::requirements::included_paths(&spec.manifest_path, scan_root)? {
            included.insert(include);
        }
    }

    specs.retain(|spec| {
        if !matches!(
            spec.kind,
            ProjectInputKind::PyRequirements | ProjectInputKind::PyRequirementsTrusted
        ) {
            return true;
        }
        match std::fs::canonicalize(&spec.manifest_path) {
            Ok(canonical) => !included.contains(&canonical),
            Err(_) => true,
        }
    });

    Ok(())
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
        // Gradle plugin markers and buildscript classpath artifacts resolve from
        // different repositories, so each group gets its own project.
        let tooling_groups = if spec.kind == ProjectInputKind::Gradle {
            let (markers, classpath) =
                gradle_plugin_scan::split_tooling_deps(parsed.unlocked_tooling_deps);
            vec![markers, classpath]
        } else {
            vec![parsed.unlocked_tooling_deps]
        };
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
    match spec.kind {
        ProjectInputKind::Cargo => Ok(ParsedInput {
            deps: parse_cargo_project_dependencies(scan_root, spec, config)?,
            ..ParsedInput::default()
        }),
        ProjectInputKind::PyProjectPoetry
        | ProjectInputKind::PyProjectUv
        | ProjectInputKind::PyRequirements
        | ProjectInputKind::PyRequirementsTrusted
        | ProjectInputKind::PyProjectLegacy => {
            parse_python_project_dependencies(scan_root, spec, opts)
        }
        ProjectInputKind::Gradle => gradle_plugin_scan::parse_gradle_project_input(spec, config),
        _ => Ok(ParsedInput {
            deps: parse_project_input(scan_root, spec)?,
            ..ParsedInput::default()
        }),
    }
}

pub(crate) fn parse_cargo_project_dependencies(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    config: &config::SloppyJoeConfig,
) -> Result<Vec<Dependency>> {
    let manifest = parsers::cargo_toml::parse_manifest_file(&spec.manifest_path)?;
    let mut deps = Vec::new();
    for dep in resolve_cargo_effective_dependencies(scan_root, &manifest, config)? {
        match dep.spec.source {
            parsers::cargo_toml::CargoSourceSpec::CratesIo
            | parsers::cargo_toml::CargoSourceSpec::RegistryAlias(_)
            | parsers::cargo_toml::CargoSourceSpec::RegistryIndex(_) => {
                let dependency = Dependency {
                    name: dep.spec.package_name,
                    version: dep.spec.version,
                    ecosystem: Ecosystem::Cargo,
                    actual_name: None,
                };
                parsers::validate_dependency(&dependency, &spec.manifest_path)?;
                deps.push(dependency);
            }
            parsers::cargo_toml::CargoSourceSpec::Path(_)
            | parsers::cargo_toml::CargoSourceSpec::Git { .. }
            | parsers::cargo_toml::CargoSourceSpec::Workspace => {}
        }
    }
    Ok(deps)
}

pub(crate) fn parse_project_input(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
) -> Result<Vec<Dependency>> {
    match spec.kind {
        ProjectInputKind::Npm => parsers::package_json::parse(spec.project_dir()),
        ProjectInputKind::PyProjectPoetry => {
            parsers::pyproject_toml::parse_poetry_file(&spec.manifest_path)
        }
        ProjectInputKind::PyProjectUv => {
            parsers::pyproject_toml::parse_legacy_file(&spec.manifest_path)
        }
        ProjectInputKind::PyRequirements => {
            parsers::requirements::parse_file(&spec.manifest_path, scan_root)
        }
        ProjectInputKind::PyRequirementsTrusted => {
            parsers::requirements::parse_file(&spec.manifest_path, scan_root)
        }
        ProjectInputKind::PyProjectLegacy => {
            parsers::pyproject_toml::parse_legacy_file(&spec.manifest_path)
        }
        ProjectInputKind::PyPipfile => parsers::pipfile::parse_file(&spec.manifest_path),
        ProjectInputKind::PySetupPy => parsers::setup_py::parse_file(&spec.manifest_path),
        ProjectInputKind::PySetupCfg => parsers::setup_cfg::parse_file(&spec.manifest_path),
        ProjectInputKind::Cargo => parsers::cargo_toml::parse(spec.project_dir()),
        ProjectInputKind::Go => parsers::go_mod::parse(spec.project_dir()),
        ProjectInputKind::Ruby => parsers::gemfile::parse(spec.project_dir()),
        ProjectInputKind::Php => parsers::composer_json::parse(spec.project_dir()),
        ProjectInputKind::Gradle | ProjectInputKind::Maven => {
            parsers::jvm::parse_manifest(&spec.manifest_path)
        }
        ProjectInputKind::Dotnet => parsers::csproj::parse_file(&spec.manifest_path),
    }
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

pub(crate) fn selected_lockfile_path(spec: &ProjectInputSpec) -> Option<std::path::PathBuf> {
    if let Some(path) = &spec.lockfile_path_override {
        return Some(path.clone());
    }
    let project_dir = spec.project_dir();
    match spec.kind {
        ProjectInputKind::Npm => spec
            .js_binding
            .as_ref()
            .and_then(|binding| binding.lockfile_path.clone())
            .or_else(|| {
                first_existing_lockfile(project_dir, &["npm-shrinkwrap.json", "package-lock.json"])
            }),
        // Lockfile named by the descriptor, next to the manifest.
        ProjectInputKind::Cargo
        | ProjectInputKind::Go
        | ProjectInputKind::Ruby
        | ProjectInputKind::Php
        | ProjectInputKind::Gradle
        | ProjectInputKind::Dotnet
        | ProjectInputKind::PyProjectPoetry
        | ProjectInputKind::PyProjectUv => spec
            .kind
            .descriptor()
            .lockfile_name
            .map(|name| project_dir.join(name)),
        ProjectInputKind::PyRequirementsTrusted => Some(spec.manifest_path.clone()),
        ProjectInputKind::PyPipfile => {
            first_existing_lockfile(project_dir, &[lockfiles::pipfile_lock::LOCKFILE_NAME])
        }
        ProjectInputKind::PyRequirements
        | ProjectInputKind::PyProjectLegacy
        | ProjectInputKind::PySetupPy
        | ProjectInputKind::PySetupCfg
        | ProjectInputKind::Maven => None,
    }
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
