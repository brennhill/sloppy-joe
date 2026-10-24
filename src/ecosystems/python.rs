use super::*;

pub(super) struct Python;

impl EcosystemSupport for Python {
    fn kinds(&self) -> &'static [ProjectInputKind] {
        &[
            ProjectInputKind::PyProjectPoetry,
            ProjectInputKind::PyProjectUv,
            ProjectInputKind::PyRequirements,
            ProjectInputKind::PyRequirementsTrusted,
            ProjectInputKind::PyProjectLegacy,
            ProjectInputKind::PyPipfile,
            ProjectInputKind::PySetupPy,
            ProjectInputKind::PySetupCfg,
        ]
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        let project_dir = spec.project_dir();
        match spec.kind {
            ProjectInputKind::PyProjectPoetry | ProjectInputKind::PyProjectUv => {
                common::named_lockfile(spec)
            }
            ProjectInputKind::PyRequirementsTrusted => Some(spec.manifest_path.clone()),
            ProjectInputKind::PyPipfile => {
                first_existing_lockfile(project_dir, &[lockfiles::pipfile_lock::LOCKFILE_NAME])
            }
            ProjectInputKind::PyRequirements
            | ProjectInputKind::PyProjectLegacy
            | ProjectInputKind::PySetupPy
            | ProjectInputKind::PySetupCfg => None,
            other => wrong_plugin(other),
        }
    }

    fn parse_manifest(&self, scan_root: &Path, spec: &ProjectInputSpec) -> Result<Vec<Dependency>> {
        let manifest = &spec.manifest_path;
        match spec.kind {
            ProjectInputKind::PyProjectPoetry => {
                parsers::pyproject_toml::parse_poetry_file(manifest)
            }
            ProjectInputKind::PyProjectUv | ProjectInputKind::PyProjectLegacy => {
                parsers::pyproject_toml::parse_legacy_file(manifest)
            }
            ProjectInputKind::PyRequirements | ProjectInputKind::PyRequirementsTrusted => {
                parsers::requirements::parse_file(manifest, scan_root)
            }
            ProjectInputKind::PyPipfile => parsers::pipfile::parse_file(manifest),
            ProjectInputKind::PySetupPy => parsers::setup_py::parse_file(manifest),
            ProjectInputKind::PySetupCfg => parsers::setup_cfg::parse_file(manifest),
            other => wrong_plugin(other),
        }
    }

    fn parse(&self, ctx: &ScanCtx<'_>, spec: &ProjectInputSpec) -> Result<ParsedInput> {
        parse_python_project_dependencies(ctx.scan_root, spec, ctx.opts)
    }

    fn detect(&self, path: &Path) -> Result<Option<ProjectInputKind>> {
        if path.file_name().and_then(|name| name.to_str()) == Some("pyproject.toml") {
            return Ok(Some(
                match parsers::pyproject_toml::classify_manifest(path)? {
                    parsers::pyproject_toml::PyprojectKind::Poetry => {
                        ProjectInputKind::PyProjectPoetry
                    }
                    parsers::pyproject_toml::PyprojectKind::Uv => ProjectInputKind::PyProjectUv,
                    parsers::pyproject_toml::PyprojectKind::Legacy => {
                        ProjectInputKind::PyProjectLegacy
                    }
                },
            ));
        }
        if let Some(kind) = common::kind_for_file_name(self.kinds(), path) {
            return Ok(Some(kind));
        }
        Ok(parsers::requirements::is_requirements_manifest_path(path)
            .then_some(ProjectInputKind::PyRequirements))
    }

    fn refine_specs(
        &self,
        scan_root: &Path,
        _config: &config::SloppyJoeConfig,
        specs: &mut Vec<ProjectInputSpec>,
    ) -> Result<()> {
        promote_trusted_pip_tools_specs(scan_root, specs)?;
        prune_included_requirement_specs(scan_root, specs)?;
        reject_ambiguous_python_project_inputs(specs)?;
        prefer_trusted_python_project_inputs(specs);
        Ok(())
    }

    fn preflight(&self, ctx: &PreflightCtx<'_>, spec: &ProjectInputSpec) -> Result<Vec<Issue>> {
        let parsed = common::parse_for_preflight(self, ctx, spec)?;
        let mut warnings = parsed.warnings.clone();
        check_python_lockfile(ctx, spec, &parsed, &mut warnings)?;
        self.validate_lockfile(ctx, spec)?;
        Ok(warnings)
    }
}

impl Python {
    /// Poetry and uv lockfiles are re-read against the resolved dependency set.
    fn validate_lockfile(&self, ctx: &PreflightCtx<'_>, spec: &ProjectInputSpec) -> Result<()> {
        let (config, opts) = (ctx.scan.config, ctx.scan.opts);
        match spec.kind {
            ProjectInputKind::PyProjectPoetry => {
                let parsed = self.parse(&ctx.scan, spec)?;
                read_validated_poetry_lockfile(
                    spec,
                    &parsed.deps,
                    &parsed.python_root_extras,
                    config,
                    opts,
                )?;
            }
            ProjectInputKind::PyProjectUv => {
                let parsed = self.parse(&ctx.scan, spec)?;
                read_validated_uv_lockfile(
                    spec,
                    &parsed.deps,
                    &parsed.python_root_extras,
                    config,
                    opts,
                )?;
            }
            ProjectInputKind::PyRequirementsTrusted
            | ProjectInputKind::PyRequirements
            | ProjectInputKind::PyProjectLegacy
            | ProjectInputKind::PyPipfile
            | ProjectInputKind::PySetupPy
            | ProjectInputKind::PySetupCfg => {}
            other => wrong_plugin(other),
        }
        Ok(())
    }
}

/// Require the lockfile the Python kind depends on (or refuse the kind under `poetry_only`).
fn check_python_lockfile(
    ctx: &PreflightCtx<'_>,
    spec: &ProjectInputSpec,
    parsed_input: &ParsedInput,
    warnings: &mut Vec<Issue>,
) -> Result<()> {
    let ScanCtx {
        scan_root,
        config,
        opts,
    } = ctx.scan;
    let deps = &parsed_input.deps;
    let poetry_only = config.python_enforcement == config::PythonEnforcement::PoetryOnly;
    match spec.kind {
        ProjectInputKind::PyProjectPoetry => {
            common::ensure_kind_lockfile(
                spec,
                &common::named_lockfile(spec).expect("Poetry names poetry.lock"),
            )?;
            let validated = read_validated_poetry_lockfile(
                spec,
                deps,
                &parsed_input.python_root_extras,
                config,
                opts,
            )?;
            warnings.extend(validated.warnings);
            warnings.extend(trusted_python_preference_warnings(spec)?);
        }
        ProjectInputKind::PyProjectUv => {
            if poetry_only {
                anyhow::bail!(
                    "Python manifest '{}' uses the uv workflow, which is not allowed in poetry_only mode. Use Poetry with pyproject.toml + poetry.lock, or relax python_enforcement to prefer_poetry.",
                    spec.manifest_path.display()
                );
            }
            common::ensure_kind_lockfile(
                spec,
                &common::named_lockfile(spec).expect("uv names uv.lock"),
            )?;
            let (_, source_warnings) = read_validated_uv_lockfile(
                spec,
                deps,
                &parsed_input.python_root_extras,
                config,
                opts,
            )?;
            warnings.extend(source_warnings);
            warnings.extend(trusted_python_preference_warnings(spec)?);
        }
        ProjectInputKind::PyRequirementsTrusted => {
            if poetry_only {
                anyhow::bail!(
                    "Python manifest '{}' uses hash-locked pip-tools requirements, which are not allowed in poetry_only mode. Use Poetry with pyproject.toml + poetry.lock, or relax python_enforcement to prefer_poetry.",
                    spec.manifest_path.display()
                );
            }
            if !validate_hash_locked_requirements_provenance(scan_root, spec, config)? {
                warnings.push(hash_locked_requirements_reduced_confidence_warning(spec));
            }
        }
        ProjectInputKind::PyRequirements
        | ProjectInputKind::PyProjectLegacy
        | ProjectInputKind::PyPipfile
        | ProjectInputKind::PySetupPy
        | ProjectInputKind::PySetupCfg => {
            if spec.kind == ProjectInputKind::PyRequirements {
                parsers::requirements::ensure_trusted_indexes(
                    &spec.manifest_path,
                    scan_root,
                    config,
                )?;
            }
            if poetry_only {
                anyhow::bail!(
                    "Legacy Python manifest '{}' is not allowed in poetry_only mode. Migrate this project to Poetry with pyproject.toml + poetry.lock, or relax python_enforcement to prefer_poetry.",
                    spec.manifest_path.display()
                );
            }
            warnings.push(python_legacy_warning(spec));
            if spec.kind == ProjectInputKind::PyPipfile {
                validate_pipfile_lockfile(spec, config)?;
            }
        }
        other => wrong_plugin(other),
    }
    Ok(())
}

fn prefer_trusted_python_project_inputs(specs: &mut Vec<ProjectInputSpec>) {
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

fn reject_ambiguous_python_project_inputs(specs: &[ProjectInputSpec]) -> Result<()> {
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

fn promote_trusted_pip_tools_specs(
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

fn prune_included_requirement_specs(
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
