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
