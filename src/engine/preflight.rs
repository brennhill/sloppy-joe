use crate::*;

#[cfg(test)]
pub(crate) fn preflight_scan_inputs(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
) -> Result<Vec<Issue>> {
    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(project_dir, project_type, &config)?;
    preflight_project_inputs(project_dir, &specs, &config)
}

#[cfg(test)]
pub(crate) fn preflight_project_inputs(
    scan_root: &std::path::Path,
    specs: &[ProjectInputSpec],
    config: &config::SloppyJoeConfig,
) -> Result<Vec<Issue>> {
    preflight_project_inputs_with_options(scan_root, specs, config, &ScanOptions::default())
}

#[cfg(test)]
pub(crate) fn preflight_project_inputs_with_options(
    scan_root: &std::path::Path,
    specs: &[ProjectInputSpec],
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> Result<Vec<Issue>> {
    preflight_selected_project_inputs(scan_root, specs, specs, config, opts)
}

pub(crate) fn preflight_selected_project_inputs(
    scan_root: &std::path::Path,
    specs: &[ProjectInputSpec],
    selected: &[ProjectInputSpec],
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> Result<Vec<Issue>> {
    let canonical_root = std::fs::canonicalize(scan_root).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {} for project manifests: {}",
            scan_root.display(),
            err
        )
    })?;
    let npm_manifests = load_npm_manifests(specs)?;
    let npm_index = index_npm_projects(&npm_manifests)?;
    let selected_locks: std::collections::HashSet<_> =
        selected.iter().filter_map(selected_lockfile_path).collect();
    let alias_specs: Vec<_> = specs
        .iter()
        .filter(|spec| {
            selected_lockfile_path(spec).is_some_and(|path| selected_locks.contains(&path))
        })
        .cloned()
        .collect();
    let npm_alias_targets = npm_alias_targets_by_lockfile(&alias_specs, &npm_manifests)?;
    let mut warnings = Vec::new();

    for spec in selected {
        let npm_manifest = npm_manifests.get(&spec.manifest_path);
        let parsed_input = match spec.kind {
            ProjectInputKind::Npm => {
                let manifest =
                    npm_manifest.expect("npm manifests should be parsed during preflight");
                parsers::package_json::parse_manifest_value(&spec.manifest_path, manifest).map(
                    |deps| ParsedInput {
                        deps,
                        ..ParsedInput::default()
                    },
                )
            }
            _ => {
                let parsed = parse_project_input_with_config(scan_root, spec, config, opts)?;
                warnings.extend(parsed.warnings.clone());
                Ok(parsed)
            }
        }
        .map_err(|err| {
            anyhow::anyhow!(
                "Broken manifest '{}': {}",
                spec.manifest_path.display(),
                err
            )
        })?;

        let deps = parsed_input.deps;

        match spec.kind {
            ProjectInputKind::Npm => ensure_authoritative_js_lockfile_readable(spec)?,
            ProjectInputKind::PyProjectPoetry => {
                ensure_lockfile_readable(
                    &spec.project_dir().join("poetry.lock"),
                    spec.kind.missing_lockfile_help().unwrap(),
                )?;
                let validated = read_validated_poetry_lockfile(
                    spec,
                    &deps,
                    &parsed_input.python_root_extras,
                    config,
                    opts,
                )?;
                warnings.extend(validated.warnings);
            }
            ProjectInputKind::PyProjectUv => {
                if config.python_enforcement == config::PythonEnforcement::PoetryOnly {
                    anyhow::bail!(
                        "Python manifest '{}' uses the uv workflow, which is not allowed in poetry_only mode. Use Poetry with pyproject.toml + poetry.lock, or relax python_enforcement to prefer_poetry.",
                        spec.manifest_path.display()
                    );
                }
                ensure_lockfile_readable(
                    &spec.project_dir().join("uv.lock"),
                    spec.kind.missing_lockfile_help().unwrap(),
                )?;
                let (_, source_warnings) = read_validated_uv_lockfile(
                    spec,
                    &deps,
                    &parsed_input.python_root_extras,
                    config,
                    opts,
                )?;
                warnings.extend(source_warnings);
            }
            ProjectInputKind::PyRequirementsTrusted => {
                if config.python_enforcement == config::PythonEnforcement::PoetryOnly {
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
                if config.python_enforcement == config::PythonEnforcement::PoetryOnly {
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
            ProjectInputKind::Cargo => ensure_lockfile_readable(
                &authoritative_cargo_lockfile_path(scan_root, &spec.manifest_path, config)?,
                spec.kind.missing_lockfile_help().unwrap(),
            )?,
            ProjectInputKind::Go => {
                let manifest_content = parsers::read_file_limited(
                    &spec.manifest_path,
                    parsers::MAX_MANIFEST_BYTES,
                )
                .map_err(|err| {
                    anyhow::anyhow!(
                        "Broken manifest '{}': {}",
                        spec.manifest_path.display(),
                        err
                    )
                })?;
                if parsers::go_mod::requires_go_sum(&manifest_content) {
                    let go_sum_path = spec.project_dir().join("go.sum");
                    ensure_lockfile_readable(
                        &go_sum_path,
                        spec.kind.missing_lockfile_help().unwrap(),
                    )?;
                    // Vendored builds ignore go.sum, so only enforce it otherwise.
                    if !spec.project_dir().join("vendor/modules.txt").is_file() {
                        let go_sum =
                            parsers::read_file_limited(&go_sum_path, parsers::MAX_MANIFEST_BYTES)?;
                        parsers::go_mod::check_go_sum_entries(&manifest_content, &go_sum)
                            .map_err(|err| {
                                anyhow::anyhow!("Broken lockfile '{}': {}", go_sum_path.display(), err)
                            })?;
                    }
                }
            }
            ProjectInputKind::Ruby => ensure_lockfile_readable(
                &spec.project_dir().join("Gemfile.lock"),
                spec.kind.missing_lockfile_help().unwrap(),
            )?,
            ProjectInputKind::Php => ensure_lockfile_readable(
                &spec.project_dir().join("composer.lock"),
                spec.kind.missing_lockfile_help().unwrap(),
            )?,
            ProjectInputKind::Gradle => ensure_lockfile_readable(
                &spec.project_dir().join("gradle.lockfile"),
                spec.kind.missing_lockfile_help().unwrap(),
            )?,
            ProjectInputKind::Dotnet => ensure_lockfile_readable(
                &spec.manifest_path.with_file_name("packages.lock.json"),
                spec.kind.missing_lockfile_help().unwrap(),
            )?,
            ProjectInputKind::Maven => warnings.push(
                Issue::new(
                    "<lockfile>",
                    checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE,
                    Severity::Warning,
                )
                .message(format!(
                    "Maven manifest '{}' has no trusted lockfile-backed verification path in sloppy-joe. Resolution-sensitive checks continue with reduced confidence. Gradle dependency locking via gradle.lockfile is recommended when practical.",
                    spec.manifest_path.display()
                ))
                .fix(
                    "Keep Maven and review resolution-sensitive findings manually, or move the build to Gradle with dependency locking if you need strict lockfile enforcement.",
                ),
            ),
        }

        if deps.is_empty()
            && matches!(
                spec.kind,
                ProjectInputKind::Gradle | ProjectInputKind::Dotnet
            )
        {
            let locked = lockfiles::LockfileData::parse_for_kind_with_lockfile_and_profile(
                spec.project_dir(),
                Some(spec.kind),
                &deps,
                spec.lockfile_path_override.as_deref(),
                None,
            )?;
            if !locked.transitive_deps.is_empty() {
                anyhow::bail!(
                    "Scan not supported: '{}' has locked packages but no supported direct dependency declarations",
                    spec.manifest_path.display()
                );
            }
        }

        if spec.kind == ProjectInputKind::Cargo {
            warnings.extend(validate_cargo_source_policy(scan_root, spec, config)?);
        }

        if matches!(
            spec.kind,
            ProjectInputKind::PyProjectPoetry | ProjectInputKind::PyProjectUv
        ) {
            warnings.extend(trusted_python_preference_warnings(spec)?);
        }

        if spec.kind == ProjectInputKind::Npm {
            if let Some(workspace) = spec
                .js_binding
                .as_ref()
                .and_then(|b| b.independent_from_workspace.as_ref())
            {
                warnings.push(Issue::new(spec.manifest_path.display().to_string(), checks::names::RESOLUTION_INDEPENDENT_INSTALL_ROOT, Severity::Warning)
                    .message(format!("Scanning '{}' independently with its own lockfile: ancestor workspace '{}' does not lock this project and has no explicit packageManager.", spec.manifest_path.display(), workspace.display()))
                    .fix("Keep this project's installer and lockfile aligned with CI; remove unused ancestor workspace declarations if appropriate."));
            }
            let manifest = npm_manifest.expect("npm manifests should be parsed during preflight");
            validate_supported_js_manager(spec)?;
            validate_js_manifest_security_policy(spec, manifest)?;
            match spec
                .js_binding
                .as_ref()
                .map(|binding| binding.manager)
                .unwrap_or(JsPackageManager::Npm)
            {
                JsPackageManager::Npm => {
                    let allowed_alias_targets = selected_lockfile_path(spec)
                        .and_then(|path| npm_alias_targets.get(&path))
                        .cloned()
                        .unwrap_or_default();
                    let (lockfile, npm_warnings) = read_validated_npm_lockfile(
                        spec,
                        manifest,
                        config,
                        &allowed_alias_targets,
                    )?;
                    warnings.extend(npm_warnings);
                    let npm_scope_root = npm_trusted_scope_root(&canonical_root, spec)?;
                    validate_local_npm_dependencies(
                        &npm_scope_root,
                        spec,
                        manifest,
                        &lockfile,
                        &npm_index,
                    )?;
                }
                JsPackageManager::Pnpm => {
                    let lockfile = read_validated_pnpm_lockfile(spec, manifest)?;
                    let pnpm_scope_root = npm_trusted_scope_root(&canonical_root, spec)?;
                    validate_local_pnpm_dependencies(
                        &pnpm_scope_root,
                        spec,
                        manifest,
                        &lockfile,
                        &npm_index,
                        &config.ignore_dirs,
                    )?;
                }
                JsPackageManager::Bun => {
                    let lockfile = read_validated_bun_lockfile(spec, manifest)?;
                    let bun_scope_root = npm_trusted_scope_root(&canonical_root, spec)?;
                    validate_local_bun_dependencies(
                        &bun_scope_root,
                        spec,
                        manifest,
                        &lockfile,
                        &npm_index,
                        &config.ignore_dirs,
                    )?;
                }
                JsPackageManager::Yarn => {
                    let lockfile = read_validated_yarn_lockfile(spec, manifest)?;
                    let yarn_scope_root = npm_trusted_scope_root(&canonical_root, spec)?;
                    validate_local_yarn_dependencies(
                        &yarn_scope_root,
                        spec,
                        manifest,
                        &lockfile,
                        &config.ignore_dirs,
                    )?;
                }
            }
        } else {
            validate_lockfile_syntax(scan_root, spec, npm_manifest, config, opts)?;
        }
    }

    Ok(warnings)
}
