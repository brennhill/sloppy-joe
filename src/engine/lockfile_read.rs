use crate::*;

pub(crate) fn read_npm_manifest_value(path: &std::path::Path) -> Result<serde_json::Value> {
    let content = parsers::read_file_limited(path, parsers::MAX_MANIFEST_BYTES)?;
    parsers::package_json::parse_manifest_json(&content).map_err(|err| {
        anyhow::anyhow!(
            "Broken manifest '{}': failed to parse JSON: {}",
            path.display(),
            err
        )
    })
}

pub(crate) fn read_validated_npm_lockfile(
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
    config: &config::SloppyJoeConfig,
    allowed_alias_targets: &std::collections::HashMap<String, String>,
) -> Result<(serde_json::Value, Vec<Issue>)> {
    let path =
        selected_lockfile_path(spec).expect("npm preflight should guarantee a lockfile exists");
    let content = parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES)?;
    let lockfile = serde_json::from_str::<serde_json::Value>(&content).map_err(|err| {
        anyhow::anyhow!(
            "Broken lockfile '{}': failed to parse JSON: {}",
            path.display(),
            err
        )
    })?;
    validate_npm_lockfile_version(&lockfile, &path, config)?;
    validate_npm_lockfile_consistency(manifest, &lockfile, &path, spec.npm_lockfile_package_key())?;
    validate_npm_lockfile_provenance(
        &lockfile,
        &path,
        allowed_alias_targets,
        &spec
            .js_binding
            .as_ref()
            .map(|b| b.npm_registries.clone())
            .unwrap_or_default(),
    )?;

    let warnings =
        if npm_lockfile_version(&lockfile, &path)? == 1 && config.allow_legacy_npm_v1_lockfile {
            legacy_npm_v1_warnings(&path)
        } else {
            Vec::new()
        };

    Ok((lockfile, warnings))
}

pub(crate) fn read_validated_pnpm_lockfile(
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
) -> Result<serde_yaml::Value> {
    let path =
        selected_lockfile_path(spec).expect("pnpm preflight should guarantee a lockfile exists");
    let content =
        parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES).map_err(|err| {
            anyhow::anyhow!(
                "Required lockfile '{}' is unreadable: {}",
                path.display(),
                err
            )
        })?;
    let lockfile: serde_yaml::Value = crate::lockfiles::parse_pnpm_lock_guarded(&content)
        .map_err(|err| anyhow::anyhow!("Broken lockfile '{}': {}", path.display(), err))?;
    validate_pnpm_lockfile_consistency(spec, manifest, &lockfile, &path)?;
    crate::lockfiles::pnpm::validate_provenance(
        &lockfile,
        &path,
        &spec
            .js_binding
            .as_ref()
            .map(|b| b.npm_registries.clone())
            .unwrap_or_default(),
    )?;
    Ok(lockfile)
}

pub(crate) fn read_validated_bun_lockfile(
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
) -> Result<serde_json::Value> {
    let path =
        selected_lockfile_path(spec).expect("bun preflight should guarantee a lockfile exists");
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("bun.lock");
    if file_name == "bun.lockb" {
        anyhow::bail!(
            "Legacy Bun binary lockfile '{}' is not supported yet. Regenerate and commit the text bun.lock.",
            path.display()
        );
    }
    let content =
        parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES).map_err(|err| {
            anyhow::anyhow!(
                "Required lockfile '{}' is unreadable: {}",
                path.display(),
                err
            )
        })?;
    let lockfile: serde_json::Value = crate::lockfiles::parse_json5_guarded(&content)
        .map_err(|err| anyhow::anyhow!("Broken lockfile '{}': {}", path.display(), err))?;
    validate_bun_lockfile_consistency(spec, manifest, &lockfile, &path)?;
    crate::lockfiles::bun::validate_provenance(&lockfile, &path)?;
    Ok(lockfile)
}

pub(crate) fn read_validated_yarn_lockfile(
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
) -> Result<crate::lockfiles::yarn::ParsedYarnLock> {
    let path =
        selected_lockfile_path(spec).expect("Yarn preflight should guarantee a lockfile exists");
    let content =
        parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES).map_err(|err| {
            anyhow::anyhow!(
                "Required lockfile '{}' is unreadable: {}",
                path.display(),
                err
            )
        })?;
    let project_name = manifest
        .get("name")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Broken manifest '{}': Yarn projects must declare a package name.",
                spec.manifest_path.display()
            )
        })?;
    let lockfile =
        crate::lockfiles::yarn::parse_lockfile(&content, path.clone(), spec.project_dir())
            .map_err(|err| anyhow::anyhow!("Broken lockfile '{}': {}", path.display(), err))?;
    crate::lockfiles::yarn::validate_manifest_consistency(
        &lockfile,
        manifest,
        spec.npm_lockfile_package_key(),
        project_name,
    )?;
    crate::lockfiles::yarn::validate_provenance(&lockfile)?;
    Ok(lockfile)
}

pub(crate) struct ValidatedPoetryLockfile {
    pub(crate) warnings: Vec<Issue>,
    pub(crate) fully_trusted: bool,
}

pub(crate) fn read_validated_poetry_lockfile(
    spec: &ProjectInputSpec,
    deps: &[Dependency],
    root_extras: &PythonRootExtras,
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> Result<ValidatedPoetryLockfile> {
    let path =
        selected_lockfile_path(spec).unwrap_or_else(|| spec.project_dir().join("poetry.lock"));
    let content =
        parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES).map_err(|err| {
            anyhow::anyhow!(
                "Required lockfile '{}' is unreadable: {}",
                path.display(),
                err
            )
        })?;
    let lockfile: toml::Value = toml::from_str(&content)
        .map_err(|err| anyhow::anyhow!("Broken lockfile '{}': {}", path.display(), err))?;
    let manifest_content =
        parsers::read_file_limited(&spec.manifest_path, parsers::MAX_MANIFEST_BYTES).map_err(
            |err| {
                anyhow::anyhow!(
                    "Required manifest '{}' is unreadable: {}",
                    spec.manifest_path.display(),
                    err
                )
            },
        )?;
    let pyproject: toml::Value = toml::from_str(&manifest_content).map_err(|err| {
        anyhow::anyhow!(
            "Broken manifest '{}': {}",
            spec.manifest_path.display(),
            err
        )
    })?;
    let declared_sources = parsers::pyproject_toml::parse_poetry_sources(&spec.manifest_path)?;
    let profile = active_python_profile(opts);
    let source_intents =
        parsers::pyproject_toml::parse_poetry_source_intents_scoped(&spec.manifest_path)?
            .into_iter()
            .map(|intent| Ok(intent.is_in_scope(&profile)?.then_some(intent.intent)))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
    let lock_profile = active_python_lockfile_profile(opts, root_extras);
    let reachable_packages = crate::lockfiles::python::reachable_package_identities(
        &lockfile,
        deps,
        Some(&lock_profile),
    )?;
    let validation = crate::lockfiles::python::validate_trusted_poetry_lockfile(
        &lockfile,
        &content,
        &pyproject,
        deps,
        &path,
        &reachable_packages,
        config.poetry_lock_policy,
    )?;
    let mut warnings = validation.warnings;
    let authorized_sources =
        crate::lockfiles::python::authorized_source_urls_for_reachable_packages(
            &lockfile,
            deps,
            &source_intents,
            Some(&lock_profile),
            &path,
        )?;
    let (used_source_urls, used_source_names) = crate::lockfiles::python::validate_source_policy(
        &lockfile,
        &declared_sources,
        &source_intents,
        config,
        &path,
        Some(&reachable_packages),
        Some(&authorized_sources),
    )?;
    warnings.extend(unused_python_source_warnings(
        &spec.manifest_path,
        &declared_sources,
        &used_source_urls,
        &used_source_names,
    ));
    Ok(ValidatedPoetryLockfile {
        warnings,
        fully_trusted: validation.fully_trusted,
    })
}

pub(crate) fn read_validated_uv_lockfile(
    spec: &ProjectInputSpec,
    deps: &[Dependency],
    root_extras: &PythonRootExtras,
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> Result<(toml::Value, Vec<Issue>)> {
    let path = selected_lockfile_path(spec).unwrap_or_else(|| spec.project_dir().join("uv.lock"));
    let content =
        parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES).map_err(|err| {
            anyhow::anyhow!(
                "Required lockfile '{}' is unreadable: {}",
                path.display(),
                err
            )
        })?;
    let lockfile: toml::Value = toml::from_str(&content)
        .map_err(|err| anyhow::anyhow!("Broken lockfile '{}': {}", path.display(), err))?;
    crate::lockfiles::uv::validate_schema(&lockfile, &path)?;
    let lock_profile = active_python_lockfile_profile(opts, root_extras);
    crate::lockfiles::uv::validate_manifest_consistency(
        &lockfile,
        deps,
        &path,
        Some(&lock_profile),
    )?;
    // Bidirectional: every locked root dependency, extra, and group entry must be declared.
    let declared = parsers::pyproject_toml::parse_legacy_scoped_file(&spec.manifest_path)?;
    crate::lockfiles::uv::validate_root_declarations_are_declared(&lockfile, &declared, &path)?;
    crate::lockfiles::uv::validate_provenance(&lockfile, &path)?;
    let declared_sources = parsers::pyproject_toml::parse_uv_sources(&spec.manifest_path)?;
    let profile = active_python_profile(opts);
    let source_intents =
        parsers::pyproject_toml::parse_uv_source_intents_scoped(&spec.manifest_path)?
            .into_iter()
            .map(|intent| Ok(intent.is_in_scope(&profile)?.then_some(intent.intent)))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
    let reachable_packages =
        crate::lockfiles::uv::reachable_package_identities(&lockfile, deps, Some(&lock_profile))?;
    let authorized_sources = crate::lockfiles::uv::authorized_source_urls_for_reachable_packages(
        &lockfile,
        deps,
        &source_intents,
        Some(&lock_profile),
        &path,
    )?;
    let (used_source_urls, used_source_names) = crate::lockfiles::uv::validate_source_policy(
        &lockfile,
        &declared_sources,
        &source_intents,
        config,
        &path,
        Some(&reachable_packages),
        Some(&authorized_sources),
    )?;
    let warnings = unused_python_source_warnings(
        &spec.manifest_path,
        &declared_sources,
        &used_source_urls,
        &used_source_names,
    );
    Ok((lockfile, warnings))
}

pub(crate) fn lockfile_data_for_scan(
    project: &ParsedProject,
    deps: &[Dependency],
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> Result<lockfiles::LockfileData> {
    if project.unlocked_tooling {
        return Ok(lockfiles::LockfileData::reduced_confidence_from_manifest(
            deps,
        ));
    }
    if project.spec.kind == ProjectInputKind::PyProjectPoetry {
        let validated = read_validated_poetry_lockfile(
            &project.spec,
            deps,
            &project.python_root_extras,
            config,
            opts,
        )?;
        if !validated.fully_trusted {
            return Ok(lockfiles::LockfileData::reduced_confidence_from_manifest(
                deps,
            ));
        }
    }

    let python_profile = (project.spec.kind.ecosystem() == Ecosystem::PyPI)
        .then(|| active_python_lockfile_profile(opts, &project.python_root_extras));
    let mut data = lockfiles::LockfileData::parse_for_kind_with_lockfile_and_profile(
        project.spec.project_dir(),
        Some(project.spec.kind),
        deps,
        project.spec.lockfile_path_override.as_deref(),
        python_profile.as_ref(),
    )?;
    if project.deps.is_empty() && python_manifest_declares_no_dependencies(&project.spec)? {
        data.scan_all_locked_packages()?;
    }
    Ok(data)
}
