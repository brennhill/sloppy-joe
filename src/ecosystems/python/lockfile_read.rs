use super::*;

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
        // The CI scan gates a release: a lock without artifact hashes is an error, as it is for uv.lock.
        if opts.scan_mode == ScanMode::Ci {
            config::PoetryLockPolicy::Strict
        } else {
            config.poetry_lock_policy
        },
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
