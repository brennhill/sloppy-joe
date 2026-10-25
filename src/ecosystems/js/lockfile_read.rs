use super::*;

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

    let applied = npm_lock_schema::check_entry_keys(&lockfile, &path, &config.config_key_allow)?;
    let mut warnings =
        if npm_lockfile_version(&lockfile, &path)? == 1 && config.allow_legacy_npm_v1_lockfile {
            legacy_npm_v1_warnings(&path)
        } else {
            Vec::new()
        };
    warnings.extend(crate::config_surface::issues(&applied));

    Ok((lockfile, warnings))
}

pub(crate) fn read_validated_pnpm_lockfile(
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
    config: &config::SloppyJoeConfig,
) -> Result<(serde_yaml::Value, Vec<Issue>)> {
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
    let lockfile: serde_yaml::Value =
        crate::lockfiles::parse_pnpm_lock_guarded(&content).map_err(|err| {
            crate::remedy::rewrap(err, |err| {
                format!("Broken lockfile '{}': {}", path.display(), err)
            })
        })?;
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
    let applied = pnpm_lock_schema::check_entry_keys(&lockfile, &path, &config.config_key_allow)?;
    Ok((lockfile, crate::config_surface::issues(&applied)))
}

pub(crate) fn read_validated_bun_lockfile(
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
    config: &config::SloppyJoeConfig,
) -> Result<(serde_json::Value, Vec<Issue>)> {
    let path =
        selected_lockfile_path(spec).expect("bun preflight should guarantee a lockfile exists");
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("bun.lock");
    if file_name == "bun.lockb" {
        return Err(crate::remedy::problem(
            &crate::remedy::BUN_BINARY_LOCKFILE,
            format!(
                "Legacy Bun binary lockfile '{}' is not supported.",
                path.display()
            ),
        ));
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
    let applied = bun_lock_schema::check_entry_keys(&lockfile, &path, &config.config_key_allow)?;
    Ok((lockfile, crate::config_surface::issues(&applied)))
}

pub(crate) fn read_validated_yarn_lockfile(
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
    config: &config::SloppyJoeConfig,
) -> Result<(crate::lockfiles::yarn::ParsedYarnLock, Vec<Issue>)> {
    let path =
        selected_lockfile_path(spec).expect("Yarn preflight should guarantee a lockfile exists");
    let content = crate::untrusted::read_line_file(&path).map_err(|err| {
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
    let applied = yarn_lock_schema::check_entry_keys(&lockfile, &config.config_key_allow)?;
    Ok((lockfile, crate::config_surface::issues(&applied)))
}
