use crate::*;

pub(crate) fn cargo_patch_scope_matches(
    scope: &parsers::cargo_toml::CargoPatchScope,
    source: &parsers::cargo_toml::CargoSourceSpec,
    config: &config::SloppyJoeConfig,
) -> bool {
    match (scope, source) {
        (
            parsers::cargo_toml::CargoPatchScope::CratesIo,
            parsers::cargo_toml::CargoSourceSpec::CratesIo,
        ) => true,
        (
            parsers::cargo_toml::CargoPatchScope::RegistryName(expected),
            parsers::cargo_toml::CargoSourceSpec::RegistryAlias(actual),
        ) => expected == actual,
        (
            parsers::cargo_toml::CargoPatchScope::SourceUrl(expected),
            parsers::cargo_toml::CargoSourceSpec::RegistryIndex(actual),
        ) => cargo_normalize_registry_source(expected) == *actual,
        (
            parsers::cargo_toml::CargoPatchScope::SourceUrl(expected),
            parsers::cargo_toml::CargoSourceSpec::RegistryAlias(alias),
        ) => cargo_registry_source_for_alias(alias, config) == Some(expected.as_str()),
        (
            parsers::cargo_toml::CargoPatchScope::SourceUrl(expected),
            parsers::cargo_toml::CargoSourceSpec::Git { url, .. },
        ) => expected == url,
        (
            parsers::cargo_toml::CargoPatchScope::RegistryName(_),
            parsers::cargo_toml::CargoSourceSpec::CratesIo,
        )
        | (
            parsers::cargo_toml::CargoPatchScope::SourceUrl(_),
            parsers::cargo_toml::CargoSourceSpec::CratesIo,
        )
        | (
            parsers::cargo_toml::CargoPatchScope::CratesIo,
            parsers::cargo_toml::CargoSourceSpec::RegistryAlias(_),
        )
        | (
            parsers::cargo_toml::CargoPatchScope::CratesIo,
            parsers::cargo_toml::CargoSourceSpec::RegistryIndex(_),
        )
        | (
            parsers::cargo_toml::CargoPatchScope::CratesIo,
            parsers::cargo_toml::CargoSourceSpec::Git { .. },
        )
        | (
            parsers::cargo_toml::CargoPatchScope::RegistryName(_),
            parsers::cargo_toml::CargoSourceSpec::RegistryIndex(_),
        )
        | (
            parsers::cargo_toml::CargoPatchScope::RegistryName(_),
            parsers::cargo_toml::CargoSourceSpec::Git { .. },
        )
        | (_, parsers::cargo_toml::CargoSourceSpec::Path(_))
        | (_, parsers::cargo_toml::CargoSourceSpec::Workspace) => false,
    }
}

pub(crate) fn cargo_patch_scope_matches_lockfile_source(
    scope: &parsers::cargo_toml::CargoPatchScope,
    lockfile_source: &str,
    config: &config::SloppyJoeConfig,
) -> bool {
    match scope {
        parsers::cargo_toml::CargoPatchScope::CratesIo => {
            lockfile_source == "registry+https://github.com/rust-lang/crates.io-index"
        }
        parsers::cargo_toml::CargoPatchScope::RegistryName(alias) => {
            cargo_registry_source_for_alias(alias, config)
                .map(|source| lockfile_source == source)
                .unwrap_or(false)
        }
        parsers::cargo_toml::CargoPatchScope::SourceUrl(url) => {
            lockfile_source == format!("registry+{url}")
                || lockfile_source.starts_with(&format!("git+{url}"))
        }
    }
}

pub(crate) fn cargo_rewrite_matches_lockfile_scope(
    rewrite: &EffectiveCargoRewrite,
    lockfile: &toml::Value,
    config: &config::SloppyJoeConfig,
) -> bool {
    let entries = cargo_lockfile_entries(lockfile);
    let has_direct_match = entries.iter().copied().any(|package| {
        let same_name = package.get("name").and_then(|value| value.as_str())
            == Some(rewrite.package_name.as_str());
        if !same_name {
            return false;
        }
        let version_matches = rewrite.replace_version.as_ref().is_none_or(|expected| {
            package.get("version").and_then(|value| value.as_str()) == Some(expected.as_str())
        });
        if !version_matches {
            return false;
        }
        let source_matches = rewrite.replace_source.as_ref().is_none_or(|expected| {
            package
                .get("source")
                .and_then(|value| value.as_str())
                .map(|source| source == expected)
                .unwrap_or(false)
        });
        if !source_matches {
            return false;
        }

        rewrite
            .patch_scope
            .as_ref()
            .and_then(|scope| {
                package
                    .get("source")
                    .and_then(|value| value.as_str())
                    .map(|source| cargo_patch_scope_matches_lockfile_source(scope, source, config))
            })
            .unwrap_or(true)
    });
    if has_direct_match {
        return true;
    }

    if !matches!(
        rewrite.spec.source,
        parsers::cargo_toml::CargoSourceSpec::Path(_)
    ) || (rewrite.replace_source.is_none() && rewrite.patch_scope.is_none())
    {
        return false;
    }

    let has_localized_target = entries.iter().copied().any(|package| {
        let same_name = package.get("name").and_then(|value| value.as_str())
            == Some(rewrite.package_name.as_str());
        if !same_name {
            return false;
        }
        let version_matches = rewrite.replace_version.as_ref().is_none_or(|expected| {
            package.get("version").and_then(|value| value.as_str()) == Some(expected.as_str())
        });
        version_matches
            && package
                .get("source")
                .and_then(|value| value.as_str())
                .is_none()
    });
    if !has_localized_target {
        return false;
    }

    !entries.iter().copied().any(|package| {
        let same_name = package.get("name").and_then(|value| value.as_str())
            == Some(rewrite.package_name.as_str());
        if !same_name {
            return false;
        }
        let version_matches = rewrite.replace_version.as_ref().is_none_or(|expected| {
            package.get("version").and_then(|value| value.as_str()) == Some(expected.as_str())
        });
        version_matches
            && package
                .get("source")
                .and_then(|value| value.as_str())
                .is_some()
    })
}

pub(crate) fn cargo_rewrite_matches(
    rewrite: &EffectiveCargoRewrite,
    dep: &parsers::cargo_toml::CargoDependencySpec,
    config: &config::SloppyJoeConfig,
) -> bool {
    rewrite.package_name == dep.package_name
        && rewrite.replace_source.as_ref().is_none_or(|source| {
            cargo_dependency_source_id(dep, config).as_deref() == Some(source.as_str())
        })
        && rewrite.replace_version.as_ref().is_none_or(|version| {
            cargo_dependency_exact_version(dep).as_deref() == Some(version.as_str())
        })
        && rewrite
            .patch_scope
            .as_ref()
            .is_none_or(|scope| cargo_patch_scope_matches(scope, &dep.source, config))
}

pub(crate) fn cargo_manifest_rewrites(
    manifest: &parsers::cargo_toml::CargoManifest,
    base_dir: &std::path::Path,
) -> Vec<EffectiveCargoRewrite> {
    manifest
        .patches
        .iter()
        .chain(manifest.replaces.iter())
        .map(|rewrite| EffectiveCargoRewrite {
            package_name: rewrite.package_name.clone(),
            patch_scope: rewrite.patch_scope.clone(),
            replace_source: rewrite.replace_source.clone(),
            replace_version: rewrite.replace_version.clone(),
            spec: rewrite.dependency.clone(),
            base_dir: base_dir.to_path_buf(),
        })
        .collect()
}

pub(crate) fn push_effective_cargo_rewrite(
    rewrites: &mut Vec<EffectiveCargoRewrite>,
    candidate: EffectiveCargoRewrite,
) -> Result<()> {
    if let Some(existing) = rewrites.iter().find(|rewrite| {
        rewrite.package_name == candidate.package_name
            && rewrite.patch_scope == candidate.patch_scope
            && rewrite.replace_source == candidate.replace_source
            && rewrite.replace_version == candidate.replace_version
    }) {
        if existing != &candidate {
            return Err(cargo_fail(
                checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
                format!(
                    "Conflicting Cargo rewrite for package '{}' and scope '{:?}'. sloppy-joe refuses to guess rewrite precedence across multiple provenance sources.",
                    candidate.package_name, candidate.patch_scope
                ),
            ));
        }
        return Ok(());
    }

    rewrites.push(candidate);
    Ok(())
}

pub(crate) fn collect_effective_cargo_rewrites(
    scan_root: &std::path::Path,
    manifest: &parsers::cargo_toml::CargoManifest,
    config: &config::SloppyJoeConfig,
    cargo_config_rewrites: &CargoConfigRewrites,
) -> Result<Vec<EffectiveCargoRewrite>> {
    let mut rewrites = Vec::new();
    let manifest_dir = manifest
        .manifest_path
        .parent()
        .expect("Cargo.toml should always have a parent directory");
    if let Some(workspace_root) =
        find_in_scope_cargo_workspace_root(scan_root, &manifest.manifest_path, config)?
    {
        if workspace_root.manifest_path == manifest.manifest_path {
            for rewrite in cargo_manifest_rewrites(manifest, manifest_dir) {
                push_effective_cargo_rewrite(&mut rewrites, rewrite)?;
            }
        } else {
            let workspace_dir = workspace_root
                .manifest_path
                .parent()
                .expect("workspace root should have a parent directory");
            for rewrite in cargo_manifest_rewrites(&workspace_root, workspace_dir) {
                push_effective_cargo_rewrite(&mut rewrites, rewrite)?;
            }
        }
    } else {
        for rewrite in cargo_manifest_rewrites(manifest, manifest_dir) {
            push_effective_cargo_rewrite(&mut rewrites, rewrite)?;
        }
    }

    for rewrite in cargo_config_rewrites.rewrite_targets.iter().cloned() {
        push_effective_cargo_rewrite(&mut rewrites, rewrite)?;
    }
    Ok(rewrites)
}

pub(crate) fn resolve_cargo_effective_dependencies(
    scan_root: &std::path::Path,
    manifest: &parsers::cargo_toml::CargoManifest,
    config: &config::SloppyJoeConfig,
) -> Result<Vec<EffectiveCargoDependency>> {
    let manifest_dir = manifest
        .manifest_path
        .parent()
        .expect("Cargo.toml should always have a parent directory");
    let cargo_config_rewrites =
        load_effective_cargo_config_rewrites(scan_root, &manifest.manifest_path, config)?.0;
    let rewrites =
        collect_effective_cargo_rewrites(scan_root, manifest, config, &cargo_config_rewrites)?;

    let mut effective = Vec::new();
    for dep in &manifest.dependencies {
        let mut current = dep.clone();
        let mut current_base_dir = manifest_dir.to_path_buf();
        let mut expected_exact_version = cargo_dependency_exact_version(dep);
        let mut workspace_hops = 0usize;

        loop {
            let rewritten = rewrites
                .iter()
                .rfind(|rewrite| cargo_rewrite_matches(rewrite, &current, config));
            if let Some(rewrite) = rewritten {
                let next_expected_exact_version = rewrite
                    .replace_version
                    .clone()
                    .or(expected_exact_version.clone());
                if rewrite.spec != current
                    || rewrite.base_dir != current_base_dir
                    || next_expected_exact_version != expected_exact_version
                {
                    expected_exact_version = next_expected_exact_version;
                    current = rewrite.spec.clone();
                    current_base_dir = rewrite.base_dir.clone();
                }
            }

            if matches!(
                current.source,
                parsers::cargo_toml::CargoSourceSpec::CratesIo
            ) && let Some(path) = cargo_config_rewrites.local_paths.get(&current.package_name)
            {
                current.source =
                    parsers::cargo_toml::CargoSourceSpec::Path(path.display().to_string());
            }
            if let Some(rewritten_source) =
                apply_cargo_config_source_rewrite(&current, &cargo_config_rewrites, config)?
            {
                current.source = rewritten_source;
            }

            if !matches!(
                current.source,
                parsers::cargo_toml::CargoSourceSpec::Workspace
            ) {
                let expected_exact_version =
                    expected_exact_version.or_else(|| cargo_dependency_exact_version(&current));
                effective.push(EffectiveCargoDependency {
                    spec: current,
                    base_dir: current_base_dir,
                    expected_exact_version,
                });
                break;
            }

            if !current.workspace_member_invalid_keys.is_empty() {
                return Err(cargo_fail(
                    checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
                    format!(
                        "'{}' uses workspace = true with unsupported member-local keys: {}.",
                        current.package_name,
                        current.workspace_member_invalid_keys.join(", ")
                    ),
                ));
            }
            let Some(workspace_root) =
                find_in_scope_cargo_workspace_root(scan_root, &manifest.manifest_path, config)?
            else {
                return Err(cargo_fail(
                    checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
                    format!(
                        "'{}' uses workspace = true but no in-scope workspace root was found.",
                        current.package_name
                    ),
                ));
            };
            let Some(inherited) = workspace_root
                .workspace_dependencies
                .get(&current.package_name)
                .cloned()
            else {
                return Err(cargo_fail(
                    checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
                    format!(
                        "'{}' uses workspace = true but the nearest in-scope [workspace.dependencies] entry is missing.",
                        current.package_name
                    ),
                ));
            };
            let workspace_dir = workspace_root
                .manifest_path
                .parent()
                .expect("workspace root should have a parent directory");
            expected_exact_version =
                expected_exact_version.or_else(|| cargo_dependency_exact_version(&inherited));
            current = inherited;
            current_base_dir = workspace_dir.to_path_buf();
            workspace_hops += 1;
            if workspace_hops > 8 {
                return Err(cargo_fail(
                    checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
                    format!(
                        "'{}' exceeded Cargo workspace inheritance resolution depth.",
                        dep.package_name
                    ),
                ));
            }
        }
    }

    Ok(effective)
}
