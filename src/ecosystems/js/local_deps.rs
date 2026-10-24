use super::*;

pub(crate) fn validate_local_npm_dependencies(
    trusted_root: &std::path::Path,
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
    lockfile: &serde_json::Value,
    npm_index: &NpmProjectIndex,
) -> Result<()> {
    let canonical_project_dir = std::fs::canonicalize(spec.project_dir()).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {}: {}",
            spec.project_dir().display(),
            err
        )
    })?;

    for (name, local_spec) in parsers::package_json::npm_dependency_entries(manifest)
        .into_iter()
        .filter(|(_, spec)| {
            spec.starts_with("workspace:") || spec.starts_with("file:") || spec.starts_with("link:")
        })
    {
        let expected_target = if local_spec.starts_with("workspace:") {
            validate_workspace_npm_dependency(
                trusted_root,
                spec,
                &name,
                &canonical_project_dir,
                npm_index,
            )?
        } else {
            let canonical_target = resolve_local_npm_target(
                trusted_root,
                spec,
                &name,
                &local_spec,
                &canonical_project_dir,
            )?;
            if !npm_index.dirs.contains(&canonical_target) {
                anyhow::bail!(
                    "Local npm dependency '{}' in '{}' resolves to '{}' inside the scan root, but no scanned npm project was found there.",
                    name,
                    spec.manifest_path.display(),
                    local_spec
                );
            }
            if npm_index
                .names_by_dir
                .get(&canonical_target)
                .is_none_or(|target_name| target_name != &name)
            {
                let actual = npm_index
                    .names_by_dir
                    .get(&canonical_target)
                    .cloned()
                    .unwrap_or_else(|| "<missing package name>".to_string());
                anyhow::bail!(
                    "Local npm dependency '{}' in '{}' resolves to '{}', but that project declares package name '{}'. Local file:/link: targets must match the dependency package identity exactly.",
                    name,
                    spec.manifest_path.display(),
                    canonical_target.display(),
                    crate::report::sanitize_for_terminal(&actual)
                );
            }
            canonical_target
        };

        validate_local_npm_lockfile_target(spec, lockfile, &name, &local_spec, &expected_target)?;
    }

    if let Some(packages) = lockfile.get("packages").and_then(|value| value.as_object()) {
        let lockfile_path =
            selected_lockfile_path(spec).expect("npm preflight selected a lockfile");
        let lockfile_dir = lockfile_path
            .parent()
            .expect("lockfile has a parent directory");
        for (key, entry) in packages {
            if entry.get("link").and_then(|value| value.as_bool()) != Some(true) {
                continue;
            }
            let Some((_, name)) = key.rsplit_once("node_modules/") else {
                continue;
            };
            let resolved = entry
                .get("resolved")
                .and_then(|value| value.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Required lockfile '{}' link '{}' is missing its resolved local target.",
                        lockfile_path.display(),
                        name
                    )
                })?;
            let target = resolve_local_npm_target(
                trusted_root,
                spec,
                name,
                &format!("file:{resolved}"),
                lockfile_dir,
            )?;
            if npm_index
                .names_by_dir
                .get(&target)
                .is_none_or(|actual| actual != name)
            {
                anyhow::bail!(
                    "Required lockfile '{}' link '{}' must resolve to a scanned local project with that package identity; target '{}' is unscanned or has a different name.",
                    lockfile_path.display(),
                    name,
                    target.display()
                );
            }
        }
    }

    Ok(())
}

pub(crate) fn validate_local_pnpm_dependencies(
    trusted_root: &std::path::Path,
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
    lockfile: &serde_yaml::Value,
    npm_index: &NpmProjectIndex,
    ignore_dirs: &[String],
) -> Result<()> {
    let canonical_project_dir = std::fs::canonicalize(spec.project_dir()).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {}: {}",
            spec.project_dir().display(),
            err
        )
    })?;

    for (name, local_spec) in parsers::package_json::npm_dependency_entries(manifest)
        .into_iter()
        .filter(|(_, spec)| {
            spec.starts_with("workspace:") || spec.starts_with("file:") || spec.starts_with("link:")
        })
    {
        let expected_target = if local_spec.starts_with("workspace:") {
            validate_workspace_pnpm_dependency(
                trusted_root,
                spec,
                &name,
                &canonical_project_dir,
                ignore_dirs,
            )?
        } else {
            let canonical_target = resolve_local_npm_target(
                trusted_root,
                spec,
                &name,
                &local_spec,
                &canonical_project_dir,
            )?;
            if !npm_index.dirs.contains(&canonical_target) {
                anyhow::bail!(
                    "Local pnpm dependency '{}' in '{}' resolves to '{}' inside the scan root, but no scanned package.json was found there.",
                    name,
                    spec.manifest_path.display(),
                    local_spec
                );
            }
            if npm_index
                .names_by_dir
                .get(&canonical_target)
                .is_none_or(|target_name| target_name != &name)
            {
                let actual = npm_index
                    .names_by_dir
                    .get(&canonical_target)
                    .cloned()
                    .unwrap_or_else(|| "<missing package name>".to_string());
                anyhow::bail!(
                    "Local pnpm dependency '{}' in '{}' resolves to '{}', but that project declares package name '{}'. Local file:/link: targets must match the dependency package identity exactly.",
                    name,
                    spec.manifest_path.display(),
                    canonical_target.display(),
                    crate::report::sanitize_for_terminal(&actual)
                );
            }
            canonical_target
        };

        validate_local_pnpm_lockfile_target(spec, lockfile, &name, &local_spec, &expected_target)?;
    }

    Ok(())
}

pub(crate) fn validate_local_bun_dependencies(
    trusted_root: &std::path::Path,
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
    lockfile: &serde_json::Value,
    npm_index: &NpmProjectIndex,
    ignore_dirs: &[String],
) -> Result<()> {
    let canonical_project_dir = std::fs::canonicalize(spec.project_dir()).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {}: {}",
            spec.project_dir().display(),
            err
        )
    })?;

    for (name, local_spec) in parsers::package_json::npm_dependency_entries(manifest)
        .into_iter()
        .filter(|(_, spec)| {
            spec.starts_with("workspace:") || spec.starts_with("file:") || spec.starts_with("link:")
        })
    {
        let expected_target = if local_spec.starts_with("workspace:") {
            validate_workspace_bun_dependency(
                trusted_root,
                spec,
                &name,
                &canonical_project_dir,
                ignore_dirs,
            )?
        } else {
            let canonical_target = resolve_local_npm_target(
                trusted_root,
                spec,
                &name,
                &local_spec,
                &canonical_project_dir,
            )?;
            if !npm_index.dirs.contains(&canonical_target) {
                anyhow::bail!(
                    "Local Bun dependency '{}' in '{}' resolves to '{}' inside the scan root, but no scanned package.json was found there.",
                    name,
                    spec.manifest_path.display(),
                    local_spec
                );
            }
            if npm_index
                .names_by_dir
                .get(&canonical_target)
                .is_none_or(|target_name| target_name != &name)
            {
                let actual = npm_index
                    .names_by_dir
                    .get(&canonical_target)
                    .cloned()
                    .unwrap_or_else(|| "<missing package name>".to_string());
                anyhow::bail!(
                    "Local Bun dependency '{}' in '{}' resolves to '{}', but that project declares package name '{}'. Local file:/link: targets must match the dependency package identity exactly.",
                    name,
                    spec.manifest_path.display(),
                    canonical_target.display(),
                    crate::report::sanitize_for_terminal(&actual)
                );
            }
            canonical_target
        };

        validate_local_bun_lockfile_target(spec, lockfile, &name, &local_spec, &expected_target)?;
    }

    validate_bun_lockfile_local_packages(trusted_root, spec, lockfile, npm_index)
}

/// Every workspace:/file:/link: entry in bun.lock (including transitive ones the
/// manifest never declares) must resolve to a scanned local project with the
/// same package identity, mirroring the npm `link: true` check.
pub(crate) fn validate_bun_lockfile_local_packages(
    trusted_root: &std::path::Path,
    spec: &ProjectInputSpec,
    lockfile: &serde_json::Value,
    npm_index: &NpmProjectIndex,
) -> Result<()> {
    let lockfile_path = selected_lockfile_path(spec).expect("bun preflight selected a lockfile");
    let lockfile_dir = lockfile_path
        .parent()
        .expect("lockfile has a parent directory");
    for local in crate::lockfiles::bun::local_package_entries(lockfile) {
        let target = resolve_local_npm_target(
            trusted_root,
            spec,
            local.name,
            &format!("file:{}", local.target),
            lockfile_dir,
        )
        .map_err(|err| {
            anyhow::anyhow!(
                "Required lockfile '{}' local Bun package '{}' ({}{}) must resolve to a scanned local project: {}",
                lockfile_path.display(),
                crate::report::sanitize_for_terminal(local.key),
                local.protocol,
                crate::report::sanitize_for_terminal(local.target),
                err
            )
        })?;
        if local.name.is_empty()
            || npm_index
                .names_by_dir
                .get(&target)
                .is_none_or(|actual| actual != local.name)
        {
            anyhow::bail!(
                "Required lockfile '{}' local Bun package '{}' ('{}') must resolve to a scanned local project with that package identity; target '{}' is unscanned or has a different name.",
                lockfile_path.display(),
                crate::report::sanitize_for_terminal(local.key),
                crate::report::sanitize_for_terminal(local.name),
                target.display()
            );
        }
    }
    Ok(())
}

pub(crate) fn validate_local_yarn_dependencies(
    trusted_root: &std::path::Path,
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
    lockfile: &crate::lockfiles::yarn::ParsedYarnLock,
    ignore_dirs: &[String],
) -> Result<()> {
    let canonical_project_dir = std::fs::canonicalize(spec.project_dir()).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {}: {}",
            spec.project_dir().display(),
            err
        )
    })?;

    for (name, local_spec) in parsers::package_json::npm_dependency_entries(manifest)
        .into_iter()
        .filter(|(_, spec)| {
            spec.starts_with("workspace:") || spec.starts_with("file:") || spec.starts_with("link:")
        })
    {
        if !local_spec.starts_with("workspace:") {
            anyhow::bail!(
                "Local Yarn dependency '{}' in '{}' uses unsupported spec '{}'. sloppy-joe currently supports Yarn workspace: dependencies, but file:/link: targets remain blocked until their lockfile provenance is modeled exactly.",
                name,
                spec.manifest_path.display(),
                crate::report::sanitize_for_terminal(&local_spec)
            );
        }

        let expected_target = validate_workspace_yarn_dependency(
            trusted_root,
            spec,
            &name,
            &canonical_project_dir,
            ignore_dirs,
        )?;
        let relative_target = if expected_target == *trusted_root {
            ".".to_string()
        } else {
            expected_target
                .strip_prefix(trusted_root)
                .map_err(|_| {
                    anyhow::anyhow!(
                        "Local Yarn dependency '{}' in '{}' resolved outside the trusted Yarn root '{}'.",
                        name,
                        spec.manifest_path.display(),
                        trusted_root.display()
                    )
                })?
                .components()
                .filter_map(|component| match component {
                    std::path::Component::Normal(part) => Some(part.to_string_lossy().to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("/")
        };

        crate::lockfiles::yarn::validate_workspace_target(lockfile, &name, &relative_target)?;
    }

    Ok(())
}

pub(crate) fn validate_local_npm_lockfile_target(
    spec: &ProjectInputSpec,
    lockfile: &serde_json::Value,
    dep_name: &str,
    local_spec: &str,
    expected_target: &std::path::Path,
) -> Result<()> {
    let lockfile_path = selected_lockfile_path(spec)
        .expect("npm projects must have a selected lockfile during preflight");
    let entry = lockfile
        .get("packages")
        .and_then(|packages| packages.as_object())
        .and_then(|packages| lockfiles::npm::installed_package_entry(packages, spec.npm_lockfile_package_key(), dep_name).map(|(_, entry)| entry))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Required lockfile '{}' is out of sync with package.json: local npm dependency '{}' is missing its lockfile entry.",
                lockfile_path.display(),
                dep_name
            )
        })?;

    if !entry
        .get("link")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' must be a local link for '{}', but link=true was not present.",
            lockfile_path.display(),
            dep_name,
            local_spec
        );
    }

    let resolved = entry
        .get("resolved")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Required lockfile '{}' entry '{}' is missing its resolved local target for '{}'.",
                lockfile_path.display(),
                dep_name,
                local_spec
            )
        })?;
    let lockfile_dir = lockfile_path
        .parent()
        .expect("lockfile paths should always have a parent directory");
    let candidate = if std::path::Path::new(resolved).is_absolute() {
        std::path::PathBuf::from(resolved)
    } else {
        lockfile_dir.join(resolved)
    };
    let normalized = normalize_filesystem_path(&candidate);
    let canonical_lockfile_target = std::fs::canonicalize(&normalized).map_err(|err| {
        anyhow::anyhow!(
            "Required lockfile '{}' entry '{}' points to '{}' but that target is missing or unreadable: {}.",
            lockfile_path.display(),
            dep_name,
            resolved,
            err
        )
    })?;

    if canonical_lockfile_target != expected_target {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' points to '{}' for '{}', but the manifest-verified local target is '{}'. Regenerate the lockfile so the local dependency binding matches exactly.",
            lockfile_path.display(),
            dep_name,
            resolved,
            local_spec,
            expected_target.display()
        );
    }

    Ok(())
}

pub(crate) fn validate_local_pnpm_lockfile_target(
    spec: &ProjectInputSpec,
    lockfile: &serde_yaml::Value,
    dep_name: &str,
    local_spec: &str,
    expected_target: &std::path::Path,
) -> Result<()> {
    let lockfile_path = selected_lockfile_path(spec)
        .expect("pnpm projects must have a selected lockfile during preflight");
    let importer_key = spec
        .js_binding
        .as_ref()
        .map(|binding| binding.package_entry_key.as_str())
        .unwrap_or(".");
    let importer = lockfile
        .get("importers")
        .and_then(|value| value.get(importer_key))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Required lockfile '{}' is out of sync: importer '{}' is missing.",
                lockfile_path.display(),
                importer_key
            )
        })?;
    let version = pnpm_importer_entry(importer, dep_name).ok_or_else(|| {
        anyhow::anyhow!(
            "Required lockfile '{}' is out of sync: local pnpm dependency '{}' is missing from importer '{}'.",
            lockfile_path.display(),
            dep_name,
            importer_key
        )
    })?;
    let resolved = version
        .strip_prefix("link:")
        .or_else(|| version.strip_prefix("file:"))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Required lockfile '{}' importer '{}' records '{}' as '{}', but local pnpm dependencies must resolve through link:/file: entries.",
                lockfile_path.display(),
                importer_key,
                dep_name,
                crate::report::sanitize_for_terminal(version)
            )
        })?;
    let lockfile_dir = lockfile_path
        .parent()
        .expect("lockfile paths should always have a parent directory");
    let importer_dir = if importer_key == "." {
        lockfile_dir.to_path_buf()
    } else {
        lockfile_dir.join(importer_key)
    };
    let candidate = if std::path::Path::new(resolved).is_absolute() {
        std::path::PathBuf::from(resolved)
    } else {
        importer_dir.join(resolved)
    };
    let normalized = normalize_filesystem_path(&candidate);
    let canonical_lockfile_target = std::fs::canonicalize(&normalized).map_err(|err| {
        anyhow::anyhow!(
            "Required lockfile '{}' importer '{}' points '{}' at '{}' but that target is missing or unreadable: {}.",
            lockfile_path.display(),
            importer_key,
            dep_name,
            resolved,
            err
        )
    })?;
    if canonical_lockfile_target != expected_target {
        anyhow::bail!(
            "Required lockfile '{}' importer '{}' points '{}' to '{}' for '{}', but the manifest-verified local target is '{}'. Regenerate pnpm-lock.yaml so the local dependency binding matches exactly.",
            lockfile_path.display(),
            importer_key,
            dep_name,
            resolved,
            local_spec,
            expected_target.display()
        );
    }
    Ok(())
}

pub(crate) fn validate_local_bun_lockfile_target(
    spec: &ProjectInputSpec,
    lockfile: &serde_json::Value,
    dep_name: &str,
    local_spec: &str,
    expected_target: &std::path::Path,
) -> Result<()> {
    let lockfile_path = selected_lockfile_path(spec)
        .expect("Bun projects must have a selected lockfile during preflight");
    let descriptor = lockfile
        .get("packages")
        .and_then(|packages| packages.get(dep_name))
        .and_then(|value| value.as_array())
        .and_then(|value| value.first())
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Required lockfile '{}' is out of sync with package.json: local Bun dependency '{}' is missing its lockfile package entry.",
                lockfile_path.display(),
                dep_name
            )
        })?;

    let (prefix, label) = if local_spec.starts_with("workspace:") {
        ("@workspace:", "workspace:")
    } else if local_spec.starts_with("file:") {
        ("@file:", "file:")
    } else if local_spec.starts_with("link:") {
        ("@link:", "link:")
    } else {
        anyhow::bail!(
            "Local Bun dependency '{}' in '{}' uses unsupported spec '{}'.",
            dep_name,
            spec.manifest_path.display(),
            crate::report::sanitize_for_terminal(local_spec)
        );
    };

    let expected_prefix = format!("{dep_name}{prefix}");
    let Some(relative_target) = descriptor.strip_prefix(&expected_prefix) else {
        anyhow::bail!(
            "Required lockfile '{}' is out of sync with package.json: local Bun dependency '{}' should resolve via {}, but the lockfile recorded '{}'.",
            lockfile_path.display(),
            dep_name,
            label,
            crate::report::sanitize_for_terminal(descriptor)
        );
    };

    let lockfile_root = lockfile_path
        .parent()
        .expect("lockfile paths should always have a parent directory");
    let canonical_lock_target = std::fs::canonicalize(lockfile_root.join(relative_target))
        .map_err(|err| {
            anyhow::anyhow!(
                "Required lockfile '{}' points local Bun dependency '{}' at '{}', but that target is unreadable: {}",
                lockfile_path.display(),
                dep_name,
                crate::report::sanitize_for_terminal(relative_target),
                err
            )
        })?;
    if canonical_lock_target != expected_target {
        anyhow::bail!(
            "Required lockfile '{}' is out of sync with package.json: local Bun dependency '{}' points to '{}', but package.json resolves to '{}'. Regenerate bun.lock from the Bun workspace root.",
            lockfile_path.display(),
            dep_name,
            canonical_lock_target.display(),
            expected_target.display()
        );
    }

    Ok(())
}

pub(crate) fn resolve_local_npm_target(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    dep_name: &str,
    local_spec: &str,
    canonical_project_dir: &std::path::Path,
) -> Result<std::path::PathBuf> {
    let raw_target = local_spec
        .strip_prefix("file:")
        .or_else(|| local_spec.strip_prefix("link:"))
        .unwrap_or("")
        .trim();
    if raw_target.is_empty() {
        anyhow::bail!(
            "Local npm dependency '{}' in '{}' has an empty target.",
            dep_name,
            spec.manifest_path.display()
        );
    }

    let candidate = if std::path::Path::new(raw_target).is_absolute() {
        std::path::PathBuf::from(raw_target)
    } else {
        canonical_project_dir.join(raw_target)
    };
    let normalized = normalize_filesystem_path(&candidate);
    let canonical_root = std::fs::canonicalize(scan_root)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", scan_root.display(), err))?;

    let canonical_target = match std::fs::canonicalize(&normalized) {
        Ok(path) => path,
        Err(err) => {
            if !normalized.starts_with(&canonical_root) {
                anyhow::bail!(
                    "Local npm dependency '{}' in '{}' resolves outside the scan root via '{}'.",
                    dep_name,
                    spec.manifest_path.display(),
                    local_spec
                );
            }
            anyhow::bail!(
                "Local npm dependency '{}' in '{}' points to '{}' but that target is missing or unreadable: {}.",
                dep_name,
                spec.manifest_path.display(),
                raw_target,
                err
            );
        }
    };

    if !canonical_target.starts_with(&canonical_root) {
        anyhow::bail!(
            "Local npm dependency '{}' in '{}' resolves outside the scan root via '{}'.",
            dep_name,
            spec.manifest_path.display(),
            local_spec
        );
    }
    if !canonical_target.is_dir() {
        anyhow::bail!(
            "Local npm dependency '{}' in '{}' points to '{}' which is not a project directory.",
            dep_name,
            spec.manifest_path.display(),
            raw_target
        );
    }

    Ok(canonical_target)
}
