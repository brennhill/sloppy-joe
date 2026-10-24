use super::*;

pub(crate) fn validate_manifest_consistency(
    parsed: &ParsedYarnLock,
    manifest: &serde_json::Value,
    package_entry_key: &str,
    project_name: &str,
) -> Result<()> {
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let manifest_entries = manifest
            .get(section)
            .and_then(|value| value.as_object())
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|(name, value)| {
                        value.as_str().map(|spec| (name.clone(), spec.to_string()))
                    })
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();

        if let Some(workspace_entry) = parsed.workspace_entry(project_name, package_entry_key) {
            let lock_entries = workspace_entry
                .sections
                .get(section)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|(name, value)| {
                    let normalized = if manifest_entries
                        .get(&name)
                        .is_some_and(|requested| requested.starts_with("npm:"))
                    {
                        value
                    } else {
                        value.trim_start_matches("npm:").to_string()
                    };
                    (name, normalized)
                })
                .collect::<BTreeMap<_, _>>();
            if manifest_entries != lock_entries {
                anyhow::bail!(
                    "Required lockfile '{}' is out of sync with package.json: workspace '{}' does not match its '{}' declarations. Regenerate yarn.lock so it matches the manifest exactly.",
                    parsed.path.display(),
                    if package_entry_key.is_empty() {
                        "<root>"
                    } else {
                        package_entry_key
                    },
                    section
                );
            }
        }

        for (name, requested) in manifest_entries {
            if requested.starts_with("workspace:")
                || requested.starts_with("file:")
                || requested.starts_with("link:")
            {
                continue;
            }
            if !manifest_selectors(&name, &requested)
                .into_iter()
                .any(|selector| parsed.by_selector.contains_key(&selector))
            {
                anyhow::bail!(
                    "Required lockfile '{}' is out of sync with package.json: '{}'@'{}' is missing from yarn.lock.",
                    parsed.path.display(),
                    name,
                    requested
                );
            }
        }
    }

    Ok(())
}

pub(crate) fn validate_provenance(parsed: &ParsedYarnLock) -> Result<()> {
    for entry in &parsed.entries {
        // Yarn Berry's lockfile header block, not a package.
        if entry.selectors.len() == 1 && entry.selectors[0] == "__metadata" {
            continue;
        }
        let Some((name, source)) = entry
            .selectors
            .iter()
            .find_map(|selector| selector_package_name_and_source(selector))
        else {
            anyhow::bail!(
                "Required lockfile '{}' entry '{}' has a selector sloppy-joe cannot attribute to a package. Unattributable entries cannot be verified.",
                parsed.path.display(),
                crate::report::sanitize_for_terminal(&entry.selectors.join(", "))
            );
        };
        match source {
            "workspace" => {
                if entry.link_type.as_deref() == Some("hard") {
                    anyhow::bail!(
                        "Required lockfile '{}' entry '{}' claims to be a workspace dependency, but linkType was hard instead of soft.",
                        parsed.path.display(),
                        entry.selectors.join(", ")
                    );
                }
            }
            "registry" => {
                let Some(version) = entry.version.as_deref() else {
                    anyhow::bail!(
                        "Required lockfile '{}' entry '{}' is missing its resolved version.",
                        parsed.path.display(),
                        entry.selectors.join(", ")
                    );
                };
                if let Some(resolution) = &entry.resolution {
                    let checksum = entry
                        .checksum
                        .as_deref()
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "Required lockfile '{}' entry '{}' is missing checksum metadata. sloppy-joe only trusts Yarn Berry registry entries with explicit artifact checksums.",
                                parsed.path.display(),
                                entry.selectors.join(", ")
                            )
                        })?;
                    validate_yarn_berry_resolution_identity(
                        name,
                        version,
                        resolution,
                        parsed.path.as_path(),
                    )?;
                    if !checksum.contains('/') {
                        anyhow::bail!(
                            "Required lockfile '{}' entry '{}' has malformed checksum metadata '{}'.",
                            parsed.path.display(),
                            entry.selectors.join(", "),
                            crate::report::sanitize_for_terminal(checksum)
                        );
                    }
                } else if let Some(resolved) = &entry.resolved {
                    let Some(integrity) = &entry.integrity else {
                        anyhow::bail!(
                            "Required lockfile '{}' entry '{}' is missing integrity metadata. sloppy-joe only trusts Yarn classic registry entries with explicit tarball provenance.",
                            parsed.path.display(),
                            entry.selectors.join(", ")
                        );
                    };
                    validate_yarn_classic_resolved_identity(
                        name,
                        version,
                        resolved,
                        integrity,
                        parsed.path.as_path(),
                    )?;
                } else {
                    anyhow::bail!(
                        "Required lockfile '{}' entry '{}' is missing explicit provenance metadata.",
                        parsed.path.display(),
                        entry.selectors.join(", ")
                    );
                }
            }
            protocol => {
                anyhow::bail!(
                    "Required lockfile '{}' contains unsupported Yarn dependency source '{}' in entry '{}'.",
                    parsed.path.display(),
                    protocol,
                    entry.selectors.join(", ")
                );
            }
        }
    }

    Ok(())
}

pub(crate) fn validate_workspace_target(
    parsed: &ParsedYarnLock,
    dep_name: &str,
    relative_target: &str,
) -> Result<()> {
    let selector = format!("{dep_name}@workspace:{relative_target}");
    if parsed.by_selector.contains_key(&selector) {
        return Ok(());
    }
    anyhow::bail!(
        "Required lockfile '{}' is out of sync with package.json: local Yarn workspace dependency '{}' is missing selector '{}'.",
        parsed.path.display(),
        dep_name,
        selector
    );
}

pub(crate) fn validate_yarn_berry_resolution_identity(
    package_name: &str,
    version: &str,
    resolution: &str,
    lockfile_path: &Path,
) -> Result<()> {
    let expected = format!("{package_name}@npm:{version}");
    if resolution.trim() != expected {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' resolves to '{}', which does not match the locked package identity '{}' at version '{}'.",
            lockfile_path.display(),
            package_name,
            crate::report::sanitize_for_terminal(resolution),
            package_name,
            version
        );
    }

    Ok(())
}

pub(crate) fn validate_yarn_classic_resolved_identity(
    package_name: &str,
    version: &str,
    resolved: &str,
    integrity: &str,
    lockfile_path: &Path,
) -> Result<()> {
    let Some(path) = yarn_registry_tarball_path(resolved) else {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' has untrusted resolved source '{}'. sloppy-joe only trusts Yarn classic registry tarball URLs with explicit package identity.",
            lockfile_path.display(),
            package_name,
            crate::report::sanitize_for_terminal(resolved)
        );
    };

    if !expected_yarn_registry_tarball_paths(package_name, version)
        .iter()
        .any(|expected| expected == path)
    {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' resolves to '{}', which does not match the locked package identity '{}' at version '{}'.",
            lockfile_path.display(),
            package_name,
            crate::report::sanitize_for_terminal(resolved),
            package_name,
            version
        );
    }

    let integrity = integrity.trim();
    if integrity.is_empty() {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' is missing integrity metadata. sloppy-joe only trusts Yarn classic registry entries with explicit tarball provenance.",
            lockfile_path.display(),
            package_name
        );
    }
    if !integrity.contains('-') {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' has malformed integrity metadata '{}'.",
            lockfile_path.display(),
            package_name,
            crate::report::sanitize_for_terminal(integrity)
        );
    }

    Ok(())
}

pub(crate) fn yarn_registry_tarball_path(resolved: &str) -> Option<&str> {
    let resolved = resolved.trim();
    let resolved = resolved.strip_prefix("https://")?;
    let resolved = resolved
        .strip_prefix("registry.yarnpkg.com/")
        .or_else(|| resolved.strip_prefix("registry.npmjs.org/"))?;
    Some(
        resolved
            .split_once('#')
            .map(|(path, _)| path)
            .unwrap_or(resolved),
    )
}

pub(crate) fn expected_yarn_registry_tarball_paths(
    package_name: &str,
    version: &str,
) -> Vec<String> {
    if let Some((scope, leaf)) = package_name.split_once('/')
        && let Some(scope_name) = scope.strip_prefix('@')
    {
        let filename = format!("{leaf}-{version}.tgz");
        return vec![
            format!("{package_name}/-/{filename}"),
            format!("%40{scope_name}%2F{leaf}/-/{filename}"),
            format!("%40{scope_name}%2f{leaf}/-/{filename}"),
        ];
    }

    vec![format!("{package_name}/-/{}-{version}.tgz", package_name)]
}
