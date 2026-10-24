use super::*;

pub(crate) fn npm_lockfile_version(
    lockfile: &serde_json::Value,
    lockfile_path: &std::path::Path,
) -> Result<u64> {
    crate::lockfiles::npm::lockfile_version(lockfile)
        .map_err(|err| anyhow::anyhow!("Broken lockfile '{}': {}", lockfile_path.display(), err))
}

pub(crate) fn npm_registry_tarball_path(resolved: &str) -> Option<&str> {
    let resolved = resolved.trim();
    // Only a literal https:// URL is a registry tarball: npm reads a scheme-less path ending in
    // `.tgz` as a local file.
    let resolved = resolved.strip_prefix("https://")?;
    resolved.strip_prefix("registry.npmjs.org/")
}

pub(crate) fn expected_npm_registry_tarball_paths(
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

pub(crate) fn validate_npm_resolved_identity(
    package_name: &str,
    version: &str,
    resolved: &str,
    lockfile_path: &std::path::Path,
) -> Result<()> {
    let Some(path) = npm_registry_tarball_path(resolved) else {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' has untrusted resolved source '{}'. sloppy-joe only trusts npm registry tarball URLs in package-lock.json and npm-shrinkwrap.json.",
            lockfile_path.display(),
            package_name,
            crate::config::redact_url_for_display(resolved)
        );
    };

    if !expected_npm_registry_tarball_paths(package_name, version)
        .iter()
        .any(|expected| expected == path)
    {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' resolves to '{}', which does not match the locked package identity '{}' at version '{}'.",
            lockfile_path.display(),
            package_name,
            crate::config::redact_url_for_display(resolved),
            package_name,
            version
        );
    }

    Ok(())
}

pub(crate) fn validate_npm_lockfile_consistency(
    manifest: &serde_json::Value,
    lockfile: &serde_json::Value,
    lockfile_path: &std::path::Path,
    package_entry_key: &str,
) -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};

    fn section_map(value: &serde_json::Value, section: &str) -> BTreeMap<String, String> {
        value
            .get(section)
            .and_then(|section| section.as_object())
            .map(|section| {
                section
                    .iter()
                    .filter_map(|(name, value)| {
                        value
                            .as_str()
                            .map(|version| (name.clone(), version.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    let manifest_sections = [
        ("dependencies", section_map(manifest, "dependencies")),
        ("devDependencies", section_map(manifest, "devDependencies")),
        (
            "optionalDependencies",
            section_map(manifest, "optionalDependencies"),
        ),
        (
            "peerDependencies",
            section_map(manifest, "peerDependencies"),
        ),
    ];

    let package_entry = lockfile
        .get("packages")
        .and_then(|packages| packages.get(package_entry_key))
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    if package_entry.is_object() {
        for (section, manifest_entries) in &manifest_sections {
            let lock_entries = section_map(&package_entry, section);
            if *manifest_entries != lock_entries {
                anyhow::bail!(
                    "Required lockfile '{}' is out of sync with package.json: package entry '{}' does not match its '{}' declarations. Regenerate the lockfile so it matches the manifest exactly.",
                    lockfile_path.display(),
                    if package_entry_key.is_empty() {
                        "<root>"
                    } else {
                        package_entry_key
                    },
                    section,
                );
            }
        }
    } else {
        if !package_entry_key.is_empty() {
            anyhow::bail!(
                "Required lockfile '{}' is missing workspace package entry '{}'. Regenerate the lockfile from the npm workspace root so it records this project explicitly.",
                lockfile_path.display(),
                package_entry_key
            );
        }
        let manifest_names: BTreeSet<String> = manifest_sections
            .iter()
            .flat_map(|(_, entries)| entries.keys().cloned())
            .collect();
        let locked_names: BTreeSet<String> = lockfile
            .get("dependencies")
            .and_then(|deps| deps.as_object())
            .map(|deps| deps.keys().cloned().collect())
            .unwrap_or_default();
        if manifest_names != locked_names {
            anyhow::bail!(
                "Required lockfile '{}' is out of sync with package.json: direct dependency entries do not match. Regenerate the lockfile so it matches the manifest exactly.",
                lockfile_path.display()
            );
        }
    }

    for (alias_name, raw_spec) in section_map(manifest, "dependencies")
        .into_iter()
        .chain(section_map(manifest, "devDependencies"))
        .chain(section_map(manifest, "optionalDependencies"))
        .chain(section_map(manifest, "peerDependencies"))
    {
        if let Some(alias_spec) = raw_spec.strip_prefix("npm:") {
            let (target_name, _) = alias_spec.rsplit_once('@').ok_or_else(|| {
                anyhow::anyhow!(
                    "Unsupported npm alias '{}' in package.json: expected npm:<package>@<version>",
                    crate::report::sanitize_for_terminal(&raw_spec)
                )
            })?;
            let entry = lockfile
                .get("packages")
                .and_then(|packages| packages.as_object())
                .and_then(|packages| lockfiles::npm::installed_package_entry(packages, package_entry_key, &alias_name).map(|(_, entry)| entry))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Required lockfile '{}' is out of sync with package.json: missing npm alias entry for '{}'.",
                        lockfile_path.display(),
                        alias_name
                    )
                })?;
            let locked_name = entry.get("name").and_then(|name| name.as_str()).ok_or_else(|| {
                anyhow::anyhow!(
                    "Required lockfile '{}' is out of sync with package.json: npm alias '{}' is missing its locked package name.",
                    lockfile_path.display(),
                    alias_name
                )
            })?;
            if locked_name != target_name {
                anyhow::bail!(
                    "Required lockfile '{}' is out of sync with package.json: npm alias '{}' targets '{}' in the manifest but '{}' in the lockfile.",
                    lockfile_path.display(),
                    alias_name,
                    target_name,
                    locked_name
                );
            }
        }
    }

    Ok(())
}

pub(crate) fn validate_pnpm_lockfile_consistency(
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
    lockfile: &serde_yaml::Value,
    lockfile_path: &std::path::Path,
) -> Result<()> {
    use std::collections::BTreeMap;

    fn manifest_section_map(value: &serde_json::Value, section: &str) -> BTreeMap<String, String> {
        value
            .get(section)
            .and_then(|section| section.as_object())
            .map(|section| {
                section
                    .iter()
                    .filter_map(|(name, value)| {
                        value
                            .as_str()
                            .map(|version| (name.clone(), version.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn importer_section_map(
        importer: &serde_yaml::Value,
        section: &str,
    ) -> Result<BTreeMap<String, String>> {
        let Some(entries) = importer.get(section) else {
            return Ok(BTreeMap::new());
        };
        let Some(entries) = entries.as_mapping() else {
            anyhow::bail!(
                "Broken lockfile importer section '{}': expected a mapping of dependencies.",
                section
            );
        };
        let mut out = BTreeMap::new();
        for (name, value) in entries {
            let Some(name) = name.as_str() else {
                anyhow::bail!(
                    "Broken lockfile importer section '{}': dependency names must be strings.",
                    section
                );
            };
            let specifier = value
                .get("specifier")
                .and_then(|value| value.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Broken lockfile importer section '{}': dependency '{}' is missing its specifier.",
                        section,
                        name
                    )
                })?;
            out.insert(name.to_string(), specifier.to_string());
        }
        Ok(out)
    }

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
                "Required lockfile '{}' is missing importer '{}'. Regenerate pnpm-lock.yaml from the workspace root so it records this project explicitly.",
                lockfile_path.display(),
                importer_key
            )
        })?;

    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let manifest_entries = manifest_section_map(manifest, section);
        let lock_entries = importer_section_map(importer, section)?;
        if manifest_entries != lock_entries {
            anyhow::bail!(
                "Required lockfile '{}' is out of sync with package.json: importer '{}' does not match its '{}' declarations. Regenerate pnpm-lock.yaml so it matches the manifest exactly.",
                lockfile_path.display(),
                importer_key,
                section
            );
        }
    }

    Ok(())
}

pub(crate) fn validate_bun_lockfile_consistency(
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
    lockfile: &serde_json::Value,
    lockfile_path: &std::path::Path,
) -> Result<()> {
    use std::collections::BTreeMap;

    fn manifest_section_map(value: &serde_json::Value, section: &str) -> BTreeMap<String, String> {
        value
            .get(section)
            .and_then(|section| section.as_object())
            .map(|section| {
                section
                    .iter()
                    .filter_map(|(name, value)| {
                        value
                            .as_str()
                            .map(|version| (name.clone(), version.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn workspace_section_map(
        workspace: &serde_json::Value,
        section: &str,
    ) -> Result<BTreeMap<String, String>> {
        let Some(entries) = workspace.get(section) else {
            return Ok(BTreeMap::new());
        };
        let Some(entries) = entries.as_object() else {
            anyhow::bail!(
                "Broken lockfile workspace section '{}': expected a mapping of dependencies.",
                section
            );
        };
        let mut out = BTreeMap::new();
        for (name, value) in entries {
            let Some(specifier) = value.as_str() else {
                anyhow::bail!(
                    "Broken lockfile workspace section '{}': dependency '{}' must have a string specifier.",
                    section,
                    name
                );
            };
            out.insert(name.to_string(), specifier.to_string());
        }
        Ok(out)
    }

    let workspace_key = spec
        .js_binding
        .as_ref()
        .map(|binding| binding.package_entry_key.as_str())
        .unwrap_or("");
    let workspace = lockfile
        .get("workspaces")
        .and_then(|value| value.get(workspace_key))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Required lockfile '{}' is missing workspace '{}'. Regenerate bun.lock from the workspace root so it records this project explicitly.",
                lockfile_path.display(),
                if workspace_key.is_empty() {
                    "<root>"
                } else {
                    workspace_key
                }
            )
        })?;

    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let manifest_entries = manifest_section_map(manifest, section);
        let lock_entries = workspace_section_map(workspace, section)?;
        if manifest_entries != lock_entries {
            anyhow::bail!(
                "Required lockfile '{}' is out of sync with package.json: workspace '{}' does not match its '{}' declarations. Regenerate bun.lock so it matches the manifest exactly.",
                lockfile_path.display(),
                if workspace_key.is_empty() {
                    "<root>"
                } else {
                    workspace_key
                },
                section
            );
        }
    }

    Ok(())
}

pub(crate) fn pnpm_importer_entry<'a>(
    importer: &'a serde_yaml::Value,
    dep_name: &str,
) -> Option<&'a str> {
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let version = importer
            .get(section)
            .and_then(|value| value.get(dep_name))
            .and_then(|value| value.get("version"))
            .and_then(|value| value.as_str());
        if version.is_some() {
            return version;
        }
    }
    None
}

pub(crate) fn validate_npm_lockfile_provenance(
    lockfile: &serde_json::Value,
    lockfile_path: &std::path::Path,
    allowed_alias_targets: &std::collections::HashMap<String, String>,
    registries: &npm_config::NpmRegistries,
) -> Result<()> {
    if let Some(packages) = lockfile.get("packages").and_then(|value| value.as_object()) {
        for (key, entry) in packages {
            validate_npm_lockfile_package_entry(
                key,
                entry,
                lockfile_path,
                allowed_alias_targets,
                registries,
            )?;
        }
        return Ok(());
    }

    if let Some(dependencies) = lockfile
        .get("dependencies")
        .and_then(|value| value.as_object())
    {
        validate_npm_lockfile_dependency_entries(
            dependencies,
            lockfile_path,
            allowed_alias_targets,
            registries,
        )?;
    }

    Ok(())
}

pub(crate) fn validate_npm_lockfile_package_entry(
    key: &str,
    entry: &serde_json::Value,
    lockfile_path: &std::path::Path,
    allowed_alias_targets: &std::collections::HashMap<String, String>,
    registries: &npm_config::NpmRegistries,
) -> Result<()> {
    if key.is_empty() {
        return Ok(());
    }
    let Some(entry) = entry.as_object() else {
        anyhow::bail!(
            "Broken lockfile '{}': package entry '{}' was not an object.",
            lockfile_path.display(),
            key
        );
    };
    if !key.contains("node_modules/") {
        return Ok(());
    }
    let expected_name = key
        .rsplit_once("node_modules/")
        .map(|(_, name)| name)
        .unwrap_or(key);
    let locked_name = entry.get("name").and_then(|value| value.as_str());
    ensure_valid_npm_lockfile_names(key, expected_name, locked_name, lockfile_path)?;
    let allowed_alias_target = allowed_alias_targets.get(expected_name).map(String::as_str);
    if let Some(locked_name) = locked_name
        && locked_name != expected_name
        && Some(locked_name) != allowed_alias_target
    {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' claims to be '{}'. npm lockfile entries must match the package they install exactly.",
            lockfile_path.display(),
            expected_name,
            locked_name
        );
    }
    validate_npm_lockfile_entry_fields(
        locked_name.unwrap_or(expected_name),
        entry,
        lockfile_path,
        registries,
    )
}

/// Lockfile entries whose installed or declared name cannot be scanned must
/// block instead of being silently dropped from the transitive set.
pub(crate) fn ensure_valid_npm_lockfile_names(
    key: &str,
    installed_name: &str,
    locked_name: Option<&str>,
    lockfile_path: &std::path::Path,
) -> Result<()> {
    for candidate in std::iter::once(installed_name).chain(locked_name) {
        if !crate::ecosystem::validate_package_name(candidate) {
            anyhow::bail!(
                "Required lockfile '{}' entry '{}' has an invalid package name '{}'.",
                lockfile_path.display(),
                crate::report::sanitize_for_terminal(key),
                crate::report::sanitize_for_terminal(candidate)
            );
        }
    }
    Ok(())
}

pub(crate) fn validate_npm_lockfile_dependency_entries(
    dependencies: &serde_json::Map<String, serde_json::Value>,
    lockfile_path: &std::path::Path,
    allowed_alias_targets: &std::collections::HashMap<String, String>,
    registries: &npm_config::NpmRegistries,
) -> Result<()> {
    for (name, entry) in dependencies {
        let Some(entry) = entry.as_object() else {
            anyhow::bail!(
                "Broken lockfile '{}': dependency entry '{}' was not an object.",
                lockfile_path.display(),
                name
            );
        };
        let locked_name = entry.get("name").and_then(|value| value.as_str());
        ensure_valid_npm_lockfile_names(name, name, locked_name, lockfile_path)?;
        let allowed_alias_target = allowed_alias_targets.get(name).map(String::as_str);
        if let Some(locked_name) = locked_name
            && locked_name != name
            && Some(locked_name) != allowed_alias_target
        {
            anyhow::bail!(
                "Required lockfile '{}' entry '{}' claims to be '{}'. npm lockfile entries must match the package they install exactly.",
                lockfile_path.display(),
                name,
                locked_name
            );
        }
        validate_npm_lockfile_entry_fields(
            locked_name.unwrap_or(name),
            entry,
            lockfile_path,
            registries,
        )?;
        if let Some(nested) = entry
            .get("dependencies")
            .and_then(|value| value.as_object())
        {
            validate_npm_lockfile_dependency_entries(
                nested,
                lockfile_path,
                allowed_alias_targets,
                registries,
            )?;
        }
    }
    Ok(())
}

pub(crate) fn validate_npm_lockfile_entry_fields(
    package_name: &str,
    entry: &serde_json::Map<String, serde_json::Value>,
    lockfile_path: &std::path::Path,
    registries: &npm_config::NpmRegistries,
) -> Result<()> {
    // npm treats any truthy `link`/`inBundle`/`bundled` as set, so only real booleans are modeled.
    for flag in ["link", "inBundle", "bundled"] {
        if entry.get(flag).is_some_and(|value| !value.is_boolean()) {
            anyhow::bail!(
                "Required lockfile '{}' entry '{}' has a non-boolean '{flag}' value; npm reads it differently than sloppy-joe, so the entry cannot be verified.",
                lockfile_path.display(),
                package_name
            );
        }
    }
    if entry
        .get("link")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        return Ok(());
    }

    if entry
        .get("inBundle")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
        || entry
            .get("bundled")
            .and_then(|value| value.as_bool())
            .unwrap_or(false)
    {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' is marked as bundled. sloppy-joe does not trust bundled npm payloads yet because the bundled code cannot be verified independently from package-lock.json.",
            lockfile_path.display(),
            package_name
        );
    }

    let resolved = entry.get("resolved").and_then(|value| value.as_str());
    // Host trust is checked before anything else so an entry cannot skip it by
    // omitting other fields such as `version`.
    if let Some(resolved) = resolved
        && !is_trusted_npm_resolved_source(resolved)
        && !registries.matches_private_source(package_name, resolved)
    {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' has untrusted resolved source at host '{}' (URL redacted). Expected a public npm tarball or a URL within its configured private registry.",
            lockfile_path.display(),
            package_name,
            reqwest::Url::parse(resolved)
                .ok()
                .and_then(|url| url.host_str().map(str::to_string))
                .unwrap_or_else(|| "<invalid>".to_string())
        );
    }

    let Some(version) = entry.get("version").and_then(|value| value.as_str()) else {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' is missing a version. sloppy-joe cannot verify npm lockfile entries without an exact locked version.",
            lockfile_path.display(),
            package_name
        );
    };

    let resolved = resolved.ok_or_else(|| {
        anyhow::anyhow!(
            "Required lockfile '{}' entry '{}' is missing a resolved source URL. sloppy-joe only trusts npm lockfile entries with explicit tarball provenance.",
            lockfile_path.display(),
            package_name
        )
    })?;
    if is_trusted_npm_resolved_source(resolved) {
        validate_npm_resolved_identity(package_name, version, resolved, lockfile_path)?;
    }

    let integrity = entry
        .get("integrity")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Required lockfile '{}' entry '{}' is missing integrity metadata. sloppy-joe only trusts npm lockfile entries with explicit integrity hashes.",
                lockfile_path.display(),
                package_name
            )
        })?;
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

pub(crate) fn is_trusted_npm_resolved_source(resolved: &str) -> bool {
    npm_registry_tarball_path(resolved).is_some()
}

#[cfg(test)]
mod flag_tests {
    use super::*;

    #[test]
    fn non_boolean_link_and_bundle_flags_block() {
        for flag in ["link", "inBundle", "bundled"] {
            let entry = serde_json::json!({"version": "1.0.0", flag: "yes"});
            let result = validate_npm_lockfile_entry_fields(
                "left-pad",
                entry.as_object().unwrap(),
                std::path::Path::new("package-lock.json"),
                &npm_config::NpmRegistries::default(),
            );
            assert!(result.is_err(), "{flag}");
        }
    }
}

#[cfg(test)]
mod scheme_tests {
    use super::*;

    #[test]
    fn only_a_literal_https_url_is_a_registry_tarball() {
        let path = "left-pad/-/left-pad-1.3.0.tgz";
        assert_eq!(
            npm_registry_tarball_path(&format!("https://registry.npmjs.org/{path}")),
            Some(path)
        );
        for resolved in [
            format!("registry.npmjs.org/{path}"),
            format!("http://registry.npmjs.org/{path}"),
            format!("./registry.npmjs.org/{path}"),
        ] {
            assert_eq!(npm_registry_tarball_path(&resolved), None, "{resolved}");
        }
    }

    #[test]
    fn a_schemeless_resolved_path_is_not_integrity_exempt() {
        let entry = serde_json::json!({"resolved": "registry.npmjs.org/a/-/a-1.0.0.tgz", "integrity": "sha512-x"});
        let validated = validate_npm_resolved_identity(
            "a",
            "1.0.0",
            "registry.npmjs.org/a/-/a-1.0.0.tgz",
            std::path::Path::new("package-lock.json"),
        );
        assert!(validated.is_err(), "{entry}");
    }
}
