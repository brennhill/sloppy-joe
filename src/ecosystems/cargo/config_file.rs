use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectiveCargoDependency {
    pub(crate) spec: parsers::cargo_toml::CargoDependencySpec,
    pub(crate) base_dir: std::path::PathBuf,
    pub(crate) expected_exact_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EffectiveCargoRewrite {
    pub(crate) package_name: String,
    pub(crate) patch_scope: Option<parsers::cargo_toml::CargoPatchScope>,
    pub(crate) replace_source: Option<String>,
    pub(crate) replace_version: Option<String>,
    pub(crate) spec: parsers::cargo_toml::CargoDependencySpec,
    pub(crate) base_dir: std::path::PathBuf,
}

#[derive(Debug, Default)]
pub(crate) struct CargoConfigRewrites {
    pub(crate) local_paths: std::collections::HashMap<String, std::path::PathBuf>,
    pub(crate) source_replace_with: std::collections::HashMap<String, String>,
    pub(crate) source_definitions: std::collections::HashMap<String, CargoConfigSourceDefinition>,
    pub(crate) rewrite_targets: Vec<EffectiveCargoRewrite>,
    /// Unlisted settings that the operator's `config_key_allow` permitted.
    pub(crate) applied_allows: Vec<crate::config_surface::AppliedAllow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CargoConfigSourceDefinition {
    Registry(String),
    Unsupported { kind: String, detail: String },
}

pub(crate) fn merge_cargo_config_rewrites(
    into: &mut CargoConfigRewrites,
    from: CargoConfigRewrites,
) {
    into.local_paths.extend(from.local_paths);
    into.source_replace_with.extend(from.source_replace_with);
    into.source_definitions.extend(from.source_definitions);
    into.rewrite_targets.extend(from.rewrite_targets);
    into.applied_allows.extend(from.applied_allows);
}

pub(crate) fn ensure_additive_cargo_config_rewrites(
    base: &CargoConfigRewrites,
    overlay: &CargoConfigRewrites,
    origin: &std::path::Path,
) -> Result<()> {
    for (package, path) in &overlay.local_paths {
        if let Some(existing) = base.local_paths.get(package)
            && existing != path
        {
            return Err(cargo_fail(
                checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
                format!(
                    "Host-local Cargo config '{}' conflicts with repo-visible local path trust for crate '{}'. sloppy-joe only allows additive host-local Cargo relaxations.",
                    origin.display(),
                    package
                ),
            ));
        }
    }

    for (source_name, alias) in &overlay.source_replace_with {
        if let Some(existing) = base.source_replace_with.get(source_name)
            && existing != alias
        {
            return Err(cargo_fail(
                checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
                format!(
                    "Host-local Cargo config '{}' conflicts with repo-visible source replacement for '{}'. sloppy-joe only allows additive host-local Cargo relaxations.",
                    origin.display(),
                    source_name
                ),
            ));
        }
    }

    for (source_name, definition) in &overlay.source_definitions {
        if let Some(existing) = base.source_definitions.get(source_name)
            && existing != definition
        {
            return Err(cargo_fail(
                checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
                format!(
                    "Host-local Cargo config '{}' conflicts with repo-visible source definition for '{}'. sloppy-joe only allows additive host-local Cargo relaxations.",
                    origin.display(),
                    source_name
                ),
            ));
        }
    }

    Ok(())
}

pub(crate) fn cargo_registry_source_for_alias<'a>(
    alias: &str,
    config: &'a config::SloppyJoeConfig,
) -> Option<&'a str> {
    config
        .trusted_registries("cargo")
        .iter()
        .find(|entry| entry.name == alias)
        .map(|entry| entry.source.as_str())
}

pub(crate) fn cargo_normalize_registry_source(source: &str) -> String {
    let trimmed = source.trim();
    if trimmed.starts_with("registry+") || trimmed.starts_with("sparse+") {
        trimmed.to_string()
    } else {
        format!("registry+{trimmed}")
    }
}

pub(crate) fn cargo_git_source_id(
    url: &str,
    rev: Option<&str>,
    branch: Option<&str>,
    tag: Option<&str>,
) -> String {
    if let Some(rev) = rev {
        return format!("git+{url}?rev={rev}#{rev}");
    }
    if let Some(branch) = branch {
        return format!("git+{url}?branch={branch}");
    }
    if let Some(tag) = tag {
        return format!("git+{url}?tag={tag}");
    }
    format!("git+{url}")
}

pub(crate) fn cargo_dependency_source_id(
    dep: &parsers::cargo_toml::CargoDependencySpec,
    config: &config::SloppyJoeConfig,
) -> Option<String> {
    match &dep.source {
        parsers::cargo_toml::CargoSourceSpec::CratesIo => {
            Some("registry+https://github.com/rust-lang/crates.io-index".to_string())
        }
        parsers::cargo_toml::CargoSourceSpec::RegistryAlias(alias) => {
            cargo_registry_source_for_alias(alias, config).map(str::to_string)
        }
        parsers::cargo_toml::CargoSourceSpec::RegistryIndex(source) => Some(source.clone()),
        parsers::cargo_toml::CargoSourceSpec::Git {
            url,
            rev,
            branch,
            tag,
        } => Some(cargo_git_source_id(
            url,
            rev.as_deref(),
            branch.as_deref(),
            tag.as_deref(),
        )),
        parsers::cargo_toml::CargoSourceSpec::Path(_)
        | parsers::cargo_toml::CargoSourceSpec::Workspace => None,
    }
}

pub(crate) fn cargo_config_source_name(
    source: &parsers::cargo_toml::CargoSourceSpec,
) -> Option<&str> {
    match source {
        parsers::cargo_toml::CargoSourceSpec::CratesIo => Some("crates-io"),
        parsers::cargo_toml::CargoSourceSpec::RegistryAlias(alias) => Some(alias.as_str()),
        _ => None,
    }
}

pub(crate) fn resolve_cargo_config_source_target(
    source_name: &str,
    rewrites: &CargoConfigRewrites,
    config: &config::SloppyJoeConfig,
    seen: &mut std::collections::HashSet<String>,
) -> Result<Option<parsers::cargo_toml::CargoSourceSpec>> {
    if !seen.insert(source_name.to_string()) {
        return Err(cargo_fail(
            checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
            format!(
                "Cargo source replacement cycle detected at source '{}'.",
                source_name
            ),
        ));
    }

    if let Some(definition) = rewrites.source_definitions.get(source_name) {
        return match definition {
            CargoConfigSourceDefinition::Registry(url) => {
                let expected_source = format!("registry+{url}");
                if config
                    .trusted_registries("cargo")
                    .iter()
                    .any(|entry| entry.name == source_name && entry.source == expected_source)
                {
                    Ok(Some(parsers::cargo_toml::CargoSourceSpec::RegistryAlias(
                        source_name.to_string(),
                    )))
                } else {
                    Err(cargo_fail(
                        checks::names::RESOLUTION_UNTRUSTED_REGISTRY_SOURCE,
                        format!(
                            "Cargo source '{}' resolves to registry '{}' but that alias/source pair is not trusted by config.",
                            source_name, expected_source
                        ),
                    ))
                }
            }
            CargoConfigSourceDefinition::Unsupported { kind, detail } => Err(cargo_fail(
                checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
                format!(
                    "Cargo source '{}' uses unsupported {} source '{}'.",
                    source_name, kind, detail
                ),
            )),
        };
    }

    if let Some(target_name) = rewrites.source_replace_with.get(source_name) {
        if rewrites.source_definitions.contains_key(target_name)
            || rewrites.source_replace_with.contains_key(target_name)
        {
            return resolve_cargo_config_source_target(target_name, rewrites, config, seen);
        }
        if config
            .trusted_registries("cargo")
            .iter()
            .any(|entry| entry.name == *target_name)
        {
            return Ok(Some(parsers::cargo_toml::CargoSourceSpec::RegistryAlias(
                target_name.clone(),
            )));
        }
    }

    Ok(None)
}

pub(crate) fn apply_cargo_config_source_rewrite(
    dep: &parsers::cargo_toml::CargoDependencySpec,
    rewrites: &CargoConfigRewrites,
    config: &config::SloppyJoeConfig,
) -> Result<Option<parsers::cargo_toml::CargoSourceSpec>> {
    let Some(source_name) = cargo_config_source_name(&dep.source) else {
        return Ok(None);
    };
    resolve_cargo_config_source_target(
        source_name,
        rewrites,
        config,
        &mut std::collections::HashSet::new(),
    )
}

pub(crate) fn parse_cargo_config_rewrites(
    config_path: &std::path::Path,
    allows: &[crate::config_surface::KeyAllow],
) -> Result<CargoConfigRewrites> {
    let content = parsers::read_file_limited(config_path, parsers::MAX_MANIFEST_BYTES)?;
    let value = toml::from_str::<toml::Value>(&content).map_err(|err| {
        anyhow::anyhow!(
            "Broken Cargo config '{}': failed to parse TOML: {}",
            config_path.display(),
            err
        )
    })?;

    let applied_allows =
        super::cargo_surface::check(&value, config_path, allows).map_err(|err| {
            cargo_fail(
                checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
                err.to_string(),
            )
        })?;

    let mut rewrites = CargoConfigRewrites {
        applied_allows,
        ..CargoConfigRewrites::default()
    };
    let config_dir = config_path
        .parent()
        .expect("Cargo config file should always have a parent directory");

    if let Some(paths) = value.get("paths").and_then(|value| value.as_array()) {
        for path in paths {
            let Some(path) = path.as_str() else {
                anyhow::bail!(
                    "Broken Cargo config '{}': paths entries must be strings.",
                    config_path.display()
                );
            };
            let candidate = normalize_filesystem_path(&config_dir.join(path));
            let manifest_path = candidate.join("Cargo.toml");
            if !parsers::path_detected(&manifest_path)? {
                continue;
            }
            if let Some(package_name) =
                parsers::cargo_toml::package_name_from_manifest(&manifest_path)?
                && let Some(existing) = rewrites
                    .local_paths
                    .insert(package_name.clone(), candidate.clone())
                && existing != candidate
            {
                return Err(cargo_fail(
                    checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
                    format!(
                        "Cargo config '{}' declares multiple local path rewrites for crate '{}': '{}' and '{}'. sloppy-joe refuses ambiguous local provenance.",
                        config_path.display(),
                        package_name,
                        existing.display(),
                        candidate.display()
                    ),
                ));
            }
        }
    }

    if let Some(source_table) = value.get("source").and_then(|value| value.as_table()) {
        for (name, entry) in source_table
            .iter()
            .filter_map(|(name, value)| value.as_table().map(|table| (name.as_str(), table)))
        {
            if let Some(alias) = entry.get("replace-with").and_then(|value| value.as_str()) {
                rewrites
                    .source_replace_with
                    .insert(name.to_string(), alias.to_string());
            }
            if let Some(url) = entry.get("registry").and_then(|value| value.as_str()) {
                rewrites.source_definitions.insert(
                    name.to_string(),
                    CargoConfigSourceDefinition::Registry(url.to_string()),
                );
            } else if let Some(path) = entry.get("directory").and_then(|value| value.as_str()) {
                rewrites.source_definitions.insert(
                    name.to_string(),
                    CargoConfigSourceDefinition::Unsupported {
                        kind: "directory".to_string(),
                        detail: path.to_string(),
                    },
                );
            } else if let Some(path) = entry.get("local-registry").and_then(|value| value.as_str())
            {
                rewrites.source_definitions.insert(
                    name.to_string(),
                    CargoConfigSourceDefinition::Unsupported {
                        kind: "local-registry".to_string(),
                        detail: path.to_string(),
                    },
                );
            } else if let Some(url) = entry.get("git").and_then(|value| value.as_str()) {
                rewrites.source_definitions.insert(
                    name.to_string(),
                    CargoConfigSourceDefinition::Unsupported {
                        kind: "git".to_string(),
                        detail: url.to_string(),
                    },
                );
            }
        }
    }

    for rewrite in parsers::cargo_toml::collect_rewrites(config_path, &value, "patch")?
        .into_iter()
        .chain(parsers::cargo_toml::collect_rewrites(
            config_path,
            &value,
            "replace",
        )?)
    {
        rewrites.rewrite_targets.push(EffectiveCargoRewrite {
            package_name: rewrite.package_name,
            patch_scope: rewrite.patch_scope,
            replace_source: rewrite.replace_source,
            replace_version: rewrite.replace_version,
            spec: rewrite.dependency,
            base_dir: config_dir.to_path_buf(),
        });
    }

    Ok(rewrites)
}

pub(crate) fn load_repo_visible_cargo_config_rewrites(
    scan_root: &std::path::Path,
    manifest_path: &std::path::Path,
    config: &config::SloppyJoeConfig,
) -> Result<CargoConfigRewrites> {
    let manifest_dir = manifest_path
        .parent()
        .expect("Cargo.toml should always have a parent directory");
    let canonical_manifest_dir = std::fs::canonicalize(manifest_dir)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", manifest_dir.display(), err))?;
    let trusted_root = cargo_trusted_scope_root(scan_root, manifest_path, config)?;
    let repo_root = cargo_config_repo_root(&trusted_root)?;
    let mut rewrites = CargoConfigRewrites::default();

    let mut ancestors = ancestor_dirs_inclusive(&canonical_manifest_dir, &repo_root)?;
    ancestors.reverse();
    for ancestor in ancestors {
        for config_name in ["config.toml", "config"] {
            let config_path = ancestor.join(".cargo").join(config_name);
            if parsers::path_detected(&config_path)? {
                merge_cargo_config_rewrites(
                    &mut rewrites,
                    parse_cargo_config_rewrites(&config_path, &config.config_key_allow)?,
                );
            }
        }
    }

    Ok(rewrites)
}

/// Cargo reads `.cargo/config.toml` in every directory from where it runs up to the filesystem
/// root. Those inside the repository (up to its git root, even above the scan root) are
/// repo-visible; the scan root itself stands in for the repository when there is no checkout.
fn cargo_config_repo_root(trusted_root: &std::path::Path) -> Result<std::path::PathBuf> {
    let git_root = crate::cache::find_git_root(trusted_root).map_err(anyhow::Error::msg)?;
    Ok(git_root
        .filter(|git_root| trusted_root.starts_with(git_root))
        .unwrap_or_else(|| trusted_root.to_path_buf()))
}

/// Directories above the repository whose `.cargo` config Cargo also reads, outermost
/// first. `CARGO_HOME` is loaded separately, so its directory is left out.
fn cargo_config_dirs_above_repo(
    repo_root: &std::path::Path,
    cargo_home: Option<&std::path::Path>,
) -> Vec<std::path::PathBuf> {
    let mut dirs: Vec<std::path::PathBuf> = repo_root
        .ancestors()
        .skip(1)
        .filter(|dir| cargo_home != Some(dir.join(".cargo").as_path()))
        .map(std::path::Path::to_path_buf)
        .collect();
    dirs.reverse();
    dirs
}

pub(crate) fn host_local_cargo_home() -> Option<std::path::PathBuf> {
    if let Some(cargo_home) = std::env::var_os("CARGO_HOME") {
        return Some(std::path::PathBuf::from(cargo_home));
    }
    std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".cargo"))
}

pub(crate) fn load_host_local_cargo_config_rewrites_from_home(
    cargo_home: &std::path::Path,
    config: &config::SloppyJoeConfig,
) -> Result<(CargoConfigRewrites, Vec<Issue>)> {
    let mut rewrites = CargoConfigRewrites::default();
    let mut warnings = Vec::new();
    let mut found = Vec::new();

    for config_name in ["config.toml", "config"] {
        let path = cargo_home.join(config_name);
        if parsers::path_detected(&path)? {
            found.push(path.clone());
            merge_cargo_config_rewrites(
                &mut rewrites,
                parse_cargo_config_rewrites(&path, &config.config_key_allow)?,
            );
        }
    }

    if found.is_empty() {
        return Ok((rewrites, warnings));
    }

    if !config.allow_host_local_cargo_config {
        return Err(cargo_fail(
            checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
            format!(
                "Found host-local Cargo config outside the repo at {}. sloppy-joe blocks hidden machine-local Cargo provenance by default.",
                found[0].display()
            ),
        ));
    }

    warnings.push(
        Issue::new(
            "<cargo-config>",
            checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
            Severity::Warning,
        )
        .message(format!(
            "Host-local Cargo config '{}' was trusted via a local-only overlay. This run depends on machine-local Cargo provenance and may differ from CI.",
            found[0].display()
        ))
        .fix(
            "Prefer repo-visible Cargo config for reviewed provenance. Keep local-only host Cargo config relaxations out of CI.",
        ),
    );

    Ok((rewrites, warnings))
}

pub(crate) fn load_effective_cargo_config_rewrites_inner(
    scan_root: &std::path::Path,
    manifest_path: &std::path::Path,
    config: &config::SloppyJoeConfig,
    cargo_home_override: Option<&std::path::Path>,
) -> Result<(CargoConfigRewrites, Vec<Issue>)> {
    let mut rewrites = load_repo_visible_cargo_config_rewrites(scan_root, manifest_path, config)?;
    let mut warnings = Vec::new();
    let cargo_home = cargo_home_override
        .map(std::path::Path::to_path_buf)
        .or_else(host_local_cargo_home);
    let repo_root =
        cargo_config_repo_root(&cargo_trusted_scope_root(scan_root, manifest_path, config)?)?;
    let host_dirs = cargo_config_dirs_above_repo(&repo_root, cargo_home.as_deref())
        .into_iter()
        .map(|dir| dir.join(".cargo"));
    for cargo_dir in host_dirs.chain(cargo_home) {
        let (host_rewrites, host_warnings) =
            load_host_local_cargo_config_rewrites_from_home(&cargo_dir, config)?;
        ensure_additive_cargo_config_rewrites(
            &rewrites,
            &host_rewrites,
            &cargo_dir.join("config.toml"),
        )?;
        merge_cargo_config_rewrites(&mut rewrites, host_rewrites);
        warnings.extend(host_warnings);
    }
    warnings.extend(crate::config_surface::issues(&rewrites.applied_allows));
    Ok((rewrites, warnings))
}

pub(crate) fn load_effective_cargo_config_rewrites(
    scan_root: &std::path::Path,
    manifest_path: &std::path::Path,
    config: &config::SloppyJoeConfig,
) -> Result<(CargoConfigRewrites, Vec<Issue>)> {
    load_effective_cargo_config_rewrites_inner(scan_root, manifest_path, config, None)
}

#[cfg(test)]
pub(crate) fn load_effective_cargo_config_rewrites_for_test(
    scan_root: &std::path::Path,
    manifest_path: &std::path::Path,
    config: &config::SloppyJoeConfig,
    cargo_home_override: Option<std::path::PathBuf>,
) -> Result<(CargoConfigRewrites, Vec<Issue>)> {
    load_effective_cargo_config_rewrites_inner(
        scan_root,
        manifest_path,
        config,
        cargo_home_override.as_deref(),
    )
}

#[cfg(test)]
pub(crate) fn cargo_host_local_config_rewrites_for_test(
    home_dir: &std::path::Path,
    config: &config::SloppyJoeConfig,
) -> Result<(CargoConfigRewrites, Vec<Issue>)> {
    load_host_local_cargo_config_rewrites_from_home(&home_dir.join(".cargo"), config)
}

#[cfg(test)]
#[path = "config_file_tests.rs"]
mod tests;
