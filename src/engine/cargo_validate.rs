use crate::*;

pub(crate) fn cargo_allowlisted_local_target(
    scan_root: &std::path::Path,
    target: &std::path::Path,
    config: &config::SloppyJoeConfig,
) -> Result<bool> {
    let canonical_target = std::fs::canonicalize(target)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", target.display(), err))?;
    let canonical_root = std::fs::canonicalize(scan_root)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", scan_root.display(), err))?;
    if canonical_target.starts_with(&canonical_root) {
        return Ok(true);
    }

    for allowlisted in config.trusted_local_paths("cargo") {
        let candidate = normalize_filesystem_path(std::path::Path::new(allowlisted));
        let Ok(canonical_allowlisted) = std::fs::canonicalize(&candidate) else {
            continue;
        };
        if canonical_allowlisted == canonical_target {
            return Ok(true);
        }
    }

    Ok(false)
}

pub(crate) fn cargo_local_target_manifest(
    scan_root: &std::path::Path,
    manifest_dir: &std::path::Path,
    path: &str,
    expected_package_name: &str,
    config: &config::SloppyJoeConfig,
) -> Result<Option<std::path::PathBuf>> {
    let candidate = normalize_filesystem_path(&manifest_dir.join(path));
    let allowlisted = match cargo_allowlisted_local_target(scan_root, &candidate, config) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if !allowlisted {
        return Ok(None);
    }

    let Ok(canonical_target) = std::fs::canonicalize(&candidate) else {
        return Ok(None);
    };
    let manifest_path = canonical_target.join("Cargo.toml");
    if !parsers::path_detected(&manifest_path)? {
        return Ok(None);
    }
    if parsers::cargo_toml::package_name_from_manifest(&manifest_path)?.as_deref()
        != Some(expected_package_name)
    {
        return Ok(None);
    }

    Ok(Some(manifest_path))
}

pub(crate) fn validate_cargo_local_target(
    scan_root: &std::path::Path,
    manifest_dir: &std::path::Path,
    dep: &parsers::cargo_toml::CargoDependencySpec,
    path: &str,
    expected_exact_version: Option<&str>,
    config: &config::SloppyJoeConfig,
) -> Result<()> {
    let candidate = normalize_filesystem_path(&manifest_dir.join(path));
    let allowlisted = cargo_allowlisted_local_target(scan_root, &candidate, config)?;
    if !allowlisted {
        return Err(cargo_fail(
            checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
            format!(
                "'{}' resolves to '{}' which is outside the scan root and not exactly allowlisted.",
                dep.package_name,
                candidate.display()
            ),
        ));
    }

    let canonical_target = std::fs::canonicalize(&candidate).map_err(|err| {
        cargo_fail(
            checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
            format!(
                "'{}' points to '{}' but that target is missing or unreadable: {}.",
                dep.package_name,
                candidate.display(),
                err
            ),
        )
    })?;

    let manifest_path = canonical_target.join("Cargo.toml");
    if !parsers::path_detected(&manifest_path)? {
        return Err(cargo_fail(
            checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
            format!(
                "'{}' points to '{}' which is not a valid Cargo crate directory.",
                dep.package_name,
                canonical_target.display()
            ),
        ));
    }

    let manifest_value = toml::from_str::<toml::Value>(&parsers::read_file_limited(
        &manifest_path,
        parsers::MAX_MANIFEST_BYTES,
    )?)
    .map_err(|err| {
        cargo_fail(
            checks::names::RESOLUTION_PARSE_FAILED,
            format!(
                "Failed to parse local Cargo target '{}': {}.",
                manifest_path.display(),
                err
            ),
        )
    })?;

    if manifest_value
        .get("package")
        .and_then(|value| value.as_table())
        .is_none()
    {
        return Err(cargo_fail(
            checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
            format!(
                "'{}' points to '{}' but that target does not declare a [package] crate.",
                dep.package_name,
                canonical_target.display()
            ),
        ));
    }

    let actual_name = manifest_value
        .get("package")
        .and_then(|value| value.as_table())
        .and_then(|package| package.get("name"))
        .and_then(|value| value.as_str());
    if actual_name != Some(dep.package_name.as_str()) {
        return Err(cargo_fail(
            checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
            format!(
                "'{}' points to '{}' but that target declares package '{}' instead of '{}'.",
                dep.package_name,
                canonical_target.display(),
                actual_name.unwrap_or("<missing>"),
                dep.package_name
            ),
        ));
    }

    let actual_version = manifest_value
        .get("package")
        .and_then(|value| value.as_table())
        .and_then(|package| package.get("version"))
        .and_then(|value| value.as_str());
    if let Some(expected_version) = expected_exact_version
        && actual_version != Some(expected_version)
    {
        return Err(cargo_fail(
            checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
            format!(
                "'{}' points to '{}' but that target declares version '{}' instead of '{}'.",
                dep.package_name,
                canonical_target.display(),
                actual_version.unwrap_or("<missing>"),
                expected_version
            ),
        ));
    }

    Ok(())
}

pub(crate) fn validate_cargo_registry_source(
    dep: &parsers::cargo_toml::CargoDependencySpec,
    expected_exact_version: Option<&str>,
    alias: Option<&str>,
    source: &str,
    lockfile: &toml::Value,
    config: &config::SloppyJoeConfig,
) -> Result<()> {
    let trusted = if let Some(alias) = alias {
        config
            .trusted_registries("cargo")
            .iter()
            .any(|entry| entry.name == alias && entry.source == source)
    } else {
        source == "registry+https://github.com/rust-lang/crates.io-index"
            || config
                .trusted_registries("cargo")
                .iter()
                .any(|entry| entry.source == source)
    };

    if !trusted {
        return Err(cargo_fail(
            checks::names::RESOLUTION_UNTRUSTED_REGISTRY_SOURCE,
            format!(
                "'{}' uses registry source '{}' which is not trusted by config.",
                dep.package_name, source
            ),
        ));
    }

    let exact_version = expected_exact_version
        .map(str::to_string)
        .or_else(|| cargo_dependency_exact_version(dep));
    let matched = cargo_lockfile_entries(lockfile).into_iter().any(|package| {
        let same_name =
            package.get("name").and_then(|value| value.as_str()) == Some(dep.package_name.as_str());
        let same_source = package.get("source").and_then(|value| value.as_str()) == Some(source);
        let version_ok = exact_version.as_ref().is_none_or(|expected| {
            package
                .get("version")
                .and_then(|value| value.as_str())
                .is_some_and(|actual| cargo_registry_versions_match(expected, actual))
        });
        same_name && same_source && version_ok
    });

    if !matched {
        return Err(cargo_fail(
            checks::names::RESOLUTION_MISSING_LOCKFILE_ENTRY,
            format!(
                "Cargo.lock did not prove a trusted registry entry for '{}' with source '{}'.",
                dep.package_name, source
            ),
        ));
    }

    Ok(())
}

pub(crate) fn cargo_registry_versions_match(expected: &str, actual: &str) -> bool {
    expected == actual || strip_cargo_build_metadata(expected) == strip_cargo_build_metadata(actual)
}

pub(crate) fn strip_cargo_build_metadata(version: &str) -> &str {
    version.split_once('+').map_or(version, |(base, _)| base)
}

pub(crate) fn validate_cargo_git_source(
    dep: &parsers::cargo_toml::CargoDependencySpec,
    expected_exact_version: Option<&str>,
    source: &parsers::cargo_toml::CargoSourceSpec,
    lockfile: &toml::Value,
    config: &config::SloppyJoeConfig,
) -> Result<Issue> {
    let parsers::cargo_toml::CargoSourceSpec::Git {
        url,
        rev,
        branch,
        tag,
    } = source
    else {
        unreachable!("validate_cargo_git_source must only be called for git specs");
    };
    if config.cargo_git_policy != config::CargoGitPolicy::WarnPinned {
        return Err(cargo_fail(
            checks::names::RESOLUTION_UNTRUSTED_GIT_SOURCE,
            format!(
                "'{}' uses git source '{}' but cargo_git_policy blocks git dependencies by default.",
                dep.package_name, url
            ),
        ));
    }
    if branch.is_some() || tag.is_some() || rev.is_none() {
        return Err(cargo_fail(
            checks::names::RESOLUTION_UNTRUSTED_GIT_SOURCE,
            format!(
                "'{}' must pin git dependencies to an exact rev; branch, tag, or unspecified refs are not allowed.",
                dep.package_name
            ),
        ));
    }
    let rev = rev.as_deref().expect("checked above");
    let is_exact_rev = rev.len() == 40
        && rev
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    if !is_exact_rev {
        return Err(cargo_fail(
            checks::names::RESOLUTION_UNTRUSTED_GIT_SOURCE,
            format!(
                "'{}' uses git rev '{}' which is not a full lowercase 40-character commit SHA.",
                dep.package_name, rev
            ),
        ));
    }
    if !config
        .trusted_git_sources("cargo")
        .iter()
        .any(|trusted| trusted.trim() == url.trim())
    {
        return Err(cargo_fail(
            checks::names::RESOLUTION_UNTRUSTED_GIT_SOURCE,
            format!(
                "'{}' uses git source '{}' which is not allowlisted.",
                dep.package_name, url
            ),
        ));
    }

    let expected_source = format!("git+{url}?rev={rev}#{rev}");
    let matched = cargo_lockfile_entries(lockfile).into_iter().any(|package| {
        package.get("name").and_then(|value| value.as_str()) == Some(dep.package_name.as_str())
            && package.get("source").and_then(|value| value.as_str())
                == Some(expected_source.as_str())
            && expected_exact_version.is_none_or(|expected| {
                package.get("version").and_then(|value| value.as_str()) == Some(expected)
            })
    });
    if !matched {
        return Err(cargo_fail(
            checks::names::RESOLUTION_UNTRUSTED_GIT_SOURCE,
            format!(
                "Cargo.lock did not prove the exact git repo and commit for '{}' as '{}'.",
                dep.package_name, expected_source
            ),
        ));
    }

    Ok(
        Issue::new(
            &dep.package_name,
            checks::names::RESOLUTION_REDUCED_CONFIDENCE_GIT,
            Severity::Warning,
        )
        .message(format!(
            "'{}' uses an allowlisted git dependency pinned to exact rev {} from '{}'. sloppy-joe continues in reduced-confidence mode because git provenance is outside normal registry trust.",
            dep.package_name, rev, url
        ))
        .fix(
            "Prefer a reviewed registry release when available. If git is required, keep the repo URL and exact revision under explicit review.",
        ),
    )
}

pub(crate) fn validate_cargo_dependency_spec(
    scan_root: &std::path::Path,
    manifest_dir: &std::path::Path,
    dep: &parsers::cargo_toml::CargoDependencySpec,
    expected_exact_version: Option<&str>,
    config: &config::SloppyJoeConfig,
    lockfile: &toml::Value,
) -> Result<Vec<Issue>> {
    match &dep.source {
        parsers::cargo_toml::CargoSourceSpec::CratesIo => validate_cargo_registry_source(
            dep,
            expected_exact_version,
            None,
            "registry+https://github.com/rust-lang/crates.io-index",
            lockfile,
            config,
        )
        .map(|_| Vec::new()),
        parsers::cargo_toml::CargoSourceSpec::Path(path) => {
            validate_cargo_local_target(
                scan_root,
                manifest_dir,
                dep,
                path,
                expected_exact_version,
                config,
            )?;
            Ok(Vec::new())
        }
        parsers::cargo_toml::CargoSourceSpec::RegistryAlias(alias) => {
            let Some(source) = config
                .trusted_registries("cargo")
                .iter()
                .find(|entry| entry.name == *alias)
                .map(|entry| entry.source.as_str())
            else {
                return Err(cargo_fail(
                    checks::names::RESOLUTION_UNTRUSTED_REGISTRY_SOURCE,
                    format!(
                        "'{}' uses registry alias '{}' which is not trusted by config.",
                        dep.package_name, alias
                    ),
                ));
            };
            validate_cargo_registry_source(
                dep,
                expected_exact_version,
                Some(alias),
                source,
                lockfile,
                config,
            )?;
            Ok(Vec::new())
        }
        parsers::cargo_toml::CargoSourceSpec::RegistryIndex(source) => {
            validate_cargo_registry_source(
                dep,
                expected_exact_version,
                None,
                source,
                lockfile,
                config,
            )?;
            Ok(Vec::new())
        }
        parsers::cargo_toml::CargoSourceSpec::Git { .. } => {
            validate_cargo_git_source(dep, expected_exact_version, &dep.source, lockfile, config)
                .map(|issue| vec![issue])
        }
        parsers::cargo_toml::CargoSourceSpec::Workspace => Err(cargo_fail(
            checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
            format!(
                "'{}' uses workspace = true but no in-scope workspace dependency was resolved.",
                dep.package_name
            ),
        )),
    }
}

pub(crate) fn validate_cargo_effective_rewrite(
    scan_root: &std::path::Path,
    rewrite: &EffectiveCargoRewrite,
    config: &config::SloppyJoeConfig,
    lockfile: &toml::Value,
) -> Result<Vec<Issue>> {
    let exact_version = cargo_dependency_exact_version(&rewrite.spec);
    let expected_version = rewrite
        .replace_version
        .as_deref()
        .or(exact_version.as_deref());
    match &rewrite.spec.source {
        parsers::cargo_toml::CargoSourceSpec::Path(path) => {
            validate_cargo_local_target(
                scan_root,
                &rewrite.base_dir,
                &rewrite.spec,
                path,
                expected_version,
                config,
            )?;
            Ok(Vec::new())
        }
        _ => validate_cargo_dependency_spec(
            scan_root,
            &rewrite.base_dir,
            &rewrite.spec,
            expected_version,
            config,
            lockfile,
        ),
    }
}

pub(crate) fn validate_cargo_source_policy(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    config: &config::SloppyJoeConfig,
) -> Result<Vec<Issue>> {
    let manifest = parsers::cargo_toml::parse_manifest_file(&spec.manifest_path)?;
    let authoritative_lockfile =
        authoritative_cargo_lockfile_path(scan_root, &spec.manifest_path, config)?;
    ensure_lockfile_readable(
        &authoritative_lockfile,
        spec.kind.missing_lockfile_help().unwrap(),
    )?;
    let lockfile = cargo_lockfile_value(&authoritative_lockfile)?;
    let (cargo_config_rewrites, config_warnings) =
        load_effective_cargo_config_rewrites(scan_root, &spec.manifest_path, config)?;
    let rewrites =
        collect_effective_cargo_rewrites(scan_root, &manifest, config, &cargo_config_rewrites)?;
    let mut warnings = config_warnings;

    for dep in resolve_cargo_effective_dependencies(scan_root, &manifest, config)? {
        let dep_warnings = validate_cargo_dependency_spec(
            scan_root,
            &dep.base_dir,
            &dep.spec,
            dep.expected_exact_version.as_deref(),
            config,
            &lockfile,
        )?;
        warnings.extend(dep_warnings);
    }

    for rewrite in rewrites
        .into_iter()
        .filter(|rewrite| cargo_rewrite_matches_lockfile_scope(rewrite, &lockfile, config))
    {
        warnings.extend(validate_cargo_effective_rewrite(
            scan_root, &rewrite, config, &lockfile,
        )?);
    }

    Ok(warnings)
}
