use crate::*;

pub(crate) fn cargo_trusted_scope_root(
    scan_root: &std::path::Path,
    manifest_path: &std::path::Path,
    config: &config::SloppyJoeConfig,
) -> Result<std::path::PathBuf> {
    let canonical_root = std::fs::canonicalize(scan_root)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", scan_root.display(), err))?;
    let manifest_dir = manifest_path
        .parent()
        .expect("Cargo.toml should always have a parent directory");
    let canonical_manifest_dir = std::fs::canonicalize(manifest_dir)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", manifest_dir.display(), err))?;

    if canonical_manifest_dir.starts_with(&canonical_root) {
        return Ok(canonical_root);
    }

    if cargo_allowlisted_local_target(scan_root, &canonical_manifest_dir, config)? {
        return Ok(canonical_manifest_dir);
    }

    anyhow::bail!(
        "Path '{}' is outside scan root '{}' and not exactly allowlisted for Cargo local provenance.",
        canonical_manifest_dir.display(),
        canonical_root.display()
    );
}

pub(crate) fn find_in_scope_cargo_workspace_root(
    scan_root: &std::path::Path,
    manifest_path: &std::path::Path,
    config: &config::SloppyJoeConfig,
) -> Result<Option<parsers::cargo_toml::CargoManifest>> {
    let manifest_dir = manifest_path
        .parent()
        .expect("Cargo.toml should always have a parent directory");
    let canonical_manifest_dir = std::fs::canonicalize(manifest_dir)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", manifest_dir.display(), err))?;
    let trusted_root = cargo_trusted_scope_root(scan_root, manifest_path, config)?;
    ensure_no_cargo_workspace_above_scan_root(
        manifest_path,
        &canonical_manifest_dir,
        &trusted_root,
    )?;

    for ancestor in ancestor_dirs_inclusive(&canonical_manifest_dir, &trusted_root)? {
        let candidate = ancestor.join("Cargo.toml");
        if !parsers::path_detected(&candidate)? {
            continue;
        }
        let manifest = parsers::cargo_toml::parse_manifest_file(&candidate)?;
        if manifest.has_workspace
            && cargo_workspace_contains_manifest(&manifest, &canonical_manifest_dir)?
        {
            return Ok(Some(manifest));
        }
    }

    Ok(None)
}

/// Cargo resolves a member against the workspace root above it, using that root's
/// `Cargo.lock` and `.cargo/config.toml`. Scanning only the member directory would check a
/// different graph than cargo installs, so that layout is refused.
pub(crate) fn ensure_no_cargo_workspace_above_scan_root(
    manifest_path: &std::path::Path,
    canonical_manifest_dir: &std::path::Path,
    trusted_root: &std::path::Path,
) -> Result<()> {
    if parsers::cargo_toml::parse_manifest_file(manifest_path)?.has_workspace {
        return Ok(());
    }
    let Some(git_root) = crate::cache::find_git_root(trusted_root).map_err(anyhow::Error::msg)?
    else {
        return Ok(());
    };
    if git_root == trusted_root || !trusted_root.starts_with(&git_root) {
        return Ok(());
    }
    let Some(start) = trusted_root.parent() else {
        return Ok(());
    };
    for ancestor in ancestor_dirs_inclusive(start, &git_root)? {
        let candidate = ancestor.join("Cargo.toml");
        if !parsers::path_detected(&candidate)? {
            continue;
        }
        let manifest = parsers::cargo_toml::parse_manifest_file(&candidate)?;
        if manifest.has_workspace
            && cargo_workspace_contains_manifest(&manifest, canonical_manifest_dir)?
        {
            anyhow::bail!(
                "Cargo manifest '{}' belongs to the workspace at '{}', which is above the scan root. Cargo uses that workspace's Cargo.lock and .cargo/config.toml, so scanning only this directory would check a different dependency graph than cargo installs. Fix: scan the workspace root.",
                manifest_path.display(),
                candidate.display()
            );
        }
    }
    Ok(())
}

pub(crate) fn cargo_workspace_contains_manifest(
    workspace: &parsers::cargo_toml::CargoManifest,
    canonical_manifest_dir: &std::path::Path,
) -> Result<bool> {
    let workspace_dir = workspace
        .manifest_path
        .parent()
        .expect("workspace manifest should always have a parent directory");
    let canonical_workspace_dir = std::fs::canonicalize(workspace_dir)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", workspace_dir.display(), err))?;

    if canonical_manifest_dir == canonical_workspace_dir {
        return Ok(true);
    }
    if !canonical_manifest_dir.starts_with(&canonical_workspace_dir) {
        return Ok(false);
    }
    if workspace.workspace_members.is_empty() {
        return Ok(false);
    }

    let excluded = workspace_patterns_match(
        &canonical_workspace_dir,
        canonical_manifest_dir,
        workspace.workspace_exclude.iter().map(String::as_str),
    );
    if excluded {
        return Ok(false);
    }

    Ok(workspace_patterns_match(
        &canonical_workspace_dir,
        canonical_manifest_dir,
        workspace.workspace_members.iter().map(String::as_str),
    ))
}

pub(crate) fn authoritative_cargo_lockfile_path(
    scan_root: &std::path::Path,
    manifest_path: &std::path::Path,
    config: &config::SloppyJoeConfig,
) -> Result<std::path::PathBuf> {
    if let Some(workspace_root) =
        find_in_scope_cargo_workspace_root(scan_root, manifest_path, config)?
    {
        let workspace_dir = workspace_root
            .manifest_path
            .parent()
            .expect("workspace manifest should always have a parent directory");
        return Ok(workspace_dir.join("Cargo.lock"));
    }

    Ok(manifest_path
        .parent()
        .expect("Cargo.toml should always have a parent directory")
        .join("Cargo.lock"))
}

pub(crate) fn cargo_lockfile_value(lockfile_path: &std::path::Path) -> Result<toml::Value> {
    let content = parsers::read_file_limited(lockfile_path, parsers::MAX_MANIFEST_BYTES)?;
    toml::from_str::<toml::Value>(&content).map_err(|err| {
        anyhow::anyhow!(
            "Broken lockfile '{}': failed to parse TOML: {}",
            lockfile_path.display(),
            err
        )
    })
}

pub(crate) fn cargo_lockfile_entries(lockfile: &toml::Value) -> Vec<&toml::value::Table> {
    lockfile
        .get("package")
        .and_then(|value| value.as_array())
        .into_iter()
        .flat_map(|packages| packages.iter())
        .filter_map(|package| package.as_table())
        .collect()
}

pub(crate) fn cargo_issue_message_prefix(check: &str) -> &'static str {
    match check {
        checks::names::RESOLUTION_LOCAL_DEPENDENCY_SOURCE => "Cargo local dependency source",
        checks::names::RESOLUTION_UNTRUSTED_REGISTRY_SOURCE => "Cargo registry source",
        checks::names::RESOLUTION_UNTRUSTED_GIT_SOURCE => "Cargo git source",
        checks::names::RESOLUTION_BLOCKED_PROVENANCE_REWRITE => "Cargo provenance rewrite",
        _ => "Cargo dependency source",
    }
}

pub(crate) fn cargo_fail(check: &str, message: impl Into<String>) -> anyhow::Error {
    anyhow::anyhow!("{}: {}", cargo_issue_message_prefix(check), message.into())
}

pub(crate) fn cargo_dependency_exact_version(
    spec: &parsers::cargo_toml::CargoDependencySpec,
) -> Option<String> {
    version::exact_version(spec.version.as_deref()?, Ecosystem::Cargo)
}
