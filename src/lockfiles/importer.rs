use super::*;

pub(crate) fn first_existing(project_dir: &Path, names: &[&str]) -> Option<PathBuf> {
    names.iter().find_map(|name| {
        let path = project_dir.join(name);
        match crate::parsers::path_detected(&path) {
            Ok(true) => Some(path),
            _ => None,
        }
    })
}

pub(crate) fn is_pnpm_lockfile_path(path: &Path) -> bool {
    path.file_name().and_then(|name| name.to_str()) == Some("pnpm-lock.yaml")
}

pub(crate) fn is_bun_lockfile_path(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("bun.lock" | "bun.lockb")
    )
}

pub(crate) fn is_yarn_lockfile_path(path: &Path) -> bool {
    path.file_name().and_then(|name| name.to_str()) == Some("yarn.lock")
}

pub(crate) fn pnpm_importer_key(project_dir: &Path, lockfile_path: &Path) -> Result<String> {
    let canonical_project_dir = std::fs::canonicalize(project_dir)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", project_dir.display(), err))?;
    let lockfile_dir = lockfile_path
        .parent()
        .expect("lockfile paths should always have a parent directory");
    let canonical_lockfile_dir = std::fs::canonicalize(lockfile_dir)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", lockfile_dir.display(), err))?;
    if canonical_project_dir == canonical_lockfile_dir {
        return Ok(".".to_string());
    }
    let relative = canonical_project_dir
        .strip_prefix(&canonical_lockfile_dir)
        .map_err(|_| {
            anyhow::anyhow!(
                "Project '{}' is outside pnpm lockfile root '{}'.",
                canonical_project_dir.display(),
                canonical_lockfile_dir.display()
            )
        })?;
    let key = relative
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/");
    if key.is_empty() {
        anyhow::bail!(
            "Could not derive pnpm importer key for '{}' relative to '{}'.",
            canonical_project_dir.display(),
            canonical_lockfile_dir.display()
        );
    }
    Ok(key)
}

pub(crate) fn js_importer_key(project_dir: &Path, lockfile_path: &Path) -> Result<String> {
    let canonical_project_dir = std::fs::canonicalize(project_dir)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", project_dir.display(), err))?;
    let lockfile_dir = lockfile_path
        .parent()
        .expect("lockfile paths should always have a parent directory");
    let canonical_lockfile_dir = std::fs::canonicalize(lockfile_dir)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", lockfile_dir.display(), err))?;
    if canonical_project_dir == canonical_lockfile_dir {
        return Ok(String::new());
    }
    let relative = canonical_project_dir
        .strip_prefix(&canonical_lockfile_dir)
        .map_err(|_| {
            anyhow::anyhow!(
                "Project '{}' is outside JS lockfile root '{}'.",
                canonical_project_dir.display(),
                canonical_lockfile_dir.display()
            )
        })?;
    let key = relative
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/");
    if key.is_empty() {
        anyhow::bail!(
            "Could not derive JS workspace key for '{}' relative to '{}'.",
            canonical_project_dir.display(),
            canonical_lockfile_dir.display()
        );
    }
    Ok(key)
}

pub(crate) fn add_manifest_exact_fallbacks(result: &mut ResolutionResult, deps: &[Dependency]) {
    for dep in deps {
        add_manifest_exact_fallback(result, dep);
    }
}

pub(crate) fn add_manifest_exact_fallback(result: &mut ResolutionResult, dep: &Dependency) {
    if let Some(exact_version) = dep.exact_version() {
        result.exact_versions.insert(
            ResolutionKey::from(dep),
            ResolvedVersion {
                version: exact_version,
                source: ResolutionSource::ManifestExact,
            },
        );
    }
}
