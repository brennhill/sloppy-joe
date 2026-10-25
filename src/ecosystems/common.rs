use super::*;

pub(super) fn broken_manifest(spec: &ProjectInputSpec, err: anyhow::Error) -> anyhow::Error {
    crate::remedy::rewrap(err, |err| {
        format!("Broken manifest '{}': {}", spec.manifest_path.display(), err)
    })
}

/// Require a readable lockfile at `lockfile`, naming the kind's remedy when it is missing.
pub(super) fn ensure_kind_lockfile(spec: &ProjectInputSpec, lockfile: &Path) -> Result<()> {
    let descriptor = spec.kind.descriptor();
    let (LockfilePolicy::Required, Some(remedy)) =
        (descriptor.lockfile, descriptor.missing_lockfile_remedy)
    else {
        anyhow::bail!(
            "Internal error: {} projects have no required lockfile to check",
            descriptor.manifest_label
        );
    };
    ensure_lockfile_readable(lockfile, remedy)
}

/// A lockfile that pins packages while the manifest declares none means the declarations were missed.
pub(super) fn ensure_no_locked_packages_without_declarations(
    spec: &ProjectInputSpec,
    deps: &[Dependency],
) -> Result<()> {
    if !deps.is_empty() {
        return Ok(());
    }
    let locked = lockfiles::LockfileData::parse_for_kind_with_lockfile_and_profile(
        spec.project_dir(),
        spec.kind.lockfile_kind(),
        deps,
        spec.lockfile_path_override.as_deref(),
        None,
    )?;
    if !locked.transitive_deps.is_empty() {
        anyhow::bail!(
            "Scan not supported: '{}' has locked packages but no supported direct dependency declarations",
            spec.manifest_path.display()
        );
    }
    Ok(())
}

/// The lockfile must parse as JSON.
pub(super) fn read_json_lockfile(path: &Path) -> Result<serde_json::Value> {
    let content = parsers::read_file_limited(path, parsers::MAX_MANIFEST_BYTES)?;
    serde_json::from_str::<serde_json::Value>(&content).map_err(|err| {
        anyhow::anyhow!(
            "Broken lockfile '{}': failed to parse JSON: {}",
            path.display(),
            err
        )
    })
}

/// The lockfile the descriptor names for this kind, next to its manifest.
pub(super) fn named_lockfile(spec: &ProjectInputSpec) -> Option<PathBuf> {
    spec.kind
        .descriptor()
        .lockfile_name
        .map(|name| spec.manifest_path.with_file_name(name))
}

/// The kind among `kinds` whose descriptor lists the manifest's exact file name.
pub(super) fn kind_for_file_name(
    kinds: &[ProjectInputKind],
    path: &Path,
) -> Option<ProjectInputKind> {
    let name = path.file_name()?.to_str()?;
    kinds
        .iter()
        .copied()
        .find(|kind| kind.descriptor().manifest_file_names.contains(&name))
}

pub(crate) fn normalize_filesystem_path(path: &std::path::Path) -> std::path::PathBuf {
    let mut normalized = std::path::PathBuf::new();

    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                normalized.push(component.as_os_str())
            }
            std::path::Component::Normal(part) => normalized.push(part),
        }
    }

    normalized
}

pub(crate) fn workspace_patterns_match<'a>(
    root_dir: &std::path::Path,
    candidate_dir: &std::path::Path,
    mut patterns: impl Iterator<Item = &'a str>,
) -> bool {
    let Ok(relative) = candidate_dir.strip_prefix(root_dir) else {
        return false;
    };
    let path_parts = relative
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if path_parts.is_empty() {
        return false;
    }

    patterns.any(|pattern| workspace_pattern_matches_parts(pattern, &path_parts))
}

pub(crate) fn workspace_pattern_matches_parts(pattern: &str, path_parts: &[String]) -> bool {
    let pattern_parts = pattern
        .trim()
        .trim_start_matches("./")
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    workspace_pattern_parts_match(&pattern_parts, path_parts)
}

pub(crate) fn workspace_pattern_parts_match(pattern_parts: &[&str], path_parts: &[String]) -> bool {
    match pattern_parts.split_first() {
        None => path_parts.is_empty(),
        Some((&"**", remaining_patterns)) => (0..=path_parts.len())
            .any(|skip| workspace_pattern_parts_match(remaining_patterns, &path_parts[skip..])),
        Some((&segment_pattern, remaining_patterns)) => {
            let Some((path_part, remaining_path)) = path_parts.split_first() else {
                return false;
            };
            wildcard_segment_matches(segment_pattern, path_part)
                && workspace_pattern_parts_match(remaining_patterns, remaining_path)
        }
    }
}

pub(crate) fn wildcard_segment_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    match pattern.split_once('*') {
        None => pattern == value,
        Some((prefix, suffix)) => {
            if !value.starts_with(prefix) || !value.ends_with(suffix) {
                return false;
            }
            value.len() >= prefix.len() + suffix.len()
        }
    }
}

pub(crate) fn ancestor_dirs_inclusive(
    start: &std::path::Path,
    root: &std::path::Path,
) -> Result<Vec<std::path::PathBuf>> {
    if !start.starts_with(root) {
        anyhow::bail!(
            "Path '{}' is outside scan root '{}'.",
            start.display(),
            root.display()
        );
    }

    let mut dirs = Vec::new();
    let mut current = start.to_path_buf();
    loop {
        dirs.push(current.clone());
        if current == root {
            break;
        }
        current = current
            .parent()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Failed to find ancestor path from '{}' back to scan root '{}'.",
                    start.display(),
                    root.display()
                )
            })?
            .to_path_buf();
    }

    Ok(dirs)
}

pub(crate) fn first_existing_lockfile(
    project_dir: &std::path::Path,
    candidates: &[&str],
) -> Option<std::path::PathBuf> {
    candidates.iter().find_map(|candidate| {
        let path = project_dir.join(candidate);
        match parsers::path_detected(&path) {
            Ok(true) => Some(path),
            _ => None,
        }
    })
}

/// Require a readable, non-empty lockfile at `path`. A missing or empty lockfile is a
/// [`crate::remedy::LockfileProblem`] carrying `remedy`; an unreadable one is not, since
/// regenerating it would discard what cannot be read.
pub(crate) fn ensure_lockfile_readable(
    path: &std::path::Path,
    remedy: &'static crate::remedy::Remedy,
) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(crate::remedy::problem(
                remedy,
                format!("Required lockfile '{}' is missing.", path.display()),
            ));
        }
        Err(err) => anyhow::bail!(
            "Required lockfile '{}' could not be inspected: {}. {}",
            path.display(),
            err,
            remedy.fix_text()
        ),
        Ok(_) => {}
    }
    let content = parsers::read_file_limited(path, parsers::MAX_MANIFEST_BYTES).map_err(|err| {
        anyhow::anyhow!(
            "Required lockfile '{}' is unreadable: {}. {}",
            path.display(),
            err,
            remedy.fix_text()
        )
    })?;
    if content.trim().is_empty() {
        return Err(crate::remedy::problem(
            remedy,
            format!("Required lockfile '{}' is empty.", path.display()),
        ));
    }
    Ok(())
}

/// Require that every lockfile among `candidates` in `project_dir` that exists is readable and
/// that one exists; a missing one carries `remedy` (see [`ensure_lockfile_readable`]).
pub(crate) fn ensure_one_lockfile_readable(
    project_dir: &std::path::Path,
    candidates: &[&str],
    remedy: &'static crate::remedy::Remedy,
) -> Result<()> {
    let mut found_readable = false;
    for candidate in candidates {
        let path = project_dir.join(candidate);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES).map_err(|err| {
                    anyhow::anyhow!(
                        "Required lockfile '{}' is unreadable: {}. {}",
                        path.display(),
                        err,
                        remedy.fix_text()
                    )
                })?;
                found_readable = true;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "Required lockfile '{}' could not be inspected: {}. {}",
                    path.display(),
                    err,
                    remedy.fix_text()
                ));
            }
        }
    }
    if found_readable {
        return Ok(());
    }
    Err(crate::remedy::problem(
        remedy,
        format!(
            "Required lockfile '{}' is missing.",
            candidates.join("' or '")
        ),
    ))
}

/// Lockfile data for the checks, read from the project's own lockfile.
pub(super) fn read_lockfile_data(
    project: &ParsedProject,
    deps: &[Dependency],
    python_profile: Option<&lockfiles::PythonLockfileProfile>,
) -> Result<lockfiles::LockfileData> {
    lockfiles::LockfileData::parse_for_kind_with_lockfile_and_profile(
        project.spec.project_dir(),
        project.spec.kind.lockfile_kind(),
        deps,
        project.spec.lockfile_path_override.as_deref(),
        python_profile,
    )
}
