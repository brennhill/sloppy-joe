use super::*;

pub(super) fn prefer_trusted_python_project_inputs(specs: &mut Vec<ProjectInputSpec>) {
    let trusted_pyproject_dirs: std::collections::HashSet<std::path::PathBuf> = specs
        .iter()
        .filter(|spec| {
            matches!(
                spec.kind,
                ProjectInputKind::PyProjectPoetry | ProjectInputKind::PyProjectUv
            )
        })
        .map(|spec| spec.project_dir().to_path_buf())
        .collect();

    // A hash-locked requirements file is one install input among the others in its directory:
    // pip installs `requirements-dev.txt`, `setup.py` and `setup.cfg` just as well, so each is
    // scanned as its own project instead of being hidden behind the trusted file.
    specs.retain(|spec| {
        if !spec.kind.is_python() {
            return true;
        }
        // `requirements/*.txt` belongs to the project in the parent directory.
        let owner_dir = if parsers::requirements::is_in_requirements_directory(&spec.manifest_path)
        {
            spec.project_dir().parent().unwrap_or(spec.project_dir())
        } else {
            spec.project_dir()
        };
        if trusted_pyproject_dirs.contains(spec.project_dir())
            || trusted_pyproject_dirs.contains(owner_dir)
        {
            return matches!(
                spec.kind,
                ProjectInputKind::PyProjectPoetry | ProjectInputKind::PyProjectUv
            );
        }
        true
    });
}

pub(super) fn reject_ambiguous_python_project_inputs(specs: &[ProjectInputSpec]) -> Result<()> {
    let mut trusted_requirements_dirs = std::collections::HashSet::new();
    let mut legacy_pyproject_dirs = std::collections::HashSet::new();

    for spec in specs {
        match spec.kind {
            ProjectInputKind::PyRequirementsTrusted => {
                trusted_requirements_dirs.insert(spec.project_dir().to_path_buf());
            }
            ProjectInputKind::PyProjectLegacy => {
                legacy_pyproject_dirs.insert(spec.project_dir().to_path_buf());
            }
            _ => {}
        }
    }

    let ambiguous_dirs: Vec<_> = trusted_requirements_dirs
        .intersection(&legacy_pyproject_dirs)
        .cloned()
        .collect();
    if let Some(dir) = ambiguous_dirs.into_iter().min() {
        anyhow::bail!(
            "Ambiguous trusted Python roots in '{}': found both a legacy pyproject.toml and a fully hash-locked requirements file. sloppy-joe refuses to guess which manifest is authoritative. Fix: remove the weaker manifest from this directory, or split the trusted requirements into a separate standalone root.",
            dir.display()
        );
    }

    Ok(())
}

pub(super) fn promote_trusted_pip_tools_specs(
    scan_root: &std::path::Path,
    specs: &mut [ProjectInputSpec],
) -> Result<()> {
    for spec in specs.iter_mut() {
        if spec.kind != ProjectInputKind::PyRequirements {
            continue;
        }
        if parsers::requirements::is_hash_locked_requirements_file(&spec.manifest_path, scan_root)?
        {
            spec.kind = ProjectInputKind::PyRequirementsTrusted;
        }
    }
    Ok(())
}

pub(super) fn prune_included_requirement_specs(
    scan_root: &std::path::Path,
    specs: &mut Vec<ProjectInputSpec>,
) -> Result<()> {
    let mut included = std::collections::HashSet::new();

    for spec in specs.iter().filter(|spec| {
        matches!(
            spec.kind,
            ProjectInputKind::PyRequirements | ProjectInputKind::PyRequirementsTrusted
        )
    }) {
        for include in parsers::requirements::included_paths(&spec.manifest_path, scan_root)? {
            included.insert(include);
        }
    }

    specs.retain(|spec| {
        if !matches!(
            spec.kind,
            ProjectInputKind::PyRequirements | ProjectInputKind::PyRequirementsTrusted
        ) {
            return true;
        }
        match std::fs::canonicalize(&spec.manifest_path) {
            Ok(canonical) => !included.contains(&canonical),
            Err(_) => true,
        }
    });

    Ok(())
}
