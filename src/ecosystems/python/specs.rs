use super::*;

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
