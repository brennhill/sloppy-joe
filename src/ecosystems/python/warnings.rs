use super::*;

/// When a Pipfile.lock is committed, reconcile it with the Pipfile and check
/// every locked entry's provenance before anything is scanned.
pub(crate) fn validate_pipfile_lockfile(
    spec: &ProjectInputSpec,
    config: &config::SloppyJoeConfig,
) -> Result<()> {
    let Some(path) = selected_lockfile_path(spec) else {
        return Ok(());
    };
    let lock = lockfiles::pipfile_lock::read_lockfile_at(&path)?;
    let pipfile = parsers::pipfile::parse_file_categories(&spec.manifest_path)?;
    lockfiles::pipfile_lock::validate(&lock, &pipfile, &path, config)
}

pub(crate) fn python_legacy_warning(spec: &ProjectInputSpec) -> Issue {
    Issue::new(
        spec.manifest_path.display().to_string(),
        checks::names::RESOLUTION_PYTHON_LEGACY_MANIFEST,
        Severity::Warning,
    )
    .message(format!(
        "Python manifest '{}' uses the legacy {} workflow. sloppy-joe will scan it, but Poetry with poetry.lock and uv with uv.lock provide the strongest trusted Python lock guarantees.",
        spec.manifest_path.display(),
        spec.kind.manifest_label()
    ))
    .fix("Migrate this project to Poetry or uv and commit the authoritative lockfile. Legacy Python manifests remain allowed, but every run will warn until the project moves to a fully trusted Python workflow.")
}

pub(crate) fn hash_locked_requirements_reduced_confidence_warning(
    spec: &ProjectInputSpec,
) -> Issue {
    Issue::new(
        spec.manifest_path.display().to_string(),
        checks::names::RESOLUTION_PYTHON_HASH_LOCKED_REQUIREMENTS,
        Severity::Warning,
    )
    .message(format!(
        "Hash-locked pip-tools requirements in '{}' provide exact pins and hashes, but sloppy-joe cannot prove the package index provenance exactly because pip source selection can also come from pip config, environment variables, and unsupported flags outside the file.",
        spec.manifest_path.display()
    ))
    .fix(
        "Prefer Poetry or uv for fully trusted Python lock enforcement. If you stay on pip-tools, keep the file fully hash-locked and review index configuration separately.",
    )
}

pub(crate) fn validate_hash_locked_requirements_provenance(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    config: &config::SloppyJoeConfig,
) -> Result<bool> {
    let provenance =
        parsers::requirements::ensure_trusted_indexes(&spec.manifest_path, scan_root, config)?;
    Ok(provenance.primary_index.is_some())
}

pub(crate) fn trusted_python_preference_warnings(spec: &ProjectInputSpec) -> Result<Vec<Issue>> {
    let mut warnings = Vec::new();
    let (tool_name, fix) = match spec.kind {
        ProjectInputKind::PyProjectPoetry => (
            "Poetry",
            "Remove or stop relying on the legacy Python manifest, and keep pyproject.toml + poetry.lock as the single trusted dependency source for this project.",
        ),
        ProjectInputKind::PyProjectUv => (
            "uv",
            "Remove or stop relying on the legacy Python manifest, and keep pyproject.toml + uv.lock as the single trusted dependency source for this project.",
        ),
        _ => return Ok(warnings),
    };
    for candidate in legacy_python_manifest_paths(spec.project_dir())? {
        warnings.push(
            Issue::new(
                candidate.display().to_string(),
                checks::names::RESOLUTION_PYTHON_LEGACY_MANIFEST,
                Severity::Warning,
            )
            .message(format!(
                "Ignoring legacy Python manifest '{}' because '{}' is a {} project. sloppy-joe prefers the trusted {} workflow as the source of truth for this directory.",
                candidate.display(),
                spec.manifest_path.display(),
                tool_name,
                tool_name
            ))
            .fix(fix),
        );
    }
    Ok(warnings)
}

pub(crate) fn active_python_profile(
    opts: &ScanOptions<'_>,
) -> parsers::python_scope::PythonProfile {
    let mut profile = parsers::python_scope::PythonProfile::runtime_for_current_host();
    if let Some(platform) = &opts.python_platform {
        profile.target_platform = platform.clone();
        profile.explicit_selection = true;
    }
    if let Some(arch) = &opts.python_arch {
        profile.target_arch = arch.clone();
        profile.explicit_selection = true;
    }
    if let Some(version) = &opts.python_version {
        profile.python_version = Some(version.clone());
        profile.python_full_version = Some(parsers::python_scope::normalize_python_full_version(
            version,
        ));
        profile.explicit_selection = true;
    }
    // Every group and extra is scanned unless the operator narrows the selection explicitly.
    if !opts.python_groups.is_empty() {
        profile.narrow_groups(&opts.python_groups);
    }
    if !opts.python_extras.is_empty() {
        profile.narrow_extras(&opts.python_extras);
    }
    profile
}

pub(crate) fn active_python_lockfile_profile(
    opts: &ScanOptions<'_>,
    root_extras: &PythonRootExtras,
) -> lockfiles::PythonLockfileProfile {
    lockfiles::PythonLockfileProfile {
        environment: active_python_profile(opts),
        root_extras: root_extras.clone(),
    }
}

pub(crate) fn implicit_runtime_profile_warning(spec: &ProjectInputSpec) -> Issue {
    Issue::new(
        spec.manifest_path.display().to_string(),
        checks::names::RESOLUTION_PYTHON_IMPLICIT_RUNTIME_PROFILE,
        Severity::Warning,
    )
    .message(format!(
        "Python dependencies in '{}' use environment markers, but no target environment was provided. sloppy-joe evaluated those markers for the current host; every dependency group and extra was still included.",
        spec.manifest_path.display()
    ))
    .fix(
        "For CI or build gating, pass the target environment with `--python-platform`, `--python-arch`, or `--python-version` so sloppy-joe evaluates markers for the environment your install uses.",
    )
}

/// Groups and extras declared in the manifest that a `--python-groups` / `--python-extras`
/// selection left out of this scan.
pub(crate) fn python_unscanned_scope_warning(
    spec: &ProjectInputSpec,
    scoped: &[parsers::python_scope::PythonScopedDependency],
    profile: &parsers::python_scope::PythonProfile,
) -> Option<Issue> {
    let mut groups = std::collections::BTreeSet::new();
    let mut extras = std::collections::BTreeSet::new();
    for dep in scoped {
        groups.extend(
            dep.groups
                .iter()
                .filter(|group| !profile.includes_group(group))
                .cloned(),
        );
        extras.extend(
            dep.extras
                .iter()
                .filter(|extra| !profile.includes_extra(extra))
                .cloned(),
        );
    }
    if groups.is_empty() && extras.is_empty() {
        return None;
    }
    let describe = |label: &str, names: &std::collections::BTreeSet<String>| {
        (!names.is_empty()).then(|| {
            format!(
                "{label} {}",
                names
                    .iter()
                    .map(|name| format!("'{}'", report::sanitize_for_terminal(name)))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
    };
    let excluded = [describe("groups", &groups), describe("extras", &extras)]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" and ");
    Some(
        Issue::new(
            spec.manifest_path.display().to_string(),
            checks::names::RESOLUTION_PYTHON_GROUPS_NOT_SCANNED,
            Severity::Warning,
        )
        .message(format!(
            "The --python-groups/--python-extras selection excluded {} declared in '{}'. Packages declared only there were not scanned.",
            excluded,
            spec.manifest_path.display()
        ))
        .fix(
            "Omit --python-groups and --python-extras to scan every dependency group and extra, or add the excluded names if your install uses them.",
        ),
    )
}

pub(crate) fn unused_python_source_warnings(
    manifest_path: &std::path::Path,
    declared_sources: &[parsers::pyproject_toml::PythonSourceDecl],
    used_source_urls: &std::collections::HashSet<String>,
    used_source_names: &std::collections::HashSet<String>,
) -> Vec<Issue> {
    let mut declared_per_url = std::collections::HashMap::new();
    for source in declared_sources {
        *declared_per_url
            .entry(source.normalized_url.clone())
            .or_insert(0usize) += 1;
    }

    declared_sources
        .iter()
        .filter(|source| {
            if source.normalized_url == config::normalized_default_pypi_index() {
                return false;
            }
            if used_source_names.contains(&source.name.to_lowercase()) {
                return false;
            }
            let duplicate_url_aliases = declared_per_url
                .get(&source.normalized_url)
                .copied()
                .unwrap_or_default()
                > 1;
            !used_source_urls.contains(&source.normalized_url) || duplicate_url_aliases
        })
        .map(|source| {
            Issue::new(
                manifest_path.display().to_string(),
                checks::names::RESOLUTION_UNUSED_DECLARED_SOURCE,
                Severity::Warning,
            )
            .message(format!(
                "Python source '{}' ({}) is declared in '{}' but no locked package currently uses it. Unused custom sources make provenance policy harder to review and maintain.",
                report::sanitize_for_terminal(&source.name),
                source.normalized_url,
                manifest_path.display()
            ))
            .fix(format!(
                "Remove the unused source '{}' from '{}' if it is no longer needed. Keeping only actively used sources improves clarity and maintenance.",
                report::sanitize_for_terminal(&source.name),
                manifest_path.display()
            ))
        })
        .collect()
}

/// Python lockfiles are walked from the manifest's roots. A manifest with no
/// roots in any scope proves nothing about its lockfile, so callers scan every
/// locked package instead of none.
pub(crate) fn python_manifest_declares_no_dependencies(spec: &ProjectInputSpec) -> Result<bool> {
    Ok(match spec.kind {
        ProjectInputKind::PyProjectPoetry => {
            parsers::pyproject_toml::parse_poetry_scoped_file(&spec.manifest_path)?.is_empty()
        }
        ProjectInputKind::PyProjectUv => {
            parsers::pyproject_toml::parse_legacy_scoped_file(&spec.manifest_path)?.is_empty()
        }
        _ => false,
    })
}

pub(crate) fn legacy_python_manifest_paths(
    project_dir: &std::path::Path,
) -> Result<Vec<std::path::PathBuf>> {
    let mut manifests = Vec::new();

    for path in legacy_requirements_files(project_dir)? {
        manifests.push(path);
    }
    for manifest in ["Pipfile", "setup.cfg", "setup.py"] {
        let path = project_dir.join(manifest);
        if parsers::path_detected(&path)? {
            manifests.push(path);
        }
    }
    let pyproject = project_dir.join("pyproject.toml");
    if parsers::path_detected(&pyproject)?
        && matches!(
            parsers::pyproject_toml::classify_manifest(&pyproject)?,
            parsers::pyproject_toml::PyprojectKind::Legacy
        )
    {
        manifests.push(pyproject);
    }

    manifests.sort();
    Ok(manifests)
}

pub(crate) fn legacy_requirements_files(
    project_dir: &std::path::Path,
) -> Result<Vec<std::path::PathBuf>> {
    let mut candidates = std::fs::read_dir(project_dir)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", project_dir.display(), err))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| parsers::requirements::is_requirements_manifest_path(path))
        .collect::<Vec<_>>();
    let requirements_dir = project_dir.join("requirements");
    if std::fs::symlink_metadata(&requirements_dir).is_ok_and(|meta| meta.is_dir()) {
        candidates.extend(
            std::fs::read_dir(&requirements_dir)
                .map_err(|err| {
                    anyhow::anyhow!("Failed to inspect {}: {}", requirements_dir.display(), err)
                })?
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .filter(|path| parsers::requirements::is_requirements_manifest_path(path)),
        );
    }
    candidates.sort();
    Ok(candidates)
}
