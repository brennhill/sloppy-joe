use crate::*;

#[cfg(test)]
pub(crate) fn detected_project_inputs(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
) -> Result<Vec<ProjectInputSpec>> {
    detected_project_inputs_with_config(
        project_dir,
        project_type,
        &config::SloppyJoeConfig::default(),
    )
}

#[cfg(test)]
pub(crate) fn detected_project_inputs_with_config(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config: &config::SloppyJoeConfig,
) -> Result<Vec<ProjectInputSpec>> {
    let mut specs = unbound_project_inputs_with_config(project_dir, project_type, config)?;
    ecosystems::bind_strict(project_dir, &mut specs)?;
    Ok(specs)
}

pub(crate) fn unbound_project_inputs_with_config(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config: &config::SloppyJoeConfig,
) -> Result<Vec<ProjectInputSpec>> {
    let mut specs = discover_project_inputs(project_dir, &config.ignore_dirs)?;
    specs.retain(|spec| project_type_includes(project_type, spec.kind));
    ecosystems::refine_specs(project_dir, config, &mut specs)?;

    if specs.is_empty()
        && let Some(message) = project_type.and_then(missing_manifest_message)
    {
        anyhow::bail!("{message}");
    }

    Ok(specs)
}

/// Whether an explicit `--type` selects manifests of `kind` (no type selects everything).
fn project_type_includes(project_type: Option<&str>, kind: ProjectInputKind) -> bool {
    project_type.is_none_or(|selected| kind.descriptor().project_type == selected)
}

/// The blocking message when an explicit `--type` finds no manifest.
fn missing_manifest_message(project_type: &str) -> Option<&'static str> {
    Some(match project_type {
        "npm" => "Required manifest 'package.json' is missing for this project type.",
        "pypi" => {
            "Required Python manifest is missing for this project type. Expected one of: pyproject.toml, requirements*.txt, Pipfile, setup.cfg, or setup.py."
        }
        "cargo" => "Required manifest 'Cargo.toml' is missing for this project type.",
        "go" => "Required manifest 'go.mod' is missing for this project type.",
        "ruby" => "Required manifest 'Gemfile' is missing for this project type.",
        "php" => "Required manifest 'composer.json' is missing for this project type.",
        "jvm" => {
            "Required manifest 'build.gradle, build.gradle.kts, or pom.xml' is missing for this project type."
        }
        "dotnet" => "Required manifest '.csproj' is missing for this project type.",
        _ => return None,
    })
}

pub(crate) fn discover_project_inputs(
    project_dir: &std::path::Path,
    ignore_dirs: &[String],
) -> Result<Vec<ProjectInputSpec>> {
    let root = std::fs::canonicalize(project_dir).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {} for project manifests: {}",
            project_dir.display(),
            err
        )
    })?;
    let mut visited = std::collections::HashSet::new();
    let mut specs = Vec::new();
    walk_project_tree(
        project_dir,
        &root,
        &mut visited,
        &mut specs,
        false,
        ignore_dirs,
    )?;
    specs.sort_by(|left, right| left.manifest_path.cmp(&right.manifest_path));
    Ok(specs)
}

pub(crate) fn walk_project_tree(
    current_dir: &std::path::Path,
    root: &std::path::Path,
    visited: &mut std::collections::HashSet<std::path::PathBuf>,
    specs: &mut Vec<ProjectInputSpec>,
    inside_installed_node_modules: bool,
    ignore_dirs: &[String],
) -> Result<()> {
    if !enter_directory(current_dir, root, visited, ignore_dirs)? {
        return Ok(());
    }

    let unreadable = |err: std::io::Error| {
        anyhow::anyhow!(
            "Failed to inspect {} for project manifests: {}",
            current_dir.display(),
            err
        )
    };
    let mut entries = std::fs::read_dir(current_dir)
        .map_err(unreadable)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(unreadable)?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        walk_entry(
            &entry,
            current_dir,
            root,
            visited,
            specs,
            inside_installed_node_modules,
            ignore_dirs,
        )?;
    }

    Ok(())
}

/// Whether `current_dir` should be scanned: inside the root, not ignored and not seen yet.
fn enter_directory(
    current_dir: &std::path::Path,
    root: &std::path::Path,
    visited: &mut std::collections::HashSet<std::path::PathBuf>,
    ignore_dirs: &[String],
) -> Result<bool> {
    let canonical_current = std::fs::canonicalize(current_dir).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {} for project manifests: {}",
            current_dir.display(),
            err
        )
    })?;

    if !canonical_current.starts_with(root) {
        anyhow::bail!(
            "Refusing to follow symlinked directory '{}' outside the scan root.",
            current_dir.display()
        );
    }

    let ignored = canonical_current
        .strip_prefix(root)
        .expect("checked scan root")
        .components()
        .any(|component| {
            ignore_dirs
                .iter()
                .any(|name| component.as_os_str() == std::ffi::OsStr::new(name))
        });
    Ok(!ignored && visited.insert(canonical_current))
}

fn walk_entry(
    entry: &std::fs::DirEntry,
    current_dir: &std::path::Path,
    root: &std::path::Path,
    visited: &mut std::collections::HashSet<std::path::PathBuf>,
    specs: &mut Vec<ProjectInputSpec>,
    inside_installed_node_modules: bool,
    ignore_dirs: &[String],
) -> Result<()> {
    let name = entry.file_name();
    let path = entry.path();
    let file_type = entry
        .file_type()
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", path.display(), err))?;

    let ignored = name
        .to_str()
        .is_some_and(|name| ignore_dirs.iter().any(|ignored| ignored == name));
    if (file_type.is_dir() || file_type.is_symlink()) && ignored {
        return Ok(());
    }
    if file_type.is_dir() {
        if name.to_str() == Some(".git") {
            return Ok(());
        }
        let child_inside_installed_node_modules = inside_installed_node_modules
            || (name.to_str() == Some("node_modules")
                && directory_has_detected_manifest(current_dir, "package.json"));
        return walk_project_tree(
            &path,
            root,
            visited,
            specs,
            child_inside_installed_node_modules,
            ignore_dirs,
        );
    }

    if file_type.is_symlink() {
        let target = std::fs::canonicalize(&path).map_err(|err| {
            anyhow::anyhow!(
                "Failed to resolve symlinked path '{}': {}",
                path.display(),
                err
            )
        })?;
        if target.is_dir() {
            if !target.starts_with(root) {
                anyhow::bail!(
                    "Refusing to follow symlinked directory '{}' outside the scan root.",
                    path.display()
                );
            }
            return walk_project_tree(
                &path,
                root,
                visited,
                specs,
                inside_installed_node_modules
                    || resolved_path_inside_installed_node_modules(root, &target),
                ignore_dirs,
            );
        }
    }

    if let Some(spec) = project_input_from_path(&path, inside_installed_node_modules)? {
        specs.push(spec);
    }
    Ok(())
}

pub(crate) fn directory_has_detected_manifest(dir: &std::path::Path, manifest_name: &str) -> bool {
    parsers::path_detected(&dir.join(manifest_name)).unwrap_or(false)
}

pub(crate) fn resolved_path_inside_installed_node_modules(
    root: &std::path::Path,
    target: &std::path::Path,
) -> bool {
    let Ok(relative) = target.strip_prefix(root) else {
        return false;
    };

    let mut current = root.to_path_buf();
    let mut inside = false;
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            continue;
        };
        if name == "node_modules" {
            inside = inside || directory_has_detected_manifest(&current, "package.json");
        }
        current.push(name);
    }
    inside
}

pub(crate) fn project_input_from_path(
    path: &std::path::Path,
    inside_installed_node_modules: bool,
) -> Result<Option<ProjectInputSpec>> {
    let Some(kind) = ecosystems::detect(path)? else {
        return Ok(None);
    };
    let spec = ProjectInputSpec {
        kind,
        manifest_path: path.to_path_buf(),
        lockfile_path_override: None,
        js_binding: None,
    };

    if inside_installed_node_modules {
        let keep = match kind.descriptor().in_installed_tree {
            InstalledTreePolicy::Scan => true,
            InstalledTreePolicy::ScanWhenLocked => selected_lockfile_path(&spec).is_some(),
            InstalledTreePolicy::Skip => false,
        };
        if !keep {
            return Ok(None);
        }
    }

    Ok(Some(spec))
}
