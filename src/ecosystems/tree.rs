//! The filesystem walk that finds project manifests. Shared by engine discovery and the JS
//! plugin's workspace expansion, so it lives below the engine.

use super::*;

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

/// On a case-insensitive filesystem (macOS, Windows) `Package.json` is read as `package.json`.
/// A file that is not a manifest by its exact name but would be with another capitalization is
/// therefore a manifest that discovery would skip.
fn reject_case_variant_manifest(path: &std::path::Path) -> Result<()> {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(());
    };
    let mut capitalized = name.to_ascii_lowercase();
    if let Some(first) = capitalized.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    for candidate in [name.to_ascii_lowercase(), capitalized] {
        if candidate != name && ecosystems::detect(&path.with_file_name(&candidate))?.is_some() {
            anyhow::bail!(
                "Manifest '{}' differs only in letter case from '{candidate}'; on a case-insensitive filesystem the package manager reads it, but discovery would skip it. Rename it.",
                path.display()
            );
        }
    }
    Ok(())
}

pub(crate) fn project_input_from_path(
    path: &std::path::Path,
    inside_installed_node_modules: bool,
) -> Result<Option<ProjectInputSpec>> {
    let Some(kind) = ecosystems::detect(path)? else {
        if !inside_installed_node_modules {
            reject_case_variant_manifest(path)?;
        }
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

#[cfg(test)]
mod case_tests {
    use super::*;

    #[test]
    fn case_variant_manifest_names_block_discovery() {
        let dir = std::env::temp_dir().join(format!("sj-case-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["Package.json", "PACKAGE.JSON", "cargo.toml", "GO.MOD"] {
            let path = dir.join(name);
            std::fs::write(&path, "{}").unwrap();
            assert!(project_input_from_path(&path, false).is_err(), "{name}");
        }
        let readme = dir.join("README.md");
        std::fs::write(&readme, "x").unwrap();
        assert!(project_input_from_path(&readme, false).unwrap().is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
