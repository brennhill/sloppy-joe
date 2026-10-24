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
    bind_js_project_inputs(project_dir, &mut specs)?;
    Ok(specs)
}

pub(crate) fn unbound_project_inputs_with_config(
    project_dir: &std::path::Path,
    project_type: Option<&str>,
    config: &config::SloppyJoeConfig,
) -> Result<Vec<ProjectInputSpec>> {
    let mut specs = discover_project_inputs(project_dir, &config.ignore_dirs)?;
    specs.retain(|spec| project_type_includes(project_type, spec.kind));
    expand_cargo_project_inputs(project_dir, &mut specs, config)?;
    promote_trusted_pip_tools_specs(project_dir, &mut specs)?;
    prune_included_requirement_specs(project_dir, &mut specs)?;
    reject_ambiguous_python_project_inputs(&specs)?;
    prefer_trusted_python_project_inputs(&mut specs);

    if specs.is_empty()
        && let Some(message) = project_type.and_then(missing_manifest_message)
    {
        anyhow::bail!("{message}");
    }

    Ok(specs)
}

/// Whether an explicit `--type` selects manifests of `kind` (no type selects everything).
fn project_type_includes(project_type: Option<&str>, kind: ProjectInputKind) -> bool {
    match project_type {
        Some("npm") => kind == ProjectInputKind::Npm,
        Some("pypi") => kind.is_python(),
        Some("cargo") => kind == ProjectInputKind::Cargo,
        Some("go") => kind == ProjectInputKind::Go,
        Some("ruby") => kind == ProjectInputKind::Ruby,
        Some("php") => kind == ProjectInputKind::Php,
        Some("jvm") => matches!(kind, ProjectInputKind::Gradle | ProjectInputKind::Maven),
        Some("dotnet") => kind == ProjectInputKind::Dotnet,
        Some(_) => false,
        None => true,
    }
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

pub(crate) fn expand_cargo_project_inputs(
    scan_root: &std::path::Path,
    specs: &mut Vec<ProjectInputSpec>,
    config: &config::SloppyJoeConfig,
) -> Result<()> {
    let mut seen = specs
        .iter()
        .map(|spec| spec.manifest_path.clone())
        .collect::<std::collections::HashSet<_>>();

    let mut index = 0usize;
    while index < specs.len() {
        if specs[index].kind != ProjectInputKind::Cargo {
            index += 1;
            continue;
        }

        let manifest_path = specs[index].manifest_path.clone();
        specs[index].lockfile_path_override = Some(authoritative_cargo_lockfile_path(
            scan_root,
            &manifest_path,
            config,
        )?);

        let manifest = parsers::cargo_toml::parse_manifest_file(&manifest_path)?;
        let (cargo_config_rewrites, _) =
            load_effective_cargo_config_rewrites(scan_root, &manifest_path, config)?;
        let rewrites =
            collect_effective_cargo_rewrites(scan_root, &manifest, config, &cargo_config_rewrites)?;
        let effective = resolve_cargo_effective_dependencies(scan_root, &manifest, config)?;

        for dep in effective {
            if let parsers::cargo_toml::CargoSourceSpec::Path(path) = dep.spec.source
                && let Some(target_manifest) = cargo_local_target_manifest(
                    scan_root,
                    &dep.base_dir,
                    &path,
                    &dep.spec.package_name,
                    config,
                )?
                && seen.insert(target_manifest.clone())
            {
                specs.push(ProjectInputSpec {
                    kind: ProjectInputKind::Cargo,
                    manifest_path: target_manifest,
                    lockfile_path_override: None,
                    js_binding: None,
                });
            }
        }

        for rewrite in rewrites {
            if let parsers::cargo_toml::CargoSourceSpec::Path(path) = &rewrite.spec.source
                && let Some(target_manifest) = cargo_local_target_manifest(
                    scan_root,
                    &rewrite.base_dir,
                    path,
                    &rewrite.spec.package_name,
                    config,
                )?
                && seen.insert(target_manifest.clone())
            {
                specs.push(ProjectInputSpec {
                    kind: ProjectInputKind::Cargo,
                    manifest_path: target_manifest,
                    lockfile_path_override: None,
                    js_binding: None,
                });
            }
        }

        index += 1;
    }

    specs.sort_by(|left, right| left.manifest_path.cmp(&right.manifest_path));
    Ok(())
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
    let Some(kind) = project_input_kind_from_path(path)? else {
        return Ok(None);
    };

    if inside_installed_node_modules {
        match kind {
            ProjectInputKind::Npm
                if has_npm_lockfile(path.parent().expect("manifest paths have parent")) => {}
            kind if kind == ProjectInputKind::Npm || kind.is_python() => return Ok(None),
            _ => {}
        }
    }

    Ok(Some(ProjectInputSpec {
        kind,
        manifest_path: path.to_path_buf(),
        lockfile_path_override: None,
        js_binding: None,
    }))
}

pub(crate) fn project_input_kind_from_path(
    path: &std::path::Path,
) -> Result<Option<ProjectInputKind>> {
    let name = path.file_name().and_then(|name| name.to_str());
    match name {
        Some("pyproject.toml") => {
            return Ok(Some(
                match parsers::pyproject_toml::classify_manifest(path)? {
                    parsers::pyproject_toml::PyprojectKind::Poetry => {
                        ProjectInputKind::PyProjectPoetry
                    }
                    parsers::pyproject_toml::PyprojectKind::Uv => ProjectInputKind::PyProjectUv,
                    parsers::pyproject_toml::PyprojectKind::Legacy => {
                        ProjectInputKind::PyProjectLegacy
                    }
                },
            ));
        }
        // Bundler 2 prefers these over Gemfile / Gemfile.lock, so a scan that only reads
        // the old names would miss the dependencies Bundler actually installs.
        Some(name @ ("gems.rb" | "gems.locked")) => anyhow::bail!(
            "Unsupported Bundler file '{name}' at '{}': sloppy-joe reads Gemfile and Gemfile.lock only, so these dependencies would go unchecked. Fix: rename to Gemfile / Gemfile.lock.",
            path.display()
        ),
        Some("packages.config") => {
            parsers::csproj::reject_packages_config(path)?;
            return Ok(None);
        }
        _ => {}
    }
    if let Some(kind) = name.and_then(project_input_kind_for_file_name) {
        return Ok(Some(kind));
    }
    if parsers::requirements::is_requirements_manifest_path(path) {
        return Ok(Some(ProjectInputKind::PyRequirements));
    }
    Ok(parsers::csproj::is_project_file(path).then_some(ProjectInputKind::Dotnet))
}

/// Manifests that are identified by their exact file name.
fn project_input_kind_for_file_name(name: &str) -> Option<ProjectInputKind> {
    Some(match name {
        "package.json" => ProjectInputKind::Npm,
        "Pipfile" => ProjectInputKind::PyPipfile,
        "setup.py" => ProjectInputKind::PySetupPy,
        "setup.cfg" => ProjectInputKind::PySetupCfg,
        "Cargo.toml" => ProjectInputKind::Cargo,
        "go.mod" => ProjectInputKind::Go,
        "Gemfile" => ProjectInputKind::Ruby,
        "composer.json" => ProjectInputKind::Php,
        "build.gradle" | "build.gradle.kts" => ProjectInputKind::Gradle,
        "pom.xml" => ProjectInputKind::Maven,
        _ => return None,
    })
}
