use crate::*;

pub(crate) fn validate_supported_js_manager(spec: &ProjectInputSpec) -> Result<()> {
    let Some(binding) = &spec.js_binding else {
        return Ok(());
    };
    if matches!(
        binding.manager,
        JsPackageManager::Npm
            | JsPackageManager::Pnpm
            | JsPackageManager::Bun
            | JsPackageManager::Yarn
    ) {
        return Ok(());
    }
    anyhow::bail!(
        "JS project '{}' is managed by '{}', rooted at '{}'. sloppy-joe detected the manager correctly, but support for {} projects is not implemented yet.",
        spec.manifest_path.display(),
        binding.manager.as_str(),
        binding.root_manifest_path.display(),
        binding.manager.as_str()
    );
}

pub(crate) fn npm_trusted_scope_root(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
) -> Result<std::path::PathBuf> {
    if let Some(binding) = &spec.js_binding {
        let root_dir = binding
            .root_manifest_path
            .parent()
            .expect("package.json should always have a parent directory");
        return std::fs::canonicalize(root_dir)
            .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", root_dir.display(), err));
    }
    std::fs::canonicalize(scan_root)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", scan_root.display(), err))
}

pub(crate) fn legacy_npm_v1_warnings(lockfile_path: &std::path::Path) -> Vec<Issue> {
    vec![
        Issue::new(
            "<lockfile>",
            checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE,
            Severity::Warning,
        )
        .message(format!(
            "Legacy npm v5/v6 lockfile '{}' is allowed by config, but sloppy-joe treats it as reduced-confidence input. package-lock v1 cannot prove modern npm artifact and graph invariants as strongly as current lockfiles.",
            lockfile_path.display()
        ))
        .fix(
            "Regenerate the lockfile with a modern npm and commit the upgraded package-lock.json or npm-shrinkwrap.json.",
        ),
        Issue::new(
            "<lockfile>",
            checks::names::RESOLUTION_NO_TRUSTED_TRANSITIVE_COVERAGE,
            Severity::Warning,
        )
        .message(format!(
            "Legacy npm v5/v6 lockfile '{}' is scanned without trusted transitive coverage. sloppy-joe skips transitive dependency extraction for package-lock v1 because the older format is too weak for strict graph trust.",
            lockfile_path.display()
        ))
        .fix(
            "Upgrade the lockfile with a modern npm if you need trusted transitive npm coverage.",
        ),
    ]
}

pub(crate) fn load_npm_manifests(
    specs: &[ProjectInputSpec],
) -> Result<std::collections::HashMap<std::path::PathBuf, serde_json::Value>> {
    let mut manifests = std::collections::HashMap::new();
    for spec in specs {
        if spec.kind == ProjectInputKind::Npm {
            manifests.insert(
                spec.manifest_path.clone(),
                read_npm_manifest_value(&spec.manifest_path)?,
            );
        }
    }
    Ok(manifests)
}

#[derive(Default)]
pub(crate) struct NpmProjectIndex {
    pub(crate) dirs: std::collections::HashSet<std::path::PathBuf>,
    pub(crate) names_by_dir: std::collections::HashMap<std::path::PathBuf, String>,
    pub(crate) by_name:
        std::collections::HashMap<String, std::collections::HashSet<std::path::PathBuf>>,
}

/// A project with its own lockfile that its enclosing workspace does not record is installed
/// on its own, unless the workspace root explicitly selects a package manager.
fn project_is_independent_of_workspace(
    root: &WorkspaceRoot,
    canonical_project_dir: &std::path::Path,
    spec: &ProjectInputSpec,
) -> Result<bool> {
    if root.project_dir == canonical_project_dir {
        return Ok(false);
    }
    let manager = detect_js_manager(
        canonical_project_dir,
        &spec.manifest_path,
        &read_npm_manifest_value(&spec.manifest_path)?,
    )?;
    if js_lockfile_path(canonical_project_dir, manager)?.is_none()
        || js_workspace_records_project(root, canonical_project_dir)?
    {
        return Ok(false);
    }
    let root_manifest = root.project_dir.join("package.json");
    let explicitly_selected = parsers::path_detected(&root_manifest)?
        && read_npm_manifest_value(&root_manifest)?
            .get("packageManager")
            .is_some();
    Ok(!explicitly_selected)
}

/// Read the root `.npmrc` and reject package-manager configuration files that redirect
/// registries or rewrite dependencies.
fn read_package_manager_config(
    canonical_project_dir: &std::path::Path,
    ancestry_root: &std::path::Path,
    canonical_root_dir: &std::path::Path,
    manager: JsPackageManager,
) -> Result<npm_config::NpmRegistries> {
    let mut npm_registries = npm_config::NpmRegistries::default();
    for dir in ancestor_dirs_inclusive(canonical_project_dir, ancestry_root)?
        .into_iter()
        .rev()
    {
        let npmrc = dir.join(".npmrc");
        if dir == canonical_root_dir && parsers::path_detected(&npmrc)? {
            npm_registries.read(&npmrc)?;
            npm_registries.validate_manager(manager.as_str(), &npmrc)?;
        }
        for (filename, owner) in [
            (".yarnrc", Some(JsPackageManager::Yarn)),
            (".yarnrc.yml", Some(JsPackageManager::Yarn)),
            (".pnpmfile.cjs", Some(JsPackageManager::Pnpm)),
            ("bunfig.toml", Some(JsPackageManager::Bun)),
        ] {
            let path = dir.join(filename);
            if owner.is_none_or(|owner| owner == manager) && parsers::path_detected(&path)? {
                anyhow::bail!(
                    "Unsupported JS package-manager configuration '{}': registry redirects and dependency rewrites cannot be verified",
                    path.display()
                );
            }
        }
    }
    Ok(npm_registries)
}

pub(crate) fn resolve_js_project_binding(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
) -> Result<JsProjectBinding> {
    let canonical_project_dir = std::fs::canonicalize(spec.project_dir()).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {}: {}",
            spec.project_dir().display(),
            err
        )
    })?;
    let ancestry_root = js_ancestry_root(scan_root, spec.project_dir())?;
    let mut workspace_root = find_js_workspace_root(&ancestry_root, &canonical_project_dir)?;
    let mut independent_from_workspace = None;
    if let Some(root) = &workspace_root
        && project_is_independent_of_workspace(root, &canonical_project_dir, spec)?
    {
        independent_from_workspace = Some(root.manifest_path.clone());
        workspace_root = None;
    }
    let (root_manifest_path, root_dir, manager) = if let Some(root) = workspace_root.as_ref() {
        (
            root.manifest_path.clone(),
            root.project_dir.clone(),
            root.manager,
        )
    } else {
        let root_manifest_path = spec.manifest_path.clone();
        let root_manifest = read_npm_manifest_value(&root_manifest_path)?;
        let root_dir = root_manifest_path
            .parent()
            .expect("package.json should always have a parent directory")
            .to_path_buf();
        let manager = detect_js_manager(&root_dir, &root_manifest_path, &root_manifest)?;
        (root_manifest_path, root_dir, manager)
    };
    let canonical_root_dir = std::fs::canonicalize(&root_dir)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", root_dir.display(), err))?;
    let npm_registries = read_package_manager_config(
        &canonical_project_dir,
        &ancestry_root,
        &canonical_root_dir,
        manager,
    )?;
    let lockfile_path = js_lockfile_path(&root_dir, manager)?;
    let package_entry_key = if canonical_project_dir == canonical_root_dir {
        match manager {
            JsPackageManager::Pnpm => ".".to_string(),
            _ => String::new(),
        }
    } else {
        relative_package_entry_key(&canonical_root_dir, &canonical_project_dir)?
    };

    Ok(JsProjectBinding {
        manager,
        root_manifest_path,
        lockfile_path,
        package_entry_key,
        npm_registries,
        independent_from_workspace,
    })
}

/// A workspace member that project discovery never binds (its manifest is
/// `package.yaml` / `package.json5`, or it sits under an ignored directory) is still
/// installed by the package manager from the workspace lockfile, so nothing would scan it.
pub(crate) fn ensure_js_workspace_members_scanned(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    scanned: &std::collections::HashSet<std::path::PathBuf>,
) -> Result<()> {
    let canonical_project_dir = std::fs::canonicalize(spec.project_dir())?;
    let canonical_scan_root = std::fs::canonicalize(scan_root)?;
    let ancestry_root = js_ancestry_root(scan_root, spec.project_dir())?;
    let Some(root) = find_js_workspace_root(&ancestry_root, &canonical_project_dir)? else {
        return Ok(());
    };
    if root.project_dir != canonical_project_dir
        || !root.project_dir.starts_with(&canonical_scan_root)
    {
        return Ok(());
    }
    let mut hidden = Vec::new();
    collect_unscanned_workspace_members(&root, &root.project_dir, scanned, &mut hidden, 0)?;
    if let Some(first) = hidden.first() {
        anyhow::bail!(
            "Workspace member '{}' is declared by '{}' but is not a scanned project (its manifest is not package.json, or it is inside an ignored directory). The package manager installs it from the workspace lockfile, so sloppy-joe would not check its dependencies. Fix: use a package.json manifest and remove the directory from ignore_dirs.",
            first.display(),
            root.manifest_path.display()
        );
    }
    Ok(())
}

pub(crate) fn collect_unscanned_workspace_members(
    root: &WorkspaceRoot,
    dir: &std::path::Path,
    scanned: &std::collections::HashSet<std::path::PathBuf>,
    hidden: &mut Vec<std::path::PathBuf>,
    depth: usize,
) -> Result<()> {
    if depth > 16 || !hidden.is_empty() {
        return Ok(());
    }
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<std::result::Result<_, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name();
        if matches!(name.to_str(), Some("node_modules" | ".git")) {
            continue;
        }
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path();
        let Ok(canonical) = std::fs::canonicalize(&path) else {
            continue;
        };
        if workspace_patterns_match(
            &root.project_dir,
            &canonical,
            root.patterns.iter().map(String::as_str),
        ) && ["package.json", "package.yaml", "package.json5"]
            .iter()
            .any(|manifest| path.join(manifest).is_file())
            && !scanned.contains(&canonical)
        {
            hidden.push(canonical.clone());
        }
        collect_unscanned_workspace_members(root, &path, scanned, hidden, depth + 1)?;
    }
    Ok(())
}

pub(crate) fn js_workspace_records_project(
    root: &WorkspaceRoot,
    project_dir: &std::path::Path,
) -> Result<bool> {
    let Some(path) = js_lockfile_path(&root.project_dir, root.manager)? else {
        return Ok(false);
    };
    let key = relative_package_entry_key(&root.project_dir, project_dir)?;
    let content = parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES)?;
    match root.manager {
        JsPackageManager::Pnpm => {
            let value: serde_yaml::Value = crate::lockfiles::parse_pnpm_lock_guarded(&content)
                .map_err(|error| {
                    anyhow::anyhow!("Broken lockfile '{}': {error}", path.display())
                })?;
            Ok(value
                .get("importers")
                .and_then(|entries| entries.get(&key))
                .is_some())
        }
        JsPackageManager::Npm => {
            let value: serde_json::Value = serde_json::from_str(&content).map_err(|error| {
                anyhow::anyhow!("Broken lockfile '{}': {error}", path.display())
            })?;
            Ok(value
                .get("packages")
                .and_then(|entries| entries.get(&key))
                .is_some())
        }
        // Other workspace formats retain their existing ownership checks.
        JsPackageManager::Yarn | JsPackageManager::Bun => Ok(true),
    }
}

pub(crate) fn js_lockfile_path(
    root: &std::path::Path,
    manager: JsPackageManager,
) -> Result<Option<std::path::PathBuf>> {
    let candidates: &[&str] = match manager {
        JsPackageManager::Npm => &["npm-shrinkwrap.json", "package-lock.json"],
        JsPackageManager::Pnpm => &["pnpm-lock.yaml"],
        JsPackageManager::Yarn => &["yarn.lock"],
        JsPackageManager::Bun => &["bun.lock", "bun.lockb"],
    };
    for name in candidates {
        let path = root.join(name);
        if parsers::path_detected(&path)? {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

pub(crate) fn js_ancestry_root(
    scan_root: &std::path::Path,
    project_dir: &std::path::Path,
) -> Result<std::path::PathBuf> {
    if let Some(git_root) = crate::cache::find_git_root(project_dir).map_err(anyhow::Error::msg)? {
        return Ok(git_root);
    }
    std::fs::canonicalize(scan_root)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", scan_root.display(), err))
}

pub(crate) fn relative_package_entry_key(
    root_dir: &std::path::Path,
    canonical_project_dir: &std::path::Path,
) -> Result<String> {
    let relative = canonical_project_dir.strip_prefix(root_dir).map_err(|_| {
        anyhow::anyhow!(
            "Path '{}' is outside npm root '{}'.",
            canonical_project_dir.display(),
            root_dir.display()
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
            "Could not derive npm workspace entry key for '{}' relative to '{}'.",
            canonical_project_dir.display(),
            root_dir.display()
        );
    }
    Ok(key)
}

pub(crate) fn detect_js_manager(
    root_dir: &std::path::Path,
    manifest_path: &std::path::Path,
    manifest: &serde_json::Value,
) -> Result<JsPackageManager> {
    let mut signals = Vec::new();
    if let Some(package_manager) = manifest
        .get("packageManager")
        .and_then(|value| value.as_str())
    {
        let manager = package_manager
            .split_once('@')
            .map(|(name, _)| name)
            .unwrap_or(package_manager);
        let manager = match manager {
            "npm" => JsPackageManager::Npm,
            "pnpm" => JsPackageManager::Pnpm,
            "yarn" => JsPackageManager::Yarn,
            "bun" => JsPackageManager::Bun,
            other => {
                anyhow::bail!(
                    "package.json '{}' declares unsupported packageManager '{}'. sloppy-joe only understands npm, pnpm, yarn, and bun at the JS manager layer.",
                    manifest_path.display(),
                    other
                );
            }
        };
        signals.push((
            manager,
            format!("packageManager in '{}'", manifest_path.display()),
        ));
    }
    for (marker, manager) in [
        ("pnpm-lock.yaml", JsPackageManager::Pnpm),
        ("pnpm-workspace.yaml", JsPackageManager::Pnpm),
        ("yarn.lock", JsPackageManager::Yarn),
        (".pnp.cjs", JsPackageManager::Yarn),
        ("bun.lock", JsPackageManager::Bun),
        ("bun.lockb", JsPackageManager::Bun),
        ("npm-shrinkwrap.json", JsPackageManager::Npm),
        ("package-lock.json", JsPackageManager::Npm),
    ] {
        let path = root_dir.join(marker);
        if parsers::path_detected(&path)? {
            signals.push((manager, path.display().to_string()));
        }
    }

    let distinct = signals
        .iter()
        .map(|(manager, _)| *manager)
        .collect::<std::collections::HashSet<_>>();
    if distinct.len() > 1 {
        let details = signals
            .into_iter()
            .map(|(manager, source)| format!("{} via {}", manager.as_str(), source))
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::bail!(
            "JS project rooted at '{}' has conflicting package-manager signals: {}. sloppy-joe requires one authoritative JS manager per root.",
            manifest_path.display(),
            details
        );
    }

    Ok(signals
        .into_iter()
        .next()
        .map(|(manager, _)| manager)
        .unwrap_or(JsPackageManager::Npm))
}

pub(crate) fn npm_alias_targets_by_lockfile(
    specs: &[ProjectInputSpec],
    manifests: &std::collections::HashMap<std::path::PathBuf, serde_json::Value>,
) -> Result<std::collections::HashMap<std::path::PathBuf, std::collections::HashMap<String, String>>>
{
    let mut by_lockfile = std::collections::HashMap::new();
    for spec in specs {
        if spec.kind != ProjectInputKind::Npm {
            continue;
        }
        let Some(lockfile_path) = selected_lockfile_path(spec) else {
            continue;
        };
        let Some(manifest) = manifests.get(&spec.manifest_path) else {
            continue;
        };
        let aliases = by_lockfile
            .entry(lockfile_path)
            .or_insert_with(std::collections::HashMap::new);
        for (alias_name, raw_spec) in npm_dependency_entries(manifest) {
            let Some(alias_spec) = raw_spec.strip_prefix("npm:") else {
                continue;
            };
            let (target_name, _) = alias_spec.rsplit_once('@').ok_or_else(|| {
                anyhow::anyhow!(
                    "Unsupported npm alias '{}' in {}: expected npm:<package>@<version>",
                    crate::report::sanitize_for_terminal(&raw_spec),
                    spec.manifest_path.display()
                )
            })?;
            if let Some(existing) = aliases.get(&alias_name)
                && existing != target_name
            {
                anyhow::bail!(
                    "Npm alias '{}' resolves to both '{}' and '{}' under authoritative lockfile '{}'. sloppy-joe requires alias bindings to be unique per lockfile.",
                    alias_name,
                    existing,
                    target_name,
                    selected_lockfile_path(spec)
                        .expect("lockfile path checked above")
                        .display()
                );
            }
            aliases.insert(alias_name, target_name.to_string());
        }
    }
    Ok(by_lockfile)
}

pub(crate) fn index_npm_projects(
    manifests: &std::collections::HashMap<std::path::PathBuf, serde_json::Value>,
) -> Result<NpmProjectIndex> {
    let mut index = NpmProjectIndex::default();
    for (manifest_path, manifest) in manifests {
        let project_dir = std::fs::canonicalize(
            manifest_path
                .parent()
                .expect("manifest paths should always have a parent directory"),
        )
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", manifest_path.display(), err))?;
        index.dirs.insert(project_dir.clone());
        if let Some(name) = manifest.get("name").and_then(|value| value.as_str()) {
            index
                .names_by_dir
                .insert(project_dir.clone(), name.to_string());
            index
                .by_name
                .entry(name.to_string())
                .or_default()
                .insert(project_dir);
        }
    }
    Ok(index)
}
