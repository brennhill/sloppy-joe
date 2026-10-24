use crate::*;

pub(crate) struct WorkspaceRoot {
    pub(crate) manifest_path: std::path::PathBuf,
    pub(crate) project_dir: std::path::PathBuf,
    pub(crate) patterns: Vec<String>,
    pub(crate) manager: JsPackageManager,
}

pub(crate) fn validate_workspace_npm_dependency(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    dep_name: &str,
    canonical_project_dir: &std::path::Path,
    npm_index: &NpmProjectIndex,
) -> Result<std::path::PathBuf> {
    let Some(workspace_root) = find_npm_workspace_root(scan_root, canonical_project_dir)? else {
        anyhow::bail!(
            "Local npm dependency '{}' in '{}' uses workspace:, but no ancestor package.json with a matching npm workspaces declaration was found. Scan the workspace root, or replace the workspace reference with a dependency source sloppy-joe can verify exactly.",
            dep_name,
            spec.manifest_path.display()
        );
    };

    let matching_dirs = npm_index
        .by_name
        .get(dep_name)
        .into_iter()
        .flat_map(|dirs| dirs.iter())
        .filter(|dir| *dir != canonical_project_dir)
        .filter(|dir| {
            workspace_patterns_match(
                &workspace_root.project_dir,
                dir,
                workspace_root.patterns.iter().map(String::as_str),
            )
        })
        .cloned()
        .collect::<Vec<_>>();

    match matching_dirs.len() {
        1 => Ok(matching_dirs[0].clone()),
        0 => anyhow::bail!(
            "Local npm dependency '{}' in '{}' does not resolve to any scanned package declared by the workspaces in '{}'. Keep workspace targets inside the declared npm workspaces set, or remove the workspace reference.",
            dep_name,
            spec.manifest_path.display(),
            workspace_root.manifest_path.display()
        ),
        _ => anyhow::bail!(
            "Local npm dependency '{}' in '{}' resolves ambiguously to multiple scanned packages declared by the workspaces in '{}'. Each workspace package name must be unique within the workspace root.",
            dep_name,
            spec.manifest_path.display(),
            workspace_root.manifest_path.display()
        ),
    }
}

pub(crate) fn validate_workspace_pnpm_dependency(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    dep_name: &str,
    canonical_project_dir: &std::path::Path,
    ignore_dirs: &[String],
) -> Result<std::path::PathBuf> {
    let Some(workspace_root) = find_pnpm_workspace_root(scan_root, canonical_project_dir)? else {
        anyhow::bail!(
            "Local pnpm dependency '{}' in '{}' uses workspace:, but no ancestor pnpm-workspace.yaml with a matching packages declaration was found. Scan the workspace root, or replace the workspace reference with a dependency source sloppy-joe can verify exactly.",
            dep_name,
            spec.manifest_path.display()
        );
    };

    let matching_dirs = workspace_manifest_paths(&workspace_root, ignore_dirs)?
        .into_iter()
        .filter_map(|manifest_path| {
            let project_dir = manifest_path.parent()?.to_path_buf();
            let canonical_dir = std::fs::canonicalize(&project_dir).ok()?;
            if canonical_dir == canonical_project_dir {
                return None;
            }
            let manifest = read_npm_manifest_value(&manifest_path).ok()?;
            let name = manifest.get("name").and_then(|value| value.as_str())?;
            (name == dep_name).then_some(canonical_dir)
        })
        .collect::<Vec<_>>();

    match matching_dirs.len() {
        1 => Ok(matching_dirs[0].clone()),
        0 => anyhow::bail!(
            "Local pnpm dependency '{}' in '{}' does not resolve to any workspace package declared by '{}'. Keep workspace targets inside pnpm-workspace.yaml, or remove the workspace reference.",
            dep_name,
            spec.manifest_path.display(),
            workspace_root
                .project_dir
                .join("pnpm-workspace.yaml")
                .display()
        ),
        _ => anyhow::bail!(
            "Local pnpm dependency '{}' in '{}' resolves ambiguously to multiple workspace packages declared by '{}'. Each pnpm workspace package name must be unique.",
            dep_name,
            spec.manifest_path.display(),
            workspace_root
                .project_dir
                .join("pnpm-workspace.yaml")
                .display()
        ),
    }
}

pub(crate) fn validate_workspace_bun_dependency(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    dep_name: &str,
    canonical_project_dir: &std::path::Path,
    ignore_dirs: &[String],
) -> Result<std::path::PathBuf> {
    let Some(workspace_root) = find_bun_workspace_root(scan_root, canonical_project_dir)? else {
        anyhow::bail!(
            "Local Bun dependency '{}' in '{}' uses workspace:, but no ancestor Bun workspace root with a matching workspaces declaration was found. Scan the workspace root, or replace the workspace reference with a dependency source sloppy-joe can verify exactly.",
            dep_name,
            spec.manifest_path.display()
        );
    };

    let matching_dirs = workspace_manifest_paths(&workspace_root, ignore_dirs)?
        .into_iter()
        .filter_map(|manifest_path| {
            let project_dir = manifest_path.parent()?.to_path_buf();
            let canonical_dir = std::fs::canonicalize(&project_dir).ok()?;
            if canonical_dir == canonical_project_dir {
                return None;
            }
            let manifest = read_npm_manifest_value(&manifest_path).ok()?;
            let name = manifest.get("name").and_then(|value| value.as_str())?;
            (name == dep_name).then_some(canonical_dir)
        })
        .collect::<Vec<_>>();

    match matching_dirs.len() {
        1 => Ok(matching_dirs[0].clone()),
        0 => anyhow::bail!(
            "Local Bun dependency '{}' in '{}' does not resolve to any workspace package declared by '{}'. Keep workspace targets inside the Bun workspaces set, or remove the workspace reference.",
            dep_name,
            spec.manifest_path.display(),
            workspace_root.manifest_path.display()
        ),
        _ => anyhow::bail!(
            "Local Bun dependency '{}' in '{}' resolves ambiguously to multiple workspace packages declared by '{}'. Each Bun workspace package name must be unique within the workspace root.",
            dep_name,
            spec.manifest_path.display(),
            workspace_root.manifest_path.display()
        ),
    }
}

pub(crate) fn validate_workspace_yarn_dependency(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    dep_name: &str,
    canonical_project_dir: &std::path::Path,
    ignore_dirs: &[String],
) -> Result<std::path::PathBuf> {
    let Some(workspace_root) = find_yarn_workspace_root(scan_root, canonical_project_dir)? else {
        anyhow::bail!(
            "Local Yarn dependency '{}' in '{}' uses workspace:, but no ancestor Yarn workspace root with a matching workspaces declaration was found. Scan the workspace root, or replace the workspace reference with a dependency source sloppy-joe can verify exactly.",
            dep_name,
            spec.manifest_path.display()
        );
    };

    let matching_dirs = workspace_manifest_paths(&workspace_root, ignore_dirs)?
        .into_iter()
        .filter_map(|manifest_path| {
            let project_dir = manifest_path.parent()?.to_path_buf();
            let canonical_dir = std::fs::canonicalize(&project_dir).ok()?;
            if canonical_dir == canonical_project_dir {
                return None;
            }
            let manifest = read_npm_manifest_value(&manifest_path).ok()?;
            let name = manifest.get("name").and_then(|value| value.as_str())?;
            (name == dep_name).then_some(canonical_dir)
        })
        .collect::<Vec<_>>();

    match matching_dirs.len() {
        1 => Ok(matching_dirs[0].clone()),
        0 => anyhow::bail!(
            "Local Yarn dependency '{}' in '{}' does not resolve to any workspace package declared by '{}'. Keep workspace targets inside the Yarn workspaces set, or remove the workspace reference.",
            dep_name,
            spec.manifest_path.display(),
            workspace_root.manifest_path.display()
        ),
        _ => anyhow::bail!(
            "Local Yarn dependency '{}' in '{}' resolves ambiguously to multiple workspace packages declared by '{}'. Each Yarn workspace package name must be unique within the workspace root.",
            dep_name,
            spec.manifest_path.display(),
            workspace_root.manifest_path.display()
        ),
    }
}

pub(crate) fn find_pnpm_workspace_root(
    scan_root: &std::path::Path,
    canonical_project_dir: &std::path::Path,
) -> Result<Option<WorkspaceRoot>> {
    Ok(find_js_workspace_root(scan_root, canonical_project_dir)?
        .filter(|root| root.manager == JsPackageManager::Pnpm))
}

pub(crate) fn find_yarn_workspace_root(
    scan_root: &std::path::Path,
    canonical_project_dir: &std::path::Path,
) -> Result<Option<WorkspaceRoot>> {
    Ok(find_js_workspace_root(scan_root, canonical_project_dir)?
        .filter(|root| root.manager == JsPackageManager::Yarn))
}

pub(crate) fn find_bun_workspace_root(
    scan_root: &std::path::Path,
    canonical_project_dir: &std::path::Path,
) -> Result<Option<WorkspaceRoot>> {
    Ok(find_js_workspace_root(scan_root, canonical_project_dir)?
        .filter(|root| root.manager == JsPackageManager::Bun))
}

pub(crate) fn find_npm_workspace_root(
    scan_root: &std::path::Path,
    canonical_project_dir: &std::path::Path,
) -> Result<Option<WorkspaceRoot>> {
    Ok(find_js_workspace_root(scan_root, canonical_project_dir)?
        .filter(|root| root.manager == JsPackageManager::Npm))
}

pub(crate) fn find_js_workspace_root(
    scan_root: &std::path::Path,
    canonical_project_dir: &std::path::Path,
) -> Result<Option<WorkspaceRoot>> {
    for ancestor_dir in ancestor_dirs_inclusive(canonical_project_dir, scan_root)? {
        let manifest_path = ancestor_dir.join("package.json");
        if parsers::path_detected(&manifest_path)? {
            let manifest = read_npm_manifest_value(&manifest_path)?;
            if ancestor_dir != canonical_project_dir {
                let manifest_patterns = parse_npm_workspaces(&manifest_path, &manifest)?;
                let pnpm_patterns = parse_pnpm_workspaces(&ancestor_dir)?;
                let applicable =
                    manifest_patterns
                        .iter()
                        .chain(pnpm_patterns.iter())
                        .any(|patterns| {
                            workspace_patterns_match(
                                &ancestor_dir,
                                canonical_project_dir,
                                patterns.iter().map(String::as_str),
                            )
                        });
                if !applicable {
                    continue;
                }
            }
            let manager = detect_js_manager(&ancestor_dir, &manifest_path, &manifest)?;
            let Some(patterns) =
                parse_js_workspace_patterns(&ancestor_dir, &manifest_path, &manifest, manager)?
            else {
                continue;
            };

            if ancestor_dir == canonical_project_dir
                || workspace_patterns_match(
                    &ancestor_dir,
                    canonical_project_dir,
                    patterns.iter().map(String::as_str),
                )
            {
                return Ok(Some(WorkspaceRoot {
                    manifest_path: manifest_path.clone(),
                    project_dir: ancestor_dir.clone(),
                    patterns,
                    manager,
                }));
            }
        }

        let pnpm_workspace_path = ancestor_dir.join("pnpm-workspace.yaml");
        if !parsers::path_detected(&pnpm_workspace_path)? {
            continue;
        }
        let Some(patterns) = parse_pnpm_workspaces(&ancestor_dir)? else {
            continue;
        };

        if ancestor_dir == canonical_project_dir
            || workspace_patterns_match(
                &ancestor_dir,
                canonical_project_dir,
                patterns.iter().map(String::as_str),
            )
        {
            return Ok(Some(WorkspaceRoot {
                manifest_path: pnpm_workspace_path,
                project_dir: ancestor_dir,
                patterns,
                manager: JsPackageManager::Pnpm,
            }));
        }
    }

    Ok(None)
}

pub(crate) fn parse_js_workspace_patterns(
    workspace_dir: &std::path::Path,
    manifest_path: &std::path::Path,
    manifest: &serde_json::Value,
    manager: JsPackageManager,
) -> Result<Option<Vec<String>>> {
    match manager {
        JsPackageManager::Npm => parse_npm_workspaces(manifest_path, manifest),
        JsPackageManager::Pnpm => parse_pnpm_workspaces(workspace_dir),
        JsPackageManager::Yarn | JsPackageManager::Bun => {
            parse_npm_workspaces(manifest_path, manifest)
        }
    }
}

pub(crate) fn parse_pnpm_workspaces(
    workspace_dir: &std::path::Path,
) -> Result<Option<Vec<String>>> {
    let path = workspace_dir.join("pnpm-workspace.yaml");
    if !parsers::path_detected(&path)? {
        return Ok(None);
    }
    let content = parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES)?;
    let value: serde_yaml::Value =
        crate::lockfiles::parse_yaml_guarded(&content).map_err(|err| {
            anyhow::anyhow!(
                "Broken manifest '{}': failed to parse YAML: {}",
                path.display(),
                err
            )
        })?;
    if value
        .as_mapping()
        .is_some_and(|mapping| mapping.keys().any(|key| key.as_str() != Some("packages")))
    {
        anyhow::bail!(
            "Unsupported pnpm workspace dependency rewrite configuration '{}': only package membership is supported",
            path.display()
        );
    }
    let packages = value
        .get("packages")
        .and_then(|value| value.as_sequence())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Broken manifest '{}': packages must be an array of strings.",
                path.display()
            )
        })?;
    let mut patterns = Vec::with_capacity(packages.len());
    for entry in packages {
        let Some(pattern) = entry.as_str() else {
            anyhow::bail!(
                "Broken manifest '{}': packages entries must be strings.",
                path.display()
            );
        };
        patterns.push(pattern.to_string());
    }
    Ok(Some(patterns))
}

pub(crate) fn workspace_manifest_paths(
    workspace_root: &WorkspaceRoot,
    ignore_dirs: &[String],
) -> Result<Vec<std::path::PathBuf>> {
    let root = std::fs::canonicalize(&workspace_root.project_dir).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {}: {}",
            workspace_root.project_dir.display(),
            err
        )
    })?;
    let mut visited = std::collections::HashSet::new();
    let mut specs = Vec::new();
    walk_project_tree(
        &workspace_root.project_dir,
        &root,
        &mut visited,
        &mut specs,
        false,
        ignore_dirs,
    )?;
    Ok(specs
        .into_iter()
        .filter(|spec| {
            spec.kind == ProjectInputKind::Npm
                && workspace_patterns_match(
                    &workspace_root.project_dir,
                    spec.project_dir(),
                    workspace_root.patterns.iter().map(String::as_str),
                )
        })
        .map(|spec| spec.manifest_path)
        .collect())
}

pub(crate) fn parse_npm_workspaces(
    manifest_path: &std::path::Path,
    manifest: &serde_json::Value,
) -> Result<Option<Vec<String>>> {
    let Some(value) = manifest.get("workspaces") else {
        return Ok(None);
    };

    let patterns = if let Some(array) = value.as_array() {
        array
            .iter()
            .map(|entry| {
                entry.as_str().map(str::to_string).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Broken manifest '{}': workspaces entries must be strings.",
                        manifest_path.display()
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?
    } else if let Some(array) = value
        .get("packages")
        .and_then(|packages| packages.as_array())
    {
        array
            .iter()
            .map(|entry| {
                entry.as_str().map(str::to_string).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Broken manifest '{}': workspaces.packages entries must be strings.",
                        manifest_path.display()
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        anyhow::bail!(
            "Broken manifest '{}': workspaces must be an array of strings or an object with a packages array.",
            manifest_path.display()
        );
    };

    Ok(Some(patterns))
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
