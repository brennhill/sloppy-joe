use crate::*;

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

pub(crate) fn validate_js_manifest_security_policy(
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
) -> Result<()> {
    if manifest.get("overrides").is_some() {
        anyhow::bail!(
            "package.json '{}' uses npm overrides. Overrides change the resolved dependency graph, and sloppy-joe does not yet have strict override verification. Remove overrides or review this project with another control until strict support exists.",
            spec.manifest_path.display()
        );
    }
    if manifest.get("resolutions").is_some() || manifest.get("pnpm").is_some() {
        anyhow::bail!(
            "Unsupported JS dependency rewrite configuration in '{}': resolutions and pnpm settings cannot be verified against the lockfile",
            spec.manifest_path.display()
        );
    }

    Ok(())
}

pub(crate) fn validate_npm_lockfile_version(
    lockfile: &serde_json::Value,
    lockfile_path: &std::path::Path,
    config: &config::SloppyJoeConfig,
) -> Result<()> {
    let version = npm_lockfile_version(lockfile, lockfile_path)?;

    if version == 1 && !config.allow_legacy_npm_v1_lockfile {
        anyhow::bail!(
            "This repo is using a legacy npm v5/v6 lockfile ('{}', lockfileVersion: 1). Regenerate with a modern npm. If you must keep it temporarily, set allow_legacy_npm_v1_lockfile to true.",
            lockfile_path.display()
        );
    }

    Ok(())
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

pub(crate) fn ensure_lockfile_readable(path: &std::path::Path, help: &str) -> Result<()> {
    parsers::read_file_limited(path, parsers::MAX_MANIFEST_BYTES)
        .and_then(|content| {
            if content.trim().is_empty() {
                anyhow::bail!("lockfile is empty");
            }
            Ok(())
        })
        .map_err(|err| {
            anyhow::anyhow!(
                "Required lockfile '{}' is missing or unreadable: {}. Fix: {}",
                path.display(),
                err,
                help
            )
        })
}

pub(crate) fn ensure_one_lockfile_readable(
    project_dir: &std::path::Path,
    candidates: &[&str],
    help: &str,
) -> Result<()> {
    let mut found_readable = false;

    for candidate in candidates {
        let path = project_dir.join(candidate);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                parsers::read_file_limited(&path, parsers::MAX_MANIFEST_BYTES).map_err(|err| {
                    anyhow::anyhow!(
                        "Required lockfile '{}' is unreadable: {}. Fix: {}",
                        path.display(),
                        err,
                        help
                    )
                })?;
                found_readable = true;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "Required lockfile '{}' could not be inspected: {}. Fix: {}",
                    path.display(),
                    err,
                    help
                ));
            }
        }
    }

    if found_readable {
        return Ok(());
    }

    anyhow::bail!(
        "Required lockfile '{}' is missing. Fix: {}",
        candidates.join("' or '"),
        help
    )
}

pub(crate) fn ensure_authoritative_js_lockfile_readable(spec: &ProjectInputSpec) -> Result<()> {
    let help = js_lockfile_help(spec);
    let Some(binding) = &spec.js_binding else {
        return ensure_one_lockfile_readable(
            spec.project_dir(),
            &["npm-shrinkwrap.json", "package-lock.json"],
            &help,
        );
    };
    let root_dir = binding
        .root_manifest_path
        .parent()
        .expect("package.json should always have a parent directory");
    let canonical_project_dir = std::fs::canonicalize(spec.project_dir()).map_err(|err| {
        anyhow::anyhow!(
            "Failed to inspect {}: {}",
            spec.project_dir().display(),
            err
        )
    })?;
    let canonical_root_dir = std::fs::canonicalize(root_dir)
        .map_err(|err| anyhow::anyhow!("Failed to inspect {}: {}", root_dir.display(), err))?;
    let shadow_lockfile = if canonical_project_dir != canonical_root_dir {
        first_existing_lockfile(
            spec.project_dir(),
            &[
                "npm-shrinkwrap.json",
                "package-lock.json",
                "pnpm-lock.yaml",
                "yarn.lock",
                "bun.lock",
                "bun.lockb",
            ],
        )
    } else {
        None
    };
    if let Some(shadow) = shadow_lockfile {
        anyhow::bail!(
            "Found shadow JS lockfile '{}' under workspace project '{}'. The authoritative {} lockfile lives at '{}'. Remove the child lockfile and keep the workspace root lockfile as the single source of truth.",
            shadow.display(),
            spec.manifest_path.display(),
            binding.manager.as_str(),
            binding
                .lockfile_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<missing>".to_string())
        );
    }
    let Some(path) = &binding.lockfile_path else {
        let expected = match binding.manager {
            JsPackageManager::Npm => "'npm-shrinkwrap.json' or 'package-lock.json'",
            JsPackageManager::Pnpm => "'pnpm-lock.yaml'",
            JsPackageManager::Yarn => "'yarn.lock'",
            JsPackageManager::Bun => "'bun.lock' or 'bun.lockb'",
        };
        anyhow::bail!(
            "Required lockfile {} is missing for {} project '{}'. Fix: {}",
            expected,
            binding.manager.as_str(),
            spec.manifest_path.display(),
            help
        );
    };
    ensure_lockfile_readable(path, &help)
}
