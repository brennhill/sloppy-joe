use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub(crate) use crate::cache::canonicalize_with_existing_ancestors;
pub use crate::cache::find_git_root;

/// Return the platform-appropriate config home directory for sloppy-joe.
///
/// Resolution order:
/// 1. `XDG_CONFIG_HOME/sloppy-joe/` if XDG_CONFIG_HOME is set
/// 2. Platform default (macOS: ~/Library/Application Support/sloppy-joe/, Linux: ~/.config/sloppy-joe/)
/// 3. Legacy fallback: `~/.sloppy-joe/` if it exists and the XDG location doesn't
pub fn config_home() -> Result<PathBuf, String> {
    // 1. XDG_CONFIG_HOME if set
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        let xdg_path = Path::new(&xdg);
        if !xdg_path.is_absolute() {
            return Err(format!(
                "XDG_CONFIG_HOME must be an absolute path.\n  Value: {}\n  Fix: Set XDG_CONFIG_HOME to an absolute path (e.g. /home/user/.config).",
                xdg_path.display()
            ));
        }
        return Ok(xdg_path.join("sloppy-joe"));
    }

    // 2. Platform default
    let home = std::env::var_os("HOME").map(PathBuf::from);

    #[cfg(target_os = "macos")]
    let platform_default = home.as_ref().map(|h| {
        h.join("Library")
            .join("Application Support")
            .join("sloppy-joe")
    });

    #[cfg(not(target_os = "macos"))]
    let platform_default = home.as_ref().map(|h| h.join(".config").join("sloppy-joe"));

    // 3. Legacy fallback: ~/.sloppy-joe/ if it exists and platform default doesn't
    if let Some(ref home) = home {
        let legacy = home.join(".sloppy-joe");
        if let Some(ref pd) = platform_default
            && !pd.exists()
            && legacy.exists()
        {
            return Ok(legacy);
        }
    }

    platform_default.ok_or_else(|| {
        "Could not determine config home directory.\n  Error: HOME environment variable is not set.\n  Fix: Set HOME or XDG_CONFIG_HOME.".to_string()
    })
}

/// Read and parse `{config_home}/registry.json`.
/// Returns an empty map if the file doesn't exist.
/// Returns a blocking error on malformed JSON.
pub fn load_registry() -> Result<BTreeMap<String, String>, String> {
    let path = config_home()?.join("registry.json");
    load_registry_from(&path)
}

fn load_registry_from(path: &Path) -> Result<BTreeMap<String, String>, String> {
    crate::cache::ensure_no_symlink(path).map_err(|e| {
        format!(
            "Refusing to read symlinked registry file.\n  Path: {}\n  Error: {}\n  Fix: Remove the symlink.",
            path.display(),
            e
        )
    })?;
    match std::fs::read_to_string(path) {
        Ok(content) => serde_json::from_str(&content).map_err(|e| {
            format!(
                "Registry file is corrupted.\n  Path: {}\n  Error: {}\n  Fix: Delete the file and re-register your projects with `sloppy-joe register`.",
                path.display(),
                e
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(format!(
            "Could not read registry file.\n  Path: {}\n  Error: {}\n  Fix: Check file permissions.",
            path.display(),
            e
        )),
    }
}

/// Atomically write the registry map to `{config_home}/registry.json`.
/// Uses `cache::atomic_write_json_checked` for safe writes with error reporting.
pub fn save_registry(entries: &BTreeMap<String, String>) -> Result<(), String> {
    let path = config_home()?.join("registry.json");
    save_registry_to(&path, entries)
}

pub(crate) fn save_registry_at_config_home(
    config_home: &Path,
    entries: &BTreeMap<String, String>,
) -> Result<(), String> {
    save_registry_to(&config_home.join("registry.json"), entries)
}

fn save_registry_to(path: &Path, entries: &BTreeMap<String, String>) -> Result<(), String> {
    // atomic_write_json_checked handles symlink checks, dir creation, and 0o600 permissions
    crate::cache::atomic_write_json_checked(path, entries)
}

/// Register a repo root → config path mapping.
/// Canonicalizes both paths and validates the config path exists.
pub fn register(repo_root: &Path, config_path: &Path) -> Result<(), String> {
    register_at_config_home(repo_root, config_path, &config_home()?)
}

#[doc(hidden)]
pub fn ensure_config_path_outside_repo(
    repo_root: &Path,
    config_path: &Path,
    label: &str,
) -> Result<(), String> {
    let canon_root = std::fs::canonicalize(repo_root).map_err(|e| {
        format!(
            "Could not resolve repo root path.\n  Path: {}\n  Error: {}\n  Fix: Check that the directory exists.",
            repo_root.display(),
            e
        )
    })?;
    let resolved_config = canonicalize_with_existing_ancestors(config_path)?;
    if resolved_config.starts_with(&canon_root) {
        return Err(format!(
            "{} must live outside the project directory.\n  Config: {}\n  Project: {}\n  Fix: Move the config file outside the repo.",
            label,
            resolved_config.display(),
            canon_root.display()
        ));
    }
    Ok(())
}

#[doc(hidden)]
pub fn ensure_config_home_outside_project(
    project_dir: &Path,
    config_home: &Path,
) -> Result<(), String> {
    let boundary_root = match find_git_root(project_dir)? {
        Some(git_root) => git_root,
        None => std::fs::canonicalize(project_dir).map_err(|e| {
            format!(
                "Could not resolve project directory.\n  Path: {}\n  Error: {}\n  Fix: Check that the directory exists and is accessible.",
                project_dir.display(),
                e
            )
        })?,
    };

    ensure_config_path_outside_repo(
        &boundary_root,
        &config_home.join("registry.json"),
        "Registry file",
    )?;
    ensure_config_path_outside_repo(
        &boundary_root,
        &config_home.join("default").join("config.json"),
        "Default config",
    )?;
    ensure_config_path_outside_repo(
        &boundary_root,
        &config_home.join("local-overlay.json"),
        "Local overlay",
    )?;
    Ok(())
}

#[doc(hidden)]
pub fn register_at_config_home(
    repo_root: &Path,
    config_path: &Path,
    config_home: &Path,
) -> Result<(), String> {
    ensure_config_path_outside_repo(repo_root, config_path, "Config file")?;

    let canon_root = std::fs::canonicalize(repo_root).map_err(|e| {
        format!(
            "Could not resolve repo root path.\n  Path: {}\n  Error: {}\n  Fix: Check that the directory exists.",
            repo_root.display(),
            e
        )
    })?;
    let canon_config = std::fs::canonicalize(config_path).map_err(|e| {
        format!(
            "Could not resolve config path.\n  Path: {}\n  Error: {}\n  Fix: Check that the config file exists.",
            config_path.display(),
            e
        )
    })?;

    // Validate config path is not inside the repo
    if canon_config.starts_with(&canon_root) {
        return Err(format!(
            "Config file must live outside the project directory.\n  Config: {}\n  Project: {}\n  Fix: Move the config file outside the repo.",
            canon_config.display(),
            canon_root.display()
        ));
    }

    let mut entries = load_registry_from(&config_home.join("registry.json"))?;
    entries.insert(
        canon_root.to_string_lossy().to_string(),
        canon_config.to_string_lossy().to_string(),
    );
    save_registry_at_config_home(config_home, &entries)
}

/// Remove a repo root from the registry.
/// Returns `Ok(true)` if an entry was removed, `Ok(false)` if the repo was not registered.
pub fn unregister(repo_root: &Path) -> Result<bool, String> {
    let canon_root = std::fs::canonicalize(repo_root).map_err(|e| {
        format!(
            "Could not resolve repo root path.\n  Path: {}\n  Error: {}\n  Fix: Check that the directory exists.",
            repo_root.display(),
            e
        )
    })?;

    let mut entries = load_registry()?;
    let removed = entries
        .remove(&canon_root.to_string_lossy().to_string())
        .is_some();
    save_registry(&entries)?;
    Ok(removed)
}

/// Look up the config path for a project directory.
///
/// Resolution:
/// 1. Find git root from project_dir
/// 2. Check registry for git root
/// 3. Check `{config_home}/default/config.json`
/// 4. Return None
pub fn lookup(project_dir: &Path) -> Result<Option<String>, String> {
    let config_home = config_home()?;
    ensure_config_home_outside_project(project_dir, &config_home)?;
    let git_root = find_git_root(project_dir)?;

    if let Some(ref root) = git_root {
        let registry_path = config_home.join("registry.json");
        let entries = load_registry_from(&registry_path)?;
        let root_str = root.to_string_lossy().to_string();
        if let Some(config_path) = entries.get(&root_str) {
            let canon = std::fs::canonicalize(config_path).map_err(|e| {
                format!(
                    "Registry entry points to missing config file.\n  Path: {}\n  Error: {}\n  Fix: Re-register the project with `sloppy-joe register` or remove the stale entry.",
                    config_path, e
                )
            })?;
            // Defense in depth: validate config is outside the project dir
            if canon.starts_with(root) {
                return Err(format!(
                    "Registry entry points to config inside the project directory.\n  Config: {}\n  Project: {}\n  Fix: Re-register with a config file outside the repo.",
                    canon.display(),
                    root.display()
                ));
            }
            return Ok(Some(canon.to_string_lossy().to_string()));
        }
    }

    // Check global default
    let default_config = config_home.join("default").join("config.json");
    if default_config.exists() {
        let canon = std::fs::canonicalize(&default_config).map_err(|e| {
            format!(
                "Could not resolve default config path.\n  Path: {}\n  Error: {}\n  Fix: Check that the default config file is accessible.",
                default_config.display(), e
            )
        })?;
        // Defense in depth: validate default config is outside the project dir
        if let Some(ref root) = git_root
            && canon.starts_with(root)
        {
            return Err(format!(
                "Default config resolves inside the project directory.\n  Config: {}\n  Project: {}\n  Fix: Move the default config outside the repo or check for symlinks.",
                canon.display(),
                root.display()
            ));
        }
        return Ok(Some(canon.to_string_lossy().to_string()));
    }

    Ok(None)
}

#[cfg(test)]
mod tests;
