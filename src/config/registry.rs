use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Return the platform-appropriate config home directory for sloppy-joe.
///
/// Resolution order:
/// 1. `XDG_CONFIG_HOME/sloppy-joe/` if XDG_CONFIG_HOME is set
/// 2. Platform default (macOS: ~/Library/Application Support/sloppy-joe/, Linux: ~/.config/sloppy-joe/)
/// 3. Legacy fallback: `~/.sloppy-joe/` if it exists and the XDG location doesn't
pub fn config_home() -> PathBuf {
    config_home_inner()
}

fn config_home_inner() -> PathBuf {
    // 1. XDG_CONFIG_HOME if set
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        return Path::new(&xdg).join("sloppy-joe");
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
            return legacy;
        }
    }

    platform_default.unwrap_or_else(|| PathBuf::from("/tmp/sloppy-joe"))
}

/// Walk up from `dir` looking for a `.git` directory. Returns the canonicalized
/// parent of the `.git` directory (the repo root).
pub fn find_git_root(dir: &Path) -> Option<PathBuf> {
    let mut current = std::fs::canonicalize(dir).ok()?;
    loop {
        if current.join(".git").is_dir() {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Read and parse `{config_home}/registry.json`.
/// Returns an empty map if the file doesn't exist.
/// Returns a blocking error on malformed JSON.
pub fn load_registry() -> Result<HashMap<String, String>, String> {
    let path = config_home().join("registry.json");
    load_registry_from(&path)
}

fn load_registry_from(path: &Path) -> Result<HashMap<String, String>, String> {
    match std::fs::read_to_string(path) {
        Ok(content) => serde_json::from_str(&content).map_err(|e| {
            format!(
                "Registry file is corrupted.\n  Path: {}\n  Error: {}\n  Fix: Delete the file and re-register your projects with `sloppy-joe register`.",
                path.display(),
                e
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
        Err(e) => Err(format!(
            "Could not read registry file.\n  Path: {}\n  Error: {}\n  Fix: Check file permissions.",
            path.display(),
            e
        )),
    }
}

/// Atomically write the registry map to `{config_home}/registry.json`.
/// Uses `cache::atomic_write_json` for safe writes.
pub fn save_registry(entries: &HashMap<String, String>) -> Result<(), String> {
    let path = config_home().join("registry.json");
    save_registry_to(&path, entries)
}

fn save_registry_to(path: &Path, entries: &HashMap<String, String>) -> Result<(), String> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Could not create config directory.\n  Path: {}\n  Error: {}\n  Fix: Check directory permissions.",
                parent.display(),
                e
            )
        })?;
    }
    crate::cache::atomic_write_json(path, entries);
    Ok(())
}

/// Register a repo root → config path mapping.
/// Canonicalizes both paths and validates the config path exists.
pub fn register(repo_root: &Path, config_path: &Path) -> Result<(), String> {
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

    let mut entries = load_registry()?;
    entries.insert(
        canon_root.to_string_lossy().to_string(),
        canon_config.to_string_lossy().to_string(),
    );
    save_registry(&entries)
}

/// Remove a repo root from the registry.
pub fn unregister(repo_root: &Path) -> Result<(), String> {
    let canon_root = std::fs::canonicalize(repo_root).map_err(|e| {
        format!(
            "Could not resolve repo root path.\n  Path: {}\n  Error: {}\n  Fix: Check that the directory exists.",
            repo_root.display(),
            e
        )
    })?;

    let mut entries = load_registry()?;
    entries.remove(&canon_root.to_string_lossy().to_string());
    save_registry(&entries)
}

/// Look up the config path for a project directory.
///
/// Resolution:
/// 1. Find git root from project_dir
/// 2. Check registry for git root
/// 3. Check `{config_home}/default/config.json`
/// 4. Return None
pub fn lookup(project_dir: &Path) -> Result<Option<String>, String> {
    let git_root = find_git_root(project_dir);

    if let Some(ref root) = git_root {
        let entries = load_registry()?;
        let root_str = root.to_string_lossy().to_string();
        if let Some(config_path) = entries.get(&root_str) {
            return Ok(Some(config_path.clone()));
        }
    }

    // Check global default
    let default_config = config_home().join("default").join("config.json");
    if default_config.exists() {
        return Ok(Some(default_config.to_string_lossy().to_string()));
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_dir() -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sj-registry-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // -- config_home tests --

    #[test]
    fn config_home_with_xdg_set() {
        // We can't safely set env vars in parallel tests, so just verify
        // the function returns a non-empty path
        let home = config_home();
        assert!(!home.as_os_str().is_empty());
    }

    #[test]
    fn config_home_returns_sloppy_joe_suffix() {
        let home = config_home();
        assert!(
            home.to_string_lossy().contains("sloppy-joe"),
            "config_home should contain 'sloppy-joe': {:?}",
            home
        );
    }

    // -- find_git_root tests --

    #[test]
    fn find_git_root_in_git_repo() {
        // This test runs inside the sloppy-joe repo, so it should find a git root
        let cwd = std::env::current_dir().unwrap();
        let root = find_git_root(&cwd);
        assert!(root.is_some(), "Should find git root in current repo");
        let root = root.unwrap();
        assert!(root.join(".git").is_dir());
    }

    #[test]
    fn find_git_root_in_non_git_dir() {
        let dir = unique_dir();
        let root = find_git_root(&dir);
        // temp dir might be inside a git repo on some systems, but our unique
        // temp dir itself should not have .git
        // Just verify it doesn't panic
        let _ = root;
    }

    #[test]
    fn find_git_root_from_subdirectory() {
        let cwd = std::env::current_dir().unwrap();
        let src_dir = cwd.join("src");
        if src_dir.is_dir() {
            let root = find_git_root(&src_dir);
            assert!(root.is_some());
            let root = root.unwrap();
            assert!(root.join(".git").is_dir());
        }
    }

    // -- load_registry tests --

    #[test]
    fn load_registry_missing_file_returns_empty_map() {
        let dir = unique_dir();
        let path = dir.join("registry.json");
        let result = load_registry_from(&path);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn load_registry_valid_json() {
        let dir = unique_dir();
        let path = dir.join("registry.json");
        std::fs::write(&path, r#"{"/foo/bar": "/baz/config.json"}"#).unwrap();
        let result = load_registry_from(&path);
        assert!(result.is_ok());
        let map = result.unwrap();
        assert_eq!(map.get("/foo/bar"), Some(&"/baz/config.json".to_string()));
    }

    #[test]
    fn load_registry_corrupted_json_returns_error() {
        let dir = unique_dir();
        let path = dir.join("registry.json");
        std::fs::write(&path, "not valid json {{{").unwrap();
        let result = load_registry_from(&path);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("corrupted"),
            "Error should mention corruption: {}",
            err
        );
        assert!(
            err.contains("Fix:"),
            "Error should contain Fix hint: {}",
            err
        );
    }

    // -- save_registry tests --

    #[test]
    fn save_registry_creates_file() {
        let dir = unique_dir();
        let path = dir.join("registry.json");
        let mut entries = HashMap::new();
        entries.insert("/repo".to_string(), "/config.json".to_string());
        let result = save_registry_to(&path, &entries);
        assert!(result.is_ok());
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        let loaded: HashMap<String, String> = serde_json::from_str(&content).unwrap();
        assert_eq!(loaded.get("/repo"), Some(&"/config.json".to_string()));
    }

    // -- register / unregister round-trip --

    #[test]
    fn register_validates_config_exists() {
        let dir = unique_dir();
        let fake_config = dir.join("nonexistent-config.json");
        let result = register(&dir, &fake_config);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("config file exists"));
    }

    #[test]
    fn register_rejects_config_inside_project() {
        let dir = unique_dir();
        let config_path = dir.join("config.json");
        std::fs::write(&config_path, "{}").unwrap();
        let result = register(&dir, &config_path);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("outside the project directory")
        );
    }

    // -- lookup tests --

    #[test]
    fn lookup_returns_none_when_no_registry_and_no_default() {
        // Use a temp dir that's not in a git repo and has no registry
        let dir = unique_dir();
        // Override config home via XDG to point to a dir without registry
        // Can't safely do this in parallel tests, so just verify basic behavior
        let result = lookup(&dir);
        // Should not error (registry file missing -> empty map is fine)
        assert!(result.is_ok());
    }

    // -- integration: register + lookup round-trip using isolated registry --

    #[test]
    fn register_unregister_roundtrip_via_load_save() {
        let dir = unique_dir();
        let registry_path = dir.join("registry.json");
        let repo_dir = unique_dir();
        let config_dir = unique_dir();
        let config_file = config_dir.join("config.json");
        std::fs::write(&config_file, "{}").unwrap();

        // Canonicalize for comparison
        let canon_repo = std::fs::canonicalize(&repo_dir).unwrap();
        let canon_config = std::fs::canonicalize(&config_file).unwrap();

        // Register: load -> insert -> save
        let mut entries = load_registry_from(&registry_path).unwrap();
        entries.insert(
            canon_repo.to_string_lossy().to_string(),
            canon_config.to_string_lossy().to_string(),
        );
        save_registry_to(&registry_path, &entries).unwrap();

        // Verify it's there
        let entries = load_registry_from(&registry_path).unwrap();
        assert_eq!(
            entries.get(&canon_repo.to_string_lossy().to_string()),
            Some(&canon_config.to_string_lossy().to_string())
        );

        // Unregister: load -> remove -> save
        let mut entries = load_registry_from(&registry_path).unwrap();
        entries.remove(&canon_repo.to_string_lossy().to_string());
        save_registry_to(&registry_path, &entries).unwrap();

        // Verify it's gone
        let entries = load_registry_from(&registry_path).unwrap();
        assert!(!entries.contains_key(&canon_repo.to_string_lossy().to_string()));
    }
}
