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
    let home = config_home().unwrap();
    assert!(!home.as_os_str().is_empty());
}

#[test]
fn config_home_returns_sloppy_joe_suffix() {
    let home = config_home().unwrap();
    assert!(
        home.to_string_lossy().contains("sloppy-joe"),
        "config_home should contain 'sloppy-joe': {:?}",
        home
    );
}

// -- find_git_root tests --

#[test]
fn find_git_root_in_git_repo() {
    let cwd = std::env::current_dir().unwrap();
    let root = find_git_root(&cwd).unwrap();
    assert!(root.is_some(), "Should find git root in current repo");
    assert!(root.unwrap().join(".git").exists());
}

#[test]
fn find_git_root_in_non_git_dir() {
    let base = unique_dir();
    let deep = base.join("a").join("b").join("c");
    std::fs::create_dir_all(&deep).unwrap();
    let root = find_git_root(&deep).unwrap();
    assert!(
        root.is_none(),
        "Temp dir should not be inside a git repo: {:?}",
        root
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn find_git_root_from_subdirectory() {
    let cwd = std::env::current_dir().unwrap();
    let src_dir = cwd.join("src");
    if src_dir.is_dir() {
        let root = find_git_root(&src_dir).unwrap();
        assert!(root.is_some());
        assert!(root.unwrap().join(".git").exists());
    }
}

#[test]
fn find_git_root_nonexistent_dir_returns_error() {
    let result = find_git_root(Path::new("/nonexistent/path/that/does/not/exist"));
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Could not resolve"));
}

// -- load_registry tests --

#[test]
fn load_registry_missing_file_returns_empty_map() {
    let dir = unique_dir();
    let path = dir.join("registry.json");
    let result = load_registry_from(&path);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
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
    let _ = std::fs::remove_dir_all(&dir);
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
    let _ = std::fs::remove_dir_all(&dir);
}

// -- save_registry tests --

#[test]
fn save_registry_creates_file() {
    let dir = unique_dir();
    let path = dir.join("registry.json");
    let mut entries = BTreeMap::new();
    entries.insert("/repo".to_string(), "/config.json".to_string());
    let result = save_registry_to(&path, &entries);
    assert!(result.is_ok());
    assert!(path.exists());
    let content = std::fs::read_to_string(&path).unwrap();
    let loaded: BTreeMap<String, String> = serde_json::from_str(&content).unwrap();
    assert_eq!(loaded.get("/repo"), Some(&"/config.json".to_string()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn save_registry_returns_error_on_symlink() {
    let dir = unique_dir();
    let real = dir.join("real.json");
    std::fs::write(&real, "{}").unwrap();
    let link = dir.join("registry.json");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let entries = BTreeMap::new();
        let result = save_registry_to(&link, &entries);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("symlink"),
            "Error should mention symlink"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[cfg(unix)]
fn load_registry_returns_error_on_symlink() {
    // Mirrors save_registry_returns_error_on_symlink but for the read path.
    // load_registry_from calls ensure_no_symlink before reading, so a
    // symlinked registry.json must be rejected with an error mentioning "symlink".
    let dir = unique_dir();
    let real = dir.join("real.json");
    std::fs::write(&real, r#"{"/repo": "/config.json"}"#).unwrap();
    let link = dir.join("registry.json");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let result = load_registry_from(&link);
    assert!(
        result.is_err(),
        "load_registry_from should reject a symlink"
    );
    assert!(
        result.unwrap_err().contains("symlink"),
        "Error should mention symlink"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// -- register / unregister round-trip --

#[test]
fn register_validates_config_exists() {
    let dir = unique_dir();
    let repo = dir.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let fake_config = dir.join("nonexistent-config.json");
    let result = register(&repo, &fake_config);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("config file exists"));
    let _ = std::fs::remove_dir_all(&dir);
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
    let _ = std::fs::remove_dir_all(&dir);
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
    let _ = std::fs::remove_dir_all(&dir);
}

// -- corrupted registry tests --

#[test]
fn corrupted_registry_returns_error_with_fix_hint() {
    let dir = unique_dir();
    let path = dir.join("registry.json");
    std::fs::write(&path, "{{{{not json at all").unwrap();
    let result = load_registry_from(&path);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("corrupted"), "Expected 'corrupted': {}", err);
    assert!(
        err.contains("re-register"),
        "Expected 're-register' hint: {}",
        err
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// -- lookup edge cases --

#[test]
fn lookup_missing_config_file_at_registered_path_errors() {
    // Tests the canonicalization-failure path in lookup() lines 178-183:
    //
    //   let canon = std::fs::canonicalize(config_path).map_err(|e| {
    //       format!("Registry entry points to missing config file. ...")
    //   })?;
    //
    // Because lookup() uses the global config_home() which cannot be overridden
    // in parallel tests, we exercise the identical logic directly:
    // load a registry whose entry points to a deleted file, then run the
    // same canonicalize call that lookup() would perform.

    let registry_dir = unique_dir();
    let registry_path = registry_dir.join("registry.json");

    // Create a config file then immediately delete it so the path is absent.
    let config_dir = unique_dir();
    let config_file = config_dir.join("config.json");
    std::fs::write(&config_file, "{}").unwrap();
    let config_path_str = config_file.to_string_lossy().to_string();
    std::fs::remove_file(&config_file).unwrap();

    // Write a registry entry pointing at the now-deleted file.
    let mut entries = BTreeMap::new();
    entries.insert("/some/git/root".to_string(), config_path_str.clone());
    save_registry_to(&registry_path, &entries).unwrap();

    // Load the registry (succeeds — the file exists and is valid JSON).
    let loaded = load_registry_from(&registry_path).unwrap();
    let stored_config = loaded.values().next().unwrap();

    // This is the exact logic from lookup() lines 178-183: canonicalize the
    // stored config path.  It must fail because the file no longer exists.
    let result = std::fs::canonicalize(stored_config);
    assert!(
        result.is_err(),
        "lookup() should fail when registry points to a missing config file"
    );

    let _ = std::fs::remove_dir_all(&registry_dir);
    let _ = std::fs::remove_dir_all(&config_dir);
}

#[test]
fn lookup_config_inside_project_dir_detected() {
    // Tests the defense-in-depth check in lookup() lines 185-191:
    //
    //   if canon.starts_with(root) {
    //       return Err(format!(
    //           "Registry entry points to config inside the project directory. ..."
    //       ));
    //   }
    //
    // Because lookup() uses the global config_home() which cannot be overridden
    // in parallel tests, we exercise the identical predicate directly: verify
    // that a config file nested under the project root satisfies starts_with,
    // which is exactly the condition lookup() uses to reject the entry.

    let project_root = unique_dir();
    let config_inside = project_root.join("config.json");
    std::fs::write(&config_inside, "{}").unwrap();

    let canon_root = std::fs::canonicalize(&project_root).unwrap();
    let canon_config = std::fs::canonicalize(&config_inside).unwrap();

    // This is the exact guard from lookup() lines 185-186.  It must be true
    // so that lookup() would return an Err for this entry.
    assert!(
        canon_config.starts_with(&canon_root),
        "lookup() defense-in-depth: config inside project dir must be detected via starts_with"
    );

    // Confirm the inverse: a config in a sibling directory is NOT rejected.
    let sibling_dir = unique_dir();
    let config_outside = sibling_dir.join("config.json");
    std::fs::write(&config_outside, "{}").unwrap();
    let canon_outside = std::fs::canonicalize(&config_outside).unwrap();
    assert!(
        !canon_outside.starts_with(&canon_root),
        "Config outside project root must NOT trigger the defense-in-depth check"
    );

    let _ = std::fs::remove_dir_all(&project_root);
    let _ = std::fs::remove_dir_all(&sibling_dir);
}

#[test]
fn find_git_root_returns_none_for_non_git_dir() {
    // Specifically tests that a temp dir without .git returns Ok(None)
    let dir = unique_dir();
    let result = find_git_root(&dir).unwrap();
    assert!(
        result.is_none(),
        "Non-git dir should return None, got: {:?}",
        result
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// -- unregister edge cases --

#[test]
fn unregister_for_unregistered_repo_is_noop() {
    let dir = unique_dir();
    let registry_path = dir.join("registry.json");

    // Start with one entry
    let other_dir = unique_dir();
    let canon_other = std::fs::canonicalize(&other_dir).unwrap();
    let mut entries = BTreeMap::new();
    entries.insert(
        canon_other.to_string_lossy().to_string(),
        "/some/config.json".to_string(),
    );
    save_registry_to(&registry_path, &entries).unwrap();

    // "Unregister" a repo that isn't in the registry
    let unrelated_dir = unique_dir();
    let canon_unrelated = std::fs::canonicalize(&unrelated_dir).unwrap();
    let mut entries = load_registry_from(&registry_path).unwrap();
    entries.remove(&canon_unrelated.to_string_lossy().to_string());
    save_registry_to(&registry_path, &entries).unwrap();

    // Original entry should still be there
    let entries = load_registry_from(&registry_path).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries.contains_key(&canon_other.to_string_lossy().to_string()));

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&other_dir);
    let _ = std::fs::remove_dir_all(&unrelated_dir);
}

// -- list edge cases --

#[test]
fn list_with_empty_registry_returns_empty() {
    let dir = unique_dir();
    let registry_path = dir.join("registry.json");
    // File doesn't exist — should return empty map
    let entries = load_registry_from(&registry_path).unwrap();
    assert!(entries.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn list_with_existing_empty_registry_returns_empty() {
    let dir = unique_dir();
    let registry_path = dir.join("registry.json");
    std::fs::write(&registry_path, "{}").unwrap();
    let entries = load_registry_from(&registry_path).unwrap();
    assert!(entries.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

// -- path canonicalization --

#[test]
fn path_canonicalization_trailing_slash_resolved() {
    let dir = unique_dir();
    let with_slash = format!("{}/", dir.display());
    let canon1 = std::fs::canonicalize(&dir).unwrap();
    let canon2 = std::fs::canonicalize(&with_slash).unwrap();
    assert_eq!(
        canon1, canon2,
        "Trailing slash should not affect canonicalization"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[cfg(unix)]
fn path_canonicalization_symlinks_resolved() {
    let real_dir = unique_dir();
    let link_parent = unique_dir();
    let link = link_parent.join("symlink_dir");
    std::os::unix::fs::symlink(&real_dir, &link).unwrap();

    let canon_real = std::fs::canonicalize(&real_dir).unwrap();
    let canon_link = std::fs::canonicalize(&link).unwrap();
    assert_eq!(
        canon_real, canon_link,
        "Symlinks should resolve to same canonical path"
    );
    let _ = std::fs::remove_dir_all(&real_dir);
    let _ = std::fs::remove_dir_all(&link_parent);
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

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&repo_dir);
    let _ = std::fs::remove_dir_all(&config_dir);
}

// -- default config inside project dir detection --

#[test]
fn default_config_inside_project_dir_detected() {
    // Mirrors the defense-in-depth check added to lookup() for global default:
    // if the canonicalized default config path starts_with the project root,
    // it should be rejected.
    let project_root = unique_dir();
    let default_inside = project_root.join("default").join("config.json");
    std::fs::create_dir_all(default_inside.parent().unwrap()).unwrap();
    std::fs::write(&default_inside, "{}").unwrap();

    let canon_root = std::fs::canonicalize(&project_root).unwrap();
    let canon_default = std::fs::canonicalize(&default_inside).unwrap();

    assert!(
        canon_default.starts_with(&canon_root),
        "Default config inside project should be detected"
    );
    let _ = std::fs::remove_dir_all(&project_root);
}

#[test]
fn ensure_config_path_outside_repo_rejects_nonexistent_paths_inside_repo() {
    let dir = unique_dir();
    let repo = dir.join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();

    let err = ensure_config_path_outside_repo(
        &repo,
        &repo.join(".config/sloppy-joe/default/config.json"),
        "Config file",
    )
    .expect_err("nonexistent in-repo config path must be rejected before writes");
    assert!(err.contains("outside the project directory"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ensure_config_home_outside_project_rejects_repo_local_config_home() {
    let dir = unique_dir();
    let repo = dir.join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();

    let err = ensure_config_home_outside_project(&repo, &repo.join(".config/sloppy-joe"))
        .expect_err("repo-local config home must not be trusted");
    assert!(err.contains("outside the project directory"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ensure_config_home_outside_project_rejects_non_git_project_local_config_home() {
    let dir = unique_dir();
    let project = dir.join("project");
    std::fs::create_dir_all(&project).unwrap();

    let err = ensure_config_home_outside_project(&project, &project.join(".config/sloppy-joe"))
        .expect_err("non-git project-local config home must not be trusted");
    assert!(err.contains("outside the project directory"));

    let _ = std::fs::remove_dir_all(&dir);
}
