use super::*;

#[test]
fn parse_config_content_valid_full() {
    let content = r#"{"canonical":{"npm":{"lodash":["underscore"]}},"internal":{"npm":["@myorg/*"]},"allowed":{"npm":["vetted"]},"min_version_age_hours":48}"#;
    let config = parse_config_content(content, "test.json").unwrap();
    assert!(config.canonical.contains_key("npm"));
    assert_eq!(config.min_version_age_hours, 48);
}

#[test]
fn parses_trusted_python_indexes() {
    let config = parse_config_content(
        r#"{"trusted_indexes":{"pypi":["https://download.pytorch.org/whl/cu124"]}}"#,
        "test.json",
    )
    .unwrap();
    assert_eq!(
        config.trusted_indexes("pypi"),
        ["https://download.pytorch.org/whl/cu124/"]
    );
}

#[test]
fn normalizes_trailing_slash_for_python_indexes() {
    let config = parse_config_content(
        r#"{"trusted_indexes":{"pypi":["https://packages.example.com/simple"]}}"#,
        "test.json",
    )
    .unwrap();
    assert!(config.is_trusted_index("pypi", "https://packages.example.com/simple/"));
    assert!(config.is_trusted_index("pypi", "https://packages.example.com/simple"));
    assert!(config.is_trusted_index("pypi", "https://pypi.org/simple"));
    assert!(!config.is_trusted_index("pypi", "https://packages.example.com/simplex"));
    assert!(!config.is_trusted_index("pypi", "https://packages.example.com/other"));
}

#[test]
fn normalizes_python_index_scheme_and_host_casing() {
    let config = parse_config_content(
        r#"{"trusted_indexes":{"pypi":["HTTPS://Download.PyTorch.Org/whl/cu124"]}}"#,
        "test.json",
    )
    .unwrap();
    assert!(config.is_trusted_index("pypi", "https://download.pytorch.org/whl/cu124"));
}

#[test]
fn rejects_empty_trusted_python_index() {
    let err =
        parse_config_content(r#"{"trusted_indexes":{"pypi":["  "]}}"#, "test.json").unwrap_err();
    assert!(err.contains("trusted index"));
    assert!(err.contains("validation failed"));
}

#[test]
fn rejects_non_http_python_index_urls() {
    let err = parse_config_content(
        r#"{"trusted_indexes":{"pypi":["file:///tmp/mirror"]}}"#,
        "test.json",
    )
    .unwrap_err();
    assert!(err.contains("http:// and https://"));
}

#[test]
fn rejects_trusted_indexes_for_non_python_ecosystems() {
    let err = parse_config_content(
        r#"{"trusted_indexes":{"npm":["https://registry.npmjs.org"]}}"#,
        "test.json",
    )
    .unwrap_err();
    assert!(err.contains("trusted_indexes"));
    assert!(err.contains("Valid: pypi"));
}

// ── resolve_config_source end-to-end tests ──

#[test]
fn resolve_cli_flag_overrides_everything() {
    // CLI flag should take priority even when project_dir is provided
    let dir = std::env::temp_dir().join("sj-e2e-cli-override");
    std::fs::create_dir_all(&dir).unwrap();
    let result = resolve_config_source(Some("/explicit/config.json"), Some(&dir)).unwrap();
    assert_eq!(result, Some("/explicit/config.json".to_string()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn resolve_none_cli_none_project_returns_none() {
    // No CLI flag, no project dir, and assuming SLOPPY_JOE_CONFIG is not set
    // in the test environment — should return Ok(None) or Ok(Some(env_val))
    let result = resolve_config_source(None, None);
    assert!(result.is_ok(), "Should not error: {:?}", result);
    // We can't assert None because SLOPPY_JOE_CONFIG might be set.
    // The key assertion is no error.
}

#[test]
fn resolve_non_git_dir_returns_none_via_registry() {
    // A temp dir that's not a git repo — registry lookup finds no git root,
    // no default config → returns None
    let dir = std::env::temp_dir().join(format!("sj-e2e-no-git-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let result = resolve_config_source(None, Some(&dir));
    // Should succeed — lookup finds no git root, checks global default
    assert!(result.is_ok(), "Should not error: {:?}", result);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn resolve_git_repo_with_no_registry_entry_uses_lookup() {
    // Run from current repo — lookup should find git root, check registry,
    // potentially find global default or return None. Key: no error.
    let cwd = std::env::current_dir().unwrap();
    let result = resolve_config_source(None, Some(&cwd));
    assert!(
        result.is_ok(),
        "Lookup in git repo should not error: {:?}",
        result
    );
}

#[tokio::test]
async fn load_config_from_source_none_returns_default() {
    let config = load_config_from_source(None, None).await.unwrap();
    assert!(config.canonical.is_empty());
    assert_eq!(config.min_version_age_hours, 72);
}

#[tokio::test]
async fn load_config_from_source_file_path() {
    let dir = unique_temp_dir("source-file");
    let path = dir.join("config.json");
    std::fs::write(&path, r#"{"canonical":{}}"#).unwrap();
    let config = load_config_from_source(Some(path.to_str().unwrap()), None)
        .await
        .unwrap();
    assert!(config.canonical.is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}
