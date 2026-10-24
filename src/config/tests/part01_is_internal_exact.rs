use super::*;

#[test]
fn is_internal_exact_match() {
    let config = SloppyJoeConfig {
        internal: HashMap::from([("npm".to_string(), vec!["my-pkg".to_string()])]),
        ..Default::default()
    };
    assert!(config.is_internal("npm", "my-pkg"));
}

#[test]
fn is_internal_glob_pattern() {
    let config = SloppyJoeConfig {
        internal: HashMap::from([("npm".to_string(), vec!["@myorg/*".to_string()])]),
        ..Default::default()
    };
    assert!(config.is_internal("npm", "@myorg/utils"));
    assert!(config.is_internal("npm", "@myorg/core"));
    assert!(!config.is_internal("npm", "@other/utils"));
}

#[test]
fn is_internal_missing_ecosystem() {
    let config = SloppyJoeConfig {
        internal: HashMap::from([("npm".to_string(), vec!["my-pkg".to_string()])]),
        ..Default::default()
    };
    assert!(!config.is_internal("pypi", "my-pkg"));
}

#[test]
fn is_allowed_exact_match() {
    let config = SloppyJoeConfig {
        allowed: HashMap::from([("npm".to_string(), vec!["vetted-pkg".to_string()])]),
        ..Default::default()
    };
    assert!(config.is_allowed("npm", "vetted-pkg"));
}

#[test]
fn is_allowed_glob_pattern() {
    let config = SloppyJoeConfig {
        allowed: HashMap::from([("go".to_string(), vec!["github.com/trusted/*".to_string()])]),
        ..Default::default()
    };
    assert!(config.is_allowed("go", "github.com/trusted/lib"));
}

#[test]
fn is_allowed_non_matching() {
    let config = SloppyJoeConfig {
        allowed: HashMap::from([("npm".to_string(), vec!["my-pkg".to_string()])]),
        ..Default::default()
    };
    assert!(!config.is_allowed("npm", "other-pkg"));
}

#[test]
fn internal_is_not_allowed() {
    let config = SloppyJoeConfig {
        internal: HashMap::from([("npm".to_string(), vec!["@myorg/*".to_string()])]),
        ..Default::default()
    };
    // Internal packages are NOT in the allowed list
    assert!(!config.is_allowed("npm", "@myorg/utils"));
    assert!(config.is_internal("npm", "@myorg/utils"));
}

#[test]
fn trusted_scopes_include_configured_npm_patterns_and_names() {
    let config = SloppyJoeConfig {
        internal: HashMap::from([("npm".to_string(), vec!["@acme/*".to_string()])]),
        allowed: HashMap::from([("npm".to_string(), vec!["@partner/widget".to_string()])]),
        canonical: HashMap::from([(
            "npm".to_string(),
            HashMap::from([("@types/node".to_string(), vec![])]),
        )]),
        ..Default::default()
    };

    let scopes = config.trusted_scopes("npm");
    assert!(scopes.contains(&"@acme".to_string()));
    assert!(scopes.contains(&"@partner".to_string()));
    assert!(scopes.contains(&"@types".to_string()));
}

#[test]
fn similarity_roots_include_exact_configured_package_names_only() {
    let config = SloppyJoeConfig {
        allowed: HashMap::from([(
            "npm".to_string(),
            vec!["acme-widget".to_string(), "@acme/*".to_string()],
        )]),
        canonical: HashMap::from([(
            "npm".to_string(),
            HashMap::from([("long-tail-lib".to_string(), vec!["other".to_string()])]),
        )]),
        ..Default::default()
    };

    let roots = config.similarity_roots("npm");
    assert!(roots.contains(&"acme-widget".to_string()));
    assert!(roots.contains(&"long-tail-lib".to_string()));
    assert!(!roots.contains(&"@acme/*".to_string()));
}

#[test]
fn alternatives_map_builds_reverse_lookup() {
    let config = SloppyJoeConfig {
        canonical: HashMap::from([(
            "npm".to_string(),
            HashMap::from([
                (
                    "lodash".to_string(),
                    vec!["underscore".to_string(), "ramda".to_string()],
                ),
                ("dayjs".to_string(), vec!["moment".to_string()]),
            ]),
        )]),
        ..Default::default()
    };
    let map = config.alternatives_map("npm");
    assert_eq!(map.get("underscore"), Some(&"lodash".to_string()));
    assert_eq!(map.get("ramda"), Some(&"lodash".to_string()));
    assert_eq!(map.get("moment"), Some(&"dayjs".to_string()));
    assert_eq!(map.get("lodash"), None);
}

#[test]
fn alternatives_map_empty_config() {
    let config = SloppyJoeConfig::default();
    let map = config.alternatives_map("npm");
    assert!(map.is_empty());
}

#[test]
fn load_config_none_returns_default() {
    let config = load_config(None).unwrap();
    assert!(config.canonical.is_empty());
    assert!(config.internal.is_empty());
    assert!(config.allowed.is_empty());
    assert!(config.similarity_exceptions.is_empty());
    assert!(config.metadata_exceptions.is_empty());
    assert_eq!(config.min_version_age_hours, 72);
    assert!(!config.allow_unresolved_versions);
    assert!(!config.allow_legacy_npm_v1_lockfile);
    assert_eq!(config.python_enforcement, PythonEnforcement::PreferPoetry);
    assert_eq!(
        config.poetry_lock_policy,
        PoetryLockPolicy::WarnMissingProofs
    );
}

#[test]
fn load_config_nonexistent_path_returns_error() {
    let result = load_config(Some(Path::new("/tmp/nonexistent-sloppy-joe-config.json")));
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Could not read config file"));
    assert!(err.contains("Fix:"));
}

#[test]
fn load_config_valid_file() {
    let dir = unique_temp_dir("config-v2");
    let path = dir.join("config.json");
    std::fs::write(
        &path,
        r#"{"canonical":{"npm":{"lodash":["underscore"]}},"internal":{"npm":["@myorg/*"]},"allowed":{"npm":["vetted"]},"similarity_exceptions":{"cargo":[{"package":"serde_json","candidate":"serde","generator":"segment-overlap","reason":"legitimate companion crate"}]},"metadata_exceptions":{"cargo":[{"package":"colored","check":"metadata/maintainer-change","version":"2.2.0","previous_publisher":"kurtlawrence","current_publisher":"hwittenborn","reason":"reviewed transfer"}]},"min_version_age_hours":48,"allow_unresolved_versions":true,"allow_legacy_npm_v1_lockfile":true,"python_enforcement":"poetry_only","poetry_lock_policy":"strict"}"#,
    ).unwrap();
    let config = load_config(Some(&path)).unwrap();
    assert!(config.canonical.contains_key("npm"));
    assert!(config.internal.contains_key("npm"));
    assert!(config.allowed.contains_key("npm"));
    assert!(config.similarity_exceptions.contains_key("cargo"));
    assert!(config.metadata_exceptions.contains_key("cargo"));
    assert_eq!(config.min_version_age_hours, 48);
    assert!(config.allow_unresolved_versions);
    assert!(config.allow_legacy_npm_v1_lockfile);
    assert_eq!(config.python_enforcement, PythonEnforcement::PoetryOnly);
    assert_eq!(config.poetry_lock_policy, PoetryLockPolicy::Strict);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn load_config_parses_cargo_provenance_fields() {
    let dir = unique_temp_dir("config-cargo-provenance");
    let path = dir.join("config.json");
    std::fs::write(
        &path,
        r#"{
  "trusted_local_paths": {
"cargo": ["/opt/company/shared-crate"]
  },
  "trusted_registries": {
"cargo": [
  {
    "name": "company",
    "source": "registry+https://cargo.company.example/index"
  }
]
  },
  "trusted_git_sources": {
"cargo": ["https://github.com/yourorg/shared-crate"]
  },
  "cargo_git_policy": "warn_pinned"
}"#,
    )
    .unwrap();

    let config = load_config(Some(&path)).unwrap();
    assert_eq!(
        config.trusted_local_paths.get("cargo"),
        Some(&vec!["/opt/company/shared-crate".to_string()])
    );
    assert_eq!(config.trusted_registries["cargo"][0].name, "company");
    assert_eq!(
        config.trusted_registries["cargo"][0].source,
        "registry+https://cargo.company.example/index"
    );
    assert_eq!(
        config.trusted_git_sources.get("cargo"),
        Some(&vec!["https://github.com/yourorg/shared-crate".to_string()])
    );
    assert_eq!(config.cargo_git_policy, CargoGitPolicy::WarnPinned);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn local_overlay_adds_cargo_provenance_relaxations_additively() {
    let dir = unique_temp_dir("local-overlay-cargo");
    let path = dir.join("local-overlay.json");
    std::fs::write(
        &path,
        r#"{
  "trusted_local_paths": {
"cargo": ["/opt/company/shared-crate"]
  },
  "trusted_git_sources": {
"cargo": ["https://github.com/yourorg/shared-crate"]
  },
  "cargo_git_policy": "warn_pinned",
  "allow_host_local_cargo_config": true
}"#,
    )
    .unwrap();

    let base = SloppyJoeConfig {
        trusted_registries: HashMap::from([(
            "cargo".to_string(),
            vec![TrustedRegistry {
                name: "company".to_string(),
                source: "registry+https://cargo.company.example/index".to_string(),
            }],
        )]),
        ..Default::default()
    };
    let merged = load_local_overlay_from_path(base, &path).unwrap();

    assert_eq!(
        merged.trusted_registries["cargo"][0].source,
        "registry+https://cargo.company.example/index"
    );
    assert_eq!(
        merged.trusted_local_paths["cargo"][0],
        "/opt/company/shared-crate"
    );
    assert_eq!(
        merged.trusted_git_sources["cargo"][0],
        "https://github.com/yourorg/shared-crate"
    );
    assert_eq!(merged.cargo_git_policy, CargoGitPolicy::WarnPinned);
    assert!(merged.allow_host_local_cargo_config);
    assert!(
        !merged.active_local_overlay_relaxations.is_empty(),
        "effective config should remember that local-only relaxations are active"
    );

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn load_config_rejects_unknown_python_enforcement() {
    let dir = unique_temp_dir("config-python-mode");
    let path = dir.join("config.json");
    std::fs::write(&path, r#"{"python_enforcement":"requirements_only"}"#).unwrap();

    let err = parse_config_content(
        &std::fs::read_to_string(&path).unwrap(),
        &path.display().to_string(),
    )
    .expect_err("unknown Python enforcement modes must fail");
    assert!(err.contains("prefer_poetry"));
    assert!(err.contains("poetry_only"));

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn load_config_rejects_unknown_poetry_lock_policy() {
    let dir = unique_temp_dir("config-poetry-lock-policy");
    let path = dir.join("config.json");
    std::fs::write(&path, r#"{"poetry_lock_policy":"trust_me_bro"}"#).unwrap();

    let err = parse_config_content(
        &std::fs::read_to_string(&path).unwrap(),
        &path.display().to_string(),
    )
    .expect_err("unknown Poetry lock policies must fail");
    assert!(err.contains("warn_missing_proofs"));
    assert!(err.contains("strict"));

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn load_config_rejects_repo_policy_when_scanning_subdirectory() {
    let repo = unique_temp_dir("nested-project-boundary");
    std::fs::create_dir(repo.join(".git")).unwrap();
    let project = repo.join("app");
    std::fs::create_dir(&project).unwrap();
    let path = repo.join("config.json");
    std::fs::write(&path, r#"{"min_version_age_hours":0}"#).unwrap();

    let err = load_config_with_project(Some(&path), Some(&project))
        .expect_err("policy anywhere inside the repo must remain untrusted");
    assert!(err.contains("outside the project directory"));
    std::fs::remove_dir_all(repo).unwrap();
}

#[test]
fn load_config_rejects_project_local_path() {
    let dir = unique_temp_dir("project-boundary");
    let path = dir.join("config.json");
    std::fs::write(&path, r#"{"canonical":{},"internal":{},"allowed":{}}"#).unwrap();
    let err = ensure_config_outside_project(&path, Some(&dir)).unwrap_err();
    assert!(err.contains("outside the project directory"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn load_config_empty_file_returns_error() {
    let dir = unique_temp_dir("empty");
    let path = dir.join("config.json");
    std::fs::write(&path, "").unwrap();
    let result = load_config(Some(&path));
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Config is empty"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn load_config_invalid_json_returns_error_with_hints() {
    let dir = unique_temp_dir("invalid");
    let path = dir.join("config.json");
    std::fs::write(&path, r#"{ "canonical": {}, // this is a comment }"#).unwrap();
    let result = load_config(Some(&path));
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Config is not valid JSON"));
    assert!(err.contains("comments"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn default_min_version_age_is_72() {
    let config = SloppyJoeConfig::default();
    assert_eq!(config.min_version_age_hours, 72);
}

#[test]
fn resolve_config_source_cli_flag_returns_it_directly() {
    let source = resolve_config_source(Some("/some/path.json"), None).unwrap();
    assert_eq!(source, Some("/some/path.json".to_string()));
}

#[test]
fn resolve_config_source_cli_flag_with_url() {
    let source = resolve_config_source(Some("https://example.com/config.json"), None).unwrap();
    assert_eq!(source, Some("https://example.com/config.json".to_string()));
}

#[test]
fn resolve_config_source_none_and_none_returns_none() {
    // When no CLI flag and no project_dir, returns None
    // (if SLOPPY_JOE_CONFIG env var happens to be set, it would return that,
    // but we can't safely clear env vars in parallel tests — this test
    // verifies the function doesn't panic and returns Ok)
    let source = resolve_config_source(None, None);
    assert!(source.is_ok());
}

#[test]
fn resolve_config_source_with_project_dir_triggers_registry_lookup() {
    // Use a temp dir that's not in a git repo — registry lookup should
    // find no git root and no default config, returning None
    let dir = std::env::temp_dir().join("sj-resolve-test");
    std::fs::create_dir_all(&dir).unwrap();
    let source = registry::lookup(&dir);
    // Should not error — exercising the registry::lookup code path
    assert!(source.is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn resolve_config_source_cli_flag_takes_priority_over_project_dir() {
    let source = resolve_config_source(
        Some("/explicit/config.json"),
        Some(Path::new("/some/project")),
    )
    .unwrap();
    assert_eq!(source, Some("/explicit/config.json".to_string()));
}

#[test]
fn validate_rejects_unknown_ecosystem() {
    let config = SloppyJoeConfig {
        internal: HashMap::from([("nodejs".to_string(), vec!["pkg".to_string()])]),
        ..Default::default()
    };
    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors[0].contains("nodejs"));
}

#[test]
fn validate_rejects_bad_glob_pattern() {
    let config = SloppyJoeConfig {
        internal: HashMap::from([("npm".to_string(), vec!["@org/*/sub".to_string()])]),
        ..Default::default()
    };
    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors[0].contains("*"));
}

#[test]
fn validate_checks_jvm_trusted_registries() {
    let ok = jvm_registry_config("gradle-plugins", "https://plugins.example.com/maven");
    assert!(ok.validate().is_empty(), "{:?}", ok.validate());
    for (name, source) in [
        ("typo-plugins", "https://plugins.example.com/maven"),
        ("gradle-plugins", "http://plugins.example.com/maven"),
        (
            "gradle-plugins",
            "https://user:pw@plugins.example.com/maven",
        ),
        ("gradle-plugins", "not a url"),
    ] {
        let errors = jvm_registry_config(name, source).validate();
        assert_eq!(errors.len(), 1, "{name} {source}: {errors:?}");
        assert!(errors[0].contains("jvm"));
    }
}

#[test]
fn validate_accepts_valid_config() {
    let config = SloppyJoeConfig {
        canonical: HashMap::from([(
            "npm".to_string(),
            HashMap::from([("lodash".to_string(), vec!["underscore".to_string()])]),
        )]),
        internal: HashMap::from([("npm".to_string(), vec!["@myorg/*".to_string()])]),
        allowed: HashMap::from([("npm".to_string(), vec!["vetted-pkg".to_string()])]),
        similarity_exceptions: HashMap::from([(
            "cargo".to_string(),
            vec![SimilarityException {
                package: "serde_json".to_string(),
                candidate: "serde".to_string(),
                generator: "segment-overlap".to_string(),
                reason: Some("legitimate companion crate".to_string()),
            }],
        )]),
        metadata_exceptions: HashMap::from([(
            "cargo".to_string(),
            vec![MetadataException {
                package: "colored".to_string(),
                check: crate::names::METADATA_MAINTAINER_CHANGE.to_string(),
                version: "2.2.0".to_string(),
                previous_publisher: Some("kurtlawrence".to_string()),
                current_publisher: Some("hwittenborn".to_string()),
                reason: Some("reviewed transfer".to_string()),
            }],
        )]),
        ..Default::default()
    };
    let errors = config.validate();
    assert!(errors.is_empty(), "Expected no errors, got: {:?}", errors);
}

#[test]
fn similarity_exception_matches_exact_pair_and_generator_only() {
    let config = SloppyJoeConfig {
        similarity_exceptions: HashMap::from([(
            "cargo".to_string(),
            vec![SimilarityException {
                package: "serde_json".to_string(),
                candidate: "serde".to_string(),
                generator: "segment-overlap".to_string(),
                reason: Some("legitimate companion crate".to_string()),
            }],
        )]),
        ..Default::default()
    };

    assert!(config.is_similarity_exception("cargo", "serde_json", "serde", "segment-overlap"));
    assert!(!config.is_similarity_exception("cargo", "serde_json", "serde", "word-reorder"));
    assert!(!config.is_similarity_exception("cargo", "serde", "serde_json", "segment-overlap"));
    assert!(!config.is_similarity_exception(
        "cargo",
        "serde_json",
        "serde_yaml",
        "segment-overlap"
    ));
}

#[test]
fn metadata_exception_matches_exact_package_version_and_publishers_only() {
    let config = SloppyJoeConfig {
        metadata_exceptions: HashMap::from([(
            "cargo".to_string(),
            vec![MetadataException {
                package: "colored".to_string(),
                check: crate::names::METADATA_MAINTAINER_CHANGE.to_string(),
                version: "2.2.0".to_string(),
                previous_publisher: Some("kurtlawrence".to_string()),
                current_publisher: Some("hwittenborn".to_string()),
                reason: Some("reviewed transfer".to_string()),
            }],
        )]),
        ..Default::default()
    };

    assert!(config.is_metadata_exception(
        "cargo",
        "colored",
        crate::names::METADATA_MAINTAINER_CHANGE,
        "2.2.0",
        Some("kurtlawrence"),
        Some("hwittenborn"),
    ));
    assert!(!config.is_metadata_exception(
        "cargo",
        "colored",
        crate::names::METADATA_MAINTAINER_CHANGE,
        "2.2.1",
        Some("kurtlawrence"),
        Some("hwittenborn"),
    ));
    assert!(!config.is_metadata_exception(
        "cargo",
        "colored",
        crate::names::METADATA_MAINTAINER_CHANGE,
        "2.2.0",
        Some("someone-else"),
        Some("hwittenborn"),
    ));
}

#[test]
fn validate_rejects_incomplete_metadata_exception() {
    let config = SloppyJoeConfig {
        metadata_exceptions: HashMap::from([(
            "cargo".to_string(),
            vec![MetadataException {
                package: "colored".to_string(),
                check: crate::names::METADATA_MAINTAINER_CHANGE.to_string(),
                version: "2.2.0".to_string(),
                previous_publisher: None,
                current_publisher: Some("hwittenborn".to_string()),
                reason: None,
            }],
        )]),
        ..Default::default()
    };

    let errors = config.validate();
    assert!(
        errors.iter().any(|err| err.contains("previous_publisher")),
        "expected validation error for incomplete metadata exception, got: {errors:?}"
    );
}

#[test]
fn validate_rejects_canonical_listed_as_alternative() {
    let config = SloppyJoeConfig {
        canonical: HashMap::from([(
            "npm".to_string(),
            HashMap::from([
                ("lodash".to_string(), vec!["underscore".to_string()]),
                ("underscore".to_string(), vec!["ramda".to_string()]),
            ]),
        )]),
        ..Default::default()
    };
    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors.iter().any(|e| e.contains("underscore")));
}

#[test]
fn load_config_valid_file_runs_validation() {
    let dir = unique_temp_dir("validate");
    let path = dir.join("config.json");
    std::fs::write(&path, r#"{"internal":{"nodejs":["pkg"]}}"#).unwrap();
    let result = load_config(Some(&path));
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("nodejs"));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn load_config_from_source_rejects_http_url() {
    let err = load_config_from_source(Some("http://example.invalid/sloppy-joe.json"), None)
        .await
        .unwrap_err();
    assert!(err.contains("must use HTTPS"));
}

#[test]
fn config_source_scheme_detection_is_case_insensitive() {
    assert!(config_source_has_scheme(
        "HTTP://example.invalid/config.json",
        "http"
    ));
    assert!(config_source_has_scheme(
        "HTTPS://example.invalid/config.json",
        "https"
    ));
    assert!(!config_source_has_scheme("/tmp/config.json", "https"));
}

#[test]
fn redact_url_for_display_strips_credentials_and_query() {
    let redacted =
        redact_url_for_display("https://user:secret@example.com/config.json?token=abc#frag");
    assert_eq!(redacted, "https://example.com/config.json");
}

// ── parse_config_content edge cases ──

#[test]
fn parse_config_content_trailing_comma_hint() {
    let content = r#"{
  "canonical": {},
  "internal": {},
}"#;
    let err = parse_config_content(content, "test.json").unwrap_err();
    assert!(err.contains("Trailing commas"));
}

#[test]
fn parse_config_content_not_object_hint() {
    let content = r#"["not", "an", "object"]"#;
    let err = parse_config_content(content, "test.json").unwrap_err();
    assert!(err.contains("must be a JSON object"));
}

#[test]
fn parse_config_content_empty_string() {
    let err = parse_config_content("", "test.json").unwrap_err();
    assert!(err.contains("Config is empty"));
}

#[test]
fn parse_config_content_whitespace_only() {
    let err = parse_config_content("   \n  ", "test.json").unwrap_err();
    assert!(err.contains("Config is empty"));
}

#[test]
fn parse_config_content_comment_hint() {
    let content = r#"{ // comment
  "canonical": {}
}"#;
    let err = parse_config_content(content, "test.json").unwrap_err();
    assert!(err.contains("comments"));
}

#[test]
fn parse_config_content_valid_minimal() {
    let content = r#"{}"#;
    let config = parse_config_content(content, "test.json").unwrap();
    assert!(config.canonical.is_empty());
    assert_eq!(config.min_version_age_hours, 72);
}

#[test]
fn parse_config_content_validation_fails() {
    let content = r#"{"internal":{"nodejs":["pkg"]}}"#;
    let err = parse_config_content(content, "test.json").unwrap_err();
    assert!(err.contains("nodejs"));
    assert!(err.contains("validation failed"));
}
