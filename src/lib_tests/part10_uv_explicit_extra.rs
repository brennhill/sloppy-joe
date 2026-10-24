use super::*;

#[tokio::test]
async fn uv_explicit_extra_includes_extra_transitive_dependencies() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["requests==2.31.0"]

[project.optional-dependencies]
docs = ["mkdocs==1.6.0"]

[tool.uv]
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("uv.lock"),
        r#"version = 1
requires-python = ">=3.12"

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/example/requests-2.31.0.tar.gz", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111", size = 1 }
wheels = [
    { url = "https://files.pythonhosted.org/packages/example/requests-2.31.0-py3-none-any.whl", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222", size = 1 },
]
dependencies = [{ name = "urllib3" }]

[[package]]
name = "urllib3"
version = "2.1.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/example/urllib3-2.1.0.tar.gz", hash = "sha256:3333333333333333333333333333333333333333333333333333333333333333", size = 1 }
wheels = [
    { url = "https://files.pythonhosted.org/packages/example/urllib3-2.1.0-py3-none-any.whl", hash = "sha256:4444444444444444444444444444444444444444444444444444444444444444", size = 1 },
]

[[package]]
name = "mkdocs"
version = "1.6.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/example/mkdocs-1.6.0.tar.gz", hash = "sha256:5555555555555555555555555555555555555555555555555555555555555555", size = 1 }
wheels = [
    { url = "https://files.pythonhosted.org/packages/example/mkdocs-1.6.0-py3-none-any.whl", hash = "sha256:6666666666666666666666666666666666666666666666666666666666666666", size = 1 },
]
dependencies = [{ name = "markdown" }]

[[package]]
name = "markdown"
version = "3.7.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/example/markdown-3.7.0.tar.gz", hash = "sha256:7777777777777777777777777777777777777777777777777777777777777777", size = 1 }
wheels = [
    { url = "https://files.pythonhosted.org/packages/example/markdown-3.7.0-py3-none-any.whl", hash = "sha256:8888888888888888888888888888888888888888888888888888888888888888", size = 1 },
]

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "requests" }]

[package.optional-dependencies]
docs = [{ name = "mkdocs" }]

[package.metadata]
requires-dist = [
    { name = "requests", specifier = "==2.31.0" },
    { name = "mkdocs", marker = "extra == 'docs'", specifier = "==1.6.0" },
]
provides-extras = ["docs"]
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig::default();
    let opts = python_profile_opts(&[], &["docs"], Some("3.12"));
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config).unwrap();
    let projects = parse_project_inputs_with_options(&dir, &specs, &config, &opts).unwrap();
    let deps = projects[0].deps.clone();

    let registry = FakeRegistry {
        existing: vec![
            "requests".to_string(),
            "urllib3".to_string(),
            "mkdocs".to_string(),
            "markdown".to_string(),
        ],
    };
    let osv = VulnOsvClient {
        vulnerable: vec!["markdown".to_string()],
    };

    let report = scan_with_services_inner_for_kind(
        Some(ProjectInputKind::PyProjectUv),
        &dir,
        config,
        deps,
        &registry,
        &osv,
        &opts,
    )
    .await
    .unwrap();

    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.package == "markdown"
                && issue.source.as_deref() == Some("transitive"))
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn poetry_requested_package_extra_includes_extra_marker_transitives() {
    let dir = unique_dir();
    let pyproject = r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
fastapi = { version = "0.116.0", extras = ["standard"] }
"#;
    write_poetry_project(
        &dir,
        pyproject,
        r#"[[package]]
name = "fastapi"
version = "0.116.0"
optional = false
python-versions = ">=3.8"
files = [{ file = "fastapi-0.116.0-py3-none-any.whl", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }]

[package.dependencies]
uvicorn = { version = ">=0.30.0", optional = true, markers = "extra == 'standard'" }

[[package]]
name = "uvicorn"
version = "0.30.0"
optional = false
python-versions = ">=3.8"
files = [{ file = "uvicorn-0.30.0-py3-none-any.whl", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222" }]

[metadata]
lock-version = "2.0"
python-versions = "^3.12"
content-hash = "__CONTENT_HASH__"
"#,
    );

    let config = config::SloppyJoeConfig::default();
    let specs = detected_project_inputs_with_config(&dir, Some("pypi"), &config).unwrap();
    let opts = ScanOptions {
        no_cache: true,
        disable_osv_disk_cache: true,
        ..Default::default()
    };
    let projects = parse_project_inputs_with_options(&dir, &specs, &config, &opts).unwrap();
    assert!(projects[0].python_root_extras["fastapi"].contains("standard"));

    let registry = FakeRegistry {
        existing: vec!["fastapi".to_string(), "uvicorn".to_string()],
    };
    let osv = VulnOsvClient {
        vulnerable: vec!["uvicorn".to_string()],
    };
    let report = scan_parsed_project(&projects[0], config, &registry, &osv, &opts)
        .await
        .unwrap();

    assert!(
        report.issues.iter().any(
            |issue| issue.package == "uvicorn" && issue.source.as_deref() == Some("transitive")
        ),
        "requested package extras should activate lockfile extra-marker edges: {:?}",
        report.issues
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_with_services_helper_preserves_python_root_package_extras() {
    let dir = unique_dir();
    let pyproject = r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
fastapi = { version = "0.116.0", extras = ["standard"] }
"#;
    write_poetry_project(
        &dir,
        pyproject,
        r#"[[package]]
name = "fastapi"
version = "0.116.0"
optional = false
python-versions = ">=3.8"
files = [{ file = "fastapi-0.116.0-py3-none-any.whl", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }]

[package.dependencies]
uvicorn = { version = ">=0.30.0", optional = true, markers = "extra == 'standard'" }

[[package]]
name = "uvicorn"
version = "0.30.0"
optional = false
python-versions = ">=3.8"
files = [{ file = "uvicorn-0.30.0-py3-none-any.whl", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222" }]

[metadata]
lock-version = "2.0"
python-versions = "^3.12"
content-hash = "__CONTENT_HASH__"
"#,
    );

    let registry = FakeRegistry {
        existing: vec!["fastapi".to_string(), "uvicorn".to_string()],
    };
    let osv = VulnOsvClient {
        vulnerable: vec!["uvicorn".to_string()],
    };
    let deps = parsers::pyproject_toml::parse_poetry(&dir).unwrap();
    let report = scan_with_services_inner_for_kind(
        Some(ProjectInputKind::PyProjectPoetry),
        &dir,
        config::SloppyJoeConfig::default(),
        deps,
        &registry,
        &osv,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("test helper should preserve root package extras for Python lock traversal");

    assert!(
        report.issues.iter().any(
            |issue| issue.package == "uvicorn" && issue.source.as_deref() == Some("transitive")
        ),
        "test helper should follow the same root-extra transitive path as production scans: {:?}",
        report.issues
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cargo_fixture_contracts_hold() {
    for case in [
        "git-dependency-fail",
        "registry-not-allowlisted-fail",
        "workspace-pass",
    ] {
        assert_fixture_preflight_outcome("cargo", case);
    }
}

#[test]
fn go_fixture_contracts_hold() {
    for case in ["go-sum-pass", "local-replace-pass", "missing-go-sum-fail"] {
        assert_fixture_preflight_outcome("go", case);
    }
}

#[test]
fn ruby_fixture_contracts_hold() {
    for case in ["git-source-fail", "rubygems-pass"] {
        assert_fixture_preflight_outcome("ruby", case);
    }
}

#[test]
fn php_fixture_contracts_hold() {
    for case in ["composer-pass", "custom-repository-fail"] {
        assert_fixture_preflight_outcome("php", case);
    }
}

#[test]
fn jvm_fixture_contracts_hold() {
    for case in ["custom-repo-fail", "gradle-pass", "maven-warning"] {
        assert_fixture_preflight_outcome("jvm", case);
    }
}

#[test]
fn dotnet_fixture_contracts_hold() {
    for case in ["missing-lock-fail", "packages-lock-pass"] {
        assert_fixture_preflight_outcome("dotnet", case);
    }
}

#[tokio::test]
async fn internal_packages_still_get_osv_checked() {
    // Internal packages should skip similarity/existence/canonical/metadata
    // but still get vulnerability (OSV) checks

    struct VulnOsvClient;
    #[async_trait]
    impl OsvClient for VulnOsvClient {
        async fn query(
            &self,
            name: &str,
            _ecosystem: &str,
            _version: Option<&str>,
        ) -> Result<Vec<String>> {
            if name == "@myorg/vulnerable-pkg" {
                Ok(vec!["GHSA-1234-abcd".to_string()])
            } else {
                Ok(vec![])
            }
        }
    }

    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"@myorg/vulnerable-pkg":"1.0.0","react":"^18.0"}}"#,
    )
    .unwrap();

    let config_dir = unique_dir();
    let config_path = config_dir.join("config.json");
    std::fs::write(
        &config_path,
        r#"{"canonical":{},"internal":{"npm":["@myorg/*"]},"allowed":{}}"#,
    )
    .unwrap();
    let config = config::load_config(Some(config_path.as_path())).unwrap();

    let registry = FakeRegistry {
        existing: vec!["react".to_string()],
    };
    let report = scan_with_services_inner(
        &dir,
        config,
        parsers::parse_dependencies(&dir, Some("npm")).unwrap(),
        &registry,
        &VulnOsvClient,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let vuln_issues: Vec<_> = report
        .issues
        .iter()
        .filter(|i| i.package == "@myorg/vulnerable-pkg" && i.check.contains("malicious"))
        .collect();
    assert!(
        !vuln_issues.is_empty(),
        "Internal packages should still be checked for known vulnerabilities. Issues: {:?}",
        report
            .issues
            .iter()
            .map(|i| format!("{}: {}", i.package, i.check))
            .collect::<Vec<_>>()
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&config_dir);
}

#[test]
fn scan_hash_is_deterministic() {
    let dir = std::env::temp_dir();
    let deps = vec![
        Dependency {
            name: "react".to_string(),
            version: Some("^18.0".to_string()),
            ecosystem: Ecosystem::Npm,
            actual_name: None,
        },
        Dependency {
            name: "lodash".to_string(),
            version: Some("^4.0".to_string()),
            ecosystem: Ecosystem::Npm,
            actual_name: None,
        },
    ];
    let hash1 = scan_hash(&dir, &deps).unwrap();
    let hash2 = scan_hash(&dir, &deps).unwrap();
    assert_eq!(hash1, hash2);
}

#[test]
fn full_scan_recommendation_reasons_include_no_successful_full_scan_when_cache_missing() {
    let (_dir, config, projects) = parsed_npm_fixture_projects("transitive-typosquat");
    let cache_dir = unique_dir();

    let reasons = full_scan_recommendation_reasons_for_projects(
        &projects,
        &cache_dir,
        &config,
        &ScanOptions::default(),
        cache::now_epoch(),
    )
    .unwrap();

    assert_eq!(
        reasons,
        vec![report::FullScanRecommendationReason::NoSuccessfulFullScan]
    );
}

#[test]
fn full_scan_fingerprint_changes_when_manager_binding_changes() {
    let (_dir, config, projects) = parsed_npm_fixture_projects("transitive-typosquat");
    let original =
        full_scan_fingerprint_for_projects(&projects, &config, &ScanOptions::default()).unwrap();

    let mut rebound = projects.clone();
    rebound[0].spec.js_binding.as_mut().unwrap().manager = JsPackageManager::Pnpm;
    let changed =
        full_scan_fingerprint_for_projects(&rebound, &config, &ScanOptions::default()).unwrap();

    assert_ne!(original, changed);
}

#[test]
fn persisting_successful_full_scan_fingerprint_clears_recommendation() {
    let (_dir, config, projects) = parsed_npm_fixture_projects("transitive-typosquat");
    let cache_dir = unique_dir();

    persist_successful_full_scan_fingerprint(
        &projects,
        &cache_dir,
        &config,
        &ScanOptions::default(),
    )
    .unwrap();
    let reasons = full_scan_recommendation_reasons_for_projects(
        &projects,
        &cache_dir,
        &config,
        &ScanOptions::default(),
        cache::now_epoch(),
    )
    .unwrap();

    assert!(reasons.is_empty());
}

#[test]
fn full_scan_recommendation_reasons_include_last_full_scan_stale_when_timestamp_expired() {
    let (_dir, config, projects) = parsed_npm_fixture_projects("transitive-typosquat");
    let cache_dir = unique_dir();
    let stale = full_scan_fingerprint_components_for_projects(
        &projects,
        &config,
        &ScanOptions::default(),
        cache::now_epoch().saturating_sub(FULL_SCAN_TTL_SECS + 1),
    )
    .unwrap();
    cache::atomic_write_json(&full_scan_fingerprint_cache_path(&cache_dir), &stale);

    let reasons = full_scan_recommendation_reasons_for_projects(
        &projects,
        &cache_dir,
        &config,
        &ScanOptions::default(),
        cache::now_epoch(),
    )
    .unwrap();

    assert_eq!(
        reasons,
        vec![report::FullScanRecommendationReason::LastFullScanStale]
    );
}

#[test]
fn full_scan_recommendation_reasons_include_policy_changed_when_config_differs() {
    let (_dir, config, projects) = parsed_npm_fixture_projects("transitive-typosquat");
    let cache_dir = unique_dir();
    persist_successful_full_scan_fingerprint(
        &projects,
        &cache_dir,
        &config,
        &ScanOptions::default(),
    )
    .unwrap();

    let mut changed_config = config.clone();
    changed_config.min_version_age_hours = 1;
    let reasons = full_scan_recommendation_reasons_for_projects(
        &projects,
        &cache_dir,
        &changed_config,
        &ScanOptions::default(),
        cache::now_epoch(),
    )
    .unwrap();

    assert_eq!(
        reasons,
        vec![report::FullScanRecommendationReason::PolicyChanged]
    );
}

#[tokio::test]
async fn empty_or_unstructured_required_lockfiles_fail_closed() {
    for (manifest, content, lockfile, locked) in [
        (
            "build.gradle",
            "dependencyLocking { lockAllConfigurations() }\ndependencies {}",
            "gradle.lockfile",
            "",
        ),
        (
            "Gemfile",
            "source 'https://rubygems.org'",
            "Gemfile.lock",
            "",
        ),
        ("app.csproj", "<Project />", "packages.lock.json", "{}"),
    ] {
        let dir = unique_dir();
        std::fs::write(dir.join(manifest), content).unwrap();
        std::fs::write(dir.join(lockfile), locked).unwrap();
        let err = scan_with_source_full_options(
            &dir,
            None,
            None,
            &ScanOptions {
                scan_mode: ScanMode::Fast,
                no_cache: true,
                ..Default::default()
            },
        )
        .await
        .expect_err("an unreadable dependency graph must not pass as an empty project");
        assert!(err.to_string().contains(lockfile), "{err}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[tokio::test]
async fn failed_full_scan_keeps_the_recommendation_to_run_a_successful_scan() {
    let dir = fixture_dir("transitive-typosquat");
    let external = unique_dir();
    let config_path = external.join("policy.json");
    std::fs::write(&config_path, r#"{"internal":{"npm":["react","expresss"]}}"#).unwrap();
    cache::atomic_write_json(
        &external.join("osv-cache.json"),
        &serde_json::json!({
            "timestamp": cache::now_epoch(),
            "entries": {
                "npm:react:18.3.1": {"vuln_ids": ["TEST-VULNERABILITY"]},
                "npm:expresss:1.0.0": {"vuln_ids": []}
            }
        }),
    );
    let opts = ScanOptions {
        cache_dir: Some(&external),
        ..Default::default()
    };
    let failed = scan_with_source_full_options(&dir, Some("npm"), config_path.to_str(), &opts)
        .await
        .unwrap();
    assert!(failed.has_errors());
    let fast = scan_with_source_full_options(
        &dir,
        Some("npm"),
        config_path.to_str(),
        &ScanOptions {
            scan_mode: ScanMode::Fast,
            ..opts
        },
    )
    .await
    .unwrap();
    assert_eq!(
        fast.full_scan_reasons,
        vec![report::FullScanRecommendationReason::NoSuccessfulFullScan]
    );
    std::fs::remove_dir_all(external).unwrap();
}

#[tokio::test]
async fn fast_mode_recommends_full_when_no_successful_full_scan_exists() {
    let dir = fixture_dir("transitive-typosquat");
    let cache_dir = unique_dir();

    let report = scan_with_config(
        &dir,
        Some("npm"),
        config::SloppyJoeConfig::default(),
        &ScanOptions {
            scan_mode: ScanMode::Fast,
            cache_dir: Some(cache_dir.as_path()),
            ..Default::default()
        },
    )
    .await
    .expect("fast mode should complete using local checks");

    assert!(report.full_scan_recommended());
    assert_eq!(
        report.full_scan_reasons,
        vec![report::FullScanRecommendationReason::NoSuccessfulFullScan]
    );
    assert!(!report.has_errors());
}

#[test]
fn scan_hash_changes_with_different_deps() {
    let dir = std::env::temp_dir();
    let deps1 = vec![Dependency {
        name: "react".to_string(),
        version: Some("^18.0".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }];
    let deps2 = vec![Dependency {
        name: "react".to_string(),
        version: Some("^19.0".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }];
    assert_ne!(
        scan_hash(&dir, &deps1).unwrap(),
        scan_hash(&dir, &deps2).unwrap()
    );
}

#[test]
fn scan_hash_order_independent() {
    let dir = std::env::temp_dir();
    let deps1 = vec![
        Dependency {
            name: "a".to_string(),
            version: None,
            ecosystem: Ecosystem::Npm,
            actual_name: None,
        },
        Dependency {
            name: "b".to_string(),
            version: None,
            ecosystem: Ecosystem::Npm,
            actual_name: None,
        },
    ];
    let deps2 = vec![
        Dependency {
            name: "b".to_string(),
            version: None,
            ecosystem: Ecosystem::Npm,
            actual_name: None,
        },
        Dependency {
            name: "a".to_string(),
            version: None,
            ecosystem: Ecosystem::Npm,
            actual_name: None,
        },
    ];
    assert_eq!(
        scan_hash(&dir, &deps1).unwrap(),
        scan_hash(&dir, &deps2).unwrap()
    );
}
