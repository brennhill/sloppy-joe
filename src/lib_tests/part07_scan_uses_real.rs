use super::*;

#[tokio::test]
async fn scan_uses_real_package_identity_for_npm_aliases() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"lodash":"npm:evil-pkg@1.2.3"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"lodash":"npm:evil-pkg@1.2.3"}},"node_modules/lodash":{"name":"evil-pkg","version":"1.2.3","resolved":"https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.2.3.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let exists_names = Arc::new(Mutex::new(Vec::new()));
    let metadata_names = Arc::new(Mutex::new(Vec::new()));
    let osv_names = Arc::new(Mutex::new(Vec::new()));
    let registry = RecordingNameRegistry {
        existing: vec!["evil-pkg".to_string()],
        exists_names: exists_names.clone(),
        metadata_names: metadata_names.clone(),
    };
    let osv_client = RecordingNameOsvClient {
        queried_names: osv_names.clone(),
    };

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        Default::default(),
        &registry,
        &osv_client,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(report.packages_checked, 1);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.check == "resolution/npm-alias"),
        "npm alias indirection should be surfaced explicitly to the user"
    );
    assert!(
        !report.issues.iter().any(|issue| issue.check == "existence"),
        "alias deps must not be checked under the alias package name"
    );
    assert!(
        !exists_names
            .lock()
            .unwrap()
            .iter()
            .any(|name| name == "lodash"),
        "registry existence queries must never use the alias package name"
    );
    assert!(
        metadata_names
            .lock()
            .unwrap()
            .iter()
            .all(|name| name == "evil-pkg"),
        "metadata checks must use the aliased package identity"
    );
    assert!(
        osv_names
            .lock()
            .unwrap()
            .iter()
            .all(|name| name == "evil-pkg"),
        "OSV checks must use the aliased package identity"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_uses_pinned_poetry_version_even_when_poetry_lock_disagrees() {
    let dir = unique_dir();
    let pyproject = "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"2.31.0\"\n";
    write_poetry_project(
        &dir,
        pyproject,
        r#"
[[package]]
name = "requests"
version = "9.9.9"
optional = false
python-versions = ">=3.8"
files = [{ file = "requests-9.9.9-py3-none-any.whl", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }]

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
content-hash = "__CONTENT_HASH__"
"#,
    );

    let registry = RecordingRegistry {
        existing: vec!["requests".to_string()],
        versions: Arc::new(Mutex::new(Vec::new())),
    };
    let osv = RecordingOsvClient {
        versions: Arc::new(Mutex::new(Vec::new())),
    };

    let deps = parsers::pyproject_toml::parse_poetry(&dir).unwrap();
    let err = scan_with_services_inner_for_kind(
        Some(ProjectInputKind::PyProjectPoetry),
        &dir,
        Default::default(),
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
    .expect_err("contradictory Poetry lockfiles must fail closed during preflight");
    assert!(err.to_string().contains("out of sync"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_pypi_uses_poetry_lock_for_transitive_dependencies() {
    let dir = unique_dir();
    let pyproject = "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"2.31.0\"\n";
    write_poetry_project(
        &dir,
        pyproject,
        r#"[[package]]
name = "requests"
version = "2.31.0"
optional = false
python-versions = ">=3.8"
files = [{ file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }]

[package.dependencies]
urllib3 = ">=2.0"

[[package]]
name = "urllib3"
version = "2.1.0"
optional = false
python-versions = ">=3.8"
files = [{ file = "urllib3-2.1.0-py3-none-any.whl", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222" }]

[metadata]
lock-version = "2.0"
python-versions = "^3.11"
content-hash = "__CONTENT_HASH__"
"#,
    );

    let registry = FakeRegistry {
        existing: vec!["requests".to_string(), "urllib3".to_string()],
    };
    let osv = VulnOsvClient {
        vulnerable: vec!["urllib3".to_string()],
    };

    let deps = parsers::pyproject_toml::parse_poetry(&dir).unwrap();
    let report = scan_with_services_inner_for_kind(
        Some(ProjectInputKind::PyProjectPoetry),
        &dir,
        Default::default(),
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
    .unwrap();

    assert!(
        report.issues.iter().any(
            |issue| issue.package == "urllib3" && issue.source.as_deref() == Some("transitive")
        ),
        "trusted Python lockfiles must surface transitive packages in the scan pipeline"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn legacy_requirements_scans_do_not_use_poetry_lock_for_transitive_dependencies() {
    let dir = unique_dir();
    std::fs::write(dir.join("requirements.txt"), "requests==2.31.0\n").unwrap();
    std::fs::write(
        dir.join("poetry.lock"),
        r#"[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "urllib3"
version = "2.1.0"

[metadata]
lock-version = "2.0"
python-versions = "^3.8"
"#,
    )
    .unwrap();

    let registry = FakeRegistry {
        existing: vec!["requests".to_string(), "urllib3".to_string()],
    };
    let osv = VulnOsvClient {
        vulnerable: vec!["urllib3".to_string()],
    };

    let deps = parsers::requirements::parse(&dir).unwrap();
    let report = scan_with_services_inner_for_kind(
        Some(ProjectInputKind::PyRequirements),
        &dir,
        Default::default(),
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
    .unwrap();

    assert!(
        !report.issues.iter().any(
            |issue| issue.package == "urllib3" && issue.source.as_deref() == Some("transitive")
        ),
        "legacy requirements scans must not silently inherit Poetry transitive coverage"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn relative_parser_paths_preserve_ancestor_source_policy() {
    const PROBE: &str = "SLOPPY_JOE_RELATIVE_PARSER_POLICY_PROBE";
    if std::env::var_os(PROBE).is_some() {
        assert!(parsers::go_mod::parse(std::path::Path::new(".")).is_err());
        assert!(parsers::csproj::parse(std::path::Path::new(".")).is_err());
        return;
    }
    let dir = unique_dir();
    std::fs::create_dir(dir.join(".git")).unwrap();
    std::fs::create_dir(dir.join("app")).unwrap();
    std::fs::write(dir.join("go.work"), "go 1.21\nuse ./app\n").unwrap();
    std::fs::write(dir.join("Directory.Build.props"), "<Project />").unwrap();
    std::fs::write(dir.join("app/go.mod"), "module example.com/app\ngo 1.21\n").unwrap();
    std::fs::write(dir.join("app/app.csproj"), "<Project />").unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::relative_parser_paths_preserve_ancestor_source_policy",
            "--nocapture",
        ])
        .env(PROBE, "1")
        .current_dir(dir.join("app"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "relative paths must retain ancestor policy: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn js_dependency_rewrites_cannot_bypass_manifest_lockfile_sync() {
    for policy in ["pnpm", "resolutions", "workspace"] {
        let dir = unique_dir();
        let manager = if policy == "resolutions" {
            "yarn"
        } else {
            "pnpm"
        };
        let mut manifest = serde_json::json!({"name":"app", "packageManager":format!("{manager}@1.0.0"), "dependencies":{"react":"18.3.1"}});
        if policy == "pnpm" {
            manifest[policy] = serde_json::json!({"overrides":{"react":"npm:payload@1.0.0"}});
        } else if policy == "resolutions" {
            manifest[policy] = serde_json::json!({"react":"npm:payload@1.0.0"});
        } else {
            std::fs::write(
                dir.join("pnpm-workspace.yaml"),
                "packages: []\noverrides:\n  react: npm:payload@1.0.0\n",
            )
            .unwrap();
        }
        std::fs::write(dir.join("package.json"), manifest.to_string()).unwrap();
        if manager == "pnpm" {
            std::fs::write(dir.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      react:\n        specifier: 18.3.1\n        version: 18.3.1\npackages:\n  react@18.3.1:\n    resolution:\n      integrity: sha512-demo\n").unwrap();
        } else {
            std::fs::write(dir.join("yarn.lock"), "# yarn lockfile v1\nreact@18.3.1:\n  version \"18.3.1\"\n  resolved \"https://registry.yarnpkg.com/react/-/react-18.3.1.tgz\"\n  integrity sha512-demo\n").unwrap();
        }
        let err = scan_with_source_full_options(
            &dir,
            Some("npm"),
            None,
            &ScanOptions {
                scan_mode: ScanMode::Fast,
                no_cache: true,
                ..Default::default()
            },
        )
        .await
        .expect_err("unmodeled dependency rewrites must fail closed");
        assert!(err.to_string().contains("rewrite"), "{policy}: {err}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[tokio::test]
async fn repo_package_manager_config_cannot_redirect_trusted_js_sources() {
    for (filename, manager) in [
        (".yarnrc", "yarn"),
        (".yarnrc.yml", "yarn"),
        (".pnpmfile.cjs", "pnpm"),
        ("bunfig.toml", "bun"),
    ] {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package.json"),
            format!(r#"{{"name":"app","packageManager":"{manager}@1.0.0","dependencies":{{}}}}"#),
        )
        .unwrap();
        std::fs::write(dir.join(filename), "registry=https://attacker.example\n").unwrap();
        let err = scan_with_source_full_options(
            &dir,
            Some("npm"),
            None,
            &ScanOptions {
                scan_mode: ScanMode::Fast,
                no_cache: true,
                ..Default::default()
            },
        )
        .await
        .expect_err("repo-controlled manager configuration must not redirect trusted identities");
        assert!(err.to_string().contains(filename), "{err}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[tokio::test]
async fn internal_direct_packages_are_not_reported_again_as_transitives() {
    let dir = fixture_dir("transitive-typosquat");
    let config =
        serde_json::from_value(serde_json::json!({"internal": {"npm": ["react", "expresss"]}}))
            .unwrap();
    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        config,
        &FakeRegistry { existing: vec![] },
        &VulnOsvClient {
            vulnerable: vec!["react".into()],
        },
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let issues: Vec<_> = report
        .issues
        .iter()
        .filter(|issue| issue.package == "react")
        .collect();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].source.as_deref(), Some("direct"));
}

#[tokio::test]
async fn vulnerability_checks_honor_the_selected_cache_and_no_cache() {
    let dir = fixture_dir("transitive-typosquat");
    let cache_dir = unique_dir();
    cache::atomic_write_json(
        &cache_dir.join("osv-cache.json"),
        &serde_json::json!({
            "timestamp": cache::now_epoch(),
            "entries": {
                "npm:react:18.3.1": {"vuln_ids": ["CACHED-VULNERABILITY"]},
                "npm:expresss:1.0.0": {"vuln_ids": []}
            }
        }),
    );
    for no_cache in [false, true] {
        let config: config::SloppyJoeConfig = serde_json::from_value(serde_json::json!({
            "internal": {"npm": ["react", "expresss"]}
        }))
        .unwrap();
        let report = scan_fixture_with_fake_services(
            &dir,
            Some("npm"),
            config,
            &FakeRegistry { existing: vec![] },
            &FakeOsvClient,
            &ScanOptions {
                cache_dir: Some(&cache_dir),
                no_cache,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            report.has_errors(),
            !no_cache,
            "cache selection and bypass must reach OSV"
        );
    }
}

#[tokio::test]
async fn transitive_exemptions_preserve_vulnerability_checks() {
    let dir = fixture_dir("transitive-typosquat");
    for policy in ["allowed", "internal"] {
        let config: config::SloppyJoeConfig = serde_json::from_value(serde_json::json!({
            policy: {"npm": ["expresss"]}
        }))
        .unwrap();
        let report = scan_fixture_with_fake_services(
            &dir,
            Some("npm"),
            config,
            &FakeRegistry {
                existing: vec!["react".into(), "expresss".into()],
            },
            &VulnOsvClient {
                vulnerable: vec!["expresss".into()],
            },
            &ScanOptions {
                no_cache: true,
                disable_osv_disk_cache: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(
            report.issues.iter().any(|issue| issue.package == "expresss"
                && issue.check == checks::names::MALICIOUS_KNOWN_VULNERABILITY
                && issue.source.as_deref() == Some("transitive")),
            "{policy} must preserve transitive OSV checks"
        );
        assert!(
            !report
                .issues
                .iter()
                .any(|issue| issue.package == "expresss" && issue.check.starts_with("similarity"))
        );
    }
}

#[tokio::test]
async fn transitive_dep_with_osv_hit_has_transitive_source() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies": {"react": "18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name": "demo", "lockfileVersion": 3, "packages": {"": {"name": "demo", "dependencies": {"react": "18.3.1"}}, "node_modules/react": {"version": "18.3.1"}, "node_modules/evil-transitive": {"version": "1.0.0"}}}"#,
    ).unwrap();

    let registry = FakeRegistry {
        existing: vec!["react".to_string(), "evil-transitive".to_string()],
    };
    let osv = VulnOsvClient {
        vulnerable: vec!["evil-transitive".to_string()],
    };

    let report = scan_with_services_inner(
        &dir,
        Default::default(),
        parsers::parse_dependencies(&dir, Some("npm")).unwrap(),
        &registry,
        &osv,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let trans_issue = report
        .issues
        .iter()
        .find(|i| i.package == "evil-transitive" && i.check.contains("malicious"));
    assert!(
        trans_issue.is_some(),
        "Expected OSV issue for evil-transitive"
    );
    assert_eq!(trans_issue.unwrap().source, Some("transitive".to_string()));

    for issue in report.issues.iter().filter(|i| i.package == "react") {
        assert_eq!(issue.source, Some("direct".to_string()));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn deep_flag_does_not_crash_and_scans_transitive() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies": {"react": "18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name": "demo", "lockfileVersion": 3, "packages": {"": {"name": "demo", "dependencies": {"react": "18.3.1"}}, "node_modules/react": {"version": "18.3.1"}, "node_modules/loose-envify": {"version": "1.4.0"}}}"#,
    ).unwrap();

    let registry = FakeRegistry {
        existing: vec!["react".to_string(), "loose-envify".to_string()],
    };

    let report = scan_with_services_inner(
        &dir,
        Default::default(),
        parsers::parse_dependencies(&dir, Some("npm")).unwrap(),
        &registry,
        &FakeOsvClient,
        &ScanOptions {
            deep: true,
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(report.packages_checked, 2);

    let report_no_deep = scan_with_services_inner(
        &dir,
        Default::default(),
        parsers::parse_dependencies(&dir, Some("npm")).unwrap(),
        &registry,
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(report_no_deep.packages_checked, 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn transitive_internal_deps_are_skipped() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies": {"react": "18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name": "demo", "lockfileVersion": 3, "packages": {"": {"name": "demo", "dependencies": {"react": "18.3.1"}}, "node_modules/react": {"version": "18.3.1"}, "node_modules/@myorg/internal-lib": {"version": "1.0.0"}}}"#,
    ).unwrap();

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
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let internal_issues: Vec<_> = report
        .issues
        .iter()
        .filter(|i| i.package.contains("myorg"))
        .collect();
    assert!(
        internal_issues.is_empty(),
        "Internal transitive deps should be skipped"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&config_dir);
}

#[tokio::test]
async fn npm_fixture_stale_shadow_package_lock_in_pnpm_repo_blocks() {
    let dir = fixture_dir("stale-shadow-package-lock-pnpm");
    let err = scan_with_source_full(&dir, Some("npm"), None, false, false, true, None)
        .await
        .expect_err("pnpm projects with a shadow package-lock must fail closed");
    let msg = err.to_string();
    assert!(msg.contains("pnpm"));
    assert!(msg.contains("package-lock"));
}

#[tokio::test]
async fn npm_fixture_stale_shadow_package_lock_in_yarn_repo_blocks() {
    let dir = fixture_dir("stale-shadow-package-lock-yarn");
    let err = scan_with_source_full(&dir, Some("npm"), None, false, false, true, None)
        .await
        .expect_err("yarn projects with a shadow package-lock must fail closed");
    let msg = err.to_string();
    assert!(msg.contains("yarn"));
    assert!(msg.contains("package-lock"));
}

#[tokio::test]
async fn npm_fixture_stale_shadow_package_lock_in_bun_repo_blocks() {
    let dir = fixture_dir("stale-shadow-package-lock-bun");
    let err = scan_with_source_full(&dir, Some("npm"), None, false, false, true, None)
        .await
        .expect_err("bun projects with a shadow package-lock must fail closed");
    let msg = err.to_string();
    assert!(msg.contains("bun"));
    assert!(msg.contains("package-lock"));
}

#[tokio::test]
async fn npm_fixture_override_only_drift_blocks_until_strict_verification_exists() {
    let dir = fixture_dir("override-only-drift");
    let err = scan_with_source_full(&dir, Some("npm"), None, false, false, true, None)
        .await
        .expect_err("overrides must not silently bypass strict lockfile trust");
    let msg = err.to_string();
    assert!(msg.contains("overrides"));
    assert!(msg.contains("package.json"));
}

#[tokio::test]
async fn npm_fixture_v1_range_drift_blocks_by_default() {
    let dir = fixture_dir("v1-range-drift");
    let err = scan_with_source_full(&dir, Some("npm"), None, false, false, true, None)
        .await
        .expect_err("legacy npm v1 lockfiles must block by default");
    let msg = err.to_string();
    assert!(msg.contains("legacy npm v5/v6 lockfile"));
    assert!(msg.contains("--lockfile-version 3"), "{msg}");
    assert!(msg.contains("sloppy-joe fix-lockfile"), "{msg}");
}
