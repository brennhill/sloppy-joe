use super::*;

#[tokio::test]
async fn npm_default_registry_overrides_and_cache_changes_remain_visible() {
    let dir = unique_dir();
    for name in ["package.json", "package-lock.json"] {
        std::fs::copy(
            fixture_dir("transitive-typosquat").join(name),
            dir.join(name),
        )
        .unwrap();
    }
    let cache_dir = unique_dir();
    let npmrc = dir.join(".npmrc");
    std::fs::write(&npmrc, "registry=\"https://registry.example/\"\n").unwrap();
    let full = ScanOptions {
        scan_mode: ScanMode::Ci,
        cache_dir: Some(&cache_dir),
        ..Default::default()
    };
    // Out-of-repo config allowlists the route for CI. Every package is routed
    // privately, so nothing is sent to the public registry or OSV.
    let config_dir = unique_dir();
    let config_path = config_dir.join("sloppy-joe.json");
    std::fs::write(
        &config_path,
        r#"{"trusted_registries":{"npm":[{"name":"default","source":"https://registry.example/"}]}}"#,
    )
    .unwrap();
    let report = scan_with_source_full_options(&dir, Some("npm"), config_path.to_str(), &full)
        .await
        .unwrap();
    assert!(!report.has_errors(), "{:?}", report.issues);
    assert_eq!(report.issues.len(), 2);
    std::fs::remove_dir_all(config_dir).unwrap();
    std::fs::write(&npmrc, "registry=https://registry.npmjs.org/\n").unwrap();
    let report = scan_with_source_full_options(
        &dir,
        Some("npm"),
        None,
        &ScanOptions {
            scan_mode: ScanMode::Fast,
            cache_dir: Some(&cache_dir),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        !report
            .issues
            .iter()
            .any(|i| i.check == "resolution/private-registry-unvetted")
    );
    assert!(
        report
            .full_scan_reasons
            .contains(&report::FullScanRecommendationReason::DependencyStateChanged)
    );
    assert!(
        report
            .full_scan_reasons
            .contains(&report::FullScanRecommendationReason::ManagerBindingChanged)
    );
    for invalid in [
        "registry=https://user:secret-must-not-appear@registry.example/",
        "registry=https://${REGISTRY_HOST}/",
        "registry=http://registry.example/",
        "overrides=secret-must-not-appear",
        "@invalid/scope:registry=https://registry.example/",
    ] {
        std::fs::write(&npmrc, invalid).unwrap();
        let error = scan_with_source_full_options(
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
        .expect_err("unmodeled config must fail explicitly");
        assert!(!error.to_string().contains("secret-must-not-appear"));
    }
    std::fs::remove_dir_all(dir).unwrap();
    std::fs::remove_dir_all(cache_dir).unwrap();
}

#[tokio::test]
async fn npm_workspace_peer_ranges_resolve_from_the_authoritative_root_lockfile() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("packages/worker")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"app","workspaces":["packages/*"],"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/worker/package.json"),
        r#"{"name":"worker","peerDependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("package-lock.json"), serde_json::json!({"lockfileVersion":3,"packages":{
        "":{"name":"app","workspaces":["packages/*"],"dependencies":{"react":"18.3.1"}},
        "packages/worker":{"name":"worker","peerDependencies":{"react":"^18.0.0"}},
        "node_modules/worker":{"resolved":"packages/worker","link":true},
        "node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}
    }}).to_string()).unwrap();
    let report = scan_with_source_full_options(
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
    .unwrap();
    assert!(
        !report.has_errors(),
        "workspace peer should use the root's exact locked version: {:?}",
        report.issues
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn planning_spikes_are_ignored_by_default_but_application_manifests_are_scanned() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"app","dependencies":{}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"name":"app","dependencies":{}}}}"#,
    )
    .unwrap();
    let spike = dir.join(".planning/spikes/camera");
    std::fs::create_dir_all(&spike).unwrap();
    std::fs::write(
        spike.join("package.json"),
        r#"{"overrides":{"adm-zip":"0.6.0"}}"#,
    )
    .unwrap();
    std::fs::write(spike.join("pyproject.toml"), "not valid toml = [").unwrap();
    let opts = ScanOptions {
        scan_mode: ScanMode::Fast,
        no_cache: true,
        ..Default::default()
    };
    let report = scan_with_source_full_options(&dir, None, None, &opts)
        .await
        .expect("planning spikes are outside the application scan");
    assert!(!report.has_errors());
    crate::bootstrap::discover_current_config(&dir)
        .expect("bootstrap discovery must also ignore planning spikes");
    let app = dir.join("web");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(
        app.join("package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    let report = scan_with_source_full_options(&dir, Some("npm"), None, &opts)
        .await
        .unwrap();
    assert!(report.has_errors() && report.has_incomplete_projects());
    assert!(report.issues.iter().any(|i| {
        i.project
            .as_deref()
            .is_some_and(|p| p.ends_with("web/package.json"))
    }));
    assert!(
        !report
            .issues
            .iter()
            .any(|i| i.message.contains(".planning"))
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn directory_exclusions_are_configurable_and_can_be_disabled() {
    let dir = unique_dir();
    let policy_dir = unique_dir();
    let policy = policy_dir.join("policy.json");
    std::fs::write(dir.join("package.json"), r#"{"dependencies":{}}"#).unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"dependencies":{}}}}"#,
    )
    .unwrap();
    for name in [".planning", "experiments"] {
        std::fs::create_dir_all(dir.join(name)).unwrap();
        std::fs::write(
            dir.join(name).join("package.json"),
            r#"{"dependencies":{"react":"18.3.1"}}"#,
        )
        .unwrap();
    }
    let opts = ScanOptions {
        scan_mode: ScanMode::Fast,
        no_cache: true,
        ..Default::default()
    };
    std::fs::write(&policy, r#"{"ignore_dirs":[".planning","experiments"]}"#).unwrap();
    let report = scan_with_source_full_options(&dir, Some("npm"), policy.to_str(), &opts)
        .await
        .unwrap();
    assert!(!report.has_errors());
    std::fs::write(&policy, r#"{"ignore_dirs":[]}"#).unwrap();
    let report = scan_with_source_full_options(&dir, Some("npm"), policy.to_str(), &opts)
        .await
        .unwrap();
    assert!(report.has_errors() && report.has_incomplete_projects());
    assert!(
        report
            .projects
            .iter()
            .any(|p| p.manifest_path.contains(".planning")
                && p.status == report::ProjectScanStatus::Unsupported)
    );
    for invalid in ["", ".", "..", "some/path", "some\\path", "*"] {
        std::fs::write(
            &policy,
            serde_json::json!({"ignore_dirs":[invalid]}).to_string(),
        )
        .unwrap();
        let error = scan_with_source_full_options(&dir, Some("npm"), policy.to_str(), &opts)
            .await
            .expect_err("exclusions accept directory names, not paths or globs");
        assert!(error.to_string().contains("ignore_dirs"), "{error}");
    }
    std::fs::remove_dir_all(dir).unwrap();
    std::fs::remove_dir_all(policy_dir).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_aliases_do_not_rediscover_ignored_planning_spikes() {
    let dir = unique_dir();
    std::fs::write(dir.join("package.json"), r#"{"dependencies":{}}"#).unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"dependencies":{}}}}"#,
    )
    .unwrap();
    std::fs::create_dir_all(dir.join(".planning")).unwrap();
    std::fs::write(
        dir.join(".planning/package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(".planning", dir.join("spike-alias")).unwrap();
    let report = scan_with_source_full_options(
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
    .expect("symlinks must respect the target's directory exclusion");
    assert!(!report.has_errors());
    // Selecting a planning project explicitly should still scan it.
    let error = scan_with_source_full_options(
        &dir.join(".planning"),
        Some("npm"),
        None,
        &ScanOptions {
            scan_mode: ScanMode::Fast,
            no_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect_err("explicit scan roots are not excluded");
    assert!(error.to_string().contains("lockfile"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn independent_npm_chains_under_a_pnpm_marker_keep_their_own_locked_versions() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pnpm-workspace.yaml"),
        "packages:\n  - web\n  - admin\n",
    )
    .unwrap();
    for (name, direct, transitive) in [("web", "18.3.1", "1.0.0"), ("admin", "19.0.0", "2.0.0")] {
        let path = dir.join(name);
        std::fs::create_dir_all(&path).unwrap();
        let manifest = serde_json::json!({"name":name,"dependencies":{"react":direct}});
        std::fs::write(path.join("package.json"), manifest.to_string()).unwrap();
        std::fs::write(path.join("package-lock.json"),serde_json::json!({"lockfileVersion":3,"packages":{
            "":{"name":name,"dependencies":{"react":direct}},
            "node_modules/react":{"version":direct,"resolved":format!("https://registry.npmjs.org/react/-/react-{direct}.tgz"),"integrity":"sha512-demo","dependencies":{"helper":transitive}},
            "node_modules/helper":{"version":transitive,"resolved":format!("https://registry.npmjs.org/helper/-/helper-{transitive}.tgz"),"integrity":"sha512-demo"}
        }}).to_string()).unwrap();
    }
    let versions = Arc::new(Mutex::new(Vec::new()));
    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        config::SloppyJoeConfig::default(),
        &FakeRegistry {
            existing: vec!["react".into(), "helper".into()],
        },
        &RecordingOsvClient {
            versions: versions.clone(),
        },
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect(
        "independent npm install roots must not be claimed by an incomplete ancestor pnpm marker",
    );
    assert_eq!(report.packages_checked, 4);
    for version in ["18.3.1", "19.0.0", "1.0.0", "2.0.0"] {
        assert!(
            versions
                .lock()
                .unwrap()
                .contains(&Some(version.to_string())),
            "chain version {version} was skipped"
        );
    }
    assert!(
        !report
            .issues
            .iter()
            .any(|i| i.check.starts_with("resolution/") && i.severity == Severity::Error),
        "{:?}",
        report.issues
    );
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.check == "resolution/independent-install-root")
    );
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\nimporters:\n  tools: {}\npackages: {}\n",
    )
    .unwrap();
    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        config::SloppyJoeConfig::default(),
        &FakeRegistry {
            existing: vec!["react".into(), "helper".into()],
        },
        &RecordingOsvClient {
            versions: versions.clone(),
        },
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("a lockfile for unrelated pnpm projects must not claim the npm chains");
    assert_eq!(report.packages_checked, 4);
    std::fs::write(
        dir.join(".npmrc"),
        "registry=https://unrelated-private.example/\n",
    )
    .unwrap();
    let isolated_versions = Arc::new(Mutex::new(Vec::new()));
    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        config::SloppyJoeConfig::default(),
        &FakeRegistry {
            existing: vec!["react".into(), "helper".into()],
        },
        &RecordingOsvClient {
            versions: isolated_versions.clone(),
        },
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        isolated_versions.lock().unwrap().len(),
        4,
        "a parent registry setting must not mark independent npm chains as private/unvetted"
    );
    assert!(
        !report
            .issues
            .iter()
            .any(|i| i.check == "resolution/private-registry-unvetted")
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn independent_project_runs_continue_after_an_unsupported_dependency_chain() {
    let dir = unique_dir();
    for name in ["a-unsupported", "z-private"] {
        std::fs::create_dir_all(dir.join(name)).unwrap();
    }
    std::fs::write(
        dir.join("a-unsupported/package.json"),
        r#"{"name":"experiment","dependencies":{},"overrides":{"adm-zip":"0.6.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("a-unsupported/package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"name":"experiment","dependencies":{}}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("z-private/.npmrc"),
        "@company:registry=https://registry.example/private/\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("z-private/package.json"),
        r#"{"dependencies":{"@company/client":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("z-private/package-lock.json"), r#"{"lockfileVersion":3,"packages":{"":{"dependencies":{"@company/client":"1.0.0"}},"node_modules/@company/client":{"version":"1.0.0","resolved":"https://registry.example/private/client.tgz","integrity":"sha512-demo"}}}"#).unwrap();
    let cache_dir = unique_dir();
    // Out-of-repo config allowlists the route so CI accepts it.
    let config_path = cache_dir.join("sloppy-joe.json");
    std::fs::write(
        &config_path,
        r#"{"trusted_registries":{"npm":[{"name":"@company","source":"https://registry.example/private/"}]}}"#,
    )
    .unwrap();
    let config_source = config_path.to_str().unwrap();
    let report = scan_with_source_full_options(
        &dir,
        Some("npm"),
        Some(config_source),
        &ScanOptions {
            scan_mode: ScanMode::Ci,
            cache_dir: Some(&cache_dir),
            ..Default::default()
        },
    )
    .await
    .expect("an unsupported project must not prevent independent chains from running");
    assert_eq!(report.packages_checked, 1);
    assert!(
        report.has_errors(),
        "incomplete repository scans must still block CI"
    );
    let json = serde_json::to_value(&report).unwrap();
    let projects = json["projects"]
        .as_array()
        .expect("report must identify the independently scanned projects");
    assert_eq!(projects.len(), 2);
    assert!(projects.iter().any(|p| {
        p["manifest_path"]
            .as_str()
            .unwrap()
            .ends_with("a-unsupported/package.json")
            && p["status"] == "unsupported"
    }));
    assert!(projects.iter().any(|p| {
        p["manifest_path"]
            .as_str()
            .unwrap()
            .ends_with("z-private/package.json")
            && p["status"] == "passed"
            && p["manager"] == "npm"
    }));
    let private = json["issues"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["check"] == "resolution/private-registry-unvetted")
        .unwrap();
    assert!(
        private["project"]
            .as_str()
            .unwrap()
            .ends_with("z-private/package.json")
    );
    assert!(
        !cache_dir.join("full-scan-fingerprint.json").exists(),
        "partial scans must not be cached as successful full scans"
    );
    assert!(report.render_human().contains("z-private"));
    std::fs::write(
        dir.join("a-unsupported/.npmrc"),
        "unsupported-rewrite=true\n",
    )
    .unwrap();
    let report = scan_with_source_full_options(
        &dir,
        Some("npm"),
        Some(config_source),
        &ScanOptions {
            scan_mode: ScanMode::Ci,
            no_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("manager-binding failures must also be isolated from independent project runs");
    assert_eq!(report.packages_checked, 1);
    assert!(report.has_incomplete_projects());
    assert_eq!(report.projects.len(), 2);
    std::fs::remove_dir_all(dir).unwrap();
    std::fs::remove_dir_all(cache_dir).unwrap();
}

#[tokio::test]
async fn repository_reports_separate_node_and_rust_dependency_chains() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("web")).unwrap();
    std::fs::create_dir_all(dir.join("backend")).unwrap();
    std::fs::write(
        dir.join("web/package.json"),
        r#"{"dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("web/package-lock.json"), r#"{"lockfileVersion":3,"packages":{"":{"dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#).unwrap();
    std::fs::write(
        dir.join("backend/Cargo.toml"),
        "[package]\nname = \"backend\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"=1.0.0\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("backend/Cargo.lock"), "version = 4\n[[package]]\nname = \"backend\"\nversion = \"0.1.0\"\ndependencies = [\"serde\"]\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n").unwrap();
    let report = scan_with_source_full_options(
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
    .unwrap();
    assert!(!report.has_errors(), "{:?}", report.issues);
    assert_eq!(report.projects.len(), 2);
    for manager in ["npm", "cargo"] {
        let project = report
            .projects
            .iter()
            .find(|p| p.manager.as_deref() == Some(manager))
            .expect("each dependency chain must report its manager");
        assert_eq!(project.packages_checked, 1);
        assert!(project.lockfile_path.is_some());
    }
    assert_eq!(report.packages_checked, 2);
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn transitive_npm_links_outside_the_scan_root_cannot_pass_full_checks() {
    let dir = unique_dir();
    let outside = unique_dir();
    let cache_dir = unique_dir();
    std::fs::write(
        outside.join("package.json"),
        r#"{"name":"evil","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"is-number":"7.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("package-lock.json"), serde_json::json!({"lockfileVersion":3,"packages":{
        "":{"dependencies":{"is-number":"7.0.0"}},
        "node_modules/is-number":{"version":"7.0.0","resolved":"https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz","integrity":"sha512-demo","dependencies":{"evil":format!("file:{}",outside.display())}},
        "node_modules/evil":{"resolved":outside.display().to_string(),"link":true}
    }}).to_string()).unwrap();
    let error = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        config::SloppyJoeConfig::default(),
        &FakeRegistry {
            existing: vec!["is-number".into()],
        },
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect_err("an installable external transitive link must not disappear from a full scan");
    assert!(
        error.to_string().contains("evil") && error.to_string().contains("outside the scan root"),
        "{error}"
    );
    let result = scan_with_source_full_options(
        &dir,
        Some("npm"),
        None,
        &ScanOptions {
            scan_mode: ScanMode::Ci,
            cache_dir: Some(&cache_dir),
            ..Default::default()
        },
    )
    .await;
    assert!(
        result.is_err(),
        "unsupported transitive sources must block before online checks"
    );
    assert!(!cache_dir.join("full-scan-fingerprint.json").exists());
    std::fs::remove_dir_all(dir).unwrap();
    std::fs::remove_dir_all(outside).unwrap();
    std::fs::remove_dir_all(cache_dir).unwrap();
}
