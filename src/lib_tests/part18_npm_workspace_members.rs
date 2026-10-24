use super::*;

#[tokio::test]
async fn npm_workspace_members_use_the_nearest_locked_dependency_version() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#,
    )
    .unwrap();
    let mut packages = serde_json::json!({
        "":{"name":"root","workspaces":["packages/*"]},
        "node_modules/is-number":{"version":"7.0.0","resolved":"https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz","integrity":"sha512-demo"},
        "packages/b/node_modules/is-number":{"version":"6.0.0","resolved":"https://registry.npmjs.org/is-number/-/is-number-6.0.0.tgz","integrity":"sha512-demo"}
    });
    for (name, version) in [("a", "7.0.0"), ("b", "6.0.0")] {
        let path = dir.join("packages").join(name);
        std::fs::create_dir_all(&path).unwrap();
        let manifest =
            serde_json::json!({"name":name,"version":"1.0.0","dependencies":{"is-number":version}});
        std::fs::write(path.join("package.json"), manifest.to_string()).unwrap();
        packages[format!("packages/{name}")] = manifest;
        packages[format!("node_modules/{name}")] =
            serde_json::json!({"resolved":format!("packages/{name}"),"link":true});
    }
    std::fs::write(
        dir.join("package-lock.json"),
        serde_json::json!({"name":"root","lockfileVersion":3,"packages":packages}).to_string(),
    )
    .unwrap();
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
        "npm's valid nested version must win over the hoisted version: {:?}",
        report.issues
    );
    let versions = Arc::new(Mutex::new(Vec::new()));
    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        config::SloppyJoeConfig::default(),
        &FakeRegistry {
            existing: vec!["is-number".into()],
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
    .unwrap();
    assert!(
        !report
            .issues
            .iter()
            .any(|i| i.check.starts_with("resolution/") && i.severity == Severity::Error),
        "{:?}",
        report.issues
    );
    for version in ["6.0.0", "7.0.0"] {
        assert!(
            versions
                .lock()
                .unwrap()
                .contains(&Some(version.to_string())),
            "installed version {version} must reach vulnerability checks"
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn unrelated_parent_manager_conflicts_do_not_suppress_independent_children() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("frontend")).unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"name":"parent"}}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("frontend/package.json"), r#"{"name":"frontend"}"#).unwrap();
    std::fs::write(
        dir.join("frontend/package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"name":"frontend"}}}"#,
    )
    .unwrap();
    let opts = ScanOptions {
        scan_mode: ScanMode::Fast,
        no_cache: true,
        ..Default::default()
    };
    for workspaces in [None, Some(serde_json::json!(["other/*"]))] {
        let mut parent = serde_json::json!({"name":"parent","packageManager":"pnpm@9.0.0"});
        if let Some(patterns) = workspaces {
            parent["workspaces"] = patterns;
        }
        std::fs::write(dir.join("package.json"), parent.to_string()).unwrap();
        let report = scan_with_source_full_options(&dir, Some("npm"), None, &opts)
            .await
            .unwrap();
        assert!(
            report.has_incomplete_projects(),
            "the parent must remain unsupported"
        );
        let child = report
            .projects
            .iter()
            .find(|p| p.manifest_path.ends_with("frontend/package.json"))
            .unwrap();
        assert_eq!(
            child.status,
            report::ProjectScanStatus::Passed,
            "an unrelated parent's manager conflict must not claim the frontend: {:?}",
            report.issues
        );
        assert_eq!(child.manager.as_deref(), Some("npm"));
    }
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"parent","packageManager":"pnpm@9.0.0","workspaces":["frontend"]}"#,
    )
    .unwrap();
    let report = scan_with_source_full_options(&dir, Some("npm"), None, &opts)
        .await
        .unwrap();
    assert!(
        report
            .projects
            .iter()
            .filter(|p| p.status == report::ProjectScanStatus::Unsupported)
            .count()
            == 2,
        "an applicable conflicting workspace must still block both projects"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn pnpm_workspace_members_that_discovery_cannot_bind_block_the_scan() {
    for (member_dir, manifest) in [
        ("packages/tools", "package.yaml"),
        (".planning/tools", "package.json"),
    ] {
        let dir = unique_dir();
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::create_dir_all(dir.join(member_dir)).unwrap();
        std::fs::write(
            dir.join("package.json"),
            r#"{"name":"root","packageManager":"pnpm@9.0.0"}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("pnpm-workspace.yaml"),
            "packages:\n  - 'packages/*'\n  - '.planning/*'\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("pnpm-lock.yaml"),
            format!("lockfileVersion: '9.0'\nimporters:\n  .: {{}}\n  {member_dir}:\n    dependencies:\n      evil-pkg:\n        specifier: 6.6.6\n        version: 6.6.6\n"),
        )
        .unwrap();
        std::fs::write(
            dir.join(member_dir).join(manifest),
            r#"{"name":"tools","dependencies":{"evil-pkg":"6.6.6"}}"#,
        )
        .unwrap();
        let blocked = match scan_with_source(&dir, Some("npm"), None, false).await {
            Err(error) => error.to_string().contains("not a scanned project"),
            Ok(report) => report
                .issues
                .iter()
                .any(|issue| issue.message.contains("not a scanned project")),
        };
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            blocked,
            "{member_dir}/{manifest} must not be silently unscanned"
        );
    }
}

#[test]
fn bundler_gems_rb_is_not_silently_skipped() {
    let project = |extra: Option<&str>| {
        let dir = unique_dir();
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app"}}}"#,
        )
        .unwrap();
        if let Some(name) = extra {
            std::fs::write(dir.join(name), "source \"https://rubygems.org\"\n").unwrap();
        }
        dir
    };
    let control = project(None);
    let control_result = preflight_scan_inputs(&control, None);
    let _ = std::fs::remove_dir_all(&control);
    assert!(
        control_result.is_ok(),
        "control project must pass: {control_result:?}"
    );
    for name in ["gems.rb", "gems.locked"] {
        let dir = project(Some(name));
        let result = preflight_scan_inputs(&dir, None);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(result.is_err(), "{name} must fail closed");
    }
}

#[test]
fn cargo_member_scans_refuse_a_workspace_root_above_the_scan_root() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("svc/src")).unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        "[workspace]\nmembers = [\"svc\"]\nresolver = \"2\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("svc/Cargo.toml"),
        "[package]\nname = \"svc\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("svc/src/lib.rs"), "").unwrap();
    let result = preflight_scan_inputs(&dir.join("svc"), Some("cargo"));
    let _ = std::fs::remove_dir_all(&dir);
    let error = result.expect_err("a member below a workspace root must not be scanned alone");
    assert!(error.to_string().contains("above the scan root"), "{error}");
}
