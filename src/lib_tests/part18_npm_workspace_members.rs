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
    // A package.yaml member is rejected when discovery detects it; an ignored directory's member
    // is caught afterwards by the workspace check.
    for (member_dir, manifest, message) in [
        ("packages/tools", "package.yaml", "Unsupported manifest"),
        (".planning/tools", "package.json", "not a scanned project"),
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
            Err(error) => error.to_string().contains(message),
            Ok(report) => report
                .issues
                .iter()
                .any(|issue| issue.message.contains(message)),
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

#[tokio::test]
async fn npm_workspace_member_missing_from_the_root_lockfile_is_an_independent_install() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("packages/b")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","private":true,"workspaces":["packages/*"]}"#,
    )
    .unwrap();
    // The root lockfile records no `packages/b` entry, so npm never installs b from it.
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"root","lockfileVersion":3,"packages":{"":{"name":"root","workspaces":["packages/*"]}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/b/package.json"),
        r#"{"name":"b","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/b/package-lock.json"),
        r#"{"name":"b","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"b","version":"1.0.0"}}}"#,
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
    let member = report
        .projects
        .iter()
        .find(|p| p.manifest_path.ends_with("packages/b/package.json"))
        .unwrap_or_else(|| panic!("member not scanned: {:?}", report.projects));
    assert_eq!(
        member.status,
        report::ProjectScanStatus::Passed,
        "{:?}",
        report.issues
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.message.contains("independent")),
        "an install outside the root lockfile must be stated: {:?}",
        report.issues
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn a_symlinked_manifest_blocks_even_beside_a_healthy_project() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    for sub in ["svc", "web", "real"] {
        std::fs::create_dir_all(dir.join(sub)).unwrap();
    }
    std::fs::write(
        dir.join("svc/go.mod"),
        "module example.com/app\n\ngo 1.21\n",
    )
    .unwrap();
    std::fs::write(dir.join("svc/go.sum"), "").unwrap();
    std::fs::write(
        dir.join("real/package.json"),
        r#"{"name":"web","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink("../real/package.json", dir.join("web/package.json")).unwrap();
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
    .await;
    let blocked = match report {
        Err(_) => true,
        Ok(report) => report.has_incomplete_projects() || report.has_errors(),
    };
    assert!(blocked, "a symlinked manifest must not be skipped silently");
    std::fs::remove_dir_all(dir).unwrap();
}

/// A pnpm workspace whose root lockfile installs `evil-pkg` into `packages/a`, while
/// `packages/a` carries its own clean lockfile. Returns whether the scan blocked.
async fn pnpm_member_with_shadow_lockfile_blocks(workspace_yaml: &str) -> bool {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("packages/a")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","private":true,"packageManager":"pnpm@9.15.0"}"#,
    )
    .unwrap();
    std::fs::write(dir.join("pnpm-workspace.yaml"), workspace_yaml).unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\nimporters:\n  .: {}\n  packages/a:\n    dependencies:\n      evil-pkg:\n        specifier: 6.6.6\n        version: 6.6.6\npackages:\n  evil-pkg@6.6.6:\n    resolution: {integrity: sha512-AAAA}\nsnapshots:\n  evil-pkg@6.6.6: {}\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/a/package.json"),
        r#"{"name":"a","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/a/pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\nimporters:\n  .: {}\n",
    )
    .unwrap();
    let opts = ScanOptions {
        scan_mode: ScanMode::Fast,
        no_cache: true,
        ..Default::default()
    };
    let blocked = match scan_with_source_full_options(&dir, Some("npm"), None, &opts).await {
        Err(_) => true,
        Ok(report) => report.has_errors() || report.has_incomplete_projects(),
    };
    let _ = std::fs::remove_dir_all(&dir);
    blocked
}

#[tokio::test]
async fn pnpm_workspace_glob_syntax_cannot_hide_a_member_behind_its_own_lockfile() {
    assert!(
        !pnpm_member_with_shadow_lockfile_blocks("packages:\n  - 'other/*'\n").await,
        "control: a project outside the workspace is scanned on its own"
    );
    for pattern in [
        "packages/*",
        "packages/{a,b}",
        "{packages,apps}/a",
        "packages/?",
        "packages/[a-c]",
        "packages/[!b]",
        "packages/{a..c}",
        "packages/**",
        "Packages/A",
    ] {
        let yaml = format!("packages:\n  - '{pattern}'\n");
        assert!(
            pnpm_member_with_shadow_lockfile_blocks(&yaml).await,
            "'{pattern}' declares packages/a a member, so its own lockfile must not stand in for the workspace lockfile"
        );
    }
}

#[tokio::test]
async fn unsupported_workspace_glob_syntax_blocks_instead_of_matching_nothing() {
    for pattern in [
        "packages/@(a|b)",
        "packages/+(a)",
        "packages/\\a",
        "packages/[[:alpha:]]",
        "packages/{a",
        "packages/[a",
        "../outside/*",
        "!!packages/a",
    ] {
        let yaml = format!("packages:\n  - 'other/*'\n  - '{pattern}'\n");
        assert!(
            pnpm_member_with_shadow_lockfile_blocks(&yaml).await,
            "'{pattern}' cannot be evaluated exactly, so it must block"
        );
    }
}

#[tokio::test]
async fn pnpm_workspace_negation_excludes_a_member_whatever_the_order() {
    for yaml in [
        "packages:\n  - 'packages/*'\n  - '!packages/a'\n",
        "packages:\n  - '!packages/a'\n  - 'packages/*'\n",
    ] {
        assert!(
            !pnpm_member_with_shadow_lockfile_blocks(yaml).await,
            "pnpm excludes negated members, so packages/a installs on its own: {yaml}"
        );
    }
    assert!(
        pnpm_member_with_shadow_lockfile_blocks("packages:\n  - 'packages/*'\n  - '!packages/b'\n")
            .await,
        "excluding a different member keeps packages/a in the workspace"
    );
}
