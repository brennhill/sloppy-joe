use super::*;

#[test]
fn preflight_accepts_workspace_child_with_only_root_lockfile() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","workspaces":["apps/*"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"root","lockfileVersion":3,"packages":{"":{"name":"root","workspaces":["apps/*"]},"apps/web":{"name":"web","dependencies":{"react":"^18.3.0"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"react":"^18.3.0"}}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, None)
        .expect("workspace children should bind to the root npm lockfile when one exists");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_shadow_child_lockfile_inside_npm_workspace() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","workspaces":["apps/*"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"root","lockfileVersion":3,"packages":{"":{"name":"root","workspaces":["apps/*"]},"apps/web":{"name":"web","dependencies":{"react":"^18.3.0"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"react":"^18.3.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package-lock.json"),
        r#"{"name":"web","lockfileVersion":3,"packages":{"":{"name":"web","dependencies":{"react":"^18.3.0"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-shadow"}}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, None).expect_err(
        "workspace children must not carry shadow npm lockfiles beside the root lockfile",
    );
    let msg = err.to_string();
    assert!(msg.contains("apps/web/package-lock.json"));
    assert!(msg.contains("workspace"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_supported_pnpm_root_alongside_unrelated_nested_npm_project() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"pnpm@9.0.0","workspaces":["apps/*"]}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\nimporters:\n  .: {}\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package-lock.json"),
        r#"{"name":"web","lockfileVersion":3,"packages":{"":{"name":"web","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, None)
        .expect("supported pnpm roots should coexist with unrelated nested npm projects");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_allows_nested_npm_project_when_ancestor_pnpm_root_does_not_claim_it() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"pnpm@9.0.0"}"#,
    )
    .unwrap();
    std::fs::write(dir.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package-lock.json"),
        r#"{"name":"web","lockfileVersion":3,"packages":{"":{"name":"web","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir.join("apps/web"), Some("npm"))
        .expect("ancestor pnpm state should not capture unrelated nested npm projects");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_standalone_pnpm_project_with_pnpm_lockfile() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"pnpm@9.0.0","dependencies":{"react":"^18.3.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: ^18.3.0
        version: 18.3.1
packages:
  react@18.3.1:
    resolution:
      integrity: sha512-react
"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, Some("npm"))
        .expect("standalone pnpm projects with pnpm-lock.yaml should be accepted");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_pnpm_lockfile_without_integrity() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"pnpm@9.0.0","dependencies":{"react":"^18.3.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: ^18.3.0
        version: 18.3.1
packages:
  react@18.3.1:
    resolution: {}
"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("pnpm lockfiles without integrity should be rejected");
    assert!(err.to_string().contains("integrity"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_pnpm_lockfile_with_wrong_tarball_identity() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"pnpm@9.0.0","dependencies":{"react":"^18.3.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: ^18.3.0
        version: 18.3.1
packages:
  react@18.3.1:
    resolution:
      integrity: sha512-react
      tarball: https://registry.npmjs.org/not-react/-/not-react-18.3.1.tgz
"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("npm"))
        .expect_err("pnpm lockfiles with the wrong tarball identity should be rejected");
    assert!(
        err.to_string()
            .contains("does not match the locked package identity")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_pnpm_workspace_child_with_root_lockfile() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::create_dir_all(dir.join("packages/workspace-lib")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"pnpm@9.0.0"}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("pnpm-workspace.yaml"),
        "packages:\n  - 'apps/*'\n  - 'packages/*'\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'
importers:
  .: {}
  apps/web:
    dependencies:
      workspace-lib:
        specifier: workspace:*
        version: link:../../packages/workspace-lib
      react:
        specifier: ^18.3.0
        version: 18.3.1
  packages/workspace-lib: {}
packages:
  react@18.3.1:
    resolution:
      integrity: sha512-react
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"workspace-lib":"workspace:*","react":"^18.3.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages/workspace-lib/package.json"),
        r#"{"name":"workspace-lib"}"#,
    )
    .unwrap();

    std::fs::create_dir_all(dir.join(".planning/spikes")).unwrap();
    std::fs::write(
        dir.join(".planning/spikes/pyproject.toml"),
        "invalid toml = [",
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir.join("apps/web"), Some("npm"))
        .expect("pnpm workspace children should bind to the root pnpm-lock.yaml");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_shadow_child_pnpm_lockfile_inside_workspace() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"pnpm@9.0.0"}"#,
    )
    .unwrap();
    std::fs::write(dir.join("pnpm-workspace.yaml"), "packages:\n  - 'apps/*'\n").unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\nimporters:\n  .: {}\n  apps/web: {}\n",
    )
    .unwrap();
    std::fs::write(dir.join("apps/web/package.json"), r#"{"name":"web"}"#).unwrap();
    std::fs::write(
        dir.join("apps/web/pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\nimporters:\n  .: {}\n",
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, None)
        .expect_err("workspace children must not carry shadow pnpm lockfiles");
    let msg = err.to_string();
    assert!(msg.contains("apps/web/pnpm-lock.yaml"));
    assert!(msg.contains("workspace"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_foreign_child_lockfile_inside_pnpm_workspace() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"pnpm@9.0.0"}"#,
    )
    .unwrap();
    std::fs::write(dir.join("pnpm-workspace.yaml"), "packages:\n  - 'apps/*'\n").unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'
importers:
  .: {}
  apps/web: {}
"#,
    )
    .unwrap();
    std::fs::write(dir.join("apps/web/package.json"), r#"{"name":"web"}"#).unwrap();
    std::fs::write(
        dir.join("apps/web/package-lock.json"),
        r#"{"name":"web","lockfileVersion":3}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir.join("apps/web"), Some("npm"))
        .expect_err("workspace children must not carry conflicting JS lockfiles");
    let msg = err.to_string();
    assert!(msg.contains("apps/web/package-lock.json"));
    assert!(msg.contains("workspace"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_uses_pnpm_lockfile_exact_versions_for_direct_dependencies() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"pnpm@9.0.0","dependencies":{"react":"^18.3.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: ^18.3.0
        version: 18.3.1
packages:
  react@18.3.1:
    resolution:
      integrity: sha512-react
"#,
    )
    .unwrap();

    let metadata_versions = Arc::new(Mutex::new(Vec::new()));
    let osv_versions = Arc::new(Mutex::new(Vec::new()));
    let registry = RecordingRegistry {
        existing: vec!["react".to_string()],
        versions: metadata_versions.clone(),
    };
    let osv = RecordingOsvClient {
        versions: osv_versions.clone(),
    };

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        Default::default(),
        &registry,
        &osv,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("pnpm lockfiles should drive exact direct versions");

    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.check == "resolution/no-exact-version")
    );
    let metadata_versions = metadata_versions.lock().unwrap().clone();
    let osv_versions = osv_versions.lock().unwrap().clone();
    assert!(metadata_versions.contains(&Some("18.3.1".to_string())));
    assert!(osv_versions.contains(&Some("18.3.1".to_string())));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_uses_pnpm_lockfile_for_transitive_dependencies() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"pnpm@9.0.0","dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: 18.3.1
        version: 18.3.1
packages:
  react@18.3.1:
    resolution:
      integrity: sha512-react
  evil-transitive@1.0.0:
    resolution:
      integrity: sha512-evil
snapshots:
  react@18.3.1:
    dependencies:
      evil-transitive: 1.0.0
"#,
    )
    .unwrap();

    let registry = FakeRegistry {
        existing: vec!["react".to_string(), "evil-transitive".to_string()],
    };
    let osv = VulnOsvClient {
        vulnerable: vec!["evil-transitive".to_string()],
    };

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        Default::default(),
        &registry,
        &osv,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("pnpm lockfiles should provide trusted transitive coverage");

    let trans_issue = report.issues.iter().find(|issue| {
        issue.package == "evil-transitive" && issue.source.as_deref() == Some("transitive")
    });
    assert!(
        trans_issue.is_some(),
        "pnpm transitive dependencies should enter the scan pipeline"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_accepts_pnpm_workspace_child_without_root_package_json() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(dir.join("pnpm-workspace.yaml"), "packages:\n  - 'apps/*'\n").unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'
importers:
  apps/web:
    dependencies:
      react:
        specifier: 18.3.1
        version: 18.3.1
packages:
  react@18.3.1:
    resolution:
      integrity: sha512-react
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir.join("apps/web"), Some("npm"))
        .expect("pnpm-workspace.yaml should be enough to bind a child to the pnpm root");
    assert!(warnings.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pnpm_workspace_child_does_not_inherit_sibling_transitives() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    let lockfile = dir.join("pnpm-lock.yaml");
    std::fs::write(
        &lockfile,
        r#"lockfileVersion: '9.0'
importers:
  apps/web:
    dependencies:
      react:
        specifier: 18.3.1
        version: 18.3.1
  apps/api:
    dependencies:
      axios:
        specifier: 1.7.0
        version: 1.7.0
packages:
  react@18.3.1:
    resolution:
      integrity: sha512-react
  evil-web@1.0.0:
    resolution:
      integrity: sha512-evil-web
  axios@1.7.0:
    resolution:
      integrity: sha512-axios
  evil-api@9.9.9:
    resolution:
      integrity: sha512-evil-api
snapshots:
  react@18.3.1:
    dependencies:
      evil-web: 1.0.0
  axios@1.7.0:
    dependencies:
      evil-api: 9.9.9
"#,
    )
    .unwrap();
    let deps = vec![Dependency {
        name: "react".to_string(),
        version: Some("18.3.1".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }];

    let lock = crate::lockfiles::LockfileData::parse_for_kind_with_lockfile(
        &dir.join("apps/web"),
        Some(ProjectInputKind::Npm.lockfile_kind()),
        &deps,
        Some(&lockfile),
    )
    .expect("pnpm workspace child should parse with authoritative root lockfile");

    assert!(
        lock.transitive_deps
            .iter()
            .any(|dep| dep.package_name() == "evil-web")
    );
    assert!(
        !lock
            .transitive_deps
            .iter()
            .any(|dep| dep.package_name() == "evil-api" || dep.package_name() == "axios")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_uses_pnpm_lock_for_alias_direct_dependencies() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","packageManager":"pnpm@9.0.0","dependencies":{"alias-react":"npm:react@^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      alias-react:
        specifier: npm:react@^18.0.0
        version: npm:react@18.3.1
packages:
  react@18.3.1:
    resolution:
      integrity: sha512-react
"#,
    )
    .unwrap();

    let metadata_versions = Arc::new(Mutex::new(Vec::new()));
    let osv_versions = Arc::new(Mutex::new(Vec::new()));
    let registry = RecordingRegistry {
        existing: vec!["react".to_string()],
        versions: metadata_versions.clone(),
    };
    let osv = RecordingOsvClient {
        versions: osv_versions.clone(),
    };

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        Default::default(),
        &registry,
        &osv,
        &ScanOptions {
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("pnpm alias direct dependencies should resolve through pnpm-lock.yaml");

    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.check == "resolution/no-exact-version")
    );
    assert!(
        metadata_versions
            .lock()
            .unwrap()
            .contains(&Some("18.3.1".to_string()))
    );
    assert!(
        osv_versions
            .lock()
            .unwrap()
            .contains(&Some("18.3.1".to_string()))
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_nested_npm_project_under_ancestor_bun_lockfile() {
    let dir = unique_dir();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::create_dir_all(dir.join("apps/web")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"root","packageManager":"bun@1.1.0","workspaces":["apps/*"]}"#,
    )
    .unwrap();
    std::fs::write(dir.join("bun.lock"), "dummy\n").unwrap();
    std::fs::write(
        dir.join("apps/web/package.json"),
        r#"{"name":"web","dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("apps/web/package-lock.json"),
        r#"{"name":"web","lockfileVersion":3,"packages":{"":{"name":"web","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, None)
        .expect_err("unsupported JS manager roots must block npm trust");
    let msg = err.to_string();
    assert!(msg.contains("bun"));

    let _ = std::fs::remove_dir_all(&dir);
}
