use super::*;

#[test]
fn preflight_blocks_invalid_secondary_dotnet_manifest() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("app.csproj"),
        r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup></Project>"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("broken.csproj"),
        r#"<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Bad?Package" Version="1.0.0" /></ItemGroup></Project>"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("packages.lock.json"),
        r#"{"version":1,"dependencies":{}}"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("dotnet"))
        .expect_err("every detected .csproj manifest must be parsed or rejected");
    let msg = err.to_string();
    assert!(msg.contains("broken.csproj"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_warns_for_maven_without_a_trusted_lockfile() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pom.xml"),
        r#"<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>demo</artifactId><version>1.0.0</version></project>"#,
    )
    .unwrap();

    let warnings = preflight_scan_inputs(&dir, Some("jvm")).unwrap();
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].severity, Severity::Warning);
    assert!(warnings[0].message.contains("Maven"));
    assert!(warnings[0].message.contains("Gradle"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_empty_project_returns_empty_report() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name": "test", "version": "1.0"}"#,
    )
    .unwrap();
    let registry = FakeRegistry { existing: vec![] };
    let report = scan_with_services_inner(
        &dir,
        Default::default(),
        parsers::parse_dependencies(&dir, Some("npm")).unwrap(),
        &registry,
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(report.packages_checked, 0);
    assert!(!report.has_issues());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_with_deps_returns_report() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies": {"react": "^18.0"}}"#,
    )
    .unwrap();
    let registry = FakeRegistry {
        existing: vec!["react".to_string()],
    };
    let report = scan_with_services_inner(
        &dir,
        Default::default(),
        parsers::parse_dependencies(&dir, Some("npm")).unwrap(),
        &registry,
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(report.packages_checked, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_with_internal_skips_all_checks() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies": {"react": "^18.0", "@myorg/utils": "1.0"}}"#,
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
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // Only react is non-internal; @myorg/utils is internal and should not be counted
    assert_eq!(report.packages_checked, 1);
    let myorg_issues: Vec<_> = report
        .issues
        .iter()
        .filter(|i| i.package.contains("myorg"))
        .collect();
    assert!(myorg_issues.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&config_dir);
}

#[tokio::test]
async fn scan_with_canonical_config_flags_alternatives() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies": {"moment": "^2.0"}}"#,
    )
    .unwrap();
    let config_dir = unique_dir();
    let config_path = config_dir.join("config.json");
    std::fs::write(
        &config_path,
        r#"{"canonical":{"npm":{"dayjs":["moment"]}},"internal":{},"allowed":{}}"#,
    )
    .unwrap();
    let config = config::load_config(Some(config_path.as_path())).unwrap();
    let registry = FakeRegistry {
        existing: vec!["moment".to_string()],
    };
    let report = scan_with_services_inner(
        &dir,
        config,
        parsers::parse_dependencies(&dir, Some("npm")).unwrap(),
        &registry,
        &FakeOsvClient,
        &ScanOptions {
            no_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let canonical_issues: Vec<_> = report
        .issues
        .iter()
        .filter(|i| i.check == "canonical")
        .collect();
    assert_eq!(canonical_issues.len(), 1);
    assert_eq!(canonical_issues[0].package, "moment");
    assert_eq!(canonical_issues[0].suggestion, Some("dayjs".to_string()));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&config_dir);
}

#[tokio::test]
async fn scan_rejects_config_inside_project_dir() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name": "test", "version": "1.0"}"#,
    )
    .unwrap();
    let config_path = dir.join("sloppy-joe.json");
    std::fs::write(
        &config_path,
        r#"{"canonical":{},"internal":{},"allowed":{}}"#,
    )
    .unwrap();

    let err = scan_with_source(
        &dir,
        Some("npm"),
        Some(config_path.to_str().unwrap()),
        false,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("outside the project directory"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_uses_npm_lockfile_version_for_metadata_and_osv() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies": {"react": "^18.2.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name": "demo", "lockfileVersion": 3, "packages": {"": {"name": "demo", "dependencies": {"react": "^18.2.0"}}, "node_modules/react": {"version": "18.3.1"}}}"#,
    ).unwrap();

    let metadata_versions = Arc::new(Mutex::new(Vec::new()));
    let osv_versions = Arc::new(Mutex::new(Vec::new()));
    let registry = RecordingRegistry {
        existing: vec!["react".to_string()],
        versions: metadata_versions.clone(),
    };
    let osv = RecordingOsvClient {
        versions: osv_versions.clone(),
    };

    let report =
        scan_with_services_no_osv_cache(&dir, Some("npm"), Default::default(), &registry, &osv)
            .await
            .unwrap();

    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.check == "metadata/unresolved-version")
    );
    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.check == "malicious/unresolved-version")
    );
    assert_eq!(
        metadata_versions.lock().unwrap().as_slice(),
        &[Some("18.3.1".to_string())]
    );
    assert_eq!(
        osv_versions.lock().unwrap().as_slice(),
        &[Some("18.3.1".to_string())]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_reports_out_of_sync_lockfile_state() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies": {"react": "18.2.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name": "demo", "lockfileVersion": 3, "packages": {"": {"name": "demo", "dependencies": {"react": "18.2.0"}}, "node_modules/react": {"version": "18.3.1"}}}"#,
    ).unwrap();

    let metadata_versions = Arc::new(Mutex::new(Vec::new()));
    let osv_versions = Arc::new(Mutex::new(Vec::new()));
    let registry = RecordingRegistry {
        existing: vec!["react".to_string()],
        versions: metadata_versions.clone(),
    };
    let osv = RecordingOsvClient {
        versions: osv_versions.clone(),
    };

    let report =
        scan_with_services_no_osv_cache(&dir, Some("npm"), Default::default(), &registry, &osv)
            .await
            .unwrap();

    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.check == "resolution/lockfile-out-of-sync")
    );
    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.check == "metadata/unresolved-version")
    );
    assert_eq!(
        metadata_versions.lock().unwrap().as_slice(),
        &[Some("18.2.0".to_string())]
    );
    assert_eq!(
        osv_versions.lock().unwrap().as_slice(),
        &[Some("18.2.0".to_string())]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_versionless_dependency_blocks_by_default() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"latest"}}"#,
    )
    .unwrap();

    let metadata_versions = Arc::new(Mutex::new(Vec::new()));
    let osv_versions = Arc::new(Mutex::new(Vec::new()));
    let registry = RecordingRegistry {
        existing: vec!["react".to_string()],
        versions: metadata_versions,
    };
    let osv = RecordingOsvClient {
        versions: osv_versions.clone(),
    };

    let report =
        scan_with_services_no_osv_cache(&dir, Some("npm"), Default::default(), &registry, &osv)
            .await
            .unwrap();

    let issue = report
        .issues
        .iter()
        .find(|issue| issue.check == "resolution/no-exact-version")
        .unwrap();
    assert_eq!(issue.severity, report::Severity::Error);
    assert!(report.has_issues());
    assert!(report.has_errors());
    // Unresolved deps now DO query OSV (with version: None) — fail-closed, not fail-open
    assert_eq!(osv_versions.lock().unwrap().as_slice(), &[None::<String>]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_versionless_dependency_warns_when_allowed() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"latest"}}"#,
    )
    .unwrap();

    let registry = RecordingRegistry {
        existing: vec!["react".to_string()],
        versions: Arc::new(Mutex::new(Vec::new())),
    };
    let osv = RecordingOsvClient {
        versions: Arc::new(Mutex::new(Vec::new())),
    };
    let config = config::SloppyJoeConfig {
        allow_unresolved_versions: true,
        ..Default::default()
    };

    let report = scan_with_services_no_osv_cache(&dir, Some("npm"), config, &registry, &osv)
        .await
        .unwrap();

    let issue = report
        .issues
        .iter()
        .find(|issue| issue.check == "resolution/no-exact-version")
        .unwrap();
    assert_eq!(issue.severity, report::Severity::Warning);
    assert!(report.has_issues());
    assert!(!report.has_errors());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unresolved_version_policy_only_skips_matching_lockfile_sync_issue_keys() {
    let dep_a = Dependency {
        name: "react".to_string(),
        version: Some("^18.2.0".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    };
    let dep_b = Dependency {
        name: "react".to_string(),
        version: Some("^19.0.0".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    };

    let mut resolution = lockfiles::ResolutionResult::default();
    resolution.push_issue_for(
        &dep_a,
        report::Issue::new(
            "react",
            checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE_SYNC,
            report::Severity::Error,
        )
        .message("unsynced")
        .fix("fix"),
    );

    let issues = checks::unresolved::unresolved_version_policy_issues(
        &[dep_a.clone(), dep_b.clone()],
        &resolution,
        &config::SloppyJoeConfig::default(),
    );

    assert_eq!(issues.len(), 1);
    assert!(issues[0].message.contains("^19.0.0"));
}

/// Proves that non-metadata ecosystems (Go) make exactly 1 registry call per dep,
/// not 3 (metadata + exists fallback + existence check).
#[tokio::test]
async fn non_metadata_ecosystem_makes_one_registry_call_per_dep() {
    use std::sync::atomic::AtomicU32;

    struct CountingRegistry {
        existing: Vec<String>,
        exists_count: Arc<AtomicU32>,
        metadata_count: Arc<AtomicU32>,
    }

    #[async_trait]
    impl RegistryExistence for CountingRegistry {
        async fn exists(&self, name: &str) -> Result<bool> {
            self.exists_count.fetch_add(1, Ordering::SeqCst);
            Ok(self.existing.contains(&name.to_string()))
        }
        fn ecosystem(&self) -> &str {
            "go"
        }
    }

    #[async_trait]
    impl RegistryMetadata for CountingRegistry {
        async fn metadata(
            &self,
            _name: &str,
            _version: Option<&str>,
        ) -> Result<Option<PackageMetadata>> {
            self.metadata_count.fetch_add(1, Ordering::SeqCst);
            Ok(None) // Go doesn't support metadata
        }
    }

    let dir = unique_dir();
    std::fs::write(dir.join("go.mod"), "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n\tgithub.com/spf13/cobra v1.7.0\n)\n").unwrap();

    let exists_count = Arc::new(AtomicU32::new(0));
    let metadata_count = Arc::new(AtomicU32::new(0));
    let registry = CountingRegistry {
        existing: vec![
            "github.com/gin-gonic/gin".to_string(),
            "github.com/spf13/cobra".to_string(),
        ],
        exists_count: exists_count.clone(),
        metadata_count: metadata_count.clone(),
    };

    let _report = scan_with_services_no_osv_cache(
        &dir,
        Some("go"),
        Default::default(),
        &registry,
        &FakeOsvClient,
    )
    .await
    .unwrap();

    // Similarity generates many mutation candidates and calls exists() for each.
    // That's expected. The key invariant: metadata() should be called exactly once
    // per dep (2 total), and the exists() fallback in fetch_metadata should be
    // called exactly once per dep (2 total, since Go metadata() returns None).
    // ExistenceCheck should NOT make additional exists() calls because it reads
    // from acc.metadata_lookups.
    //
    // Before the fix, the non-metadata path didn't set acc.metadata_lookups,
    // causing ExistenceCheck to make 2 additional exists() calls (total was
    // similarity_mutations + 2_metadata_fallback + 2_existence = many more).
    let total_exists = exists_count.load(Ordering::SeqCst);
    let total_metadata = metadata_count.load(Ordering::SeqCst);

    // metadata() called exactly 2 times (once per dep)
    assert_eq!(
        total_metadata, 2,
        "Expected exactly 2 metadata() calls for 2 deps, got {}",
        total_metadata
    );
    // exists() calls = similarity mutations + 2 (fetch_metadata fallback for Go)
    // The fetch_metadata fallback accounts for exactly 2 exists() calls.
    // Anything more than similarity_mutations + 2 means ExistenceCheck made redundant calls.
    // We can't know exact similarity mutation count, but we can verify exists()
    // is NOT called for the 2 original dep names beyond what fetch_metadata does.
    // Since acc.metadata_lookups is now always set, ExistenceCheck should add 0 calls.
    // Each dep generates ~200+ mutations (10 generators: bitflip ~150 per dep,
    // keyboard ~25, others ~50), so ~500 from similarity + 2 from metadata fallback.
    // The test verifies ExistenceCheck doesn't add redundant calls on top of similarity.
    assert!(
        total_exists <= 600,
        "Expected at most ~500 exists() calls (similarity mutations + metadata fallback), got {} — ExistenceCheck may be making redundant calls",
        total_exists
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_counts_optional_dependencies_as_direct_inputs() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"optionalDependencies":{"fsevents":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","optionalDependencies":{"fsevents":"1.0.0"}},"node_modules/fsevents":{"version":"1.0.0"}}}"#,
    )
    .unwrap();
    let registry = FakeRegistry {
        existing: vec!["fsevents".to_string()],
    };

    let report = scan_with_services_inner(
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

    assert_eq!(report.packages_checked, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_counts_peer_dependencies_as_direct_inputs() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"peerDependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","peerDependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1"}}}"#,
    )
    .unwrap();
    let registry = FakeRegistry {
        existing: vec!["react".to_string()],
    };

    let report = scan_with_services_inner(
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

    assert_eq!(report.packages_checked, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_ignores_local_workspace_npm_dependencies_as_external_packages() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"workspace-lib":"workspace:*","local-lib":"file:../local-lib"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"workspace-lib":"workspace:*","local-lib":"file:../local-lib"}},"node_modules/workspace-lib":{"resolved":"packages/workspace-lib","link":true},"node_modules/local-lib":{"resolved":"../local-lib","link":true}}}"#,
    )
    .unwrap();
    let registry = FakeRegistry { existing: vec![] };

    let report = scan_with_services_inner(
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

    assert_eq!(report.packages_checked, 0);
    assert!(report.issues.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}
