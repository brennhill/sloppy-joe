use super::*;

#[tokio::test]
async fn version_age_cannot_ignore_timezone_offsets_or_invalid_seconds() {
    struct DateRegistry(String);
    #[async_trait]
    impl RegistryExistence for DateRegistry {
        async fn exists(&self, _: &str) -> Result<bool> {
            Ok(true)
        }
        fn ecosystem(&self) -> &str {
            "npm"
        }
    }
    #[async_trait]
    impl RegistryMetadata for DateRegistry {
        async fn metadata(&self, _: &str, _: Option<&str>) -> Result<Option<PackageMetadata>> {
            Ok(Some(PackageMetadata {
                latest_version_date: Some(self.0.clone()),
                created: Some("2020-01-01T00:00:00Z".to_owned()),
                downloads: Some(50000),
                ..Default::default()
            }))
        }
    }
    let dir = unique_dir();
    for name in ["package.json", "package-lock.json"] {
        std::fs::copy(
            fixture_dir("transitive-typosquat").join(name),
            dir.join(name),
        )
        .unwrap();
    }
    let older_wall_time =
        cache::epoch_millis_to_iso8601(((cache::now_epoch() - 80 * 3600) * 1000) as i64).unwrap();
    for date in [
        older_wall_time.replace('Z', "-12:00"),
        "2020-01-01T00:00:garbageZ".to_owned(),
    ] {
        let mut config = config::SloppyJoeConfig::default();
        config.allowed.insert(
            "npm".to_owned(),
            vec!["react".to_owned(), "expresss".to_owned()],
        );
        let report = scan_fixture_with_fake_services(
            &dir,
            Some("npm"),
            config,
            &DateRegistry(date.clone()),
            &FakeOsvClient,
            &ScanOptions {
                scan_mode: ScanMode::Ci,
                no_cache: true,
                disable_osv_disk_cache: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.check == "metadata/version-age"
                    && issue.severity == Severity::Error),
            "invalid or fresh date {date} passed"
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn future_full_scan_timestamp_does_not_suppress_refresh_guidance() {
    let (dir, config, projects) = parsed_npm_fixture_projects("transitive-typosquat");
    let cache_dir = unique_dir();
    let opts = ScanOptions {
        scan_mode: ScanMode::Fast,
        cache_dir: Some(&cache_dir),
        ..Default::default()
    };
    let future = full_scan_fingerprint_components_for_projects(
        &projects,
        &config,
        &opts,
        cache::now_epoch() + 86400,
    )
    .unwrap();
    cache::atomic_write_json(&full_scan_fingerprint_cache_path(&cache_dir), &future);
    let report = scan_with_source_full_options(&dir, Some("npm"), None, &opts)
        .await
        .unwrap();
    assert!(
        report
            .full_scan_reasons
            .contains(&report::FullScanRecommendationReason::LastFullScanStale)
    );
    std::fs::remove_dir_all(cache_dir).unwrap();
}

#[test]
fn legacy_python_build_and_test_dependencies_are_visible() {
    for (manifest, content) in [
        (
            "setup.py",
            "setup(setup_requires=['build-payload==1.0.0'], tests_require=['test-payload==1.0.0'])",
        ),
        (
            "setup.cfg",
            "[options]\nsetup_requires = build-payload==1.0.0\ntests_require: test-payload==1.0.0\n",
        ),
    ] {
        let dir = unique_dir();
        std::fs::write(dir.join(manifest), content).unwrap();
        let deps = if manifest == "setup.py" {
            parsers::setup_py::parse(&dir)
        } else {
            parsers::setup_cfg::parse(&dir)
        }
        .unwrap();
        let names = deps.iter().map(|dep| dep.name.as_str()).collect::<Vec<_>>();
        assert!(
            names.contains(&"build-payload"),
            "build dependency omitted from {manifest}"
        );
        assert!(
            names.contains(&"test-payload"),
            "test dependency omitted from {manifest}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[tokio::test]
async fn uv_packaged_editable_root_is_scanned_as_the_local_project() {
    let dir = unique_dir();
    let fixture = ecosystem_fixture_dir("python", "uv-pass");
    std::fs::copy(fixture.join("pyproject.toml"), dir.join("pyproject.toml")).unwrap();
    let locked = std::fs::read_to_string(fixture.join("uv.lock"))
        .unwrap()
        .replace("virtual = \".\"", "editable = \".\"");
    std::fs::write(dir.join("uv.lock"), locked).unwrap();
    let report = scan_with_source_full_options(
        &dir,
        Some("pypi"),
        None,
        &ScanOptions {
            scan_mode: ScanMode::Fast,
            no_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("uv editable root should be trusted as the project, not a dependency");
    assert_eq!(report.packages_checked, 1);
    assert!(!report.has_errors());
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn adjacent_uv_lock_selects_uv_without_redundant_tool_metadata() {
    let dir = unique_dir();
    let fixture = ecosystem_fixture_dir("python", "uv-pass");
    let manifest = std::fs::read_to_string(fixture.join("pyproject.toml"))
        .unwrap()
        .replace("[tool.uv]", "");
    std::fs::write(dir.join("pyproject.toml"), manifest).unwrap();
    std::fs::copy(fixture.join("uv.lock"), dir.join("uv.lock")).unwrap();
    let report = scan_with_source_full_options(
        &dir,
        Some("pypi"),
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
        !report
            .issues
            .iter()
            .any(|issue| issue.check == "resolution/python-legacy-manifest"),
        "a real uv lockfile must not be treated as legacy Python"
    );
    assert!(!report.has_errors());
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn uv_locked_range_is_verified_against_the_resolved_version() {
    let dir = unique_dir();
    let fixture = ecosystem_fixture_dir("python", "uv-pass");
    let manifest = std::fs::read_to_string(fixture.join("pyproject.toml"))
        .unwrap()
        .replace("==2.32.3", ">=2.32,<3");
    let locked = std::fs::read_to_string(fixture.join("uv.lock"))
        .unwrap()
        .replace("==2.32.3", ">=2.32,<3");
    std::fs::write(dir.join("pyproject.toml"), manifest).unwrap();
    std::fs::write(dir.join("uv.lock"), locked).unwrap();
    let report = scan_with_source_full_options(
        &dir,
        Some("pypi"),
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
        "a synchronized, uniquely resolved uv range must pass: {:?}",
        report.issues
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn uv_locked_ranges_reject_excluded_and_mismatched_versions() {
    let fixture = ecosystem_fixture_dir("python", "uv-pass");
    for specifier in [
        ">=2.0,!=2.32.*",
        ">=2.0,!=2.032.*",
        "==2.32.3.4.*",
        ">=3,<4",
    ] {
        let dir = unique_dir();
        let manifest = std::fs::read_to_string(fixture.join("pyproject.toml"))
            .unwrap()
            .replace("==2.32.3", specifier);
        let locked = std::fs::read_to_string(fixture.join("uv.lock"))
            .unwrap()
            .replace("==2.32.3", specifier);
        std::fs::write(dir.join("pyproject.toml"), manifest).unwrap();
        std::fs::write(dir.join("uv.lock"), locked).unwrap();
        let outcome = scan_with_source_full_options(
            &dir,
            Some("pypi"),
            None,
            &ScanOptions {
                scan_mode: ScanMode::Fast,
                no_cache: true,
                ..Default::default()
            },
        )
        .await;
        assert!(
            outcome.is_err() || outcome.unwrap().has_errors(),
            "excluded locked version passed {specifier}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[tokio::test]
async fn uv_ranges_accept_valid_prerelease_postrelease_and_local_versions() {
    let fixture = ecosystem_fixture_dir("python", "uv-pass");
    for (version, specifier) in [
        ("2.32.3rc1", ">=2.32.3rc1,<3"),
        ("2.32.3.post1", ">=2.32.3,<3"),
        ("2.32.3+build.1", ">=2.32,<3"),
    ] {
        let dir = unique_dir();
        let manifest = std::fs::read_to_string(fixture.join("pyproject.toml"))
            .unwrap()
            .replace("==2.32.3", specifier);
        let locked = std::fs::read_to_string(fixture.join("uv.lock"))
            .unwrap()
            .replace("2.32.3", version)
            .replace(&format!("=={version}"), specifier);
        std::fs::write(dir.join("pyproject.toml"), manifest).unwrap();
        std::fs::write(dir.join("uv.lock"), locked).unwrap();
        let report = scan_with_source_full_options(
            &dir,
            Some("pypi"),
            None,
            &ScanOptions {
                scan_mode: ScanMode::Fast,
                no_cache: true,
                ..Default::default()
            },
        )
        .await
        .expect("valid PEP440 versions must be supported");
        assert!(
            !report.has_errors(),
            "valid version {version} failed: {:?}",
            report.issues
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[tokio::test]
async fn cargo_hyphen_alias_is_not_reported_as_a_different_crate() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n[dependencies]\npep440_rs = \"=0.7.3\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n[[package]]\nname = \"pep440_rs\"\nversion = \"0.7.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n").unwrap();
    let registry = FakeRegistry {
        existing: vec!["pep440_rs".to_owned(), "pep440-rs".to_owned()],
    };
    let report = scan_fixture_with_fake_services(
        &dir,
        Some("cargo"),
        Default::default(),
        &registry,
        &FakeOsvClient,
        &ScanOptions {
            scan_mode: ScanMode::Ci,
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
            .any(|issue| issue.check.starts_with("similarity/")),
        "Cargo spellings that identify the same crate are not typosquats: {:?}",
        report.issues
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn generated_scoped_npm_names_do_not_cause_registry_outage_findings() {
    struct ValidatingRegistry(FakeRegistry);
    #[async_trait]
    impl RegistryExistence for ValidatingRegistry {
        async fn exists(&self, name: &str) -> Result<bool> {
            self.validate_name(name)?;
            self.0.exists(name).await
        }
        fn ecosystem(&self) -> &str {
            "npm"
        }
    }
    #[async_trait]
    impl RegistryMetadata for ValidatingRegistry {
        async fn metadata(
            &self,
            name: &str,
            version: Option<&str>,
        ) -> Result<Option<PackageMetadata>> {
            self.0.metadata(name, version).await
        }
    }
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","dependencies":{"@types/node":"22.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("package-lock.json"), r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"@types/node":"22.0.0"}},"node_modules/@types/node":{"version":"22.0.0","resolved":"https://registry.npmjs.org/@types/node/-/node-22.0.0.tgz","integrity":"sha512-demo"}}}"#).unwrap();
    let registry = ValidatingRegistry(FakeRegistry {
        existing: vec!["@types/node".to_owned()],
    });
    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        Default::default(),
        &registry,
        &FakeOsvClient,
        &ScanOptions {
            scan_mode: ScanMode::Ci,
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        !report.has_errors(),
        "invalid generated candidates must be discarded before registry queries: {:?}",
        report.issues
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn private_npm_registry_packages_are_unvetted_nonblocking_and_never_queried_publicly() {
    let dir = unique_dir();
    std::fs::write(dir.join(".npmrc"), "@company:registry=https://gitlab.example/api/v4/projects/${PROJECT_ID}/packages/npm/\n//gitlab.example/:_authToken=secret-must-not-appear\n").unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"app","dependencies":{"@company/client":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("package-lock.json"), serde_json::json!({
        "lockfileVersion":3,"packages": {
            "":{"dependencies":{"@company/client":"1.0.0"}},
            "node_modules/@company/client":{"version":"1.0.0","resolved":"https://gitlab.example/api/v4/projects/42/packages/npm/@company/client/-/@company/client-1.0.0.tgz","integrity":"sha512-demo","dependencies":{"@company/helper":"2.0.0"}},
            "node_modules/@company/helper":{"version":"2.0.0","resolved":"https://gitlab.example/api/v4/projects/42/packages/npm/@company/helper/-/@company/helper-2.0.0.tgz","integrity":"sha512-demo"}
        }
    }).to_string()).unwrap();
    // Recording services prove private identities stay local: no public
    // registry or OSV query names them. CI needs the route allowlisted.
    let mut config = config::SloppyJoeConfig::default();
    config.trusted_registries.insert(
        "npm".into(),
        vec![config::TrustedRegistry {
            name: "@company".into(),
            source: "https://gitlab.example/api/v4/projects/${PROJECT_ID}/packages/npm/".into(),
        }],
    );
    let exists_names = Arc::new(Mutex::new(Vec::new()));
    let metadata_names = Arc::new(Mutex::new(Vec::new()));
    let osv_names = Arc::new(Mutex::new(Vec::new()));
    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        config,
        &RecordingNameRegistry {
            existing: vec![],
            exists_names: exists_names.clone(),
            metadata_names: metadata_names.clone(),
        },
        &RecordingNameOsvClient {
            queried_names: osv_names.clone(),
        },
        &ScanOptions {
            scan_mode: ScanMode::Ci,
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .expect("private registries must not prevent scans");
    assert!(!report.has_errors(), "{:?}", report.issues);
    for names in [&exists_names, &metadata_names, &osv_names] {
        assert!(names.lock().unwrap().is_empty(), "{:?}", names);
    }
    assert_eq!(report.packages_checked, 2);
    assert_eq!(report.issues.len(), 2);
    for (name, source) in [
        ("@company/client", "direct"),
        ("@company/helper", "transitive"),
    ] {
        let warning = report.issues.iter().find(|i| i.package == name).unwrap();
        assert_eq!(warning.check, "resolution/private-registry-unvetted");
        assert_eq!(warning.severity, Severity::Warning);
        assert_eq!(warning.source.as_deref(), Some(source));
        assert!(warning.message.contains("unvetted"));
    }
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("secret-must-not-appear")
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn private_npm_registry_source_mismatches_block_without_leaking_credentials() {
    let dir = unique_dir();
    std::fs::write(
        dir.join(".npmrc"),
        "@company:registry=https://registry.example/private/\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"app","dependencies":{"@company/client":"1.0.0"}}"#,
    )
    .unwrap();
    for resolved in [
        "https://user:secret-must-not-appear@registry.example/private/client.tgz",
        "https://attacker.example/private/client.tgz",
        "https://registry.example/private-other/client.tgz",
        "http://registry.example/private/client.tgz",
        "https://registry.npmjs.org/@company/client/-/client-1.0.0.tgz?token=secret-must-not-appear",
    ] {
        std::fs::write(dir.join("package-lock.json"), serde_json::json!({
            "lockfileVersion":3,"packages": {
                "":{"dependencies":{"@company/client":"1.0.0"}},
                "node_modules/@company/client":{"version":"1.0.0","resolved":resolved,"integrity":"sha512-demo"}
            }
        }).to_string()).unwrap();
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
        .expect_err("unvetted registry support must preserve source boundary validation");
        assert!(
            !err.to_string().contains("secret-must-not-appear"),
            "credential leaked: {err}"
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn pnpm_private_registry_routing_is_unvetted_with_integrity_still_required() {
    let dir = unique_dir();
    std::fs::write(
        dir.join(".npmrc"),
        "@company:registry=https://registry.example/private/\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"packageManager":"pnpm@9.0.0","dependencies":{"@company/client":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      '@company/client':\n        specifier: 1.0.0\n        version: 1.0.0\npackages:\n  '@company/client@1.0.0':\n    resolution:\n      integrity: sha512-demo\n      tarball: https://registry.example/private/client.tgz\n").unwrap();
    let opts = ScanOptions {
        scan_mode: ScanMode::Ci,
        no_cache: true,
        disable_osv_disk_cache: true,
        ..Default::default()
    };
    let mut trusted = config::SloppyJoeConfig::default();
    trusted.trusted_registries.insert(
        "npm".into(),
        vec![config::TrustedRegistry {
            name: "@company".into(),
            source: "https://registry.example/private/".into(),
        }],
    );
    let osv_names = Arc::new(Mutex::new(Vec::new()));
    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        trusted,
        &FakeRegistry { existing: vec![] },
        &RecordingNameOsvClient {
            queried_names: osv_names.clone(),
        },
        &opts,
    )
    .await
    .unwrap();
    assert!(!report.has_errors(), "{:?}", report.issues);
    assert!(osv_names.lock().unwrap().is_empty(), "{osv_names:?}");
    assert_eq!(report.issues.len(), 1);
    assert_eq!(
        report.issues[0].check,
        "resolution/private-registry-unvetted"
    );
    let path = dir.join("pnpm-lock.yaml");
    let original = std::fs::read_to_string(&path).unwrap();
    for tarball in [
        "https://user:secret-must-not-appear@registry.example/private/client.tgz",
        "https://attacker.example/client.tgz",
        "https://user:secret-must-not-appear@[invalid/client.tgz",
        "https://registry.npmjs.org/@company/client/-/client-1.0.0.tgz?token=secret-must-not-appear",
    ] {
        std::fs::write(
            &path,
            original.replace("https://registry.example/private/client.tgz", tarball),
        )
        .unwrap();
        let error = scan_with_source_full_options(&dir, Some("npm"), None, &opts)
            .await
            .expect_err("pnpm private source must match routing");
        assert!(
            !error.to_string().contains("secret-must-not-appear"),
            "credential leaked: {error}"
        );
    }
    std::fs::write(&path, &original).unwrap();
    std::fs::write(
        &path,
        std::fs::read_to_string(&path)
            .unwrap()
            .replace("      integrity: sha512-demo\n", ""),
    )
    .unwrap();
    let error = scan_with_source_full_options(&dir, Some("npm"), None, &opts)
        .await
        .expect_err("private sources still need integrity");
    assert!(error.to_string().contains("integrity"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn private_npm_routes_preserve_public_direct_and_transitive_vulnerability_checks() {
    let dir = unique_dir();
    for name in ["package.json", "package-lock.json"] {
        std::fs::copy(
            fixture_dir("transitive-typosquat").join(name),
            dir.join(name),
        )
        .unwrap();
    }
    std::fs::write(
        dir.join(".npmrc"),
        "@company:registry=https://registry.example/\n",
    )
    .unwrap();
    let manifest_path = dir.join("package.json");
    let lock_path = dir.join("package-lock.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let mut lock: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&lock_path).unwrap()).unwrap();
    manifest["dependencies"]["@company/client"] = serde_json::json!("1.0.0");
    lock["packages"][""]["dependencies"]["@company/client"] = serde_json::json!("1.0.0");
    lock["packages"]["node_modules/@company/client"] = serde_json::json!({"version":"1.0.0","resolved":"https://registry.example/client.tgz","integrity":"sha512-demo"});
    std::fs::write(&manifest_path, manifest.to_string()).unwrap();
    std::fs::write(&lock_path, lock.to_string()).unwrap();
    let mut trusted = config::SloppyJoeConfig::default();
    trusted.trusted_registries.insert(
        "npm".into(),
        vec![config::TrustedRegistry {
            name: "@company".into(),
            source: "https://registry.example/".into(),
        }],
    );
    let report = scan_fixture_with_fake_services(
        &dir,
        Some("npm"),
        trusted,
        &FakeRegistry {
            existing: vec!["react".into(), "expresss".into()],
        },
        &VulnOsvClient {
            vulnerable: vec!["react".into(), "expresss".into(), "@company/client".into()],
        },
        &ScanOptions {
            scan_mode: ScanMode::Ci,
            no_cache: true,
            disable_osv_disk_cache: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    for (package, source) in [("react", "direct"), ("expresss", "transitive")] {
        assert!(
            report.issues.iter().any(|i| i.package == package
                && i.check == "malicious/known-vulnerability"
                && i.severity == Severity::Error
                && i.source.as_deref() == Some(source)),
            "{:?}",
            report.issues
        );
    }
    let private: Vec<_> = report
        .issues
        .iter()
        .filter(|i| i.package == "@company/client")
        .collect();
    // OSV would flag @company/client, but private names are never sent to OSV.
    assert_eq!(private.len(), 1, "{private:?}");
    assert_eq!(private[0].check, "resolution/private-registry-unvetted");
    std::fs::remove_dir_all(dir).unwrap();
}
