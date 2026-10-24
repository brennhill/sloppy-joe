use super::*;

#[tokio::test]
async fn cargo_scan_allows_mixed_registry_and_allowlisted_git_deps_in_reduced_confidence_mode() {
    let dir = unique_dir();
    let rev = "0123456789abcdef0123456789abcdef01234567";
    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"
shared = {{ git = "https://github.com/yourorg/shared-crate", rev = "{rev}" }}
"#
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("Cargo.lock"),
        format!(
            r#"version = 4

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "shared"
version = "0.1.0"
source = "git+https://github.com/yourorg/shared-crate?rev={rev}#{rev}"
"#
        ),
    )
    .unwrap();

    let config = config::SloppyJoeConfig {
        cargo_git_policy: config::CargoGitPolicy::WarnPinned,
        trusted_git_sources: std::collections::HashMap::from([(
            "cargo".to_string(),
            vec!["https://github.com/yourorg/shared-crate".to_string()],
        )]),
        ..Default::default()
    };

    let report = scan_fixture_with_fake_services(
        &dir,
        Some("cargo"),
        config,
        &FakeRegistry {
            existing: vec!["serde".to_string()],
        },
        &FakeOsvClient,
        &ScanOptions::default(),
    )
    .await
    .expect("allowlisted pinned Cargo git deps should not break the full scan path");

    assert!(report.issues.iter().any(|issue| {
        issue.check == checks::names::RESOLUTION_REDUCED_CONFIDENCE_GIT
            && issue.package == "shared"
            && issue.severity == Severity::Warning
    }));
    assert!(
        !report
            .issues
            .iter()
            .any(|issue| issue.check == checks::names::RESOLUTION_PARSE_FAILED),
        "mixed Cargo registry+git scans must not degrade into lockfile parse failures: {:?}",
        report.issues
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn host_local_cargo_config_rewrites_warn_when_local_overlay_allows_them() {
    let home = unique_dir();
    let cargo_home = home.join(".cargo");
    std::fs::create_dir_all(&cargo_home).unwrap();
    std::fs::write(
        cargo_home.join("config.toml"),
        r#"[source.crates-io]
replace-with = "company"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig {
        allow_host_local_cargo_config: true,
        ..Default::default()
    };
    let (rewrites, warnings) = cargo_host_local_config_rewrites_for_test(&home, &config)
        .expect("local-only Cargo overlay should be able to trust host-local Cargo config");

    assert_eq!(
        rewrites
            .source_replace_with
            .get("crates-io")
            .map(String::as_str),
        Some("company")
    );
    assert!(
        !warnings.is_empty(),
        "trusting host-local Cargo config must emit a warning on every run"
    );

    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn load_effective_cargo_config_rewrites_blocks_host_local_conflicts_with_repo_visible_config() {
    let dir = unique_dir();
    let cargo_config_dir = dir.join(".cargo");
    let home = unique_dir();
    let home_cargo = home.join(".cargo");
    std::fs::create_dir_all(&cargo_config_dir).unwrap();
    std::fs::create_dir_all(&home_cargo).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "=1.0.228"
"#,
    )
    .unwrap();
    std::fs::write(dir.join("Cargo.lock"), "version = 4\n").unwrap();
    std::fs::write(
        cargo_config_dir.join("config.toml"),
        r#"[source.crates-io]
replace-with = "company"
"#,
    )
    .unwrap();
    std::fs::write(
        home_cargo.join("config.toml"),
        r#"[source.crates-io]
replace-with = "mirror"
"#,
    )
    .unwrap();

    let config = config::SloppyJoeConfig {
        allow_host_local_cargo_config: true,
        ..Default::default()
    };
    let err = load_effective_cargo_config_rewrites_for_test(
        &dir,
        &dir.join("Cargo.toml"),
        &config,
        Some(home.join(".cargo")),
    )
    .expect_err("host-local Cargo config must not override repo-visible rewrite state");
    assert!(err.to_string().contains("conflicts with repo-visible"));

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn preflight_blocks_composer_custom_repository_sources() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("composer.json"),
        r#"{
  "repositories":[{"type":"vcs","url":"https://github.com/acme/fork"}],
  "require":{"acme/pkg":"^1.0"}
}"#,
    )
    .unwrap();
    std::fs::write(dir.join("composer.lock"), r#"{"packages":[]}"#).unwrap();

    let err = preflight_scan_inputs(&dir, Some("php"))
        .expect_err("Composer custom repositories must block strict scanning");
    assert!(err.to_string().contains("repositories"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_gradle_custom_repository_sources() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("build.gradle"),
        r#"repositories { maven { url "https://evil.example/maven" } }
dependencies { implementation "com.google.guava:guava:31.1-jre" }"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("gradle.lockfile"),
        "com.google.guava:guava:31.1-jre=runtimeClasspath\n",
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("jvm"))
        .expect_err("Gradle custom repositories must block strict scanning");
    assert!(err.to_string().contains("repository"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_multiline_gradle_custom_repository_sources() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("build.gradle"),
        r#"repositories
{
  maven
  {
    url "https://evil.example/maven"
  }
}

dependencies {
  implementation "com.google.guava:guava:31.1-jre"
}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("gradle.lockfile"),
        "com.google.guava:guava:31.1-jre=runtimeClasspath\n",
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("jvm"))
        .expect_err("multiline Gradle custom repositories must still block strict scanning");
    assert!(err.to_string().contains("repository"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_multiline_gradle_local_project_dependency_sources() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("build.gradle"),
        r#"repositories {
  mavenCentral()
}

dependencies {
  implementation(
    project(":shared")
  )
}"#,
    )
    .unwrap();
    std::fs::write(dir.join("gradle.lockfile"), "").unwrap();

    let err = preflight_scan_inputs(&dir, Some("jvm"))
        .expect_err("multiline Gradle project dependencies must still block strict scanning");
    assert!(err.to_string().contains("local project"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_maven_custom_repository_sources() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pom.xml"),
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <repositories>
    <repository>
      <id>evil</id>
      <url>https://evil.example/maven</url>
    </repository>
  </repositories>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>31.1-jre</version>
    </dependency>
  </dependencies>
</project>"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("jvm"))
        .expect_err("Maven custom repositories must block strict scanning");
    assert!(err.to_string().contains("repository"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_maven_repository_tags_with_whitespace() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pom.xml"),
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <repositories
  >
    <repository
    >
      <id>evil</id>
      <url>https://evil.example/maven</url>
    </repository>
  </repositories>
</project>"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("jvm"))
        .expect_err("whitespace-padded Maven repository tags must still block strict scanning");
    assert!(err.to_string().contains("repository"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn preflight_blocks_maven_system_path_tags_with_whitespace() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pom.xml"),
        r#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>local-jar</artifactId>
      <version>1.0.0</version>
      <systemPath
      >/tmp/local.jar</systemPath>
    </dependency>
  </dependencies>
</project>"#,
    )
    .unwrap();

    let err = preflight_scan_inputs(&dir, Some("jvm"))
        .expect_err("whitespace-padded Maven systemPath tags must still block strict scanning");
    assert!(err.to_string().contains("systemPath"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn scan_hash_does_not_follow_symlinked_lockfile() {
    let dir = unique_dir();
    let deps = vec![Dependency {
        name: "react".to_string(),
        version: Some("^18.0".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }];
    let real = dir.join("real-lock.json");
    std::fs::write(&real, r#"{"lockfileVersion":3}"#).unwrap();
    std::os::unix::fs::symlink(&real, dir.join("package-lock.json")).unwrap();

    let err = scan_hash(&dir, &deps)
        .expect_err("present but unsafe lockfiles must disable hash-based skipping");
    assert!(err.contains("package-lock.json"));
    assert!(err.contains("safely hash"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn scan_hash_matches_cache_refuses_unhashable_lockfile() {
    let dir = unique_dir();
    let cache_dir = unique_dir();
    let deps = vec![Dependency {
        name: "react".to_string(),
        version: Some("^18.0".to_string()),
        ecosystem: Ecosystem::Npm,
        actual_name: None,
    }];

    let hash_path = cache_dir.join("scan-hash.json");
    cache::atomic_write_json(
        &hash_path,
        &ScanHashCache {
            timestamp: cache::now_epoch(),
            hash: scan_hash(&dir, &deps).unwrap(),
        },
    );

    let real = dir.join("real-lock.json");
    std::fs::write(&real, r#"{"lockfileVersion":3}"#).unwrap();
    std::os::unix::fs::symlink(&real, dir.join("package-lock.json")).unwrap();

    let err = scan_hash_matches_cache(&dir, &deps, &cache_dir)
        .expect_err("unsafe lockfiles must disable cache-based scan skipping");
    assert!(err.contains("package-lock.json"));

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&cache_dir);
}

#[tokio::test]
async fn scan_with_source_full_blocks_when_any_detected_manifest_is_broken() {
    let dir = unique_dir();
    std::fs::write(dir.join("package.json"), r#"{}"#).unwrap();
    std::fs::write(dir.join("package-lock.json"), r#"{"lockfileVersion":3}"#).unwrap();
    std::fs::write(dir.join("Cargo.toml"), "[package").unwrap();
    std::fs::write(dir.join("Cargo.lock"), "").unwrap();

    let err = scan_with_source_full(&dir, None, None, false, false, false, None)
        .await
        .expect_err("broken detected manifests must block the scan");
    let msg = err.to_string();
    assert!(msg.contains("Cargo.toml"));
    assert!(msg.contains("parse"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_with_source_full_blocks_when_required_lockfile_is_missing() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();

    let err = scan_with_source_full(&dir, Some("npm"), None, false, false, true, None)
        .await
        .expect_err("strict lockfile policy must block npm scans without a lockfile");
    let msg = err.to_string();
    assert!(msg.contains("package-lock.json"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_with_source_full_blocks_when_required_lockfile_is_malformed() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("package.json"),
        r#"{"dependencies":{"react":"^18.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("package-lock.json"), "{not json").unwrap();

    let err = scan_with_source_full(&dir, Some("npm"), None, false, false, true, None)
        .await
        .expect_err("malformed npm lockfiles must block the scan");
    let msg = err.to_string();
    assert!(msg.contains("package-lock.json"));
    assert!(msg.contains("parse"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_with_source_full_blocks_when_npm_lockfile_root_is_out_of_sync() {
    let dir = unique_dir();
    std::fs::write(dir.join("package.json"), r#"{"name":"demo"}"#).unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.0.0"}},"node_modules/react":{"version":"18.3.1"}}}"#,
    )
    .unwrap();

    let err = scan_with_source_full(&dir, Some("npm"), None, false, false, true, None)
        .await
        .expect_err("strict npm scans must block out-of-sync manifest and lockfile roots");
    let msg = err.to_string();
    assert!(msg.contains("package-lock.json"));
    assert!(msg.contains("out of sync"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_with_source_full_blocks_on_malformed_poetry_lock_when_scanning_poetry_projects() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pyproject.toml"),
        "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"2.31.0\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("poetry.lock"), "not = [valid").unwrap();

    let err = scan_with_source_full(&dir, Some("pypi"), None, false, false, true, None)
        .await
        .expect_err("Poetry projects must fail closed on malformed poetry.lock");
    assert!(err.to_string().contains("poetry.lock"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn scan_with_source_full_emits_maven_lockfile_warning() {
    let dir = unique_dir();
    std::fs::write(
        dir.join("pom.xml"),
        r#"<project><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>demo</artifactId><version>1.0.0</version></project>"#,
    )
    .unwrap();

    let report = scan_with_source_full(&dir, Some("jvm"), None, false, false, true, None)
        .await
        .expect("maven lockfile policy should warn and continue");
    assert_eq!(report.packages_checked, 0);
    assert_eq!(report.issues.len(), 1);
    assert_eq!(report.issues[0].severity, Severity::Warning);
    assert!(report.issues[0].message.contains("Maven"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mark_source_does_not_overwrite_existing() {
    let mut issues = vec![
        Issue::new("pkg1", "existence", Severity::Error)
            .message("msg")
            .fix("fix"),
        Issue::new("pkg2", "existence", Severity::Error)
            .message("msg")
            .fix("fix"),
    ];
    // Pre-set source on first issue
    issues[0].source = Some("already-set".to_string());
    mark_source(&mut issues, "direct");
    assert_eq!(
        issues[0].source.as_deref(),
        Some("already-set"),
        "Should not overwrite existing source"
    );
    assert_eq!(
        issues[1].source.as_deref(),
        Some("direct"),
        "Should set source when None"
    );
}

#[tokio::test]
async fn empty_direct_graph_with_locked_packages_is_unsupported() {
    for (manifest, content, lockfile, locked) in [
        (
            "build.gradle",
            "plugins { id 'java' }\ngetDependencies().add('implementation', 'com.example:payload:1.0.0')",
            "gradle.lockfile",
            "com.example:payload:1.0.0=runtimeClasspath\n",
        ),
        (
            "app.csproj",
            "<Project><ItemGroup><ProjectReference Include=\"../other/other.csproj\" /></ItemGroup></Project>",
            "packages.lock.json",
            r#"{"version":1,"dependencies":{"net8.0":{"Payload":{"type":"Transitive","resolved":"1.0.0","contentHash":"abc"}}}}"#,
        ),
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
        .expect_err("locked packages must not be silently skipped");
        assert!(err.to_string().contains("Scan not supported"), "{err}");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[tokio::test]
async fn full_scan_cannot_skip_age_gate_without_a_valid_publish_date() {
    struct UndatedRegistry {
        date: Option<&'static str>,
        omit_metadata: bool,
    }
    #[async_trait]
    impl RegistryExistence for UndatedRegistry {
        async fn exists(&self, _: &str) -> Result<bool> {
            Ok(true)
        }
        fn ecosystem(&self) -> &str {
            "npm"
        }
    }
    #[async_trait]
    impl RegistryMetadata for UndatedRegistry {
        async fn metadata(&self, _: &str, _: Option<&str>) -> Result<Option<PackageMetadata>> {
            if self.omit_metadata {
                return Ok(None);
            }
            Ok(Some(PackageMetadata {
                latest_version_date: self.date.map(str::to_owned),
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
    for (date, date_is_valid) in [
        (None, false),
        (Some("not-a-date"), false),
        (Some("2999-01-01T00:00:00Z"), false),
        (Some("999999999999-01-01T00:00:00Z"), false),
        (Some("2020-01-01T00:00:00"), true),
    ] {
        for omit_metadata in [false, true] {
            for min_age in [72, 0] {
                let mut config = config::SloppyJoeConfig {
                    min_version_age_hours: min_age,
                    ..Default::default()
                };
                config.allowed.insert(
                    "npm".to_owned(),
                    vec!["react".to_owned(), "expresss".to_owned()],
                );
                let report = scan_fixture_with_fake_services(
                    &dir,
                    Some("npm"),
                    config,
                    &UndatedRegistry {
                        date,
                        omit_metadata,
                    },
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
                assert_eq!(
                    report
                        .issues
                        .iter()
                        .any(|issue| issue.check == "metadata/version-age"
                            && issue.severity == Severity::Error),
                    min_age > 0 && (omit_metadata || !date_is_valid),
                    "unverifiable publication date {date:?} passed the age gate"
                );
            }
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}
