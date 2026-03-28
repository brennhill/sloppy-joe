use super::*;
use crate::registry::{RegistryExistence, RegistryMetadata};
use crate::report::Severity;
use async_trait::async_trait;

struct FakeRegistry {
    metadata_response: Option<PackageMetadata>,
}

#[async_trait]
impl RegistryExistence for FakeRegistry {
    async fn exists(&self, _name: &str) -> Result<bool> {
        Ok(true)
    }
    fn ecosystem(&self) -> &str {
        "npm"
    }
}

#[async_trait]
impl RegistryMetadata for FakeRegistry {
    async fn metadata(
        &self,
        _name: &str,
        _version: Option<&str>,
    ) -> Result<Option<PackageMetadata>> {
        Ok(self.metadata_response.clone())
    }
}

use crate::test_helpers::dep_with;
use crate::test_helpers::npm_dep as dep;

fn dep_with_version(name: &str, version: &str) -> Dependency {
    dep_with(name, Some(version), crate::Ecosystem::Npm)
}

fn config_with_age(hours: u64) -> SloppyJoeConfig {
    SloppyJoeConfig {
        min_version_age_hours: hours,
        ..Default::default()
    }
}

fn default_meta() -> PackageMetadata {
    PackageMetadata {
        created: Some("2020-01-01T00:00:00Z".to_string()),
        latest_version_date: Some("2020-01-01T00:00:00Z".to_string()),
        downloads: Some(50000),
        has_install_scripts: false,
        dependency_count: None,
        previous_dependency_count: None,
        current_publisher: None,
        previous_publisher: None,
        repository_url: Some("https://github.com/example/pkg".to_string()),
    }
}

fn empty_similarity() -> HashSet<String> {
    HashSet::new()
}
fn no_resolution() -> ResolutionResult {
    ResolutionResult::default()
}

#[test]
fn age_in_hours_parses_iso8601() {
    let age = age_in_hours("2020-01-01T00:00:00.000Z");
    assert!(age.is_some());
    assert!(age.unwrap() > 40000);
}

#[test]
fn age_in_hours_returns_none_for_garbage() {
    assert!(age_in_hours("not a date").is_none());
    assert!(age_in_hours("").is_none());
}

#[tokio::test]
async fn version_too_new_is_blocked() {
    let now = chrono_free_now();
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            latest_version_date: Some(now),
            ..default_meta()
        }),
    };
    let deps = vec![dep_with_version("some-pkg", "1.2.3")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(issues.iter().any(|i| i.check.contains("version-age")));
}

#[tokio::test]
async fn old_version_passes() {
    let registry = FakeRegistry {
        metadata_response: Some(default_meta()),
    };
    let deps = vec![dep_with_version("some-pkg", "1.2.3")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(!issues.iter().any(|i| i.check.contains("version-age")));
}

#[tokio::test]
async fn new_package_is_flagged() {
    let now = chrono_free_now();
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            created: Some(now.clone()),
            latest_version_date: Some(now),
            ..default_meta()
        }),
    };
    let deps = vec![dep("brand-new-pkg")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(issues.iter().any(|i| i.check.contains("new-package")));
}

#[test]
fn new_package_uses_ecosystem_registry_url() {
    let now = chrono_free_now();
    let lookups = vec![MetadataLookup {
        package: "requests".to_string(),
        ecosystem: crate::Ecosystem::PyPI,
        version: None,
        resolved_version: None,
        unresolved_version: false,
        exists: true,
        metadata: Some(PackageMetadata {
            created: Some(now.clone()),
            latest_version_date: Some(now),
            ..default_meta()
        }),
    }];
    let issues = issues_from_lookups(&lookups, &config_with_age(72), &empty_similarity());
    let issue = issues
        .iter()
        .find(|i| i.check == "metadata/new-package")
        .unwrap();
    assert_eq!(
        issue.registry_url.as_deref(),
        Some("https://pypi.org/project/requests/")
    );
}

#[tokio::test]
async fn low_downloads_flagged() {
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            downloads: Some(5),
            ..default_meta()
        }),
    };
    let deps = vec![dep("obscure-pkg")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(issues.iter().any(|i| i.check.contains("low-downloads")));
}

#[tokio::test]
async fn high_downloads_not_flagged() {
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            downloads: Some(1000000),
            ..default_meta()
        }),
    };
    let deps = vec![dep("popular-pkg")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(issues.is_empty());
}

#[tokio::test]
async fn age_gate_disabled_with_zero() {
    let now = chrono_free_now();
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            created: Some(now.clone()),
            latest_version_date: Some(now),
            downloads: Some(5),
            ..default_meta()
        }),
    };
    let deps = vec![dep_with_version("some-pkg", "1.2.3")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(0),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(!issues.iter().any(|i| i.check == "metadata/version-age"));
    assert!(issues.iter().any(|i| i.check == "metadata/new-package"));
    assert!(issues.iter().any(|i| i.check == "metadata/low-downloads"));
}

#[tokio::test]
async fn no_metadata_emits_parse_failed_warning_when_exists() {
    let registry = FakeRegistry {
        metadata_response: None,
    };
    let deps = vec![dep("some-pkg")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].check, "metadata/parse-failed");
    assert_eq!(issues[0].severity, Severity::Warning);
}

#[tokio::test]
async fn registry_errors_emit_blocking_issue() {
    struct ErrorRegistry;
    #[async_trait]
    impl RegistryExistence for ErrorRegistry {
        async fn exists(&self, _name: &str) -> Result<bool> {
            Ok(true)
        }
        fn ecosystem(&self) -> &str {
            "npm"
        }
    }
    #[async_trait]
    impl RegistryMetadata for ErrorRegistry {
        async fn metadata(
            &self,
            _name: &str,
            _version: Option<&str>,
        ) -> Result<Option<PackageMetadata>> {
            anyhow::bail!("metadata unavailable");
        }
    }
    // Need enough deps to exceed the hard error limit (5) so fail-closed triggers
    let deps: Vec<_> = (0..6).map(|i| dep(&format!("pkg-{}", i))).collect();
    let issues = check_metadata(
        &ErrorRegistry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(
        issues
            .iter()
            .any(|i| i.check.contains("registry-unreachable")),
        "Expected fail-closed blocking issue, got: {:?}",
        issues.iter().map(|i| &i.check).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn non_exact_versions_skip_version_age_checks() {
    let now = chrono_free_now();
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            latest_version_date: Some(now),
            ..default_meta()
        }),
    };
    let deps = vec![dep_with_version("some-pkg", "^1.2.3")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(!issues.iter().any(|i| i.check == "metadata/version-age"));
}

#[tokio::test]
async fn versionless_dependencies_skip_version_age_checks() {
    let now = chrono_free_now();
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            latest_version_date: Some(now),
            ..default_meta()
        }),
    };
    let deps = vec![dep("some-pkg")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(!issues.iter().any(|i| i.check == "metadata/version-age"));
}

#[tokio::test]
async fn install_script_with_low_downloads_flagged() {
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            downloads: Some(12),
            has_install_scripts: true,
            ..default_meta()
        }),
    };
    let deps = vec![dep_with_version("expresz", "1.2.3")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(
        issues
            .iter()
            .any(|i| i.check == "metadata/install-script-risk")
    );
}

#[tokio::test]
async fn install_script_with_new_package_flagged() {
    let now = chrono_free_now();
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            created: Some(now.clone()),
            latest_version_date: Some(now),
            downloads: Some(50000),
            has_install_scripts: true,
            ..default_meta()
        }),
    };
    let deps = vec![dep_with_version("new-pkg-with-scripts", "1.2.3")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(
        issues
            .iter()
            .any(|i| i.check == "metadata/install-script-risk")
    );
}

#[tokio::test]
async fn install_script_with_high_downloads_old_package_not_flagged() {
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            downloads: Some(100000),
            has_install_scripts: true,
            ..default_meta()
        }),
    };
    let deps = vec![dep_with_version("well-known-pkg", "1.2.3")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(
        !issues
            .iter()
            .any(|i| i.check == "metadata/install-script-risk")
    );
}

#[tokio::test]
async fn no_install_script_not_flagged() {
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            downloads: Some(12),
            has_install_scripts: false,
            ..default_meta()
        }),
    };
    let deps = vec![dep_with_version("low-dl-pkg", "1.2.3")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(
        !issues
            .iter()
            .any(|i| i.check == "metadata/install-script-risk")
    );
}

#[tokio::test]
async fn dependency_explosion_flagged() {
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            dependency_count: Some(18),
            previous_dependency_count: Some(3),
            ..default_meta()
        }),
    };
    let deps = vec![dep_with_version("some-pkg", "1.2.3")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    let explosion: Vec<_> = issues
        .iter()
        .filter(|i| i.check == "metadata/dependency-explosion")
        .collect();
    assert!(!explosion.is_empty());
    assert!(explosion[0].message.contains("added 15"));
}

#[tokio::test]
async fn small_increase_not_flagged() {
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            dependency_count: Some(5),
            previous_dependency_count: Some(3),
            ..default_meta()
        }),
    };
    let deps = vec![dep_with_version("some-pkg", "1.2.3")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(
        !issues
            .iter()
            .any(|i| i.check == "metadata/dependency-explosion")
    );
}

#[tokio::test]
async fn no_previous_version_not_flagged() {
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            dependency_count: Some(18),
            previous_dependency_count: None,
            ..default_meta()
        }),
    };
    let deps = vec![dep_with_version("some-pkg", "1.2.3")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(
        !issues
            .iter()
            .any(|i| i.check == "metadata/dependency-explosion")
    );
}

#[tokio::test]
async fn maintainer_changed_flagged() {
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            current_publisher: Some("new-person".to_string()),
            previous_publisher: Some("original-author".to_string()),
            ..default_meta()
        }),
    };
    let deps = vec![dep_with_version("some-pkg", "1.2.3")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(
        issues
            .iter()
            .any(|i| i.check == "metadata/maintainer-change")
    );
}

#[tokio::test]
async fn same_maintainer_not_flagged() {
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            current_publisher: Some("same".to_string()),
            previous_publisher: Some("same".to_string()),
            ..default_meta()
        }),
    };
    let deps = vec![dep_with_version("some-pkg", "1.2.3")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(
        !issues
            .iter()
            .any(|i| i.check == "metadata/maintainer-change")
    );
}

#[tokio::test]
async fn install_script_with_no_repo_flagged() {
    let meta = PackageMetadata {
        has_install_scripts: true,
        repository_url: None,
        ..default_meta()
    };
    let registry = FakeRegistry {
        metadata_response: Some(meta),
    };
    let deps = vec![dep_with_version("sketchy-pkg", "1.0.0")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(
        issues
            .iter()
            .any(|i| i.check == crate::checks::names::METADATA_INSTALL_SCRIPT_RISK),
        "Expected install-script-risk when install scripts + no repo URL"
    );
}

#[tokio::test]
async fn install_script_with_repo_not_amplified() {
    let meta = PackageMetadata {
        has_install_scripts: true,
        repository_url: Some("https://github.com/example/pkg".to_string()),
        ..default_meta() // old, 50K downloads
    };
    let registry = FakeRegistry {
        metadata_response: Some(meta),
    };
    let deps = vec![dep_with_version("legit-pkg", "5.0.0")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(
        !issues
            .iter()
            .any(|i| i.check == crate::checks::names::METADATA_INSTALL_SCRIPT_RISK),
        "Should not flag install scripts on old popular package WITH repo"
    );
}

#[tokio::test]
async fn no_repository_on_new_package_flagged() {
    use crate::cache;
    let meta = PackageMetadata {
        created: Some(cache::now_iso8601()),
        downloads: Some(50),
        repository_url: None,
        ..default_meta()
    };
    let registry = FakeRegistry {
        metadata_response: Some(meta),
    };
    let deps = vec![dep_with_version("suspicious-pkg", "0.1.0")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(0),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(
        issues
            .iter()
            .any(|i| i.check == crate::checks::names::METADATA_NO_REPOSITORY),
        "Expected no-repository warning for new+low-download package without repo URL"
    );
}

#[tokio::test]
async fn spoofed_repo_url_still_flagged() {
    use crate::cache;
    let meta = PackageMetadata {
        created: Some(cache::now_iso8601()),
        downloads: Some(50),
        repository_url: Some("https://evil-site.com/fake-repo".to_string()),
        ..default_meta()
    };
    let registry = FakeRegistry {
        metadata_response: Some(meta),
    };
    let deps = vec![dep_with_version("spoofed-pkg", "0.1.0")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(0),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(
        issues
            .iter()
            .any(|i| i.check == crate::checks::names::METADATA_NO_REPOSITORY),
        "Non-code-host repo URL should still trigger no-repository warning"
    );
}

#[tokio::test]
async fn has_repository_not_flagged() {
    use crate::cache;
    let meta = PackageMetadata {
        created: Some(cache::now_iso8601()),
        downloads: Some(50),
        repository_url: Some("https://github.com/example/pkg".to_string()),
        ..default_meta()
    };
    let registry = FakeRegistry {
        metadata_response: Some(meta),
    };
    let deps = vec![dep_with_version("ok-pkg", "0.1.0")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(0),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(
        !issues
            .iter()
            .any(|i| i.check == crate::checks::names::METADATA_NO_REPOSITORY),
        "Should not flag package with repository URL"
    );
}

#[tokio::test]
async fn no_repository_on_old_popular_package_not_flagged() {
    let meta = PackageMetadata {
        repository_url: None,
        ..default_meta() // old (2020), 50K downloads
    };
    let registry = FakeRegistry {
        metadata_response: Some(meta),
    };
    let deps = vec![dep_with_version("old-pkg", "5.0.0")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(
        !issues
            .iter()
            .any(|i| i.check == crate::checks::names::METADATA_NO_REPOSITORY),
        "Should not flag old popular package even without repo URL"
    );
}

#[tokio::test]
async fn no_publisher_info_not_flagged() {
    let registry = FakeRegistry {
        metadata_response: Some(default_meta()),
    };
    let deps = vec![dep_with_version("some-pkg", "1.2.3")];
    let issues = check_metadata(
        &registry,
        &deps,
        &config_with_age(72),
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(
        !issues
            .iter()
            .any(|i| i.check == "metadata/maintainer-change")
    );
}

#[test]
fn parse_failed_warning_when_exists_but_no_metadata() {
    let lookups = vec![MetadataLookup {
        package: "broken-pkg".to_string(),
        ecosystem: crate::Ecosystem::Npm,
        version: None,
        resolved_version: None,
        unresolved_version: false,
        exists: true,
        metadata: None,
    }];
    let issues = issues_from_lookups(&lookups, &config_with_age(72), &empty_similarity());
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].check, "metadata/parse-failed");
    assert_eq!(issues[0].severity, Severity::Warning);
}

#[test]
fn no_warning_when_package_does_not_exist() {
    let lookups = vec![MetadataLookup {
        package: "nonexistent-pkg".to_string(),
        ecosystem: crate::Ecosystem::Npm,
        version: None,
        resolved_version: None,
        unresolved_version: false,
        exists: false,
        metadata: None,
    }];
    let issues = issues_from_lookups(&lookups, &config_with_age(72), &empty_similarity());
    assert!(!issues.iter().any(|i| i.check == "metadata/parse-failed"));
}

fn chrono_free_now() -> String {
    crate::cache::now_iso8601()
}
