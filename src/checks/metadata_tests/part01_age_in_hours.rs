use super::*;

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

#[test]
fn age_in_hours_returns_none_for_invalid_calendar_dates() {
    assert!(age_in_hours("2026-02-30T00:00:00Z").is_none());
    assert!(age_in_hours("2026-13-01T00:00:00Z").is_none());
}

#[test]
fn age_in_hours_returns_none_for_future_dates() {
    assert!(age_in_hours("2999-01-01T00:00:00Z").is_none());
}

#[tokio::test]
async fn version_too_new_is_blocked() {
    let now = chrono_free_now();
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            latest_version_date: Some(now),
            ..default_meta()
        }),
        owners_response: None,
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
        owners_response: None,
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
        owners_response: None,
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
        owners_response: None,
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
        owners_response: None,
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
        owners_response: None,
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
        owners_response: None,
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
    let deps = vec![dep("pkg-0")];
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
        owners_response: None,
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
        owners_response: None,
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
        owners_response: None,
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
        owners_response: None,
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
        owners_response: None,
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
        owners_response: None,
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
        owners_response: None,
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
        owners_response: None,
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
async fn dependency_explosion_handles_extreme_metadata_counts() {
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            dependency_count: Some(u64::MAX),
            previous_dependency_count: Some(u64::MAX - 5),
            ..default_meta()
        }),
        owners_response: None,
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
        owners_response: None,
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
        owners_response: None,
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
async fn exact_metadata_exception_suppresses_reviewed_maintainer_change_only() {
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            current_publisher: Some("new-person".to_string()),
            previous_publisher: Some("original-author".to_string()),
            ..default_meta()
        }),
        owners_response: None,
    };
    let deps = vec![dep_with_version("some-pkg", "1.2.3")];
    let config = SloppyJoeConfig {
        metadata_exceptions: std::collections::HashMap::from([(
            "npm".to_string(),
            vec![crate::report::MetadataException {
                package: "some-pkg".to_string(),
                check: crate::names::METADATA_MAINTAINER_CHANGE.to_string(),
                version: "1.2.3".to_string(),
                previous_publisher: Some("original-author".to_string()),
                current_publisher: Some("new-person".to_string()),
                reason: Some("reviewed maintainer transfer".to_string()),
            }],
        )]),
        ..config_with_age(72)
    };
    let issues = check_metadata(
        &registry,
        &deps,
        &config,
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(
        !issues
            .iter()
            .any(|i| i.check == "metadata/maintainer-change"),
        "exact reviewed metadata exception should suppress only the matched maintainer-change finding"
    );
}

#[tokio::test]
async fn metadata_exception_near_miss_does_not_suppress_maintainer_change() {
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            current_publisher: Some("new-person".to_string()),
            previous_publisher: Some("original-author".to_string()),
            ..default_meta()
        }),
        owners_response: None,
    };
    let deps = vec![dep_with_version("some-pkg", "1.2.3")];
    let config = SloppyJoeConfig {
        metadata_exceptions: std::collections::HashMap::from([(
            "npm".to_string(),
            vec![crate::report::MetadataException {
                package: "some-pkg".to_string(),
                check: crate::names::METADATA_MAINTAINER_CHANGE.to_string(),
                version: "1.2.4".to_string(),
                previous_publisher: Some("original-author".to_string()),
                current_publisher: Some("new-person".to_string()),
                reason: Some("wrong version".to_string()),
            }],
        )]),
        ..config_with_age(72)
    };
    let issues = check_metadata(
        &registry,
        &deps,
        &config,
        &empty_similarity(),
        &no_resolution(),
    )
    .await
    .unwrap();
    assert!(
        issues
            .iter()
            .any(|i| i.check == "metadata/maintainer-change"),
        "metadata exceptions must remain exact; a version mismatch must still block"
    );
}

#[tokio::test]
async fn review_candidates_include_owner_evidence_and_exact_exception_object() {
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            current_publisher: Some("new-person".to_string()),
            previous_publisher: Some("original-author".to_string()),
            repository_url: Some("https://github.com/example/pkg".to_string()),
            ..default_meta()
        }),
        owners_response: Some(vec!["alice".to_string(), "bob".to_string()]),
    };
    let lookups = vec![MetadataLookup {
        package: "some-pkg".to_string(),
        ecosystem: crate::Ecosystem::Npm,
        version: Some("1.2.3".to_string()),
        resolved_version: Some("1.2.3".to_string()),
        unresolved_version: false,
        exists: true,
        metadata: registry.metadata_response.clone(),
    }];

    let candidates =
        review_candidates_from_lookups(&registry, &lookups, &config_with_age(72)).await;

    assert_eq!(candidates.len(), 1);
    let candidate = &candidates[0];
    assert_eq!(candidate.ecosystem, "npm");
    assert_eq!(candidate.package, "some-pkg");
    assert_eq!(candidate.check, "metadata/maintainer-change");
    assert_eq!(candidate.version, "1.2.3");
    assert_eq!(candidate.previous_publisher, "original-author");
    assert_eq!(candidate.current_publisher, "new-person");
    assert_eq!(candidate.owners, vec!["alice", "bob"]);
    assert_eq!(
        candidate.repository_url.as_deref(),
        Some("https://github.com/example/pkg")
    );
    assert_eq!(candidate.metadata_exception.package, "some-pkg");
    assert_eq!(
        candidate.metadata_exception.check,
        crate::names::METADATA_MAINTAINER_CHANGE
    );
    assert_eq!(candidate.metadata_exception.version, "1.2.3");
    assert_eq!(
        candidate.metadata_exception.previous_publisher.as_deref(),
        Some("original-author")
    );
    assert_eq!(
        candidate.metadata_exception.current_publisher.as_deref(),
        Some("new-person")
    );
}
