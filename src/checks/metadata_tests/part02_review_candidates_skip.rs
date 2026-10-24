use super::*;

#[tokio::test]
async fn review_candidates_skip_already_configured_metadata_exception() {
    let registry = FakeRegistry {
        metadata_response: Some(PackageMetadata {
            current_publisher: Some("new-person".to_string()),
            previous_publisher: Some("original-author".to_string()),
            ..default_meta()
        }),
        owners_response: Some(vec!["alice".to_string()]),
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
    let config = SloppyJoeConfig {
        metadata_exceptions: std::collections::HashMap::from([(
            "npm".to_string(),
            vec![crate::report::MetadataException {
                package: "some-pkg".to_string(),
                check: crate::names::METADATA_MAINTAINER_CHANGE.to_string(),
                version: "1.2.3".to_string(),
                previous_publisher: Some("original-author".to_string()),
                current_publisher: Some("new-person".to_string()),
                reason: Some("reviewed".to_string()),
            }],
        )]),
        ..config_with_age(72)
    };

    let candidates = review_candidates_from_lookups(&registry, &lookups, &config).await;

    assert!(
        candidates.is_empty(),
        "review mode should not suggest metadata exceptions that are already configured"
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
        owners_response: None,
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
            .any(|i| i.check == crate::names::METADATA_INSTALL_SCRIPT_RISK),
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
        owners_response: None,
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
            .any(|i| i.check == crate::names::METADATA_INSTALL_SCRIPT_RISK),
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
        owners_response: None,
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
            .any(|i| i.check == crate::names::METADATA_NO_REPOSITORY),
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
        owners_response: None,
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
            .any(|i| i.check == crate::names::METADATA_NO_REPOSITORY),
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
        owners_response: None,
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
            .any(|i| i.check == crate::names::METADATA_NO_REPOSITORY),
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
        owners_response: None,
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
            .any(|i| i.check == crate::names::METADATA_NO_REPOSITORY),
        "Should not flag old popular package even without repo URL"
    );
}

#[tokio::test]
async fn no_publisher_info_not_flagged() {
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
