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
    async fn metadata(&self, _name: &str, _version: Option<&str>) -> Result<Option<PackageMetadata>> {
        Ok(self.metadata_response.clone())
    }
}

fn dep(name: &str) -> Dependency {
    Dependency { name: name.to_string(), version: None, ecosystem: "npm".to_string() }
}

fn dep_with_version(name: &str, version: &str) -> Dependency {
    Dependency { name: name.to_string(), version: Some(version.to_string()), ecosystem: "npm".to_string() }
}

fn config_with_age(hours: u64) -> SloppyJoeConfig {
    SloppyJoeConfig { min_version_age_hours: hours, ..Default::default() }
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
    }
}

fn empty_similarity() -> HashSet<String> { HashSet::new() }
fn no_resolution() -> ResolutionResult { ResolutionResult::default() }

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
    let registry = FakeRegistry { metadata_response: Some(PackageMetadata { latest_version_date: Some(now), ..default_meta() }) };
    let deps = vec![dep_with_version("some-pkg", "1.2.3")];
    let issues = check_metadata(&registry, &deps, &config_with_age(72), &empty_similarity(), &no_resolution()).await.unwrap();
    assert!(issues.iter().any(|i| i.check.contains("version-age")));
}

#[tokio::test]
async fn old_version_passes() {
    let registry = FakeRegistry { metadata_response: Some(default_meta()) };
    let deps = vec![dep_with_version("some-pkg", "1.2.3")];
    let issues = check_metadata(&registry, &deps, &config_with_age(72), &empty_similarity(), &no_resolution()).await.unwrap();
    assert!(!issues.iter().any(|i| i.check.contains("version-age")));
}

#[tokio::test]
async fn new_package_is_flagged() {
    let now = chrono_free_now();
    let registry = FakeRegistry { metadata_response: Some(PackageMetadata { created: Some(now.clone()), latest_version_date: Some(now), ..default_meta() }) };
    let deps = vec![dep("brand-new-pkg")];
    let issues = check_metadata(&registry, &deps, &config_with_age(72), &empty_similarity(), &no_resolution()).await.unwrap();
    assert!(issues.iter().any(|i| i.check.contains("new-package")));
}

#[test]
fn new_package_uses_ecosystem_registry_url() {
    let now = chrono_free_now();
    let lookups = vec![MetadataLookup {
        package: "requests".to_string(), ecosystem: "pypi".to_string(),
        version: None, resolved_version: None, unresolved_version: false, exists: true,
        metadata: Some(PackageMetadata { created: Some(now.clone()), latest_version_date: Some(now), ..default_meta() }),
    }];
    let issues = issues_from_lookups(&lookups, &config_with_age(72), &empty_similarity());
    let issue = issues.iter().find(|i| i.check == "metadata/new-package").unwrap();
    assert_eq!(issue.registry_url.as_deref(), Some("https://pypi.org/project/requests/"));
}

#[tokio::test]
async fn low_downloads_flagged() {
    let registry = FakeRegistry { metadata_response: Some(PackageMetadata { downloads: Some(5), ..default_meta() }) };
    let deps = vec![dep("obscure-pkg")];
    let issues = check_metadata(&registry, &deps, &config_with_age(72), &empty_similarity(), &no_resolution()).await.unwrap();
    assert!(issues.iter().any(|i| i.check.contains("low-downloads")));
}

#[tokio::test]
async fn high_downloads_not_flagged() {
    let registry = FakeRegistry { metadata_response: Some(PackageMetadata { downloads: Some(1000000), ..default_meta() }) };
    let deps = vec![dep("popular-pkg")];
    let issues = check_metadata(&registry, &deps, &config_with_age(72), &empty_similarity(), &no_resolution()).await.unwrap();
    assert!(issues.is_empty());
}

#[tokio::test]
async fn age_gate_disabled_with_zero() {
    let now = chrono_free_now();
    let registry = FakeRegistry { metadata_response: Some(PackageMetadata { created: Some(now.clone()), latest_version_date: Some(now), downloads: Some(5), ..default_meta() }) };
    let deps = vec![dep_with_version("some-pkg", "1.2.3")];
    let issues = check_metadata(&registry, &deps, &config_with_age(0), &empty_similarity(), &no_resolution()).await.unwrap();
    assert!(!issues.iter().any(|i| i.check == "metadata/version-age"));
    assert!(issues.iter().any(|i| i.check == "metadata/new-package"));
    assert!(issues.iter().any(|i| i.check == "metadata/low-downloads"));
}

#[tokio::test]
async fn no_metadata_emits_parse_failed_warning_when_exists() {
    let registry = FakeRegistry { metadata_response: None };
    let deps = vec![dep("some-pkg")];
    let issues = check_metadata(&registry, &deps, &config_with_age(72), &empty_similarity(), &no_resolution()).await.unwrap();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].check, "metadata/parse-failed");
    assert_eq!(issues[0].severity, Severity::Warning);
}

#[tokio::test]
async fn registry_errors_fail_the_check() {
    struct ErrorRegistry;
    #[async_trait]
    impl RegistryExistence for ErrorRegistry {
        async fn exists(&self, _name: &str) -> Result<bool> { Ok(true) }
        fn ecosystem(&self) -> &str { "npm" }
    }
    #[async_trait]
    impl RegistryMetadata for ErrorRegistry {
        async fn metadata(&self, _name: &str, _version: Option<&str>) -> Result<Option<PackageMetadata>> {
            anyhow::bail!("metadata unavailable");
        }
    }
    let deps = vec![dep("some-pkg")];
    let err = check_metadata(&ErrorRegistry, &deps, &config_with_age(72), &empty_similarity(), &no_resolution()).await.unwrap_err();
    assert!(err.to_string().contains("metadata unavailable"));
}

#[tokio::test]
async fn non_exact_versions_skip_version_age_checks() {
    let now = chrono_free_now();
    let registry = FakeRegistry { metadata_response: Some(PackageMetadata { latest_version_date: Some(now), ..default_meta() }) };
    let deps = vec![dep_with_version("some-pkg", "^1.2.3")];
    let issues = check_metadata(&registry, &deps, &config_with_age(72), &empty_similarity(), &no_resolution()).await.unwrap();
    assert!(!issues.iter().any(|i| i.check == "metadata/version-age"));
}

#[tokio::test]
async fn versionless_dependencies_skip_version_age_checks() {
    let now = chrono_free_now();
    let registry = FakeRegistry { metadata_response: Some(PackageMetadata { latest_version_date: Some(now), ..default_meta() }) };
    let deps = vec![dep("some-pkg")];
    let issues = check_metadata(&registry, &deps, &config_with_age(72), &empty_similarity(), &no_resolution()).await.unwrap();
    assert!(!issues.iter().any(|i| i.check == "metadata/version-age"));
}

#[tokio::test]
async fn install_script_with_low_downloads_flagged() {
    let registry = FakeRegistry { metadata_response: Some(PackageMetadata { downloads: Some(12), has_install_scripts: true, ..default_meta() }) };
    let deps = vec![dep_with_version("expresz", "1.2.3")];
    let issues = check_metadata(&registry, &deps, &config_with_age(72), &empty_similarity(), &no_resolution()).await.unwrap();
    assert!(issues.iter().any(|i| i.check == "metadata/install-script-risk"));
}

#[tokio::test]
async fn install_script_with_new_package_flagged() {
    let now = chrono_free_now();
    let registry = FakeRegistry { metadata_response: Some(PackageMetadata { created: Some(now.clone()), latest_version_date: Some(now), downloads: Some(50000), has_install_scripts: true, ..default_meta() }) };
    let deps = vec![dep_with_version("new-pkg-with-scripts", "1.2.3")];
    let issues = check_metadata(&registry, &deps, &config_with_age(72), &empty_similarity(), &no_resolution()).await.unwrap();
    assert!(issues.iter().any(|i| i.check == "metadata/install-script-risk"));
}

#[tokio::test]
async fn install_script_with_high_downloads_old_package_not_flagged() {
    let registry = FakeRegistry { metadata_response: Some(PackageMetadata { downloads: Some(100000), has_install_scripts: true, ..default_meta() }) };
    let deps = vec![dep_with_version("well-known-pkg", "1.2.3")];
    let issues = check_metadata(&registry, &deps, &config_with_age(72), &empty_similarity(), &no_resolution()).await.unwrap();
    assert!(!issues.iter().any(|i| i.check == "metadata/install-script-risk"));
}

#[tokio::test]
async fn no_install_script_not_flagged() {
    let registry = FakeRegistry { metadata_response: Some(PackageMetadata { downloads: Some(12), has_install_scripts: false, ..default_meta() }) };
    let deps = vec![dep_with_version("low-dl-pkg", "1.2.3")];
    let issues = check_metadata(&registry, &deps, &config_with_age(72), &empty_similarity(), &no_resolution()).await.unwrap();
    assert!(!issues.iter().any(|i| i.check == "metadata/install-script-risk"));
}

#[tokio::test]
async fn dependency_explosion_flagged() {
    let registry = FakeRegistry { metadata_response: Some(PackageMetadata { dependency_count: Some(18), previous_dependency_count: Some(3), ..default_meta() }) };
    let deps = vec![dep_with_version("some-pkg", "1.2.3")];
    let issues = check_metadata(&registry, &deps, &config_with_age(72), &empty_similarity(), &no_resolution()).await.unwrap();
    let explosion: Vec<_> = issues.iter().filter(|i| i.check == "metadata/dependency-explosion").collect();
    assert!(!explosion.is_empty());
    assert!(explosion[0].message.contains("added 15"));
}

#[tokio::test]
async fn small_increase_not_flagged() {
    let registry = FakeRegistry { metadata_response: Some(PackageMetadata { dependency_count: Some(5), previous_dependency_count: Some(3), ..default_meta() }) };
    let deps = vec![dep_with_version("some-pkg", "1.2.3")];
    let issues = check_metadata(&registry, &deps, &config_with_age(72), &empty_similarity(), &no_resolution()).await.unwrap();
    assert!(!issues.iter().any(|i| i.check == "metadata/dependency-explosion"));
}

#[tokio::test]
async fn no_previous_version_not_flagged() {
    let registry = FakeRegistry { metadata_response: Some(PackageMetadata { dependency_count: Some(18), previous_dependency_count: None, ..default_meta() }) };
    let deps = vec![dep_with_version("some-pkg", "1.2.3")];
    let issues = check_metadata(&registry, &deps, &config_with_age(72), &empty_similarity(), &no_resolution()).await.unwrap();
    assert!(!issues.iter().any(|i| i.check == "metadata/dependency-explosion"));
}

#[tokio::test]
async fn maintainer_changed_flagged() {
    let registry = FakeRegistry { metadata_response: Some(PackageMetadata { current_publisher: Some("new-person".to_string()), previous_publisher: Some("original-author".to_string()), ..default_meta() }) };
    let deps = vec![dep_with_version("some-pkg", "1.2.3")];
    let issues = check_metadata(&registry, &deps, &config_with_age(72), &empty_similarity(), &no_resolution()).await.unwrap();
    assert!(issues.iter().any(|i| i.check == "metadata/maintainer-change"));
}

#[tokio::test]
async fn same_maintainer_not_flagged() {
    let registry = FakeRegistry { metadata_response: Some(PackageMetadata { current_publisher: Some("same".to_string()), previous_publisher: Some("same".to_string()), ..default_meta() }) };
    let deps = vec![dep_with_version("some-pkg", "1.2.3")];
    let issues = check_metadata(&registry, &deps, &config_with_age(72), &empty_similarity(), &no_resolution()).await.unwrap();
    assert!(!issues.iter().any(|i| i.check == "metadata/maintainer-change"));
}

#[tokio::test]
async fn no_publisher_info_not_flagged() {
    let registry = FakeRegistry { metadata_response: Some(default_meta()) };
    let deps = vec![dep_with_version("some-pkg", "1.2.3")];
    let issues = check_metadata(&registry, &deps, &config_with_age(72), &empty_similarity(), &no_resolution()).await.unwrap();
    assert!(!issues.iter().any(|i| i.check == "metadata/maintainer-change"));
}

#[test]
fn parse_failed_warning_when_exists_but_no_metadata() {
    let lookups = vec![MetadataLookup {
        package: "broken-pkg".to_string(), ecosystem: "npm".to_string(),
        version: None, resolved_version: None, unresolved_version: false, exists: true, metadata: None,
    }];
    let issues = issues_from_lookups(&lookups, &config_with_age(72), &empty_similarity());
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].check, "metadata/parse-failed");
    assert_eq!(issues[0].severity, Severity::Warning);
}

#[test]
fn no_warning_when_package_does_not_exist() {
    let lookups = vec![MetadataLookup {
        package: "nonexistent-pkg".to_string(), ecosystem: "npm".to_string(),
        version: None, resolved_version: None, unresolved_version: false, exists: false, metadata: None,
    }];
    let issues = issues_from_lookups(&lookups, &config_with_age(72), &empty_similarity());
    assert!(!issues.iter().any(|i| i.check == "metadata/parse-failed"));
}

fn chrono_free_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let days_per_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut rem_days = secs / 86400;
    let mut year = 1970i64;
    loop {
        let ydays = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
        if rem_days < ydays { break; }
        rem_days -= ydays;
        year += 1;
    }
    let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let mut month = 1i64;
    for (i, &md) in days_per_month.iter().enumerate() {
        let md = if i == 1 && is_leap { md + 1 } else { md } as i64;
        if rem_days < md { break; }
        rem_days -= md;
        month += 1;
    }
    let day = rem_days + 1;
    let remaining = secs % 86400;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, remaining / 3600, (remaining % 3600) / 60, remaining % 60)
}
