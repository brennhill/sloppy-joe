use crate::Dependency;
use crate::config::SloppyJoeConfig;
use crate::lockfiles::ResolutionResult;
use crate::registry::{PackageMetadata, Registry};
use crate::report::{Issue, Severity};
use anyhow::Result;
use futures::stream::{self, StreamExt, TryStreamExt};
use std::collections::HashSet;

/// Parse an ISO 8601 date string and return the age in hours.
fn age_in_hours(date_str: &str) -> Option<u64> {
    // Parse common ISO 8601 formats: "2026-03-21T10:30:00.000Z"
    let cleaned = date_str.trim().trim_end_matches('Z');
    // Try parsing with chrono-like manual parsing (avoid adding chrono dep)
    // Format: YYYY-MM-DDTHH:MM:SS
    let parts: Vec<&str> = cleaned.split('T').collect();
    if parts.len() != 2 {
        return None;
    }
    let date_parts: Vec<&str> = parts[0].split('-').collect();
    let time_parts: Vec<&str> = parts[1].split(':').collect();
    if date_parts.len() != 3 || time_parts.len() < 2 {
        return None;
    }
    let year: i64 = date_parts[0].parse().ok()?;
    let month: i64 = date_parts[1].parse().ok()?;
    let day: i64 = date_parts[2].parse().ok()?;
    let hour: i64 = time_parts[0].parse().ok()?;
    let min: i64 = time_parts[1].split('.').next()?.parse().ok()?;

    // Rough epoch calculation (good enough for age comparison)
    let pkg_epoch = rough_epoch(year, month, day, hour, min);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;

    let diff_seconds = now - pkg_epoch;
    if diff_seconds < 0 {
        return Some(0);
    }
    Some((diff_seconds / 3600) as u64)
}

/// Rough seconds-since-epoch. Not perfectly accurate (ignores leap years
/// in some edge cases) but sufficient for "is this older than 72 hours?"
fn rough_epoch(year: i64, month: i64, day: i64, hour: i64, min: i64) -> i64 {
    let days_per_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut days: i64 = 0;
    // Years since 1970
    for y in 1970..year {
        days += if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
            366
        } else {
            365
        };
    }
    // Months
    for m in 0..((month - 1) as usize) {
        days += days_per_month.get(m).copied().unwrap_or(30) as i64;
    }
    // Leap day
    if month > 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
        days += 1;
    }
    days += day - 1;
    days * 86400 + hour * 3600 + min * 60
}

#[derive(Debug, Clone)]
pub(crate) struct MetadataLookup {
    pub package: String,
    pub ecosystem: String,
    pub version: Option<String>,
    pub resolved_version: Option<String>,
    pub unresolved_version: bool,
    pub exists: bool,
    pub metadata: Option<PackageMetadata>,
}

pub(crate) async fn fetch_metadata(
    registry: &dyn Registry,
    deps: &[Dependency],
    resolution: &ResolutionResult,
) -> Result<Vec<MetadataLookup>> {
    stream::iter(deps)
        .map(|dep| {
            let package = dep.name.clone();
            let ecosystem = dep.ecosystem.clone();
            let version = dep.version.clone();
            let exact_version = resolution.exact_version(dep).map(str::to_string);
            let unresolved_version = resolution.is_unresolved(dep);
            async move {
                let metadata = registry
                    .metadata(&package, exact_version.as_deref())
                    .await?;
                // If metadata parsing succeeded, the package exists.
                // If metadata is None, it could be "not found" OR "found but
                // metadata parse failed". Fall back to exists() to distinguish.
                let exists = if metadata.is_some() {
                    true
                } else {
                    registry.exists(&package).await?
                };
                Ok::<_, anyhow::Error>(MetadataLookup {
                    package,
                    ecosystem,
                    version,
                    resolved_version: exact_version,
                    unresolved_version,
                    exists,
                    metadata,
                })
            }
        })
        .buffer_unordered(10)
        .try_collect::<Vec<_>>()
        .await
}

pub(crate) fn issues_from_lookups(
    lookups: &[MetadataLookup],
    config: &SloppyJoeConfig,
    similarity_flagged: &HashSet<String>,
) -> Vec<Issue> {
    let min_age = config.min_version_age_hours;
    let mut issues = Vec::new();

    for lookup in lookups {
        let name = &lookup.package;
        let ecosystem = &lookup.ecosystem;
        let version = &lookup.version;
        let resolved_version = &lookup.resolved_version;
        let unresolved_version = lookup.unresolved_version;

        let Some(meta) = lookup.metadata.as_ref() else {
            continue;
        };

        let mut is_new_package = false;
        let mut is_low_downloads = false;

        if !unresolved_version
            && let Some(ref date) = meta.latest_version_date
            && let Some(age_hours) = age_in_hours(date)
            && age_hours < min_age
        {
            let version_label = if let Some(v) = resolved_version.as_ref().or(version.as_ref()) {
                format!("Version '{}' of '{}'", v, name)
            } else {
                format!("The latest version of '{}'", name)
            };
            issues.push(Issue {
                package: name.clone(),
                check: "metadata/version-age".to_string(),
                severity: Severity::Error,
                message: format!(
                    "{} was published {} hours ago (minimum: {} hours). New versions need time for the community and security scanners to review them.",
                    version_label, age_hours, min_age
                ),
                fix: format!(
                    "Wait until the version is at least {} hours old, or pin to an older version. If this is urgent, set min_version_age_hours to 0 in your config (not recommended).",
                    min_age
                ),
                suggestion: None,
                registry_url: None,
            });
        }

        if let Some(ref date) = meta.created
            && let Some(age_hours) = age_in_hours(date)
            && age_hours < 720
        {
            is_new_package = true;
            let age_days = age_hours / 24;
            issues.push(Issue {
                package: name.clone(),
                check: "metadata/new-package".to_string(),
                severity: Severity::Error,
                message: format!(
                    "'{}' was first published {} day{} ago. New packages are higher risk — verify this is a legitimate, maintained project before depending on it.",
                    name, age_days, if age_days == 1 { "" } else { "s" }
                ),
                fix: format!(
                    "Verify '{}' at its registry page and source repository. If it's legitimate, add it to the 'allowed' list in your config.",
                    name
                ),
                suggestion: None,
                registry_url: Some(crate::checks::existence::registry_url(ecosystem, name)),
            });
        }

        if let Some(downloads) = meta.downloads
            && downloads < 100
        {
            is_low_downloads = true;
            issues.push(Issue {
                package: name.clone(),
                check: "metadata/low-downloads".to_string(),
                severity: Severity::Error,
                message: format!(
                    "'{}' has only {} downloads. Low-download packages are more likely to be typosquats, placeholders, or abandoned projects.",
                    name, downloads
                ),
                fix: format!(
                    "Verify '{}' is the package you intend to use. If it's legitimate, add it to the 'allowed' list.",
                    name
                ),
                suggestion: None,
                registry_url: None,
            });
        }

        if !unresolved_version && meta.has_install_scripts {
            let has_similarity = similarity_flagged.contains(name);
            let has_low_downloads = meta.downloads.is_some_and(|d| d < 1000);

            if is_new_package || is_low_downloads || has_low_downloads || has_similarity {
                let mut reasons = Vec::new();
                if is_new_package
                    && let Some(ref date) = meta.created
                    && let Some(age_hours) = age_in_hours(date)
                {
                    let age_days = age_hours / 24;
                    reasons.push(format!("was published {} days ago", age_days));
                }
                if let Some(downloads) = meta.downloads
                    && downloads < 1000
                {
                    reasons.push(format!("with {} downloads", downloads));
                }
                if has_similarity {
                    reasons
                        .push("was flagged for name similarity to a popular package".to_string());
                }
                let reason_str = reasons.join(" and ");

                issues.push(Issue {
                    package: name.clone(),
                    check: "metadata/install-script-risk".to_string(),
                    severity: Severity::Error,
                    message: format!(
                        "'{}' has install scripts AND {}. Install scripts on new, low-download packages are the #1 malware delivery vector.",
                        name, reason_str
                    ),
                    fix: "Do not install this package. Verify it is legitimate before proceeding.".to_string(),
                    suggestion: None,
                    registry_url: None,
                });
            }
        }

        if !unresolved_version
            && let (Some(current), Some(previous)) =
                (meta.dependency_count, meta.previous_dependency_count)
            && current >= previous + 10
        {
            let added = current - previous;
            issues.push(Issue {
                package: name.clone(),
                check: "metadata/dependency-explosion".to_string(),
                severity: Severity::Error,
                message: format!(
                    "'{}' added {} new dependencies in its latest version (was {}, now {}). Sudden dependency additions in patch versions are a known supply chain attack vector.",
                    name, added, previous, current
                ),
                fix: "Review the new dependencies manually before installing.".to_string(),
                suggestion: None,
                registry_url: None,
            });
        }

        if !unresolved_version
            && let (Some(current_pub), Some(previous_pub)) =
                (&meta.current_publisher, &meta.previous_publisher)
            && current_pub != previous_pub
        {
            issues.push(Issue {
                package: name.clone(),
                check: "metadata/maintainer-change".to_string(),
                severity: Severity::Error,
                message: format!(
                    "The publisher of '{}' changed from '{}' to '{}' between versions. Maintainer takeovers are a known supply chain attack vector.",
                    name, previous_pub, current_pub
                ),
                fix: "Verify the maintainer change is legitimate before installing.".to_string(),
                suggestion: None,
                registry_url: None,
            });
        }
    }

    issues
}

/// Check metadata signals: version age, package age, download count,
/// install script amplifier, dependency explosion, and maintainer change.
/// Only runs on non-internal packages. Allowed packages ARE subject to age gating.
///
/// `similarity_flagged` is the set of package names that triggered a similarity check.
/// This is used for the install script signal amplifier.
pub async fn check_metadata(
    registry: &dyn Registry,
    deps: &[Dependency],
    config: &SloppyJoeConfig,
    similarity_flagged: &HashSet<String>,
    resolution: &ResolutionResult,
) -> Result<Vec<Issue>> {
    let lookups = fetch_metadata(registry, deps, resolution).await?;
    Ok(issues_from_lookups(&lookups, config, similarity_flagged))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    struct FakeRegistry {
        metadata_response: Option<PackageMetadata>,
    }

    #[async_trait]
    impl Registry for FakeRegistry {
        async fn exists(&self, _name: &str) -> Result<bool> {
            Ok(true)
        }
        async fn metadata(
            &self,
            _name: &str,
            _version: Option<&str>,
        ) -> Result<Option<PackageMetadata>> {
            Ok(self.metadata_response.clone())
        }
        fn ecosystem(&self) -> &str {
            "npm"
        }
    }

    fn dep(name: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        }
    }

    fn dep_with_version(name: &str, version: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: Some(version.to_string()),
            ecosystem: "npm".to_string(),
        }
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
        // A date far in the past should return a large number
        let age = age_in_hours("2020-01-01T00:00:00.000Z");
        assert!(age.is_some());
        assert!(age.unwrap() > 40000); // More than ~4.5 years
    }

    #[test]
    fn age_in_hours_returns_none_for_garbage() {
        assert!(age_in_hours("not a date").is_none());
        assert!(age_in_hours("").is_none());
    }

    #[tokio::test]
    async fn version_too_new_is_blocked() {
        // Version published "now" — age is 0 hours
        let now = chrono_free_now();
        let registry = FakeRegistry {
            metadata_response: Some(PackageMetadata {
                latest_version_date: Some(now),
                ..default_meta()
            }),
        };
        let deps = vec![dep_with_version("some-pkg", "1.2.3")];
        let config = config_with_age(72);
        let issues = check_metadata(
            &registry,
            &deps,
            &config,
            &empty_similarity(),
            &no_resolution(),
        )
        .await
        .unwrap();
        let age_issues: Vec<_> = issues
            .iter()
            .filter(|i| i.check.contains("version-age"))
            .collect();
        assert!(!age_issues.is_empty());
    }

    #[tokio::test]
    async fn old_version_passes() {
        let registry = FakeRegistry {
            metadata_response: Some(default_meta()),
        };
        let deps = vec![dep_with_version("some-pkg", "1.2.3")];
        let config = config_with_age(72);
        let issues = check_metadata(
            &registry,
            &deps,
            &config,
            &empty_similarity(),
            &no_resolution(),
        )
        .await
        .unwrap();
        let age_issues: Vec<_> = issues
            .iter()
            .filter(|i| i.check.contains("version-age"))
            .collect();
        assert!(age_issues.is_empty());
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
        let config = config_with_age(72);
        let issues = check_metadata(
            &registry,
            &deps,
            &config,
            &empty_similarity(),
            &no_resolution(),
        )
        .await
        .unwrap();
        let new_pkg: Vec<_> = issues
            .iter()
            .filter(|i| i.check.contains("new-package"))
            .collect();
        assert!(!new_pkg.is_empty());
    }

    #[test]
    fn new_package_uses_ecosystem_registry_url() {
        let now = chrono_free_now();
        let lookups = vec![MetadataLookup {
            package: "requests".to_string(),
            ecosystem: "pypi".to_string(),
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
            .find(|issue| issue.check == "metadata/new-package")
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
        let config = config_with_age(72);
        let issues = check_metadata(
            &registry,
            &deps,
            &config,
            &empty_similarity(),
            &no_resolution(),
        )
        .await
        .unwrap();
        let dl_issues: Vec<_> = issues
            .iter()
            .filter(|i| i.check.contains("low-downloads"))
            .collect();
        assert!(!dl_issues.is_empty());
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
        let config = config_with_age(72);
        let issues = check_metadata(
            &registry,
            &deps,
            &config,
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
        let config = config_with_age(0);
        let issues = check_metadata(
            &registry,
            &deps,
            &config,
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
    async fn no_metadata_no_issues() {
        let registry = FakeRegistry {
            metadata_response: None,
        };
        let deps = vec![dep("some-pkg")];
        let config = config_with_age(72);
        let issues = check_metadata(
            &registry,
            &deps,
            &config,
            &empty_similarity(),
            &no_resolution(),
        )
        .await
        .unwrap();
        assert!(issues.is_empty());
    }

    #[tokio::test]
    async fn registry_errors_fail_the_check() {
        struct ErrorRegistry;

        #[async_trait]
        impl Registry for ErrorRegistry {
            async fn exists(&self, _name: &str) -> Result<bool> {
                Ok(true)
            }

            async fn metadata(
                &self,
                _name: &str,
                _version: Option<&str>,
            ) -> Result<Option<PackageMetadata>> {
                anyhow::bail!("metadata unavailable");
            }

            fn ecosystem(&self) -> &str {
                "npm"
            }
        }

        let deps = vec![dep("some-pkg")];
        let config = config_with_age(72);
        let err = check_metadata(
            &ErrorRegistry,
            &deps,
            &config,
            &empty_similarity(),
            &no_resolution(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("metadata unavailable"));
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
        let config = config_with_age(72);
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
                .any(|i| i.check == "metadata/unresolved-version")
        );
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
        let config = config_with_age(72);
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
                .any(|i| i.check == "metadata/unresolved-version")
        );
        assert!(!issues.iter().any(|i| i.check == "metadata/version-age"));
    }

    // ── Feature 1: Install script signal amplifier ──

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
        let config = config_with_age(72);
        let issues = check_metadata(
            &registry,
            &deps,
            &config,
            &empty_similarity(),
            &no_resolution(),
        )
        .await
        .unwrap();
        let script_issues: Vec<_> = issues
            .iter()
            .filter(|i| i.check == "metadata/install-script-risk")
            .collect();
        assert!(!script_issues.is_empty());
        assert!(script_issues[0].message.contains("install scripts"));
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
        let config = config_with_age(72);
        let issues = check_metadata(
            &registry,
            &deps,
            &config,
            &empty_similarity(),
            &no_resolution(),
        )
        .await
        .unwrap();
        let script_issues: Vec<_> = issues
            .iter()
            .filter(|i| i.check == "metadata/install-script-risk")
            .collect();
        assert!(!script_issues.is_empty());
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
        let config = config_with_age(72);
        let issues = check_metadata(
            &registry,
            &deps,
            &config,
            &empty_similarity(),
            &no_resolution(),
        )
        .await
        .unwrap();
        let script_issues: Vec<_> = issues
            .iter()
            .filter(|i| i.check == "metadata/install-script-risk")
            .collect();
        assert!(script_issues.is_empty());
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
        let config = config_with_age(72);
        let issues = check_metadata(
            &registry,
            &deps,
            &config,
            &empty_similarity(),
            &no_resolution(),
        )
        .await
        .unwrap();
        let script_issues: Vec<_> = issues
            .iter()
            .filter(|i| i.check == "metadata/install-script-risk")
            .collect();
        assert!(script_issues.is_empty());
    }

    // ── Feature 2: Dependency explosion ──

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
        let config = config_with_age(72);
        let issues = check_metadata(
            &registry,
            &deps,
            &config,
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
        assert!(explosion[0].message.contains("added 15 new dependencies"));
        assert!(explosion[0].message.contains("was 3, now 18"));
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
        let config = config_with_age(72);
        let issues = check_metadata(
            &registry,
            &deps,
            &config,
            &empty_similarity(),
            &no_resolution(),
        )
        .await
        .unwrap();
        let explosion: Vec<_> = issues
            .iter()
            .filter(|i| i.check == "metadata/dependency-explosion")
            .collect();
        assert!(explosion.is_empty());
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
        let config = config_with_age(72);
        let issues = check_metadata(
            &registry,
            &deps,
            &config,
            &empty_similarity(),
            &no_resolution(),
        )
        .await
        .unwrap();
        let explosion: Vec<_> = issues
            .iter()
            .filter(|i| i.check == "metadata/dependency-explosion")
            .collect();
        assert!(explosion.is_empty());
    }

    // ── Feature 4: Maintainer change ──

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
        let config = config_with_age(72);
        let issues = check_metadata(
            &registry,
            &deps,
            &config,
            &empty_similarity(),
            &no_resolution(),
        )
        .await
        .unwrap();
        let mc: Vec<_> = issues
            .iter()
            .filter(|i| i.check == "metadata/maintainer-change")
            .collect();
        assert!(!mc.is_empty());
        assert!(mc[0].message.contains("original-author"));
        assert!(mc[0].message.contains("new-person"));
    }

    #[tokio::test]
    async fn same_maintainer_not_flagged() {
        let registry = FakeRegistry {
            metadata_response: Some(PackageMetadata {
                current_publisher: Some("same-person".to_string()),
                previous_publisher: Some("same-person".to_string()),
                ..default_meta()
            }),
        };
        let deps = vec![dep_with_version("some-pkg", "1.2.3")];
        let config = config_with_age(72);
        let issues = check_metadata(
            &registry,
            &deps,
            &config,
            &empty_similarity(),
            &no_resolution(),
        )
        .await
        .unwrap();
        let mc: Vec<_> = issues
            .iter()
            .filter(|i| i.check == "metadata/maintainer-change")
            .collect();
        assert!(mc.is_empty());
    }

    #[tokio::test]
    async fn no_publisher_info_not_flagged() {
        let registry = FakeRegistry {
            metadata_response: Some(default_meta()),
        };
        let deps = vec![dep_with_version("some-pkg", "1.2.3")];
        let config = config_with_age(72);
        let issues = check_metadata(
            &registry,
            &deps,
            &config,
            &empty_similarity(),
            &no_resolution(),
        )
        .await
        .unwrap();
        let mc: Vec<_> = issues
            .iter()
            .filter(|i| i.check == "metadata/maintainer-change")
            .collect();
        assert!(mc.is_empty());
    }

    /// Generate a "now" timestamp without chrono dependency.
    fn chrono_free_now() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Approximate: good enough for tests
        let days_since_epoch = secs / 86400;
        let year = 1970 + days_since_epoch / 365; // rough
        let month = 3; // close enough for test
        let day = 21;
        let hour = (secs % 86400) / 3600;
        let min = (secs % 3600) / 60;
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:00Z",
            year, month, day, hour, min
        )
    }
}
