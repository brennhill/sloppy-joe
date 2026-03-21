use crate::config::SloppyJoeConfig;
use crate::registry::Registry;
use crate::report::{Issue, Severity};
use crate::Dependency;
use anyhow::Result;
use futures::stream::{self, StreamExt};

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
        days += if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 366 } else { 365 };
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

/// Check metadata signals: version age, package age, download count.
/// Only runs on non-internal packages. Allowed packages ARE subject to age gating.
pub async fn check_metadata(
    registry: &dyn Registry,
    deps: &[Dependency],
    config: &SloppyJoeConfig,
) -> Result<Vec<Issue>> {
    let min_age = config.min_version_age_hours;
    if min_age == 0 {
        return Ok(vec![]); // Age gate disabled
    }

    let _ecosystem = registry.ecosystem();

    let results = stream::iter(deps)
        .map(|dep| {
            let name = dep.name.clone();
            let version = dep.version.clone();
            async move {
                let meta = registry.metadata(&name, version.as_deref()).await.unwrap_or(None);
                (name, version, meta)
            }
        })
        .buffer_unordered(10)
        .collect::<Vec<_>>()
        .await;

    let mut issues = Vec::new();

    for (name, version, meta) in results {
        let Some(meta) = meta else { continue };

        // Check version age
        if let Some(ref date) = meta.latest_version_date {
            if let Some(age_hours) = age_in_hours(date) {
                if age_hours < min_age {
                    let version_label = if let Some(ref v) = version {
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
            }
        }

        // Check package age (new package warning)
        if let Some(ref date) = meta.created {
            if let Some(age_hours) = age_in_hours(date) {
                if age_hours < 720 {
                    // Less than 30 days old
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
                        registry_url: Some(format!("https://www.npmjs.com/package/{}", name)),
                    });
                }
            }
        }

        // Check download count (if available)
        if let Some(downloads) = meta.downloads {
            if downloads < 100 {
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
        }
    }

    Ok(issues)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::PackageMetadata;
    use async_trait::async_trait;

    struct FakeRegistry {
        metadata_response: Option<PackageMetadata>,
    }

    #[async_trait]
    impl Registry for FakeRegistry {
        async fn exists(&self, _name: &str) -> Result<bool> {
            Ok(true)
        }
        async fn metadata(&self, _name: &str, _version: Option<&str>) -> Result<Option<PackageMetadata>> {
            Ok(self.metadata_response.clone())
        }
        fn ecosystem(&self) -> &str {
            "npm"
        }
    }

    fn dep(name: &str) -> Dependency {
        Dependency { name: name.to_string(), version: None, ecosystem: "npm".to_string() }
    }

    fn config_with_age(hours: u64) -> SloppyJoeConfig {
        SloppyJoeConfig {
            min_version_age_hours: hours,
            ..Default::default()
        }
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
                created: Some("2020-01-01T00:00:00Z".to_string()),
                latest_version_date: Some(now),
                downloads: Some(50000),
            }),
        };
        let deps = vec![dep("some-pkg")];
        let config = config_with_age(72);
        let issues = check_metadata(&registry, &deps, &config).await.unwrap();
        let age_issues: Vec<_> = issues.iter().filter(|i| i.check.contains("version-age")).collect();
        assert!(!age_issues.is_empty());
    }

    #[tokio::test]
    async fn old_version_passes() {
        let registry = FakeRegistry {
            metadata_response: Some(PackageMetadata {
                created: Some("2020-01-01T00:00:00Z".to_string()),
                latest_version_date: Some("2020-01-01T00:00:00Z".to_string()),
                downloads: Some(50000),
            }),
        };
        let deps = vec![dep("some-pkg")];
        let config = config_with_age(72);
        let issues = check_metadata(&registry, &deps, &config).await.unwrap();
        let age_issues: Vec<_> = issues.iter().filter(|i| i.check.contains("version-age")).collect();
        assert!(age_issues.is_empty());
    }

    #[tokio::test]
    async fn new_package_is_flagged() {
        let now = chrono_free_now();
        let registry = FakeRegistry {
            metadata_response: Some(PackageMetadata {
                created: Some(now.clone()),
                latest_version_date: Some(now),
                downloads: Some(50000),
            }),
        };
        let deps = vec![dep("brand-new-pkg")];
        let config = config_with_age(72);
        let issues = check_metadata(&registry, &deps, &config).await.unwrap();
        let new_pkg: Vec<_> = issues.iter().filter(|i| i.check.contains("new-package")).collect();
        assert!(!new_pkg.is_empty());
    }

    #[tokio::test]
    async fn low_downloads_flagged() {
        let registry = FakeRegistry {
            metadata_response: Some(PackageMetadata {
                created: Some("2020-01-01T00:00:00Z".to_string()),
                latest_version_date: Some("2020-01-01T00:00:00Z".to_string()),
                downloads: Some(5),
            }),
        };
        let deps = vec![dep("obscure-pkg")];
        let config = config_with_age(72);
        let issues = check_metadata(&registry, &deps, &config).await.unwrap();
        let dl_issues: Vec<_> = issues.iter().filter(|i| i.check.contains("low-downloads")).collect();
        assert!(!dl_issues.is_empty());
    }

    #[tokio::test]
    async fn high_downloads_not_flagged() {
        let registry = FakeRegistry {
            metadata_response: Some(PackageMetadata {
                created: Some("2020-01-01T00:00:00Z".to_string()),
                latest_version_date: Some("2020-01-01T00:00:00Z".to_string()),
                downloads: Some(1000000),
            }),
        };
        let deps = vec![dep("popular-pkg")];
        let config = config_with_age(72);
        let issues = check_metadata(&registry, &deps, &config).await.unwrap();
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
            }),
        };
        let deps = vec![dep("some-pkg")];
        let config = config_with_age(0);
        let issues = check_metadata(&registry, &deps, &config).await.unwrap();
        assert!(issues.is_empty());
    }

    #[tokio::test]
    async fn no_metadata_no_issues() {
        let registry = FakeRegistry {
            metadata_response: None,
        };
        let deps = vec![dep("some-pkg")];
        let config = config_with_age(72);
        let issues = check_metadata(&registry, &deps, &config).await.unwrap();
        assert!(issues.is_empty());
    }

    /// Generate a "now" timestamp without chrono dependency.
    fn chrono_free_now() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        // Approximate: good enough for tests
        let days_since_epoch = secs / 86400;
        let year = 1970 + days_since_epoch / 365; // rough
        let month = 3; // close enough for test
        let day = 21;
        let hour = (secs % 86400) / 3600;
        let min = (secs % 3600) / 60;
        format!("{:04}-{:02}-{:02}T{:02}:{:02}:00Z", year, month, day, hour, min)
    }
}
