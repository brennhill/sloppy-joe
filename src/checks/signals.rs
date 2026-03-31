//! Individual metadata signal checks. Each function examines one aspect of
//! a package's metadata and returns an optional Issue.

use crate::checks::existence::registry_url;
use crate::registry::PackageMetadata;
use crate::report::{Issue, Severity};
use std::collections::HashSet;

use super::metadata::{MetadataLookup, age_in_hours};

/// Version published too recently.
pub(crate) fn check_version_age(
    lookup: &MetadataLookup,
    meta: &PackageMetadata,
    min_age: u64,
) -> Option<Issue> {
    if lookup.unresolved_version {
        return None;
    }
    let date = meta.latest_version_date.as_ref()?;
    let age_hours = age_in_hours(date)?;
    if age_hours >= min_age {
        return None;
    }

    let version_label =
        if let Some(v) = lookup.resolved_version.as_ref().or(lookup.version.as_ref()) {
            format!("Version '{}' of '{}'", v, lookup.package)
        } else {
            format!("The latest version of '{}'", lookup.package)
        };

    Some(
        Issue::new(&lookup.package, super::names::METADATA_VERSION_AGE, Severity::Error)
            .message(format!(
                "{} was published {} hours ago (minimum: {} hours). New versions need time for the community and security scanners to review them.",
                version_label, age_hours, min_age
            ))
            .fix(format!(
                "Wait until the version is at least {} hours old, or pin to an older version. If this is urgent, set min_version_age_hours to 0 in your config (not recommended).",
                min_age
            )),
    )
}

/// Package created less than 30 days ago.
pub(crate) fn check_new_package(lookup: &MetadataLookup, meta: &PackageMetadata) -> Option<Issue> {
    let date = meta.created.as_ref()?;
    let age_hours = age_in_hours(date)?;
    if age_hours >= 720 {
        return None;
    }

    let age_days = age_hours / 24;
    Some(
        Issue::new(&lookup.package, super::names::METADATA_NEW_PACKAGE, Severity::Error)
            .message(format!(
                "'{}' was first published {} day{} ago. New packages are higher risk — verify this is a legitimate, maintained project before depending on it.",
                lookup.package, age_days, if age_days == 1 { "" } else { "s" }
            ))
            .fix(format!(
                "Verify '{}' at its registry page and source repository. If it's legitimate, add it to the 'allowed' list in your config.",
                lookup.package
            ))
            .registry_url(registry_url(lookup.ecosystem, &lookup.package)),
    )
}

/// Fewer than 100 downloads.
pub(crate) fn check_low_downloads(
    lookup: &MetadataLookup,
    meta: &PackageMetadata,
) -> Option<Issue> {
    let downloads = meta.downloads?;
    if downloads >= 100 {
        return None;
    }

    Some(
        Issue::new(&lookup.package, super::names::METADATA_LOW_DOWNLOADS, Severity::Error)
            .message(format!(
                "'{}' has only {} downloads. Low-download packages are more likely to be typosquats, placeholders, or abandoned projects.",
                lookup.package, downloads
            ))
            .fix(format!(
                "Verify '{}' is the package you intend to use. If it's legitimate, add it to the 'allowed' list.",
                lookup.package
            )),
    )
}

/// Install scripts on a new, low-download, or similarity-flagged package.
pub(crate) fn check_install_script_risk(
    lookup: &MetadataLookup,
    meta: &PackageMetadata,
    is_new_package: bool,
    is_low_downloads: bool,
    similarity_flagged: &HashSet<String>,
) -> Option<Issue> {
    if lookup.unresolved_version || !meta.has_install_scripts {
        return None;
    }

    let has_similarity = similarity_flagged.contains(&lookup.package);
    let has_low_downloads = meta.downloads.is_some_and(|d| d < 1000);
    let has_no_repository = meta
        .repository_url
        .as_deref()
        .map(|url| !is_plausible_repo_url(url))
        .unwrap_or(true);

    if !is_new_package
        && !is_low_downloads
        && !has_low_downloads
        && !has_similarity
        && !has_no_repository
    {
        return None;
    }

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
        reasons.push("was flagged for name similarity to a popular package".to_string());
    }
    if has_no_repository {
        reasons.push("has no source repository URL".to_string());
    }
    let reason_str = reasons.join(" and ");

    Some(
        Issue::new(&lookup.package, super::names::METADATA_INSTALL_SCRIPT_RISK, Severity::Error)
            .message(format!(
                "'{}' has install scripts AND {}. Install scripts on new, low-download packages are the #1 malware delivery vector.",
                lookup.package, reason_str
            ))
            .fix("Do not install this package. Verify it is legitimate before proceeding."),
    )
}

/// 10+ new dependencies added in the latest version.
pub(crate) fn check_dependency_explosion(
    lookup: &MetadataLookup,
    meta: &PackageMetadata,
) -> Option<Issue> {
    if lookup.unresolved_version {
        return None;
    }
    let (current, previous) = match (meta.dependency_count, meta.previous_dependency_count) {
        (Some(c), Some(p)) => (c, p),
        _ => return None,
    };
    if current < previous + 10 {
        return None;
    }

    let added = current - previous;
    Some(
        Issue::new(&lookup.package, super::names::METADATA_DEPENDENCY_EXPLOSION, Severity::Error)
            .message(format!(
                "'{}' added {} new dependencies in its latest version (was {}, now {}). Sudden dependency additions in patch versions are a known supply chain attack vector.",
                lookup.package, added, previous, current
            ))
            .fix("Review the new dependencies manually before installing."),
    )
}

/// Publisher changed between versions.
pub(crate) fn check_maintainer_change(
    lookup: &MetadataLookup,
    meta: &PackageMetadata,
) -> Option<Issue> {
    if lookup.unresolved_version {
        return None;
    }
    let (current_pub, previous_pub) = match (&meta.current_publisher, &meta.previous_publisher) {
        (Some(c), Some(p)) => (c, p),
        _ => return None,
    };
    if current_pub == previous_pub {
        return None;
    }

    Some(
        Issue::new(&lookup.package, super::names::METADATA_MAINTAINER_CHANGE, Severity::Error)
            .message(format!(
                "The publisher of '{}' changed from '{}' to '{}' between versions. Maintainer takeovers are a known supply chain attack vector.",
                lookup.package, previous_pub, current_pub
            ))
            .fix("Verify the maintainer change is legitimate before installing."),
    )
}

/// Package exists but metadata couldn't be parsed.
pub(crate) fn check_parse_failed(lookup: &MetadataLookup) -> Option<Issue> {
    if lookup.metadata.is_some() || !lookup.exists {
        return None;
    }

    Some(
        Issue::new(&lookup.package, super::names::METADATA_PARSE_FAILED, Severity::Warning)
            .message(format!(
                "'{}' exists on the {} registry but its metadata could not be parsed. \
                 Metadata-based checks (version age, install scripts, etc.) are skipped for this package.",
                lookup.package, lookup.ecosystem
            ))
            .fix(format!(
                "This may be a transient registry issue. Retry later. If it persists, check '{}' manually.",
                lookup.package
            )),
    )
}

/// Known code hosting domains. A repository URL pointing elsewhere is suspicious.
const KNOWN_CODE_HOSTS: &[&str] = &[
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "codeberg.org",
    "sr.ht",
    "gitea.com",
    "dev.azure.com",
    "ssh.dev.azure.com",
];

/// Check if a repository URL is plausible (points to a known code host).
fn is_plausible_repo_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    KNOWN_CODE_HOSTS.iter().any(|host| lower.contains(host))
}

use crate::registry::VERSION_HISTORY_WINDOW_HOURS;

/// Publisher changed within 12 months AND install scripts present.
/// Detects the event-stream pattern: attacker gains publish access, then
/// adds install scripts in a later version.
pub(crate) fn check_publisher_script_combo(
    lookup: &MetadataLookup,
    meta: &PackageMetadata,
) -> Option<Issue> {
    if lookup.unresolved_version {
        return None;
    }
    if meta.version_history.is_empty() {
        return None;
    }
    if !meta.has_install_scripts {
        return None;
    }

    // Walk chronologically to find the most recent publisher change.
    let mut change_idx: Option<usize> = None;
    for i in 1..meta.version_history.len() {
        let prev = &meta.version_history[i - 1];
        let curr = &meta.version_history[i];
        if let (Some(prev_pub), Some(curr_pub)) = (&prev.publisher, &curr.publisher)
            && prev_pub != curr_pub
        {
            change_idx = Some(i);
        }
    }

    let change_idx = change_idx?;
    let change_version = &meta.version_history[change_idx];
    let prev_version = &meta.version_history[change_idx - 1];

    // Check the publisher change is within 12 months
    let date = change_version.date.as_ref()?;
    let age = age_in_hours(date)?;
    if age > VERSION_HISTORY_WINDOW_HOURS {
        return None;
    }

    let old_publisher = prev_version.publisher.as_deref().unwrap_or("unknown");
    let new_publisher = change_version.publisher.as_deref().unwrap_or("unknown");

    // Check if scripts existed before the publisher change
    let scripts_predate = prev_version.has_install_scripts;

    let message = if scripts_predate {
        format!(
            "The publisher of '{}' changed from '{}' to '{}' in version {} and install scripts were already present before the change. \
             The new publisher inherited control of existing install scripts. This matches known supply chain attack patterns.",
            lookup.package, old_publisher, new_publisher, change_version.version
        )
    } else {
        format!(
            "The publisher of '{}' changed from '{}' to '{}' in version {} and install scripts were added afterward. \
             This matches known supply chain attack patterns (e.g., event-stream).",
            lookup.package, old_publisher, new_publisher, change_version.version
        )
    };

    Some(
        Issue::new(
            &lookup.package,
            super::names::METADATA_PUBLISHER_SCRIPT_COMBO,
            Severity::Error,
        )
        .message(message)
        .fix("Wait 30 days after the install scripts were added. Audit the install scripts. Verify the publisher change was legitimate. If verified, add to the allowed list."),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ecosystem;
    use crate::registry::VersionRecord;

    fn make_lookup(package: &str, unresolved: bool, meta: PackageMetadata) -> (MetadataLookup, PackageMetadata) {
        let lookup = MetadataLookup {
            package: package.to_string(),
            ecosystem: Ecosystem::Npm,
            version: Some("2.0.0".to_string()),
            resolved_version: Some("2.0.0".to_string()),
            unresolved_version: unresolved,
            exists: true,
            metadata: Some(meta.clone()),
        };
        (lookup, meta)
    }

    fn base_meta() -> PackageMetadata {
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
            version_history: Vec::new(),
        }
    }

    /// Helper: returns an ISO date string N months ago (approximate).
    fn months_ago(months: u64) -> String {
        let secs = crate::cache::now_epoch() as i64 - (months as i64 * 30 * 24 * 3600);
        // Convert back to rough ISO string
        let (y, m, d, h, mi, s) = epoch_to_date(secs);
        format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, h, mi, s)
    }

    fn epoch_to_date(epoch: i64) -> (i64, i64, i64, i64, i64, i64) {
        let s = epoch % 60;
        let mi = (epoch / 60) % 60;
        let h = (epoch / 3600) % 24;
        let mut days = epoch / 86400;
        let mut y = 1970i64;
        loop {
            let dy = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 366 } else { 365 };
            if days < dy { break; }
            days -= dy;
            y += 1;
        }
        let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
        let mdays = [31, if leap {29} else {28}, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let mut m = 0i64;
        for (i, &md) in mdays.iter().enumerate() {
            if days < md as i64 { m = i as i64 + 1; break; }
            days -= md as i64;
        }
        (y, m, days + 1, h, mi, s)
    }

    // Test 1: Combo fires when publisher changed 6 months ago + scripts added after
    #[test]
    fn combo_fires_publisher_change_6_months_scripts_after() {
        let change_date = months_ago(6);
        let meta = PackageMetadata {
            has_install_scripts: true,
            version_history: vec![
                VersionRecord {
                    version: "1.0.0".to_string(),
                    publisher: Some("alice".to_string()),
                    has_install_scripts: false,
                    date: Some(months_ago(8)),
                },
                VersionRecord {
                    version: "1.1.0".to_string(),
                    publisher: Some("bob".to_string()),
                    has_install_scripts: false,
                    date: Some(change_date.clone()),
                },
                VersionRecord {
                    version: "2.0.0".to_string(),
                    publisher: Some("bob".to_string()),
                    has_install_scripts: true,
                    date: Some(months_ago(1)),
                },
            ],
            ..base_meta()
        };
        let (lookup, meta) = make_lookup("evil-pkg", false, meta);
        let issue = check_publisher_script_combo(&lookup, &meta);
        assert!(issue.is_some(), "Should fire when publisher changed 6 months ago + scripts added after");
        let issue = issue.unwrap();
        assert_eq!(issue.check, super::super::names::METADATA_PUBLISHER_SCRIPT_COMBO);
        assert_eq!(issue.severity, Severity::Error);
        assert!(issue.message.contains("alice"), "Message should mention old publisher");
        assert!(issue.message.contains("bob"), "Message should mention new publisher");
    }

    // Test 2: Does NOT fire when no publisher change in history
    #[test]
    fn no_fire_no_publisher_change() {
        let meta = PackageMetadata {
            has_install_scripts: true,
            version_history: vec![
                VersionRecord {
                    version: "1.0.0".to_string(),
                    publisher: Some("alice".to_string()),
                    has_install_scripts: false,
                    date: Some(months_ago(6)),
                },
                VersionRecord {
                    version: "2.0.0".to_string(),
                    publisher: Some("alice".to_string()),
                    has_install_scripts: true,
                    date: Some(months_ago(1)),
                },
            ],
            ..base_meta()
        };
        let (lookup, meta) = make_lookup("safe-pkg", false, meta);
        let issue = check_publisher_script_combo(&lookup, &meta);
        assert!(issue.is_none(), "Should not fire when no publisher change");
    }

    // Test 3: Does NOT fire when publisher change is >12 months old
    #[test]
    fn no_fire_publisher_change_old() {
        let meta = PackageMetadata {
            has_install_scripts: true,
            version_history: vec![
                VersionRecord {
                    version: "1.0.0".to_string(),
                    publisher: Some("alice".to_string()),
                    has_install_scripts: false,
                    date: Some(months_ago(18)),
                },
                VersionRecord {
                    version: "2.0.0".to_string(),
                    publisher: Some("bob".to_string()),
                    has_install_scripts: true,
                    date: Some(months_ago(14)),
                },
            ],
            ..base_meta()
        };
        let (lookup, meta) = make_lookup("old-change-pkg", false, meta);
        let issue = check_publisher_script_combo(&lookup, &meta);
        assert!(issue.is_none(), "Should not fire when publisher change is >12 months old");
    }

    // Test 4: Does NOT fire when no install scripts in current version
    #[test]
    fn no_fire_no_install_scripts() {
        let meta = PackageMetadata {
            has_install_scripts: false,
            version_history: vec![
                VersionRecord {
                    version: "1.0.0".to_string(),
                    publisher: Some("alice".to_string()),
                    has_install_scripts: false,
                    date: Some(months_ago(6)),
                },
                VersionRecord {
                    version: "2.0.0".to_string(),
                    publisher: Some("bob".to_string()),
                    has_install_scripts: false,
                    date: Some(months_ago(1)),
                },
            ],
            ..base_meta()
        };
        let (lookup, meta) = make_lookup("no-scripts-pkg", false, meta);
        let issue = check_publisher_script_combo(&lookup, &meta);
        assert!(issue.is_none(), "Should not fire when no install scripts");
    }

    // Test 5: Fires with different message when scripts pre-date the publisher change
    #[test]
    fn fires_different_message_scripts_predate_change() {
        let meta = PackageMetadata {
            has_install_scripts: true,
            version_history: vec![
                VersionRecord {
                    version: "1.0.0".to_string(),
                    publisher: Some("alice".to_string()),
                    has_install_scripts: true, // scripts already present
                    date: Some(months_ago(8)),
                },
                VersionRecord {
                    version: "1.1.0".to_string(),
                    publisher: Some("bob".to_string()),
                    has_install_scripts: true,
                    date: Some(months_ago(3)),
                },
            ],
            ..base_meta()
        };
        let (lookup, meta) = make_lookup("inherited-pkg", false, meta);
        let issue = check_publisher_script_combo(&lookup, &meta);
        assert!(issue.is_some(), "Should fire when scripts pre-date publisher change");
        let issue = issue.unwrap();
        assert!(issue.message.contains("already present") || issue.message.contains("pre-date") || issue.message.contains("inherited"),
            "Message should note scripts pre-date the change, got: {}", issue.message);
    }

    // Test 6: Skips when unresolved_version is true
    #[test]
    fn skips_unresolved_version() {
        let meta = PackageMetadata {
            has_install_scripts: true,
            version_history: vec![
                VersionRecord {
                    version: "1.0.0".to_string(),
                    publisher: Some("alice".to_string()),
                    has_install_scripts: false,
                    date: Some(months_ago(6)),
                },
                VersionRecord {
                    version: "2.0.0".to_string(),
                    publisher: Some("bob".to_string()),
                    has_install_scripts: true,
                    date: Some(months_ago(1)),
                },
            ],
            ..base_meta()
        };
        let (lookup, meta) = make_lookup("unresolved-pkg", true, meta);
        let issue = check_publisher_script_combo(&lookup, &meta);
        assert!(issue.is_none(), "Should skip when unresolved_version is true");
    }

    // Test 7: Skips when version_history is empty
    #[test]
    fn skips_empty_version_history() {
        let meta = PackageMetadata {
            has_install_scripts: true,
            version_history: Vec::new(),
            ..base_meta()
        };
        let (lookup, meta) = make_lookup("empty-history-pkg", false, meta);
        let issue = check_publisher_script_combo(&lookup, &meta);
        assert!(issue.is_none(), "Should skip when version_history is empty");
    }
}

/// Package has no valid repository URL and is either new or low-download.
pub(crate) fn check_no_repository(
    lookup: &MetadataLookup,
    meta: &PackageMetadata,
    is_new_package: bool,
    is_low_downloads: bool,
) -> Option<Issue> {
    // Only flag if repo URL is missing or doesn't point to a known code host
    if let Some(ref url) = meta.repository_url
        && is_plausible_repo_url(url)
    {
        return None;
    }
    // Only flag if also new or low-download — lots of legitimate old packages lack repo links
    if !is_new_package && !is_low_downloads {
        return None;
    }

    let mut reasons = Vec::new();
    if is_new_package {
        reasons.push("is a new package (< 30 days old)");
    }
    if is_low_downloads {
        reasons.push("has low downloads (< 100)");
    }

    Some(
        Issue::new(&lookup.package, super::names::METADATA_NO_REPOSITORY, Severity::Warning)
            .message(format!(
                "'{}' has no source repository URL and {}. \
                 Legitimate packages almost always link to their source code. \
                 The absence of a repository link on a new or low-download package is a supply chain risk indicator.",
                lookup.package,
                reasons.join(" and ")
            ))
            .fix(format!(
                "Verify '{}' at its registry page. If it's legitimate, add it to the 'allowed' list.",
                lookup.package
            )),
    )
}
