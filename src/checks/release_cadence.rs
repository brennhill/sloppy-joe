//! Release-timing signals for a freshly published version.
//!
//! Account takeovers and worms show up as timing, not content: a package that
//! was silent for a year suddenly ships (stolen or abandoned account), or a
//! burst of versions lands within a day (automated republishing). Both only
//! matter while the selected version is recent; old releases are history.
//!
//! Dormancy is a warning on its own (legitimate revivals exist) and blocks
//! when the same version also carries install-time execution or a publisher
//! change. A burst is a warning.

use super::metadata::MetadataLookup;
use crate::cache::now_epoch;
use crate::registry::PackageMetadata;
use crate::report::{Issue, Severity};

/// A selected version published within this window is "recent".
const RECENT_SECONDS: i64 = 30 * 24 * 3600;
/// Silence before the selected version that counts as dormancy.
const DORMANT_SECONDS: i64 = 365 * 24 * 3600;
/// Other releases within the prior 24 hours that count as a burst.
const BURST_PRIOR_RELEASES: u32 = 5;

pub(crate) fn check_release_cadence(lookup: &MetadataLookup, meta: &PackageMetadata) -> Vec<Issue> {
    check_release_cadence_at(lookup, meta, now_epoch() as i64)
}

fn check_release_cadence_at(
    lookup: &MetadataLookup,
    meta: &PackageMetadata,
    now: i64,
) -> Vec<Issue> {
    let Some(cadence) = meta.release_cadence.as_ref() else {
        return Vec::new();
    };
    if lookup.unresolved_version || now - cadence.published_epoch > RECENT_SECONDS {
        return Vec::new();
    }
    let version = lookup
        .resolved_version
        .as_deref()
        .or(lookup.version.as_deref())
        .unwrap_or("the selected version");
    let mut issues = Vec::new();
    if let Some(previous) = cadence.previous_release_epoch {
        let quiet = cadence.published_epoch - previous;
        if quiet >= DORMANT_SECONDS {
            issues.push(dormant_issue(lookup, meta, version, quiet / 86_400));
        }
    }
    if cadence.releases_prior_24h >= BURST_PRIOR_RELEASES {
        issues.push(
            Issue::new(&lookup.package, super::names::METADATA_RELEASE_BURST, Severity::Warning)
                .message(format!(
                    "'{}' published {} other versions in the 24 hours before '{}'. Automated republishing from a compromised account looks like this.",
                    lookup.package, cadence.releases_prior_24h, version
                ))
                .fix("Check the project's release notes and repository for a matching release before installing."),
        );
    }
    issues
}

fn dormant_issue(
    lookup: &MetadataLookup,
    meta: &PackageMetadata,
    version: &str,
    days: i64,
) -> Issue {
    let publisher_changed = matches!(
        (&meta.current_publisher, &meta.previous_publisher),
        (Some(current), Some(previous)) if current != previous
    );
    let reason = if meta.has_install_scripts {
        Some("it also runs install-time code")
    } else if publisher_changed {
        Some("its publisher also changed")
    } else {
        None
    };
    let severity = if reason.is_some() {
        Severity::Error
    } else {
        Severity::Warning
    };
    let also = reason.map(|r| format!(" and {r}")).unwrap_or_default();
    Issue::new(&lookup.package, super::names::METADATA_DORMANT_RELEASE, severity)
        .message(format!(
            "'{}' shipped '{}' after {} days without a release{}. A stolen or taken-over dormant account is a common way malicious versions get published.",
            lookup.package, version, days, also
        ))
        .fix("Confirm the project is active again (repository activity, release notes, announced maintainer) before installing, or pin to the last version you reviewed.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ecosystem;
    use crate::registry::cadence::ReleaseCadence;

    const NOW: i64 = 2_000_000_000;
    const DAY: i64 = 86_400;

    fn lookup() -> MetadataLookup {
        MetadataLookup {
            package: "pkg".into(),
            ecosystem: Ecosystem::PyPI,
            version: Some("2.0".into()),
            resolved_version: Some("2.0".into()),
            unresolved_version: false,
            exists: true,
            metadata: None,
        }
    }

    fn meta(published_days_ago: i64, quiet_days: Option<i64>, prior: u32) -> PackageMetadata {
        let published = NOW - published_days_ago * DAY;
        PackageMetadata {
            release_cadence: Some(ReleaseCadence {
                published_epoch: published,
                previous_release_epoch: quiet_days.map(|d| published - d * DAY),
                releases_prior_24h: prior,
            }),
            ..Default::default()
        }
    }

    fn run(m: &PackageMetadata) -> Vec<Issue> {
        check_release_cadence_at(&lookup(), m, NOW)
    }

    #[test]
    fn recent_release_after_a_year_of_silence_warns() {
        let issues = run(&meta(2, Some(400), 0));
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].check, "metadata/dormant-release");
        assert_eq!(issues[0].severity, Severity::Warning);
    }

    #[test]
    fn dormant_release_with_install_scripts_blocks() {
        let mut m = meta(2, Some(400), 0);
        m.has_install_scripts = true;
        assert_eq!(run(&m)[0].severity, Severity::Error);
    }

    #[test]
    fn dormant_release_with_publisher_change_blocks() {
        let mut m = meta(2, Some(400), 0);
        m.current_publisher = Some("new".into());
        m.previous_publisher = Some("old".into());
        assert_eq!(run(&m)[0].severity, Severity::Error);
    }

    #[test]
    fn same_publisher_stays_a_warning() {
        let mut m = meta(2, Some(400), 0);
        m.current_publisher = Some("same".into());
        m.previous_publisher = Some("same".into());
        assert_eq!(run(&m)[0].severity, Severity::Warning);
    }

    #[test]
    fn under_a_year_of_silence_is_quiet() {
        assert!(run(&meta(2, Some(300), 0)).is_empty());
    }

    #[test]
    fn old_release_is_history_not_a_signal() {
        assert!(run(&meta(90, Some(900), 9)).is_empty());
    }

    #[test]
    fn burst_of_prior_releases_warns() {
        let issues = run(&meta(1, Some(1), 5));
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].check, "metadata/release-burst");
        assert!(run(&meta(1, Some(1), 4)).is_empty());
    }

    #[test]
    fn first_release_and_missing_cadence_are_quiet() {
        assert!(run(&meta(1, None, 0)).is_empty());
        assert!(run(&PackageMetadata::default()).is_empty());
    }

    #[test]
    fn unresolved_version_is_skipped() {
        let mut l = lookup();
        l.unresolved_version = true;
        assert!(check_release_cadence_at(&l, &meta(1, Some(900), 9), NOW).is_empty());
    }
}
