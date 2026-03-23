//! Individual metadata signal checks. Each function examines one aspect of
//! a package's metadata and returns an optional Issue.

use crate::checks::existence::registry_url;
use crate::registry::PackageMetadata;
use crate::report::{Issue, Severity};
use std::collections::HashSet;

use super::metadata::{age_in_hours, MetadataLookup};

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

    Some(Issue {
        package: lookup.package.clone(),
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
        source: None,
    })
}

/// Package created less than 30 days ago.
pub(crate) fn check_new_package(
    lookup: &MetadataLookup,
    meta: &PackageMetadata,
) -> Option<Issue> {
    let date = meta.created.as_ref()?;
    let age_hours = age_in_hours(date)?;
    if age_hours >= 720 {
        return None;
    }

    let age_days = age_hours / 24;
    Some(Issue {
        package: lookup.package.clone(),
        check: "metadata/new-package".to_string(),
        severity: Severity::Error,
        message: format!(
            "'{}' was first published {} day{} ago. New packages are higher risk — verify this is a legitimate, maintained project before depending on it.",
            lookup.package, age_days, if age_days == 1 { "" } else { "s" }
        ),
        fix: format!(
            "Verify '{}' at its registry page and source repository. If it's legitimate, add it to the 'allowed' list in your config.",
            lookup.package
        ),
        suggestion: None,
        registry_url: Some(registry_url(lookup.ecosystem, &lookup.package)),
        source: None,
    })
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

    Some(Issue {
        package: lookup.package.clone(),
        check: "metadata/low-downloads".to_string(),
        severity: Severity::Error,
        message: format!(
            "'{}' has only {} downloads. Low-download packages are more likely to be typosquats, placeholders, or abandoned projects.",
            lookup.package, downloads
        ),
        fix: format!(
            "Verify '{}' is the package you intend to use. If it's legitimate, add it to the 'allowed' list.",
            lookup.package
        ),
        suggestion: None,
        registry_url: None,
        source: None,
    })
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

    if !is_new_package && !is_low_downloads && !has_low_downloads && !has_similarity {
        return None;
    }

    let mut reasons = Vec::new();
    if is_new_package
        && let Some(ref date) = meta.created
            && let Some(age_hours) = age_in_hours(date) {
                let age_days = age_hours / 24;
                reasons.push(format!("was published {} days ago", age_days));
            }
    if let Some(downloads) = meta.downloads
        && downloads < 1000 {
            reasons.push(format!("with {} downloads", downloads));
        }
    if has_similarity {
        reasons.push("was flagged for name similarity to a popular package".to_string());
    }
    let reason_str = reasons.join(" and ");

    Some(Issue {
        package: lookup.package.clone(),
        check: "metadata/install-script-risk".to_string(),
        severity: Severity::Error,
        message: format!(
            "'{}' has install scripts AND {}. Install scripts on new, low-download packages are the #1 malware delivery vector.",
            lookup.package, reason_str
        ),
        fix: "Do not install this package. Verify it is legitimate before proceeding."
            .to_string(),
        suggestion: None,
        registry_url: None,
        source: None,
    })
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
    Some(Issue {
        package: lookup.package.clone(),
        check: "metadata/dependency-explosion".to_string(),
        severity: Severity::Error,
        message: format!(
            "'{}' added {} new dependencies in its latest version (was {}, now {}). Sudden dependency additions in patch versions are a known supply chain attack vector.",
            lookup.package, added, previous, current
        ),
        fix: "Review the new dependencies manually before installing.".to_string(),
        suggestion: None,
        registry_url: None,
        source: None,
    })
}

/// Publisher changed between versions.
pub(crate) fn check_maintainer_change(
    lookup: &MetadataLookup,
    meta: &PackageMetadata,
) -> Option<Issue> {
    if lookup.unresolved_version {
        return None;
    }
    let (current_pub, previous_pub) =
        match (&meta.current_publisher, &meta.previous_publisher) {
            (Some(c), Some(p)) => (c, p),
            _ => return None,
        };
    if current_pub == previous_pub {
        return None;
    }

    Some(Issue {
        package: lookup.package.clone(),
        check: "metadata/maintainer-change".to_string(),
        severity: Severity::Error,
        message: format!(
            "The publisher of '{}' changed from '{}' to '{}' between versions. Maintainer takeovers are a known supply chain attack vector.",
            lookup.package, previous_pub, current_pub
        ),
        fix: "Verify the maintainer change is legitimate before installing.".to_string(),
        suggestion: None,
        registry_url: None,
        source: None,
    })
}

/// Package exists but metadata couldn't be parsed.
pub(crate) fn check_parse_failed(lookup: &MetadataLookup) -> Option<Issue> {
    if lookup.metadata.is_some() || !lookup.exists {
        return None;
    }

    Some(Issue {
        package: lookup.package.clone(),
        check: "metadata/parse-failed".to_string(),
        severity: Severity::Warning,
        message: format!(
            "'{}' exists on the {} registry but its metadata could not be parsed. \
             Metadata-based checks (version age, install scripts, etc.) are skipped for this package.",
            lookup.package, lookup.ecosystem
        ),
        fix: format!(
            "This may be a transient registry issue. Retry later. If it persists, check '{}' manually.",
            lookup.package
        ),
        suggestion: None,
        registry_url: None,
        source: None,
    })
}
