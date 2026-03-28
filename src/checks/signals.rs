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
