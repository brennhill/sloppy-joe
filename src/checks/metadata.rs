use crate::Dependency;
use crate::Ecosystem;
use crate::config::SloppyJoeConfig;
use crate::lockfiles::ResolutionResult;
use crate::registry::{PackageMetadata, Registry};
use crate::report::{Issue, Severity};
use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::collections::HashSet;

/// Parse an ISO 8601 date string and return the age in hours.
pub(crate) fn age_in_hours(date_str: &str) -> Option<u64> {
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
    // Guard against malformed dates that would cause loops in rough_epoch
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || year < 1970 {
        return None;
    }
    let hour: i64 = time_parts[0].parse().ok()?;
    let min: i64 = time_parts[1].split('.').next()?.parse().ok()?;
    let sec: i64 = time_parts
        .get(2)
        .and_then(|s| s.split('.').next()?.parse().ok())
        .unwrap_or(0);

    let pkg_epoch = crate::cache::date_to_epoch(year, month, day, hour, min, sec);
    let now = crate::cache::now_epoch() as i64;

    let diff_seconds = now - pkg_epoch;
    if diff_seconds < 0 {
        return Some(0);
    }
    Some((diff_seconds / 3600) as u64)
}

#[derive(Debug, Clone)]
pub struct MetadataLookup {
    pub package: String,
    pub ecosystem: Ecosystem,
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
) -> (Vec<MetadataLookup>, Vec<Issue>) {
    // Pre-compute per-dep data to avoid borrowing deps inside the async stream.
    let prepared: Vec<_> = deps
        .iter()
        .map(|dep| {
            (
                dep.name.clone(),
                dep.ecosystem,
                dep.version.clone(),
                resolution.exact_version(dep).map(str::to_string),
                resolution.is_unresolved(dep),
            )
        })
        .collect();

    let results: Vec<_> = stream::iter(prepared)
        .map(
            |(package, ecosystem, version, exact_version, unresolved_version)| async move {
                let result: std::result::Result<MetadataLookup, anyhow::Error> = async {
                    let metadata = registry
                        .metadata(&package, exact_version.as_deref())
                        .await?;
                    let exists = if metadata.is_some() {
                        true
                    } else {
                        registry.exists(&package).await?
                    };
                    Ok(MetadataLookup {
                        package: package.clone(),
                        ecosystem,
                        version,
                        resolved_version: exact_version,
                        unresolved_version,
                        exists,
                        metadata,
                    })
                }
                .await;
                (package, result)
            },
        )
        .buffer_unordered(10)
        .collect()
        .await;

    let total_queries = results.len();
    let mut error_count = 0usize;
    let mut lookups = Vec::new();
    let mut issues = Vec::new();

    for (_package, result) in results {
        match result {
            Ok(lookup) => lookups.push(lookup),
            Err(_) => {
                error_count += 1;
            }
        }
    }

    let ecosystem = deps
        .first()
        .map(|d| d.ecosystem)
        .unwrap_or(crate::Ecosystem::Npm);
    if super::exceeds_error_threshold(error_count, total_queries, ecosystem) {
        let error_rate = error_count as f64 / total_queries.max(1) as f64;
        issues.push(
            Issue::new(
                "<registry>",
                super::names::METADATA_REGISTRY_UNREACHABLE,
                Severity::Error,
            )
            .message(format!(
                "Registry queries failed for {} of {} metadata checks ({:.0}%). \
                     Metadata detection is unreliable. Fix network connectivity or retry.",
                error_count,
                total_queries,
                error_rate * 100.0
            ))
            .fix("Ensure the registry is reachable and retry the scan."),
        );
    }

    (lookups, issues)
}

pub(crate) fn issues_from_lookups(
    lookups: &[MetadataLookup],
    config: &SloppyJoeConfig,
    similarity_flagged: &HashSet<String>,
) -> Vec<Issue> {
    use super::signals;

    let min_age = config.min_version_age_hours;
    let mut issues = Vec::new();

    for lookup in lookups {
        let Some(meta) = lookup.metadata.as_ref() else {
            issues.extend(signals::check_parse_failed(lookup));
            continue;
        };

        issues.extend(signals::check_version_age(lookup, meta, min_age));

        let is_new_package = signals::check_new_package(lookup, meta);
        let is_low_downloads = signals::check_low_downloads(lookup, meta);

        if let Some(issue) = &is_new_package {
            issues.push(issue.clone());
        }
        if let Some(issue) = &is_low_downloads {
            issues.push(issue.clone());
        }

        let ctx = signals::SignalContext {
            is_new_package: is_new_package.is_some(),
            is_low_downloads: is_low_downloads.is_some(),
            is_similarity_flagged: similarity_flagged.contains(&lookup.package),
        };

        issues.extend(signals::check_install_script_risk(lookup, meta, &ctx));
        issues.extend(signals::check_dependency_explosion(lookup, meta));
        issues.extend(signals::check_maintainer_change(lookup, meta));
        issues.extend(signals::check_publisher_script_combo(lookup, meta));
        issues.extend(signals::check_no_repository(lookup, meta, &ctx));
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
    let (lookups, mut issues) = fetch_metadata(registry, deps, resolution).await;
    issues.extend(issues_from_lookups(&lookups, config, similarity_flagged));
    Ok(issues)
}

#[cfg(test)]
#[path = "metadata_tests.rs"]
mod tests;
