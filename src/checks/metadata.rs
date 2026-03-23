use crate::Dependency;
use crate::Ecosystem;
use crate::config::SloppyJoeConfig;
use crate::lockfiles::ResolutionResult;
use crate::registry::{PackageMetadata, Registry};
use crate::report::Issue;
use anyhow::Result;
use futures::stream::{self, StreamExt, TryStreamExt};
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
) -> Result<Vec<MetadataLookup>> {
    // Pre-compute per-dep data to avoid borrowing deps inside the async stream.
    // stream::iter(&[T]).map(|item| async { ... }) requires higher-ranked lifetimes
    // that Rust can't prove when the items are references and the future captures them.
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
    stream::iter(prepared)
        .map(|(package, ecosystem, version, exact_version, unresolved_version)| {
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

        issues.extend(signals::check_install_script_risk(
            lookup,
            meta,
            is_new_package.is_some(),
            is_low_downloads.is_some(),
            similarity_flagged,
        ));
        issues.extend(signals::check_dependency_explosion(lookup, meta));
        issues.extend(signals::check_maintainer_change(lookup, meta));
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
#[path = "metadata_tests.rs"]
mod tests;

