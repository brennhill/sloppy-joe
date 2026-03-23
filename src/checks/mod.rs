pub mod canonical;
pub mod existence;
pub mod malicious;
pub mod metadata;
pub mod names;
pub mod pipeline;
pub(crate) mod signals;
pub mod similarity;

use crate::config::SloppyJoeConfig;
use crate::lockfiles::ResolutionResult;
use crate::registry::Registry;
use crate::report::Issue;
use crate::{Dependency, Ecosystem, ScanOptions};
use anyhow::Result;
use std::collections::HashSet;

/// Immutable context shared by all checks in the pipeline.
pub struct CheckContext<'a> {
    /// Dependencies subject to full checks (not internal, not allowed).
    /// Used by similarity and existence checks.
    pub checkable_deps: &'a [Dependency],
    /// All non-internal dependencies (allowed + checkable).
    /// Used by canonical, metadata, and malicious checks.
    pub non_internal_deps: &'a [Dependency],
    /// User-provided configuration (canonical mappings, internal/allowed lists, thresholds).
    pub config: &'a SloppyJoeConfig,
    /// Registry client for existence and metadata queries.
    pub registry: &'a dyn Registry,
    /// OSV client for known-vulnerability lookups.
    pub osv_client: &'a dyn malicious::OsvClient,
    /// Lockfile-resolved versions for all dependencies.
    pub resolution: &'a ResolutionResult,
    /// Ecosystem of the project being scanned (determines registry, mutation rules, etc.).
    pub ecosystem: Ecosystem,
    /// Runtime options (--deep, --no-cache, --cache-dir).
    pub opts: &'a ScanOptions<'a>,
}

/// Mutable accumulator that checks write to and read from.
/// Checks execute in order; later checks can read earlier results.
pub struct ScanAccumulator {
    pub issues: Vec<Issue>,
    /// Packages flagged by similarity — written by SimilarityCheck,
    /// read by MetadataCheck for signal amplification.
    pub similarity_flagged: HashSet<String>,
    /// Metadata lookups — written by MetadataCheck,
    /// read by ExistenceCheck for existence-from-metadata.
    pub metadata_lookups: Option<Vec<metadata::MetadataLookup>>,
}

impl ScanAccumulator {
    pub fn new() -> Self {
        Self {
            issues: Vec::new(),
            similarity_flagged: HashSet::new(),
            metadata_lookups: None,
        }
    }
}

impl Default for ScanAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimum number of queries before the error rate threshold applies.
/// Below this, only the hard error count limit triggers fail-closed.
/// This prevents 2/2 failures from triggering "registry unreachable"
/// when most queries were served from cache.
const MIN_QUERIES_FOR_RATE: usize = 5;

/// Check if error count/rate exceeds ecosystem-aware thresholds.
/// Returns true if the check should emit a fail-closed blocking issue.
pub(crate) fn exceeds_error_threshold(
    error_count: usize,
    total_queries: usize,
    ecosystem: Ecosystem,
) -> bool {
    if error_count == 0 {
        return false;
    }
    // Hard limit: always applies regardless of sample size
    if error_count > ecosystem.error_hard_limit() {
        return true;
    }
    // Rate limit: only applies with enough queries to be meaningful
    if total_queries >= MIN_QUERIES_FOR_RATE {
        let error_rate = error_count as f64 / total_queries as f64;
        if error_rate > ecosystem.error_rate_threshold() {
            return true;
        }
    }
    false
}

/// A composable check. Checks execute in pipeline order and can read/write
/// the accumulator. New checks are added by implementing this trait and
/// appending to the pipeline vector.
///
/// Uses explicit lifetime instead of async_trait to avoid lifetime erasure
/// issues with stream::iter + buffer_unordered patterns inside check impls.
pub trait Check: Send + Sync {
    fn name(&self) -> &str;
    fn run<'a>(
        &'a self,
        ctx: &'a CheckContext<'a>,
        acc: &'a mut ScanAccumulator,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_errors_never_exceeds() {
        assert!(!exceeds_error_threshold(0, 100, Ecosystem::Npm));
        assert!(!exceeds_error_threshold(0, 0, Ecosystem::Npm));
    }

    #[test]
    fn hard_limit_always_triggers() {
        // 6 errors > 5 hard limit for npm, regardless of total
        assert!(exceeds_error_threshold(6, 1000, Ecosystem::Npm));
        // Even with few total queries
        assert!(exceeds_error_threshold(6, 6, Ecosystem::Npm));
    }

    #[test]
    fn rate_needs_minimum_queries() {
        // 2/2 = 100% but below MIN_QUERIES_FOR_RATE (5), so no trigger
        assert!(!exceeds_error_threshold(2, 2, Ecosystem::Npm));
        // 3/3 = 100% still below minimum
        assert!(!exceeds_error_threshold(3, 3, Ecosystem::Npm));
        // 4/5 = 80% with exactly 5 queries — triggers (above 10%)
        assert!(exceeds_error_threshold(4, 5, Ecosystem::Npm));
    }

    #[test]
    fn go_has_higher_rate_threshold() {
        // 2/10 = 20% — exceeds npm (10%) but not Go (25%)
        assert!(exceeds_error_threshold(2, 10, Ecosystem::Npm));
        assert!(!exceeds_error_threshold(2, 10, Ecosystem::Go));
        // 3/10 = 30% — exceeds Go (25%)
        assert!(exceeds_error_threshold(3, 10, Ecosystem::Go));
    }

    #[test]
    fn go_has_higher_hard_limit() {
        // 6 errors — exceeds npm (5) but not Go (10)
        assert!(exceeds_error_threshold(6, 100, Ecosystem::Npm));
        assert!(!exceeds_error_threshold(6, 100, Ecosystem::Go));
        // 11 errors — exceeds Go (10)
        assert!(exceeds_error_threshold(11, 100, Ecosystem::Go));
    }
}
