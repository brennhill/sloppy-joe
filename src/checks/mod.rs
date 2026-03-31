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

/// Check if any query error occurred.
/// Returns true if the check should emit a fail-closed blocking issue.
pub(crate) fn exceeds_error_threshold(
    error_count: usize,
    _total_queries: usize,
    _ecosystem: Ecosystem,
) -> bool {
    error_count > 0
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
        // Any error now triggers fail-closed immediately.
        assert!(exceeds_error_threshold(6, 1000, Ecosystem::Npm));
        assert!(exceeds_error_threshold(6, 6, Ecosystem::Npm));
    }

    #[test]
    fn any_error_triggers_fail_closed_even_for_small_samples() {
        assert!(exceeds_error_threshold(1, 1, Ecosystem::Npm));
        assert!(exceeds_error_threshold(2, 2, Ecosystem::Npm));
        assert!(exceeds_error_threshold(1, 1, Ecosystem::Go));
    }

    #[test]
    fn go_has_higher_rate_threshold() {
        assert!(exceeds_error_threshold(2, 10, Ecosystem::Npm));
        assert!(exceeds_error_threshold(2, 10, Ecosystem::Go));
        assert!(exceeds_error_threshold(3, 10, Ecosystem::Go));
    }

    #[test]
    fn go_has_higher_hard_limit() {
        assert!(exceeds_error_threshold(6, 100, Ecosystem::Npm));
        assert!(exceeds_error_threshold(6, 100, Ecosystem::Go));
        assert!(exceeds_error_threshold(11, 100, Ecosystem::Go));
    }

    // ── Edge cases for exceeds_error_threshold (lines 63-64) ──

    #[test]
    fn exactly_at_previous_hard_limit_still_triggers() {
        assert!(exceeds_error_threshold(5, 100, Ecosystem::Npm));
        assert!(exceeds_error_threshold(10, 100, Ecosystem::Go));
    }

    #[test]
    fn one_above_hard_limit_triggers() {
        assert!(exceeds_error_threshold(6, 100, Ecosystem::Npm));
        assert!(exceeds_error_threshold(11, 100, Ecosystem::Go));
    }

    #[test]
    fn rate_exactly_at_previous_threshold_still_triggers() {
        assert!(exceeds_error_threshold(1, 10, Ecosystem::Npm));
    }

    #[test]
    fn rate_just_above_threshold_triggers() {
        assert!(exceeds_error_threshold(2, 10, Ecosystem::Npm));
    }

    #[test]
    fn jvm_rate_threshold() {
        assert!(exceeds_error_threshold(2, 10, Ecosystem::Jvm));
        assert!(exceeds_error_threshold(3, 10, Ecosystem::Jvm));
    }

    #[test]
    fn single_error_below_min_queries_still_triggers() {
        assert!(exceeds_error_threshold(1, 4, Ecosystem::Npm));
    }

    #[test]
    fn accumulator_default_is_empty() {
        let acc = ScanAccumulator::default();
        assert!(acc.issues.is_empty());
        assert!(acc.similarity_flagged.is_empty());
        assert!(acc.metadata_lookups.is_none());
    }
}
