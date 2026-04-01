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
pub(crate) fn has_query_errors(error_count: usize) -> bool {
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
    fn no_errors_do_not_trigger_fail_closed() {
        assert!(!has_query_errors(0));
    }

    #[test]
    fn any_error_triggers_fail_closed() {
        assert!(has_query_errors(1));
        assert!(has_query_errors(6));
    }

    #[test]
    fn multiple_errors_still_trigger_fail_closed() {
        assert!(has_query_errors(2));
        assert!(has_query_errors(10));
    }

    #[test]
    fn accumulator_default_is_empty() {
        let acc = ScanAccumulator::default();
        assert!(acc.issues.is_empty());
        assert!(acc.similarity_flagged.is_empty());
        assert!(acc.metadata_lookups.is_none());
    }
}
