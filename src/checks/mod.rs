pub mod canonical;
pub mod existence;
pub mod malicious;
pub mod metadata;
pub mod pipeline;
pub(crate) mod signals;
pub mod similarity;

use crate::config::SloppyJoeConfig;
use crate::error_budget::ErrorBudget;
use crate::lockfiles::ResolutionResult;
use crate::registry::Registry;
use crate::report::Issue;
use crate::{Dependency, ScanOptions};
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashSet;

/// Immutable context shared by all checks.
pub struct CheckContext<'a> {
    /// Checkable deps (not internal, not allowed) — for similarity/existence
    pub checkable_deps: &'a [Dependency],
    /// Non-internal deps (allowed + checkable) — for canonical/metadata/malicious
    pub non_internal_deps: &'a [Dependency],
    pub config: &'a SloppyJoeConfig,
    pub registry: &'a dyn Registry,
    pub osv_client: &'a dyn malicious::OsvClient,
    pub resolution: &'a ResolutionResult,
    pub error_budget: &'a ErrorBudget,
    pub ecosystem: &'a str,
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
