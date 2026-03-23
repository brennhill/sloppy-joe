pub mod canonical;
pub mod existence;
pub mod malicious;
pub mod metadata;
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

/// Context passed to each check. Contains everything a check needs
/// to do its job without reaching into global state.
pub struct CheckContext<'a> {
    /// Dependencies to check (checkable or non-internal depending on check)
    pub deps: &'a [Dependency],
    pub config: &'a SloppyJoeConfig,
    pub registry: &'a dyn Registry,
    pub resolution: &'a ResolutionResult,
    pub error_budget: &'a ErrorBudget,
    pub ecosystem: &'a str,
    pub opts: &'a ScanOptions<'a>,
    /// Packages flagged by similarity (used by metadata for signal amplification)
    pub similarity_flagged: &'a HashSet<String>,
}

/// A composable check that produces issues from a context.
/// New checks can be added by implementing this trait.
#[async_trait]
pub trait Check: Send + Sync {
    fn name(&self) -> &str;
    async fn run(&self, ctx: &CheckContext<'_>) -> Result<Vec<Issue>>;
}
