mod result_cache;
pub(crate) use result_cache::*;
mod messages;
pub(crate) use messages::*;
mod confusables;
pub mod generators;
mod popular;
mod run;
pub(crate) use run::check_similarity_with_options;

use crate::Dependency;
use crate::Ecosystem;
use crate::cache;
use crate::registry::Registry;
use crate::report::{Issue, Severity};
use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub use generators::{MutationGenerator, default_generators};
use generators::{extract_scope, known_scopes};

pub(crate) struct SimilarityRunOptions<'a> {
    pub cache_dir: Option<&'a Path>,
    pub no_cache: bool,
    pub paranoid: bool,
    pub dep_metadata: Option<&'a [crate::checks::metadata::MetadataLookup]>,
    pub config: &'a crate::config::SloppyJoeConfig,
}

fn is_case_insensitive(ecosystem: Ecosystem) -> bool {
    ecosystem.is_case_insensitive()
}

/// Max allowed Levenshtein distance, scaled by name length (for scope squatting).
fn max_distance(name_len: usize) -> usize {
    match name_len {
        0..=4 => 1,
        5..=8 => 2,
        _ => 3,
    }
}

/// Generator severity ordering (higher = more dangerous, reported first).
fn generator_severity(name: &str) -> u8 {
    match name {
        "homoglyph" => 9,
        "bitflip" => 8,
        "confused-forms" => 7,
        "segment-overlap" => 6,
        "keyboard-proximity" => 5,
        "char-swap" => 4,
        "collapse-repeated" => 3,
        "extra-char" => 2,
        "version-suffix" => 1,
        "word-reorder" => 1,
        "separator-swap" => 0,
        _ => 0,
    }
}

/// Generate all mutation candidates for a package name using default generators.
/// Returns a map of candidate → generator_name, tagged for classification.
#[cfg(test)]
fn generate_mutations(name: &str, ecosystem: Ecosystem) -> HashMap<String, &'static str> {
    generate_mutations_with(&default_generators(), name, ecosystem)
}

/// Generate mutations using a specific set of generators.
/// Returns HashMap<candidate, generator_name>. If multiple generators produce
/// the same candidate, the highest-severity generator wins.
fn generate_mutations_with(
    generators: &[Box<dyn MutationGenerator>],
    name: &str,
    ecosystem: Ecosystem,
) -> HashMap<String, &'static str> {
    let lower = name.to_lowercase();
    let case_insensitive = ecosystem.is_case_insensitive();
    let mut candidates: HashMap<String, &'static str> = HashMap::new();

    for generator in generators {
        let gen_name = generator.name();
        for variant in generator.generate(name, ecosystem) {
            candidates
                .entry(variant)
                .and_modify(|existing| {
                    if generator_severity(gen_name) > generator_severity(existing) {
                        *existing = gen_name;
                    }
                })
                .or_insert(gen_name);
        }
    }

    // On case-insensitive registries, remove candidates that only differ by case
    if case_insensitive {
        candidates.retain(|c, _| c != &lower);
    }

    // Remove the original name itself
    candidates.remove(&lower);
    candidates
}

/// Main entry point. Registry-based similarity checking.
///
/// Phase 0: Scope squatting (no registry)
/// Phase 1: Intra-manifest comparison (no network)
/// Phase 2: Generate mutations, batch-query registry.exists()
/// Phase 3: Fetch metadata for matches, build issues
/// Check similarity with default cache settings.
pub async fn check_similarity(
    registry: &dyn Registry,
    deps: &[Dependency],
    ecosystem: Ecosystem,
) -> Result<Vec<Issue>> {
    let config = crate::config::SloppyJoeConfig::default();
    check_similarity_with_options(
        registry,
        deps,
        ecosystem,
        SimilarityRunOptions {
            cache_dir: None,
            no_cache: false,
            paranoid: false,
            dep_metadata: None,
            config: &config,
        },
    )
    .await
}

pub async fn check_similarity_with_config(
    registry: &dyn Registry,
    deps: &[Dependency],
    ecosystem: Ecosystem,
    config: &crate::config::SloppyJoeConfig,
) -> Result<Vec<Issue>> {
    check_similarity_with_options(
        registry,
        deps,
        ecosystem,
        SimilarityRunOptions {
            cache_dir: None,
            no_cache: false,
            paranoid: false,
            dep_metadata: None,
            config,
        },
    )
    .await
}

/// Check similarity with configurable cache and generator selection.
/// `dep_metadata` provides download counts for the original dependencies,
/// enabling download disparity evidence (see `download_disparity_note`).
pub async fn check_similarity_with_cache(
    registry: &dyn Registry,
    deps: &[Dependency],
    ecosystem: Ecosystem,
    cache_dir: Option<&Path>,
    no_cache: bool,
    paranoid: bool,
    dep_metadata: Option<&[crate::checks::metadata::MetadataLookup]>,
) -> Result<Vec<Issue>> {
    let config = crate::config::SloppyJoeConfig::default();
    check_similarity_with_options(
        registry,
        deps,
        ecosystem,
        SimilarityRunOptions {
            cache_dir,
            no_cache,
            paranoid,
            dep_metadata,
            config: &config,
        },
    )
    .await
}

/// Download counts at or below this are "obscure" for disparity evidence.
const DISPARITY_OBSCURE_MAX: u64 = 1_000;
/// Download counts above this are "popular" for disparity evidence.
const DISPARITY_POPULAR_MIN: u64 = 10_000;

/// Download-disparity evidence for a similarity match, where `dep_name` (from
/// the manifest) is flagged as a possible typosquat of `candidate`.
///
/// - Dependency obscure, candidate popular: classic typosquat shape, so the
///   finding is HIGH CONFIDENCE.
/// - Dependency popular, candidate obscure: evidence *against* the dependency
///   being the squat (the candidate is more likely the imitation). This is
///   noted as LOW CONFIDENCE but the severity is not lowered, because download
///   counts are cheap to inflate and must never clear a finding on their own.
/// - Either count missing, or no large gap: no confidence claim.
pub(crate) fn download_disparity_note(
    dep_name: &str,
    dep_downloads: Option<u64>,
    candidate: &str,
    candidate_downloads: Option<u64>,
) -> Option<String> {
    let (dep_dl, candidate_dl) = (dep_downloads?, candidate_downloads?);
    if dep_dl < DISPARITY_OBSCURE_MAX && candidate_dl > DISPARITY_POPULAR_MIN {
        return Some(format!(
            "HIGH CONFIDENCE: '{}' has {} downloads vs {} for '{}', the far more popular package it resembles",
            dep_name, dep_dl, candidate_dl, candidate
        ));
    }
    if dep_dl > DISPARITY_POPULAR_MIN && candidate_dl < DISPARITY_OBSCURE_MAX {
        return Some(format!(
            "LOW CONFIDENCE: '{}' has {} downloads vs {} for '{}', so '{}' is more likely the lookalike; confirm '{}' is the name you intend (download counts can be inflated)",
            dep_name, dep_dl, candidate_dl, candidate, candidate, dep_name
        ));
    }
    None
}

fn make_issue(package: &str, popular: &str, check_type: &str, message: &str, fix: &str) -> Issue {
    Issue::new(
        package,
        crate::names::similarity_check_name(check_type),
        Severity::Error,
    )
    .message(message)
    .fix(fix)
    .suggestion(popular)
}

#[cfg(test)]
mod hardening_tests;

#[cfg(test)]
mod download_disparity_tests;

#[cfg(test)]
mod tests;
