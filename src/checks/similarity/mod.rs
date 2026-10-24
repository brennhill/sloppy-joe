mod confusables;
pub mod generators;
mod popular;

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

const SIMILARITY_CACHE_TTL_SECS: u64 = 7 * 24 * 3600; // 7 days

/// On-disk similarity existence cache.
///
/// Each entry carries its own `checked_at` so that rewriting the file with new
/// results never renews the lifetime of older entries (a stale negative entry
/// would otherwise hide a typosquat target registered after the first scan).
/// The file-level `timestamp` records the last write.
#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
struct SimilarityCache {
    timestamp: u64,
    entries: HashMap<String, SimilarityCacheEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
enum SimilarityCacheEntry {
    Timed {
        exists: bool,
        checked_at: u64,
    },
    /// Pre-per-entry format: a bare bool aged by the file timestamp.
    Legacy(bool),
}

impl SimilarityCache {
    /// Normalize legacy entries to the file timestamp and drop every entry
    /// older than the TTL (or dated in the future).
    fn normalize_and_expire(mut self, now: u64, ttl_secs: u64) -> Self {
        let file_ts = self.timestamp;
        self.entries = self
            .entries
            .into_iter()
            .filter_map(|(name, entry)| {
                let (exists, checked_at) = match entry {
                    SimilarityCacheEntry::Timed { exists, checked_at } => (exists, checked_at),
                    SimilarityCacheEntry::Legacy(exists) => (exists, file_ts),
                };
                let age = now.checked_sub(checked_at)?;
                (age < ttl_secs)
                    .then_some((name, SimilarityCacheEntry::Timed { exists, checked_at }))
            })
            .collect();
        self
    }

    fn get(&self, name: &str) -> Option<bool> {
        self.entries.get(name).map(|entry| match *entry {
            SimilarityCacheEntry::Timed { exists, .. } | SimilarityCacheEntry::Legacy(exists) => {
                exists
            }
        })
    }
}

pub(crate) struct SimilarityRunOptions<'a> {
    pub cache_dir: Option<&'a Path>,
    pub no_cache: bool,
    pub paranoid: bool,
    pub dep_metadata: Option<&'a [crate::checks::metadata::MetadataLookup]>,
    pub config: &'a crate::config::SloppyJoeConfig,
}

fn cache_path_for(ecosystem: Ecosystem, cache_dir: Option<&Path>) -> PathBuf {
    let base = cache_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| cache::user_cache_dir().join("sloppy-joe"));
    base.join(format!("similarity-{}.json", ecosystem))
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

/// Format a human-readable message for a match, given the generator name (from tagged mutations).
/// Replaces the old `classify_match` which re-ran all generators to determine the match type.
fn format_match_message(dep_name: &str, candidate: &str, generator: &str) -> String {
    match generator {
        "homoglyph" => format!(
            "'{}' contains non-Latin characters that look identical to letters in '{}'. \
             This is a homoglyph attack -- the package name uses lookalike Unicode characters \
             to impersonate a legitimate package. \
             Examine both packages and add the intended one to your allowed list.",
            dep_name, candidate
        ),
        "separator-swap" => format!(
            "'{}' matches '{}' after normalizing separators (-, _, .). \
             These may resolve to different packages. \
             Examine both packages and add the intended one to your allowed list.",
            dep_name, candidate
        ),
        "collapse-repeated" => format!(
            "'{}' matches '{}' after removing a repeated character. \
             This is a common typosquatting pattern. \
             Examine both packages and add the intended one to your allowed list.",
            dep_name, candidate
        ),
        "version-suffix" => format!(
            "'{}' looks like '{}' with a version suffix appended. \
             An attacker could register the suffixed variant as a separate package. \
             Examine both packages and add the intended one to your allowed list.",
            dep_name, candidate
        ),
        "word-reorder" => format!(
            "'{}' is a reordering of '{}'. Word-swapped package names are a known \
             typosquatting vector. \
             Examine both packages and add the intended one to your allowed list.",
            dep_name, candidate
        ),
        "char-swap" => format!(
            "'{}' matches '{}' with two adjacent characters swapped. \
             This is a common typo and a known typosquatting pattern. \
             Examine both packages and add the intended one to your allowed list.",
            dep_name, candidate
        ),
        "extra-char" => format!(
            "'{}' matches '{}' with one character removed. \
             An extra character may have been added -- this is a common typosquatting pattern. \
             Examine both packages and add the intended one to your allowed list.",
            dep_name, candidate
        ),
        "confused-forms" => format!(
            "'{}' is a confused form of '{}'. These are commonly interchanged but \
             resolve to different packages. \
             Examine both packages and add the intended one to your allowed list.",
            dep_name, candidate
        ),
        "bitflip" => format!(
            "'{}' matches '{}' with a single-bit character change. \
             Bitflip attacks exploit hardware errors or deliberate bit manipulation \
             to produce names that differ by exactly one bit in a character. \
             Examine both packages and add the intended one to your allowed list.",
            dep_name, candidate
        ),
        "segment-overlap" => format!(
            "'{}' is a known popular package '{}' with extra segments added. \
             An attacker could register an extended name to impersonate the real package. \
             Examine both packages and add the intended one to your allowed list.",
            dep_name, candidate
        ),
        "keyboard-proximity" => format!(
            "'{}' matches '{}' with a keyboard-adjacent character substitution. \
             An attacker could register a name where one key is replaced by its \
             neighbor on a QWERTY keyboard. \
             Examine both packages and add the intended one to your allowed list.",
            dep_name, candidate
        ),
        _ => format!(
            "'{}' is suspiciously similar to '{}'. \
             Examine both packages and add the intended one to your allowed list.",
            dep_name, candidate
        ),
    }
}

fn is_suppressed(
    config: &crate::config::SloppyJoeConfig,
    ecosystem: Ecosystem,
    package: &str,
    candidate: &str,
    generator: &str,
) -> bool {
    config.is_similarity_exception(ecosystem.as_str(), package, candidate, generator)
}

/// Longest package name that is expanded into lookalike variants (npm's own limit is 214).
const MAX_SIMILARITY_NAME_CHARS: usize = 214;

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

pub(crate) async fn check_similarity_with_options(
    registry: &dyn Registry,
    deps: &[Dependency],
    ecosystem: Ecosystem,
    options: SimilarityRunOptions<'_>,
) -> Result<Vec<Issue>> {
    for dep in deps {
        if !ecosystem.supports_package_name_length(dep.package_name()) {
            anyhow::bail!(
                "Scan not supported: oversized package name for {}",
                ecosystem
            );
        }
    }
    let SimilarityRunOptions {
        cache_dir,
        no_cache,
        paranoid,
        dep_metadata,
        config,
    } = options;
    let case_insensitive = is_case_insensitive(ecosystem);
    let mut issues = Vec::new();
    let mut flagged: HashSet<String> = HashSet::new();
    // Every name is expanded into thousands of registry probes, so absurdly long names
    // would multiply requests. Skipping them silently would be a gap, so they block.
    for dep in deps {
        if dep.package_name().chars().count() > MAX_SIMILARITY_NAME_CHARS
            && flagged.insert(dep.package_name().to_string())
        {
            issues.push(
                Issue::new(
                    dep.package_name().chars().take(64).collect::<String>() + "...",
                    crate::names::SIMILARITY_NAME_TOO_LONG,
                    Severity::Error,
                )
                .message(format!(
                    "Package name is longer than {MAX_SIMILARITY_NAME_CHARS} characters, so its lookalike variants cannot be checked without an unbounded number of registry requests."
                ))
                .fix("Verify the dependency manually and replace it with a package that has a conventional name."),
            );
        }
    }

    // Build a set of all dep names for intra-manifest comparison
    let dep_names: HashSet<String> = deps
        .iter()
        .map(|d| d.package_name().to_lowercase())
        .collect();

    // ---- Phase 0: Scope squatting (no registry needed) ----
    let configured_scopes = config.trusted_scopes(ecosystem.as_str());
    for dep in deps {
        if let Some(scope) = extract_scope(dep.package_name(), ecosystem) {
            let scope_lower = scope.to_lowercase();
            let all_known = || {
                known_scopes(ecosystem)
                    .iter()
                    .copied()
                    .chain(configured_scopes.iter().map(String::as_str))
            };
            // Exact match to any known scope is safe -- check the whole list
            // first, since a real scope (e.g. @auth0) can be a near-match of
            // another real scope listed earlier (@auth).
            if all_known().any(|known| known.to_lowercase() == scope_lower) {
                continue;
            }
            for known in all_known() {
                let known_lower = known.to_lowercase();
                let distance = strsim::levenshtein(&scope_lower, &known_lower);
                let threshold = max_distance(scope_lower.len());
                if distance > 0 && distance <= threshold {
                    let candidate = dep.package_name().replace(&scope, known);
                    if is_suppressed(
                        config,
                        ecosystem,
                        dep.package_name(),
                        &candidate,
                        "scope-squatting",
                    ) {
                        continue;
                    }
                    if flagged.insert(dep.package_name().to_string()) {
                        issues.push(make_issue(
                            dep.package_name(),
                            &candidate,
                            "scope-squatting",
                            &format!(
                                "Scope '{}' is {} character{} away from the known scope '{}'.\n      \
                                 Scope squatting is a known supply chain attack vector.",
                                scope,
                                distance,
                                if distance == 1 { "" } else { "s" },
                                known
                            ),
                            &format!("If you meant '{}', fix the scope in your manifest.", candidate),
                        ));
                    }
                    break;
                }
            }
        }
    }

    // ---- Pre-compute tagged mutations once for Phase 1 + Phase 2 ----
    let generators = if paranoid {
        generators::paranoid_generators()
    } else {
        generators::default_generators()
    };
    let configured_roots = config.similarity_roots(ecosystem.as_str());
    let mut all_mutations: HashMap<String, HashMap<String, &'static str>> = HashMap::new();
    let dep_downloads = dep_metadata
        .map(|lookups| {
            lookups
                .iter()
                .filter_map(|lookup| {
                    Some((lookup.package.clone(), lookup.metadata.as_ref()?.downloads?))
                })
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();
    for dep in deps {
        if !flagged.contains(dep.package_name()) {
            let mut mutations = generate_mutations_with(&generators, dep.package_name(), ecosystem);
            for candidate in generators::segment_overlap_variants_with_additional_roots(
                dep.package_name(),
                ecosystem,
                &configured_roots,
            ) {
                mutations
                    .entry(candidate)
                    .and_modify(|existing| {
                        if generator_severity("segment-overlap") > generator_severity(existing) {
                            *existing = "segment-overlap";
                        }
                    })
                    .or_insert("segment-overlap");
            }
            if ecosystem == Ecosystem::Cargo {
                let identity = dep.package_name().replace('-', "_");
                mutations.retain(|candidate, _| {
                    !candidate.replace('-', "_").eq_ignore_ascii_case(&identity)
                });
            }
            mutations.retain(|candidate, _| {
                crate::ecosystem::validate_package_name_for_ecosystem(candidate, ecosystem)
            });
            all_mutations.insert(dep.package_name().to_string(), mutations);
        }
    }

    // ---- Phase 1: Intra-manifest comparison (no network) ----
    for dep in deps {
        if flagged.contains(dep.package_name()) {
            continue;
        }
        if let Some(mutations) = all_mutations.get(dep.package_name()) {
            for (mutation, gen_name) in mutations {
                let mutation_lower = mutation.to_lowercase();
                if is_suppressed(
                    config,
                    ecosystem,
                    dep.package_name(),
                    &mutation_lower,
                    gen_name,
                ) {
                    continue;
                }
                if dep_names.contains(&mutation_lower)
                    && mutation_lower != dep.package_name().to_lowercase()
                {
                    if flagged.insert(dep.package_name().to_string()) {
                        let message =
                            format_match_message(dep.package_name(), &mutation_lower, gen_name);
                        issues.push(make_issue(
                            dep.package_name(),
                            &mutation_lower,
                            gen_name,
                            &format!(
                                "{} Both '{}' and '{}' are in your manifest.",
                                message,
                                dep.package_name(),
                                mutation_lower
                            ),
                            "Examine both packages and add the intended one to your allowed list.",
                        ));
                    }
                    break;
                }
            }
        }
    }

    // ---- Phase 2: Batch-query registry for non-flagged deps ----
    let mut queries: Vec<(String, String)> = Vec::new();
    for dep in deps {
        if flagged.contains(dep.package_name()) {
            continue;
        }
        if let Some(mutations) = all_mutations.get(dep.package_name()) {
            for mutation in mutations.keys() {
                queries.push((dep.package_name().to_string(), mutation.clone()));
            }
        }
    }

    // Load disk cache (7-day TTL) using shared cache utilities (symlink protection, atomic writes)
    let cp = cache_path_for(ecosystem, cache_dir);
    let mut cache = if no_cache {
        SimilarityCache::default()
    } else {
        cache::read_json_cache(&cp, SIMILARITY_CACHE_TTL_SECS, |c: &SimilarityCache| {
            c.timestamp
        })
        .map(|c| c.normalize_and_expire(cache::now_epoch(), SIMILARITY_CACHE_TTL_SECS))
        .unwrap_or_default()
    };

    // Split queries into cached and uncached
    let mut cached_matches: Vec<(String, String)> = Vec::new();
    let mut uncached: Vec<(String, String)> = Vec::new();
    for (dep_name, candidate) in queries {
        if let Some(exists) = cache.get(&candidate) {
            if exists {
                cached_matches.push((dep_name, candidate));
            }
        } else {
            uncached.push((dep_name, candidate));
        }
    }

    // Batch-query registry for uncached candidates only
    let concurrency = ecosystem.similarity_concurrency();
    let fresh_results: Vec<(String, String, std::result::Result<bool, anyhow::Error>)> =
        stream::iter(uncached)
            .map(|(dep_name, candidate)| async move {
                let result = registry.exists(&candidate).await;
                (dep_name, candidate, result)
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;

    // Track registry errors and fail closed above threshold
    let total_queries = fresh_results.len();
    let mut error_count = 0usize;

    // Update cache with fresh results (only cache successes)
    let checked_at = cache::now_epoch();
    for (_, candidate, result) in &fresh_results {
        match result {
            Ok(exists) => {
                cache.entries.insert(
                    candidate.clone(),
                    SimilarityCacheEntry::Timed {
                        exists: *exists,
                        checked_at,
                    },
                );
            }
            Err(_) => {
                error_count += 1;
            }
        }
    }
    if !no_cache && !fresh_results.is_empty() {
        cache.timestamp = cache::now_epoch();
        cache::atomic_write_json(&cp, &cache);
    }

    // Emit blocking error if registry is unreachable (fail closed)
    if crate::checks::has_query_errors(error_count) {
        let error_rate = error_count as f64 / total_queries.max(1) as f64;
        issues.push(
            Issue::new(
                "<registry>",
                crate::names::SIMILARITY_REGISTRY_UNREACHABLE,
                Severity::Error,
            )
            .message(format!(
                "Registry queries failed for {} of {} similarity checks ({:.0}%). \
                     Similarity detection is unreliable. Fix network connectivity or retry.",
                error_count,
                total_queries,
                error_rate * 100.0
            ))
            .fix("Ensure the registry is reachable. Use --no-cache to bypass stale cache data."),
        );
        return Ok(issues);
    }

    // Collect matches from cached + fresh results
    let mut matches: HashMap<String, Vec<String>> = HashMap::new();
    for (dep_name, candidate) in cached_matches {
        matches.entry(dep_name).or_default().push(candidate);
    }
    for (dep_name, candidate, result) in fresh_results {
        if matches!(result, Ok(true)) {
            matches.entry(dep_name).or_default().push(candidate);
        }
    }

    // ---- Phase 3: Fetch metadata for matches concurrently, build issues ----
    // For each dep with matches, pick the highest-severity match (deterministic).
    let metadata_queries: Vec<(String, String)> = deps
        .iter()
        .filter(|dep| !flagged.contains(dep.package_name()))
        .filter_map(|dep| {
            let dep_matches = matches.get(dep.package_name())?;
            let dep_mutations = all_mutations.get(dep.package_name())?;
            // Pick the candidate with the highest generator severity
            let best = dep_matches
                .iter()
                .filter(|candidate| {
                    let generator = dep_mutations
                        .get(candidate.as_str())
                        .copied()
                        .unwrap_or("mutation-match");
                    !is_suppressed(config, ecosystem, dep.package_name(), candidate, generator)
                })
                .max_by_key(|c| {
                    dep_mutations
                        .get(c.as_str())
                        .map(|g| generator_severity(g))
                        .unwrap_or(0)
                })?;
            Some((dep.package_name().to_string(), best.clone()))
        })
        .collect();

    // Fetch metadata concurrently
    let metadata_results: Vec<(String, String, Option<crate::registry::PackageMetadata>)> =
        stream::iter(metadata_queries)
            .map(|(dep_name, candidate)| async move {
                let meta = registry.metadata(&candidate, None).await.ok().flatten();
                (dep_name, candidate, meta)
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;

    for (dep_name, candidate, metadata) in metadata_results {
        if flagged.insert(dep_name.clone()) {
            // Look up the generator name from tagged mutations (deterministic classification)
            let gen_name = all_mutations
                .get(&dep_name)
                .and_then(|m| m.get(candidate.as_str()).copied())
                .unwrap_or("mutation-match");
            let mut message = format_match_message(&dep_name, &candidate, gen_name);

            if let Some(ref meta) = metadata {
                let mut evidence_parts = Vec::new();
                if let Some(downloads) = meta.downloads {
                    evidence_parts.push(format!("{} has {} downloads", candidate, downloads));
                }
                if let Some(ref created) = meta.created {
                    evidence_parts.push(format!("was first published {}", created));
                }

                if let Some(note) = download_disparity_note(
                    &dep_name,
                    dep_downloads.get(&dep_name).copied(),
                    &candidate,
                    meta.downloads,
                ) {
                    evidence_parts.push(note);
                }

                if !evidence_parts.is_empty() {
                    message = format!("{} ({})", message, evidence_parts.join("; "));
                }
            }

            issues.push(make_issue(
                &dep_name,
                &candidate,
                gen_name,
                &message,
                "Examine both packages and add the intended one to your allowed list.",
            ));
        }
    }

    // ---- Case variant check for case-sensitive registries ----
    if !case_insensitive {
        let mut case_variant_queries = 0usize;
        let mut case_variant_errors = 0usize;
        for dep in deps {
            if flagged.contains(dep.package_name()) {
                continue;
            }
            // On case-sensitive registries, check if the lowercased name exists on registry
            let dep_lower = dep.package_name().to_lowercase();
            if dep_lower != dep.package_name() {
                case_variant_queries += 1;
                let exists = match registry.exists(&dep_lower).await {
                    Ok(v) => v,
                    Err(_) => {
                        case_variant_errors += 1;
                        continue;
                    }
                };
                if is_suppressed(
                    config,
                    ecosystem,
                    dep.package_name(),
                    &dep_lower,
                    "case-variant",
                ) {
                    continue;
                }
                if exists && flagged.insert(dep.package_name().to_string()) {
                    issues.push(make_issue(
                        dep.package_name(),
                        &dep_lower,
                        "case-variant",
                        &format!(
                            "'{}' differs from '{}' only in letter casing. \
                             On case-sensitive registries ({}) these resolve to different packages. \
                             An attacker could register the case variant.",
                            dep.package_name(),
                            dep_lower,
                            ecosystem
                        ),
                        &format!(
                            "Use the exact casing '{}' in your manifest.",
                            dep_lower
                        ),
                    ));
                }
            }
        }
        if crate::checks::has_query_errors(case_variant_errors) {
            let error_rate = case_variant_errors as f64 / case_variant_queries.max(1) as f64;
            issues.push(
                Issue::new(
                    "<registry>",
                    crate::names::SIMILARITY_REGISTRY_UNREACHABLE,
                    Severity::Error,
                )
                .message(format!(
                    "Registry queries failed for {} of {} similarity checks ({:.0}%). \
                     Similarity detection is unreliable. Fix network connectivity or retry.",
                    case_variant_errors,
                    case_variant_queries,
                    error_rate * 100.0
                ))
                .fix(
                    "Ensure the registry is reachable. Use --no-cache to bypass stale cache data.",
                ),
            );
        }
    }

    Ok(issues)
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
