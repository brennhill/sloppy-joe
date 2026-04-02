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

#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
struct SimilarityCache {
    timestamp: u64,
    entries: HashMap<String, bool>,
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
/// enabling download disparity detection (HIGH CONFIDENCE on large gaps).
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

    // Build a set of all dep names for intra-manifest comparison
    let dep_names: HashSet<String> = deps
        .iter()
        .map(|d| d.package_name().to_lowercase())
        .collect();

    // ---- Phase 0: Scope squatting (no registry needed) ----
    for dep in deps {
        if let Some(scope) = extract_scope(dep.package_name(), ecosystem) {
            let scopes = known_scopes(ecosystem);
            let scope_lower = scope.to_lowercase();
            for &known in scopes {
                let known_lower = known.to_lowercase();
                if scope_lower == known_lower {
                    // Exact match to a known scope -- safe
                    break;
                }
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
    let mut all_mutations: HashMap<String, HashMap<String, &'static str>> = HashMap::new();
    for dep in deps {
        if !flagged.contains(dep.package_name()) {
            all_mutations.insert(
                dep.package_name().to_string(),
                generate_mutations_with(&generators, dep.package_name(), ecosystem),
            );
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
        .unwrap_or_default()
    };

    // Split queries into cached and uncached
    let mut cached_matches: Vec<(String, String)> = Vec::new();
    let mut uncached: Vec<(String, String)> = Vec::new();
    for (dep_name, candidate) in queries {
        if let Some(&exists) = cache.entries.get(&candidate) {
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
    for (_, candidate, result) in &fresh_results {
        match result {
            Ok(exists) => {
                cache.entries.insert(candidate.clone(), *exists);
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
                crate::checks::names::SIMILARITY_REGISTRY_UNREACHABLE,
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

                // Download disparity: if original dep has >10K downloads and
                // candidate has <1000, this is high confidence typosquatting
                if let Some(candidate_downloads) = meta.downloads {
                    let original_downloads = dep_metadata
                        .and_then(|lookups| lookups.iter().find(|l| l.package == dep_name))
                        .and_then(|l| l.metadata.as_ref())
                        .and_then(|m| m.downloads);
                    if let Some(orig_dl) = original_downloads
                        && orig_dl > 10_000
                        && candidate_downloads < 1_000
                    {
                        evidence_parts.push(format!(
                            "HIGH CONFIDENCE: '{}' has {} downloads vs {} for '{}'",
                            dep_name, orig_dl, candidate_downloads, candidate
                        ));
                    }
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
                    crate::checks::names::SIMILARITY_REGISTRY_UNREACHABLE,
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

fn make_issue(package: &str, popular: &str, check_type: &str, message: &str, fix: &str) -> Issue {
    Issue::new(
        package,
        crate::checks::names::similarity_check_name(check_type),
        Severity::Error,
    )
    .message(message)
    .fix(fix)
    .suggestion(popular)
}

#[cfg(test)]
mod tests {
    use super::generators::*;
    use super::*;
    use crate::config::{SimilarityException, SloppyJoeConfig};
    use crate::registry::{PackageMetadata, RegistryExistence, RegistryMetadata};
    use async_trait::async_trait;
    use std::collections::HashMap;

    struct FakeRegistry {
        existing: HashSet<String>,
    }

    impl FakeRegistry {
        fn with(names: &[&str]) -> Self {
            FakeRegistry {
                existing: names.iter().map(|s| s.to_string()).collect(),
            }
        }

        fn empty() -> Self {
            FakeRegistry {
                existing: HashSet::new(),
            }
        }
    }

    #[async_trait]
    impl RegistryExistence for FakeRegistry {
        async fn exists(&self, package_name: &str) -> Result<bool> {
            Ok(self.existing.contains(package_name))
        }

        fn ecosystem(&self) -> &str {
            "npm"
        }
    }

    #[async_trait]
    impl RegistryMetadata for FakeRegistry {
        async fn metadata(
            &self,
            package_name: &str,
            _version: Option<&str>,
        ) -> Result<Option<PackageMetadata>> {
            if self.existing.contains(package_name) {
                Ok(Some(PackageMetadata {
                    created: Some("2020-01-01T00:00:00Z".to_string()),
                    latest_version_date: Some("2020-01-01T00:00:00Z".to_string()),
                    downloads: Some(500), // Low downloads for candidates (enables disparity detection)
                    ..Default::default()
                }))
            } else {
                Ok(None)
            }
        }
    }

    use crate::test_helpers::npm_dep as dep;

    fn dep_eco(name: &str, ecosystem: Ecosystem) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: None,
            ecosystem,
            actual_name: None,
        }
    }

    // -- Repeated chars --

    #[tokio::test]
    async fn repeated_chars_caught() {
        let registry = FakeRegistry::with(&["express"]);
        let deps = vec![dep("expresss")];
        let issues = check_similarity(&registry, &deps, Ecosystem::Npm)
            .await
            .unwrap();
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("repeated"));
        assert_eq!(issues[0].suggestion, Some("express".to_string()));
    }

    // -- Version suffix --

    #[tokio::test]
    async fn version_suffix_caught() {
        let registry = FakeRegistry::with(&["react"]);
        let deps = vec![dep("react2")];
        let issues = check_similarity(&registry, &deps, Ecosystem::Npm)
            .await
            .unwrap();
        assert!(!issues.is_empty());
        assert!(
            issues[0].check.contains("extra-char") || issues[0].check.contains("version-suffix"),
            "Expected extra-char or version-suffix, got: {}",
            issues[0].check
        );
        assert_eq!(issues[0].suggestion, Some("react".to_string()));
    }

    // -- Adjacent swap --

    #[tokio::test]
    async fn adjacent_swap_caught() {
        let registry = FakeRegistry::with(&["requests"]);
        let deps = vec![dep_eco("reqeusts", Ecosystem::PyPI)];
        let issues = check_similarity(&registry, &deps, Ecosystem::PyPI)
            .await
            .unwrap();
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("char-swap"));
        assert_eq!(issues[0].suggestion, Some("requests".to_string()));
    }

    // -- Extra char --

    #[tokio::test]
    async fn extra_char_caught() {
        let registry = FakeRegistry::with(&["express"]);
        let deps = vec![dep("expressx")];
        let issues = check_similarity(&registry, &deps, Ecosystem::Npm)
            .await
            .unwrap();
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("extra-char"));
        assert_eq!(issues[0].suggestion, Some("express".to_string()));
    }

    // -- No match --

    #[tokio::test]
    async fn no_match_produces_no_issue() {
        let registry = FakeRegistry::with(&["react", "express"]);
        let deps = vec![dep("zzzzzzzzzzzzz")];
        let issues = check_similarity(&registry, &deps, Ecosystem::Npm)
            .await
            .unwrap();
        assert!(issues.is_empty());
    }

    // -- Any package catch (registry returns true for mutation) --

    #[tokio::test]
    async fn any_package_catch() {
        let registry = FakeRegistry::with(&["my-lib"]);
        let deps = vec![dep("myy-lib")];
        let issues = check_similarity(&registry, &deps, Ecosystem::Npm)
            .await
            .unwrap();
        assert!(!issues.is_empty());
    }

    // -- Intra-manifest --

    #[tokio::test]
    async fn intra_manifest_flags_both_present() {
        let registry = FakeRegistry::empty();
        let deps = vec![dep("lodash"), dep("lodahs")];
        let issues = check_similarity(&registry, &deps, Ecosystem::Npm)
            .await
            .unwrap();
        assert!(!issues.is_empty());
        assert!(
            issues
                .iter()
                .any(|i| i.package == "lodahs" || i.package == "lodash"),
            "Expected intra-manifest flag"
        );
    }

    #[tokio::test]
    async fn exact_similarity_exception_suppresses_specific_pair_only() {
        let registry = FakeRegistry::empty();
        let deps = vec![
            dep_eco("serde", Ecosystem::Cargo),
            dep_eco("serde_json", Ecosystem::Cargo),
        ];
        let config = SloppyJoeConfig {
            similarity_exceptions: HashMap::from([(
                "cargo".to_string(),
                vec![SimilarityException {
                    package: "serde_json".to_string(),
                    candidate: "serde".to_string(),
                    generator: "segment-overlap".to_string(),
                    reason: Some("legitimate companion crate".to_string()),
                }],
            )]),
            ..Default::default()
        };

        let issues = check_similarity_with_config(&registry, &deps, Ecosystem::Cargo, &config)
            .await
            .unwrap();
        assert!(
            issues.is_empty(),
            "exact similarity exception should suppress the serde_json/serde segment-overlap false positive"
        );
    }

    #[tokio::test]
    async fn exact_similarity_exception_does_not_broadly_allow_package() {
        let registry = FakeRegistry::with(&["serde_json"]);
        let deps = vec![dep_eco("serde_jsom", Ecosystem::Cargo)];
        let config = SloppyJoeConfig {
            similarity_exceptions: HashMap::from([(
                "cargo".to_string(),
                vec![SimilarityException {
                    package: "serde_json".to_string(),
                    candidate: "serde".to_string(),
                    generator: "segment-overlap".to_string(),
                    reason: Some("legitimate companion crate".to_string()),
                }],
            )]),
            ..Default::default()
        };

        let issues = check_similarity_with_config(&registry, &deps, Ecosystem::Cargo, &config)
            .await
            .unwrap();
        assert!(
            issues.iter().any(|issue| issue.package == "serde_jsom"),
            "package-specific exception must not suppress unrelated similarity findings"
        );
    }

    // -- PyPI separator suppression --

    #[tokio::test]
    async fn pypi_separator_suppressed() {
        let registry = FakeRegistry::with(&["python_dateutil"]);
        let deps = vec![dep_eco("python-dateutil", Ecosystem::PyPI)];
        let issues = check_similarity(&registry, &deps, Ecosystem::PyPI)
            .await
            .unwrap();
        let sep_issues: Vec<_> = issues
            .iter()
            .filter(|i| i.check.contains("separator"))
            .collect();
        assert!(
            sep_issues.is_empty(),
            "PyPI should suppress separator-confusion"
        );
    }

    // -- npm separator flagged --

    #[tokio::test]
    async fn npm_separator_flagged() {
        let registry = FakeRegistry::with(&["socket.io"]);
        let deps = vec![dep("socket_io")];
        let issues = check_similarity(&registry, &deps, Ecosystem::Npm)
            .await
            .unwrap();
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("separator"));
    }

    // -- Scope squatting --

    #[tokio::test]
    async fn scope_squatting_flagged() {
        let registry = FakeRegistry::empty();
        let deps = vec![dep("@typos/lodash")];
        let issues = check_similarity(&registry, &deps, Ecosystem::Npm)
            .await
            .unwrap();
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("scope-squatting"));
        assert!(issues[0].message.contains("@typos"));
        assert!(issues[0].message.contains("@types"));
    }

    #[tokio::test]
    async fn scope_squatting_nextjs_detected() {
        let registry = FakeRegistry::empty();
        let deps = vec![dep("@nexjs/config")];
        let issues = check_similarity(&registry, &deps, Ecosystem::Npm)
            .await
            .unwrap();
        assert!(
            issues.iter().any(|i| i.check.contains("scope-squatting")),
            "Expected @nexjs flagged as close to @nextjs"
        );
    }

    #[tokio::test]
    async fn scope_exact_match_no_flag() {
        let registry = FakeRegistry::empty();
        let deps = vec![dep("@types/lodash")];
        let issues = check_similarity(&registry, &deps, Ecosystem::Npm)
            .await
            .unwrap();
        let scope_issues: Vec<_> = issues
            .iter()
            .filter(|i| i.check.contains("scope-squatting"))
            .collect();
        assert!(scope_issues.is_empty());
    }

    // -- Case variant --

    #[tokio::test]
    async fn case_variant_flagged_on_case_sensitive_registry() {
        let registry = FakeRegistry::with(&["github.com/spf13/cobra"]);
        let deps = vec![dep_eco("Github.com/spf13/cobra", Ecosystem::Go)];
        let issues = check_similarity(&registry, &deps, Ecosystem::Go)
            .await
            .unwrap();
        assert!(
            issues.iter().any(|i| i.check.contains("case-variant")),
            "Expected case-variant issue on case-sensitive registry"
        );
    }

    #[tokio::test]
    async fn case_insensitive_registry_no_case_variant() {
        let registry = FakeRegistry::with(&["react"]);
        let deps = vec![dep("React")];
        let issues = check_similarity(&registry, &deps, Ecosystem::Npm)
            .await
            .unwrap();
        let case_issues: Vec<_> = issues
            .iter()
            .filter(|i| i.check.contains("case-variant"))
            .collect();
        assert!(case_issues.is_empty());
    }

    // -- Deduplication --

    #[tokio::test]
    async fn no_duplicate_flags_for_same_package() {
        let registry = FakeRegistry::with(&["express"]);
        let deps = vec![dep("expresss")];
        let issues = check_similarity(&registry, &deps, Ecosystem::Npm)
            .await
            .unwrap();
        let count = issues.iter().filter(|i| i.package == "expresss").count();
        assert_eq!(count, 1);
    }

    // -- Homoglyph --

    #[tokio::test]
    async fn homoglyph_caught() {
        let registry = FakeRegistry::with(&["requests"]);
        let deps = vec![dep_eco("r\u{0435}quests", Ecosystem::PyPI)];
        let issues = check_similarity(&registry, &deps, Ecosystem::PyPI)
            .await
            .unwrap();
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("homoglyph"));
    }

    // -- Helper unit tests --

    #[test]
    fn normalize_separators_works() {
        assert_eq!(normalize_separators("a-b_c.d"), "abcd");
        assert_eq!(normalize_separators("express"), "express");
    }

    #[test]
    fn collapse_one_repeated_works() {
        let variants = collapse_one_repeated("expresss");
        assert!(variants.contains(&"express".to_string()));

        let variants = collapse_one_repeated("reeact");
        assert!(variants.contains(&"react".to_string()));

        let variants = collapse_one_repeated("react");
        assert!(variants.is_empty());
    }

    #[test]
    fn strip_version_suffix_works() {
        assert_eq!(strip_version_suffix("requests2"), "requests");
        assert_eq!(strip_version_suffix("lodash-4"), "lodash");
        assert_eq!(strip_version_suffix("react"), "react");
        assert_eq!(strip_version_suffix("vue3"), "vue");
    }

    #[test]
    fn word_reorderings_works() {
        let results = word_reorderings("json-parse");
        assert!(results.contains(&"parse-json".to_string()));
    }

    #[test]
    fn adjacent_swaps_works() {
        let results = adjacent_swaps("ab");
        assert!(results.contains(&"ba".to_string()));
        let results = adjacent_swaps("abc");
        assert!(results.contains(&"bac".to_string()));
        assert!(results.contains(&"acb".to_string()));
    }

    #[test]
    fn delete_one_char_works() {
        let variants = delete_one_char("expressx");
        assert!(variants.contains(&"express".to_string()));
    }

    #[test]
    fn test_homoglyph_normalize_works() {
        let (normalized, replaced) = normalize_homoglyphs("r\u{0435}qu\u{0435}sts");
        assert_eq!(normalized, "requests");
        assert!(replaced);

        let (normalized, replaced) = normalize_homoglyphs("requests");
        assert_eq!(normalized, "requests");
        assert!(!replaced);
    }

    #[test]
    fn is_case_insensitive_correct() {
        assert!(is_case_insensitive(Ecosystem::Npm));
        assert!(is_case_insensitive(Ecosystem::PyPI));
        assert!(is_case_insensitive(Ecosystem::Cargo));
        assert!(is_case_insensitive(Ecosystem::Dotnet));
        assert!(is_case_insensitive(Ecosystem::Php));
        assert!(!is_case_insensitive(Ecosystem::Go));
        assert!(!is_case_insensitive(Ecosystem::Jvm));
        assert!(!is_case_insensitive(Ecosystem::Ruby));
    }

    #[test]
    fn test_extract_scope_npm() {
        assert_eq!(
            extract_scope("@types/lodash", Ecosystem::Npm),
            Some("@types".to_string())
        );
        assert_eq!(extract_scope("lodash", Ecosystem::Npm), None);
    }

    #[test]
    fn test_extract_scope_php() {
        assert_eq!(
            extract_scope("laravel/framework", Ecosystem::Php),
            Some("laravel".to_string())
        );
        assert_eq!(extract_scope("monolog", Ecosystem::Php), None);
    }

    #[test]
    fn test_extract_scope_go() {
        assert_eq!(
            extract_scope("github.com/google/protobuf", Ecosystem::Go),
            Some("github.com/google".to_string())
        );
    }

    #[test]
    fn test_extract_scope_jvm() {
        assert_eq!(
            extract_scope("com.google.guava:guava", Ecosystem::Jvm),
            Some("com.google".to_string())
        );
    }

    #[test]
    fn test_known_scopes_populated() {
        for eco in [
            Ecosystem::Npm,
            Ecosystem::Php,
            Ecosystem::Go,
            Ecosystem::Jvm,
        ] {
            assert!(
                !known_scopes(eco).is_empty(),
                "known_scopes empty for {}",
                eco
            );
        }
        assert!(known_scopes(Ecosystem::PyPI).is_empty());
    }

    #[test]
    fn confused_form_pypi_py_vs_python() {
        let forms = apply_confused_forms("python-utils", Ecosystem::PyPI);
        assert!(forms.contains(&"py-utils".to_string()));
        let forms = apply_confused_forms("py-utils", Ecosystem::PyPI);
        assert!(forms.contains(&"python-utils".to_string()));
    }

    #[test]
    fn confused_form_go_github_gitlab() {
        let forms = apply_confused_forms("github.com/spf13/cobra", Ecosystem::Go);
        assert!(forms.contains(&"gitlab.com/spf13/cobra".to_string()));
    }

    #[tokio::test]
    async fn match_reporting_is_deterministic() {
        let registry = FakeRegistry::with(&["express"]);
        let deps = vec![dep("expresss")];

        for _ in 0..5 {
            let issues = check_similarity(&registry, &deps, Ecosystem::Npm)
                .await
                .unwrap();
            assert_eq!(issues.len(), 1);
            assert!(
                issues[0].check.contains("collapse-repeated"),
                "Expected deterministic collapse-repeated, got: {}",
                issues[0].check
            );
        }
    }

    #[test]
    fn generator_severity_ordering_is_correct() {
        assert!(generator_severity("homoglyph") > generator_severity("bitflip"));
        assert!(generator_severity("bitflip") > generator_severity("confused-forms"));
        assert!(generator_severity("confused-forms") > generator_severity("segment-overlap"));
        assert!(generator_severity("segment-overlap") >= generator_severity("keyboard-proximity"));
        assert!(generator_severity("keyboard-proximity") >= generator_severity("char-swap"));
        assert!(generator_severity("char-swap") > generator_severity("collapse-repeated"));
        assert!(generator_severity("collapse-repeated") > generator_severity("extra-char"));
        assert!(generator_severity("extra-char") >= generator_severity("version-suffix"));
        assert!(generator_severity("version-suffix") >= generator_severity("word-reorder"));
        assert!(generator_severity("word-reorder") >= generator_severity("separator-swap"));
    }

    #[test]
    fn tagged_mutations_include_generator_names() {
        let mutations = generate_mutations("expresss", Ecosystem::Npm);
        let gen_name = mutations.get("express");
        assert!(gen_name.is_some(), "Expected 'express' in mutations");
        assert_eq!(*gen_name.unwrap(), "collapse-repeated");
    }

    // -- Bitflip --

    #[test]
    fn bitflip_variants_produce_single_bit_changes() {
        let variants = bitflip_variants("ab");
        // 'a' (0x61) XOR 1 = 'b' (0x60 is backtick, not valid; 0x61^1=0x60)
        // 'a' XOR 2 = 'c'
        assert!(variants.contains(&"cb".to_string()), "a XOR 2 = c");
        // 'a' XOR 4 = 'e'
        assert!(variants.contains(&"eb".to_string()), "a XOR 4 = e");
    }

    #[test]
    fn bitflip_only_produces_valid_chars() {
        let variants = bitflip_variants("react");
        for v in &variants {
            assert!(
                v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "Bitflip produced invalid char in: {}",
                v
            );
        }
    }

    // -- Keyboard proximity --

    #[test]
    fn keyboard_proximity_produces_adjacent_keys() {
        let variants = keyboard_proximity_variants("react");
        // 'r' neighbors: e, t, d, f
        assert!(variants.contains(&"eeact".to_string()), "r -> e");
        assert!(variants.contains(&"teact".to_string()), "r -> t");
        // 'a' neighbors: q, w, s, z
        assert!(variants.contains(&"reqct".to_string()), "a -> q");
        assert!(variants.contains(&"resct".to_string()), "a -> s");
    }

    #[test]
    fn keyboard_proximity_ignores_non_qwerty_chars() {
        let variants = keyboard_proximity_variants("a-b");
        // '-' has no keyboard neighbors in our map, so only a and b get variants
        assert!(!variants.is_empty());
        // All variants should still contain a hyphen at position 1
        for v in &variants {
            assert!(v.len() == 3, "Expected same length: {}", v);
        }
    }

    // -- Segment overlap --

    #[test]
    fn segment_overlap_detects_extended_package() {
        // "react-dom" is in NPM_TOP, so "react-dom-utils" should match
        let variants = segment_overlap_variants("react-dom-utils", Ecosystem::Npm);
        assert!(
            variants.contains(&"react-dom".to_string()),
            "Expected 'react-dom' from removing 'utils' segment. Got: {:?}",
            variants
        );
    }

    #[test]
    fn segment_overlap_single_segment_skipped() {
        let variants = segment_overlap_variants("react", Ecosystem::Npm);
        assert!(
            variants.is_empty(),
            "Single segment should produce no variants"
        );
    }

    #[test]
    fn segment_overlap_no_match_returns_empty() {
        let variants = segment_overlap_variants("my-custom-tool", Ecosystem::Npm);
        // "my-custom", "my-tool", "custom-tool" — none are in top packages
        assert!(variants.is_empty());
    }

    #[test]
    fn segment_overlap_normalizes_separators() {
        // "react_dom_utils" should still match "react-dom" via separator normalization
        let variants = segment_overlap_variants("react_dom_utils", Ecosystem::Npm);
        assert!(
            variants.contains(&"react_dom".to_string()),
            "Should normalize separators for matching. Got: {:?}",
            variants
        );
    }

    // -- Download disparity --

    #[tokio::test]
    async fn high_confidence_on_download_disparity() {
        use crate::checks::metadata::MetadataLookup;
        let registry = FakeRegistry::with(&["express"]);
        let deps = vec![dep("expresss")];

        // Simulate metadata lookups with high download original
        let dep_lookups = vec![MetadataLookup {
            package: "expresss".to_string(),
            ecosystem: Ecosystem::Npm,
            version: None,
            resolved_version: None,
            unresolved_version: false,
            exists: true,
            metadata: Some(PackageMetadata {
                downloads: Some(50_000_000),
                ..Default::default()
            }),
        }];

        let issues = check_similarity_with_cache(
            &registry,
            &deps,
            Ecosystem::Npm,
            None,
            false,
            false,
            Some(&dep_lookups),
        )
        .await
        .unwrap();

        assert!(!issues.is_empty());
        // The candidate "express" has 50K downloads (from FakeRegistry metadata),
        // original "expresss" has 50M — should show HIGH CONFIDENCE
        let has_high_confidence = issues.iter().any(|i| i.message.contains("HIGH CONFIDENCE"));
        assert!(
            has_high_confidence,
            "Expected HIGH CONFIDENCE in message when download disparity is large. Messages: {:?}",
            issues.iter().map(|i| &i.message).collect::<Vec<_>>()
        );
    }
}
