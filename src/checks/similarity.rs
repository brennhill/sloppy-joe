use crate::cache;
use crate::registry::Registry;
use crate::report::{Issue, Severity};
use crate::Dependency;
use anyhow::Result;
use futures::stream::{self, StreamExt};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

const SIMILARITY_CACHE_TTL_SECS: u64 = 7 * 24 * 3600; // 7 days

/// Registry error tracking threshold: >5 errors OR >10% failure rate triggers blocking issue.
const REGISTRY_ERROR_HARD_LIMIT: usize = 5;
const REGISTRY_ERROR_RATE_THRESHOLD: f64 = 0.10;

#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
struct SimilarityCache {
    timestamp: u64,
    entries: HashMap<String, bool>,
}

fn cache_path_for(ecosystem: &str, cache_dir: Option<&Path>) -> PathBuf {
    let base = cache_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| cache::user_cache_dir().join("sloppy-joe"));
    base.join(format!("similarity-{}.json", ecosystem))
}

// -- Mutation generator trait ------------------------------------------------

/// A mutation generator produces candidate names from a dependency name.
/// Implementations are composed into a vector and iterated by generate_mutations.
pub trait MutationGenerator: Send + Sync {
    fn name(&self) -> &str;
    fn generate(&self, name: &str, ecosystem: &str) -> Vec<String>;
}

/// Returns the default set of mutation generators.
pub fn default_generators() -> Vec<Box<dyn MutationGenerator>> {
    vec![
        Box::new(SeparatorSwapGen),
        Box::new(CollapseRepeatedGen),
        Box::new(VersionSuffixGen),
        Box::new(WordReorderGen),
        Box::new(AdjacentSwapGen),
        Box::new(DeleteOneCharGen),
        Box::new(HomoglyphGen),
        Box::new(ConfusedFormsGen),
    ]
}

struct SeparatorSwapGen;
impl MutationGenerator for SeparatorSwapGen {
    fn name(&self) -> &str { "separator-swap" }
    fn generate(&self, name: &str, ecosystem: &str) -> Vec<String> {
        if ecosystem == "pypi" { return vec![]; }
        let lower = name.to_lowercase();
        let mut results = Vec::new();
        let stripped = normalize_separators(&lower);
        if stripped != lower { results.push(stripped); }
        for &sep in &['-', '_', '.'] {
            let with_sep: String = lower.chars().map(|c| if c == '-' || c == '_' || c == '.' { sep } else { c }).collect();
            if with_sep != lower { results.push(with_sep); }
        }
        results
    }
}

struct CollapseRepeatedGen;
impl MutationGenerator for CollapseRepeatedGen {
    fn name(&self) -> &str { "collapse-repeated" }
    fn generate(&self, name: &str, _ecosystem: &str) -> Vec<String> {
        collapse_one_repeated(&name.to_lowercase())
    }
}

struct VersionSuffixGen;
impl MutationGenerator for VersionSuffixGen {
    fn name(&self) -> &str { "version-suffix" }
    fn generate(&self, name: &str, _ecosystem: &str) -> Vec<String> {
        let lower = name.to_lowercase();
        let stripped = strip_version_suffix(&lower);
        if stripped != lower { vec![stripped] } else { vec![] }
    }
}

struct WordReorderGen;
impl MutationGenerator for WordReorderGen {
    fn name(&self) -> &str { "word-reorder" }
    fn generate(&self, name: &str, _ecosystem: &str) -> Vec<String> {
        word_reorderings(&name.to_lowercase())
    }
}

struct AdjacentSwapGen;
impl MutationGenerator for AdjacentSwapGen {
    fn name(&self) -> &str { "adjacent-swap" }
    fn generate(&self, name: &str, _ecosystem: &str) -> Vec<String> {
        adjacent_swaps(&name.to_lowercase())
    }
}

struct DeleteOneCharGen;
impl MutationGenerator for DeleteOneCharGen {
    fn name(&self) -> &str { "delete-one-char" }
    fn generate(&self, name: &str, _ecosystem: &str) -> Vec<String> {
        delete_one_char(&name.to_lowercase()).into_iter().collect()
    }
}

struct HomoglyphGen;
impl MutationGenerator for HomoglyphGen {
    fn name(&self) -> &str { "homoglyph" }
    fn generate(&self, name: &str, _ecosystem: &str) -> Vec<String> {
        let (normalized, had_homoglyphs) = normalize_homoglyphs(name);
        if had_homoglyphs { vec![normalized.to_lowercase()] } else { vec![] }
    }
}

struct ConfusedFormsGen;
impl MutationGenerator for ConfusedFormsGen {
    fn name(&self) -> &str { "confused-forms" }
    fn generate(&self, name: &str, ecosystem: &str) -> Vec<String> {
        apply_confused_forms(name, ecosystem)
    }
}

/// Ecosystem-specific confused forms: terms that are interchangeable
/// and commonly swapped by AI or humans.
fn confused_forms(ecosystem: &str) -> &'static [(&'static str, &'static str)] {
    match ecosystem {
        "pypi" => &[("python", "py"), ("python-", "py-"), ("python_", "py_")],
        "go" => &[
            ("github.com", "gitlab.com"),
            ("golang", "go"),
            ("golang-", "go-"),
        ],
        _ => &[],
    }
}

// -- Homoglyph detection ---------------------------------------------------

/// Map of common homoglyphs: (lookalike char, Latin equivalent).
fn homoglyph_map() -> &'static [(char, char)] {
    &[
        ('\u{0430}', 'a'), // Cyrillic a -> Latin a
        ('\u{0435}', 'e'), // Cyrillic e -> Latin e
        ('\u{043E}', 'o'), // Cyrillic o -> Latin o
        ('\u{0440}', 'p'), // Cyrillic p -> Latin p
        ('\u{0441}', 'c'), // Cyrillic c -> Latin c
        ('\u{0443}', 'y'), // Cyrillic y -> Latin y
        ('\u{0445}', 'x'), // Cyrillic x -> Latin x
        ('\u{0455}', 's'), // Cyrillic s -> Latin s
        ('\u{0456}', 'i'), // Cyrillic i -> Latin i
        ('\u{0458}', 'j'), // Cyrillic j -> Latin j
        ('\u{0501}', 'd'), // Cyrillic d -> Latin d
        ('\u{0261}', 'g'), // Latin g -> Latin g
        ('\u{2113}', 'l'), // Script l -> Latin l
        ('\u{FF10}', '0'), // Fullwidth 0
        ('\u{FF11}', '1'), // Fullwidth 1
        ('\u{2170}', 'i'), // Roman numeral i -> Latin i
        ('\u{217C}', 'l'), // Roman numeral l -> Latin l
    ]
}

/// Normalize a name by replacing homoglyphs with their Latin equivalents.
/// Returns the normalized string and whether any replacements were made.
fn normalize_homoglyphs(name: &str) -> (String, bool) {
    let map = homoglyph_map();
    let mut result = String::with_capacity(name.len());
    let mut replaced = false;
    for ch in name.chars() {
        if let Some((_, latin)) = map.iter().find(|(lookalike, _)| *lookalike == ch) {
            result.push(*latin);
            replaced = true;
        } else {
            result.push(ch);
        }
    }
    (result, replaced)
}

// -- Scope/namespace squatting detection ------------------------------------

/// Known-good scopes/namespaces per ecosystem.
fn known_scopes(ecosystem: &str) -> &'static [&'static str] {
    match ecosystem {
        "npm" => &[
            "@types",
            "@babel",
            "@angular",
            "@vue",
            "@nuxt",
            "@nestjs",
            "@react-native",
            "@emotion",
            "@mui",
            "@chakra-ui",
            "@testing-library",
            "@storybook",
            "@typescript-eslint",
            "@rollup",
            "@vitejs",
            "@svelte",
            "@tanstack",
            "@aws-sdk",
            "@azure",
            "@google-cloud",
            "@firebase",
            "@prisma",
            "@trpc",
            "@reduxjs",
            "@apollo",
            "@eslint",
            "@prettier",
            "@jest",
            "@playwright",
            "@vercel",
            "@netlify",
            "@cloudflare",
            "@octokit",
            "@actions",
            "@github",
            "@sentry",
            "@datadog",
            "@grpc",
            "@protobuf",
        ],
        "php" => &[
            "laravel",
            "symfony",
            "illuminate",
            "doctrine",
            "league",
            "guzzlehttp",
            "phpunit",
            "monolog",
            "spatie",
            "barryvdh",
            "filament",
            "livewire",
            "intervention",
            "predis",
            "ramsey",
            "vlucas",
            "phpstan",
            "mockery",
            "nikic",
            "twig",
            "psr",
            "composer",
            "sebastian",
        ],
        "go" => &[
            "github.com/gin-gonic",
            "github.com/labstack",
            "github.com/gofiber",
            "github.com/spf13",
            "github.com/stretchr",
            "github.com/gorilla",
            "github.com/go-chi",
            "github.com/go-redis",
            "github.com/sirupsen",
            "github.com/rs",
            "github.com/valyala",
            "github.com/jackc",
            "github.com/nats-io",
            "github.com/hashicorp",
            "github.com/prometheus",
            "github.com/grpc",
            "github.com/golang",
            "github.com/google",
            "github.com/aws",
            "github.com/Azure",
            "github.com/kubernetes",
            "github.com/docker",
            "github.com/etcd-io",
            "github.com/cockroachdb",
            "go.uber.org",
            "google.golang.org",
            "golang.org",
            "cloud.google.com",
        ],
        "jvm" => &[
            "com.google",
            "org.springframework",
            "org.apache",
            "io.netty",
            "com.fasterxml",
            "org.jetbrains",
            "com.squareup",
            "io.grpc",
            "org.slf4j",
            "ch.qos",
            "org.mockito",
            "org.assertj",
            "junit",
            "io.micrometer",
            "com.zaxxer",
            "org.hibernate",
            "org.projectlombok",
        ],
        _ => &[],
    }
}

/// Extract the scope/namespace from a package name for a given ecosystem.
fn extract_scope(name: &str, ecosystem: &str) -> Option<String> {
    match ecosystem {
        "npm" => {
            // @scope/package -> @scope
            if name.starts_with('@') {
                name.split('/').next().map(|s| s.to_string())
            } else {
                None
            }
        }
        "php" => {
            // vendor/package -> vendor
            name.split('/')
                .next()
                .filter(|_| name.contains('/'))
                .map(|s| s.to_string())
        }
        "go" => {
            // github.com/org/repo -> github.com/org
            let parts: Vec<&str> = name.splitn(3, '/').collect();
            if parts.len() >= 2 {
                Some(format!("{}/{}", parts[0], parts[1]))
            } else {
                None
            }
        }
        "jvm" => {
            // com.google.guava:guava -> com.google
            name.split(':').next().and_then(|group| {
                let parts: Vec<&str> = group.splitn(3, '.').collect();
                if parts.len() >= 2 {
                    Some(format!("{}.{}", parts[0], parts[1]))
                } else {
                    None
                }
            })
        }
        _ => None,
    }
}

// -- Generative checks ------------------------------------------------------
// Each function takes a dependency name and returns candidate names
// that would match a known package if this is a typosquat.

/// Normalize separators: strip `-`, `_`, `.` for comparison.
/// Catches: "python-dateutil" vs "pythondateutil"
fn normalize_separators(name: &str) -> String {
    name.chars()
        .filter(|c| *c != '-' && *c != '_' && *c != '.')
        .collect()
}

/// Generate variants with one repeated character removed at each position.
/// "expresss" -> ["express"], "reeact" -> ["react"], "llodash" -> ["lodash"]
/// Returns all variants where a consecutive duplicate is collapsed once.
fn collapse_one_repeated(name: &str) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut results = Vec::new();
    let mut i = 0;
    while i < chars.len().saturating_sub(1) {
        if chars[i] == chars[i + 1] {
            // Remove one instance of the repeated char
            let mut variant: Vec<char> = Vec::with_capacity(chars.len() - 1);
            variant.extend_from_slice(&chars[..i]);
            variant.extend_from_slice(&chars[i + 1..]);
            let s: String = variant.into_iter().collect();
            if !results.contains(&s) {
                results.push(s);
            }
            // Skip past all consecutive duplicates
            while i < chars.len().saturating_sub(1) && chars[i] == chars[i + 1] {
                i += 1;
            }
        }
        i += 1;
    }
    results
}

/// Strip trailing version suffixes: "requests2" -> "requests", "lodash-4" -> "lodash"
fn strip_version_suffix(name: &str) -> String {
    let trimmed = name.trim_end_matches(|c: char| c.is_ascii_digit());
    trimmed
        .trim_end_matches('-')
        .trim_end_matches('_')
        .to_string()
}

/// Generate word-reordered variants: "json-parse" -> "parse-json"
/// Returns all permutations of segments split on `-`, `_`, `.`
fn word_reorderings(name: &str) -> Vec<String> {
    let separators = ['-', '_', '.'];
    let mut sep_char = None;
    for s in &separators {
        if name.contains(*s) {
            sep_char = Some(*s);
            break;
        }
    }
    let Some(sep) = sep_char else { return vec![] };
    let mut segments: Vec<&str> = name.split(sep).collect();
    if segments.len() < 2 || segments.len() > 3 {
        return vec![];
    }
    // Generate all permutations
    let mut results = Vec::new();
    permutations(&mut segments, 0, sep, &mut results);
    // Remove the original
    let original = name.to_string();
    results.retain(|r| r != &original);
    results
}

fn permutations(segments: &mut Vec<&str>, start: usize, sep: char, results: &mut Vec<String>) {
    if start == segments.len() {
        results.push(segments.join(&sep.to_string()));
        return;
    }
    for i in start..segments.len() {
        segments.swap(start, i);
        permutations(segments, start + 1, sep, results);
        segments.swap(start, i);
    }
}

/// Generate ecosystem-specific confused forms.
/// "python-dateutil" -> "py-dateutil", "py-utils" -> "python-utils"
fn apply_confused_forms(name: &str, ecosystem: &str) -> Vec<String> {
    let forms = confused_forms(ecosystem);
    let mut results = Vec::new();
    let lower = name.to_lowercase();
    for (a, b) in forms {
        if lower.contains(a) {
            results.push(lower.replace(a, b));
        }
        if lower.contains(b) {
            results.push(lower.replace(b, a));
        }
    }
    results
}

/// Delete one character at each position: "expressx" -> ["xpressx", "epressx", ..., "express"]
/// Catches extra-char typosquats where one letter was added.
fn delete_one_char(name: &str) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut results = HashSet::new();
    for i in 0..chars.len() {
        let variant: String = chars
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, c)| c)
            .collect();
        if !variant.is_empty() {
            results.insert(variant);
        }
    }
    results.into_iter().collect()
}

/// Swap adjacent characters: "reqeust" -> "request"
fn adjacent_swaps(name: &str) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut results = Vec::new();
    for i in 0..chars.len().saturating_sub(1) {
        let mut swapped = chars.clone();
        swapped.swap(i, i + 1);
        let s: String = swapped.into_iter().collect();
        if s != name {
            results.push(s);
        }
    }
    results
}

// -- Orchestration -----------------------------------------------------------

fn is_case_insensitive(ecosystem: &str) -> bool {
    matches!(ecosystem, "npm" | "pypi" | "cargo" | "dotnet" | "php")
}

/// Max allowed Levenshtein distance, scaled by name length (for scope squatting).
fn max_distance(name_len: usize) -> usize {
    match name_len {
        0..=4 => 1,
        5..=8 => 2,
        _ => 3,
    }
}

/// Generate all mutation candidates for a package name.
/// Returns a set of candidate names to query the registry for.
fn generate_mutations(name: &str, ecosystem: &str) -> HashSet<String> {
    generate_mutations_with(&default_generators(), name, ecosystem)
}

/// Generate mutations using a specific set of generators.
fn generate_mutations_with(
    generators: &[Box<dyn MutationGenerator>],
    name: &str,
    ecosystem: &str,
) -> HashSet<String> {
    let lower = name.to_lowercase();
    let case_insensitive = is_case_insensitive(ecosystem);
    let mut candidates = HashSet::new();

    for generator in generators {
        for variant in generator.generate(name, ecosystem) {
            candidates.insert(variant);
        }
    }

    // On case-insensitive registries, remove candidates that only differ by case
    if case_insensitive {
        candidates.retain(|c| c != &lower);
    }

    // Remove the original name itself
    candidates.remove(&lower);
    candidates
}

/// Classify which generator produced a candidate match.
fn classify_match(dep_name: &str, candidate: &str, ecosystem: &str) -> (&'static str, String) {
    let dep_lower = dep_name.to_lowercase();
    let suppress_separators = ecosystem == "pypi";

    // Homoglyph check
    let (normalized, had_homoglyphs) = normalize_homoglyphs(dep_name);
    if had_homoglyphs && normalized.to_lowercase() == candidate.to_lowercase() {
        return (
            "homoglyph",
            format!(
                "'{}' contains non-Latin characters that look identical to letters in '{}'. \
                 This is a homoglyph attack -- the package name uses lookalike Unicode characters \
                 to impersonate a legitimate package. \
                 Examine both packages and add the intended one to your allowed list.",
                dep_name, candidate
            ),
        );
    }

    // Separator normalization
    if !suppress_separators {
        let dep_normalized = normalize_separators(&dep_lower);
        let cand_normalized = normalize_separators(candidate);
        if dep_normalized == cand_normalized && dep_lower != candidate {
            return (
                "separator-confusion",
                format!(
                    "'{}' matches '{}' after normalizing separators (-, _, .). \
                     These may resolve to different packages. \
                     Examine both packages and add the intended one to your allowed list.",
                    dep_name, candidate
                ),
            );
        }
    }

    // Collapsed repeated characters
    let collapsed = collapse_one_repeated(&dep_lower);
    if collapsed.iter().any(|v| v == candidate) {
        return (
            "repeated-chars",
            format!(
                "'{}' matches '{}' after removing a repeated character. \
                 This is a common typosquatting pattern. \
                 Examine both packages and add the intended one to your allowed list.",
                dep_name, candidate
            ),
        );
    }

    // Version suffix stripping
    let stripped = strip_version_suffix(&dep_lower);
    if stripped != dep_lower && stripped == candidate {
        return (
            "version-suffix",
            format!(
                "'{}' looks like '{}' with a version suffix appended. \
                 An attacker could register the suffixed variant as a separate package. \
                 Examine both packages and add the intended one to your allowed list.",
                dep_name, candidate
            ),
        );
    }

    // Word reordering
    let reorderings = word_reorderings(&dep_lower);
    if reorderings.iter().any(|v| v == candidate) {
        return (
            "word-reorder",
            format!(
                "'{}' is a reordering of '{}'. Word-swapped package names are a known \
                 typosquatting vector. \
                 Examine both packages and add the intended one to your allowed list.",
                dep_name, candidate
            ),
        );
    }

    // Adjacent swap
    let swaps = adjacent_swaps(&dep_lower);
    if swaps.iter().any(|v| v == candidate) {
        return (
            "char-swap",
            format!(
                "'{}' matches '{}' with two adjacent characters swapped. \
                 This is a common typo and a known typosquatting pattern. \
                 Examine both packages and add the intended one to your allowed list.",
                dep_name, candidate
            ),
        );
    }

    // Delete-one-char (extra char in dep name)
    let deletions = delete_one_char(&dep_lower);
    if deletions.iter().any(|v| v == candidate) {
        return (
            "extra-char",
            format!(
                "'{}' matches '{}' with one character removed. \
                 An extra character may have been added -- this is a common typosquatting pattern. \
                 Examine both packages and add the intended one to your allowed list.",
                dep_name, candidate
            ),
        );
    }

    // Confused forms
    let confused = apply_confused_forms(dep_name, ecosystem);
    if confused.iter().any(|v| v == candidate) {
        return (
            "confused-form",
            format!(
                "'{}' is a confused form of '{}'. These are commonly interchanged but \
                 resolve to different packages. \
                 Examine both packages and add the intended one to your allowed list.",
                dep_name, candidate
            ),
        );
    }

    // Fallback (should not normally reach here)
    (
        "mutation-match",
        format!(
            "'{}' is suspiciously similar to '{}'. \
             Examine both packages and add the intended one to your allowed list.",
            dep_name, candidate
        ),
    )
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
    ecosystem: &str,
) -> Result<Vec<Issue>> {
    check_similarity_with_cache(registry, deps, ecosystem, None, false).await
}

/// Check similarity with configurable cache.
pub async fn check_similarity_with_cache(
    registry: &dyn Registry,
    deps: &[Dependency],
    ecosystem: &str,
    cache_dir: Option<&Path>,
    no_cache: bool,
) -> Result<Vec<Issue>> {
    let case_insensitive = is_case_insensitive(ecosystem);
    let mut issues = Vec::new();
    let mut flagged: HashSet<String> = HashSet::new();

    // Build a set of all dep names for intra-manifest comparison
    let dep_names: HashSet<String> = deps.iter().map(|d| d.name.to_lowercase()).collect();

    // ---- Phase 0: Scope squatting (no registry needed) ----
    for dep in deps {
        if let Some(scope) = extract_scope(&dep.name, ecosystem) {
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
                    if flagged.insert(dep.name.clone()) {
                        issues.push(make_issue(
                            &dep.name,
                            &dep.name,
                            "scope-squatting",
                            &format!(
                                "Scope '{}' is {} character{} away from the known scope '{}'.\n      \
                                 Scope squatting is a known supply chain attack vector.",
                                scope,
                                distance,
                                if distance == 1 { "" } else { "s" },
                                known
                            ),
                            &format!(
                                "If you meant '{}', fix the scope in your manifest.",
                                dep.name.replace(&scope, known)
                            ),
                        ));
                    }
                    break;
                }
            }
        }
    }

    // ---- Pre-compute mutations once for Phase 1 + Phase 2 ----
    let mut all_mutations: HashMap<String, HashSet<String>> = HashMap::new();
    for dep in deps {
        if !flagged.contains(&dep.name) {
            all_mutations.insert(dep.name.clone(), generate_mutations(&dep.name, ecosystem));
        }
    }

    // ---- Phase 1: Intra-manifest comparison (no network) ----
    for dep in deps {
        if flagged.contains(&dep.name) {
            continue;
        }
        if let Some(mutations) = all_mutations.get(&dep.name) {
            for mutation in mutations {
                let mutation_lower = mutation.to_lowercase();
                if dep_names.contains(&mutation_lower)
                    && mutation_lower != dep.name.to_lowercase()
                {
                    if flagged.insert(dep.name.clone()) {
                        let (check_type, message) =
                            classify_match(&dep.name, &mutation_lower, ecosystem);
                        issues.push(make_issue(
                            &dep.name,
                            &mutation_lower,
                            check_type,
                            &format!(
                                "{} Both '{}' and '{}' are in your manifest.",
                                message, dep.name, mutation_lower
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
        if flagged.contains(&dep.name) {
            continue;
        }
        if let Some(mutations) = all_mutations.get(&dep.name) {
            for mutation in mutations {
                queries.push((dep.name.clone(), mutation.clone()));
            }
        }
    }

    // Load disk cache (7-day TTL) using shared cache utilities (symlink protection, atomic writes)
    let cp = cache_path_for(ecosystem, cache_dir);
    let mut cache = if no_cache {
        SimilarityCache::default()
    } else {
        cache::read_json_cache(&cp, SIMILARITY_CACHE_TTL_SECS, |c: &SimilarityCache| c.timestamp)
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
    let concurrency = crate::registry::similarity_concurrency(ecosystem);
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
        let _ = cache::atomic_write_json(&cp, &cache); // non-fatal: cache write failure should not abort scan
    }

    // Emit blocking error if registry is unreachable (fail closed)
    let error_rate = if total_queries > 0 {
        error_count as f64 / total_queries as f64
    } else {
        0.0
    };
    if error_count > REGISTRY_ERROR_HARD_LIMIT
        || (total_queries > 0 && error_rate > REGISTRY_ERROR_RATE_THRESHOLD)
    {
        issues.push(Issue {
            package: "<registry>".to_string(),
            check: "similarity/registry-unreachable".to_string(),
            severity: Severity::Error,
            message: format!(
                "Registry queries failed for {} of {} similarity checks ({:.0}%). \
                 Similarity detection is unreliable. Fix network connectivity or retry.",
                error_count,
                total_queries,
                error_rate * 100.0
            ),
            fix: "Ensure the registry is reachable. Use --no-cache to bypass stale cache data."
                .to_string(),
            suggestion: None,
            registry_url: None,
            source: None,
        });
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
    // Collect all (dep_name, candidate) pairs that need metadata
    let metadata_queries: Vec<(String, String)> = deps
        .iter()
        .filter(|dep| !flagged.contains(&dep.name))
        .filter_map(|dep| {
            matches.get(&dep.name).and_then(|candidates| {
                candidates.first().map(|c| (dep.name.clone(), c.clone()))
            })
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
            let (check_type, mut message) =
                classify_match(&dep_name, &candidate, ecosystem);

            if let Some(ref meta) = metadata {
                let mut evidence_parts = Vec::new();
                if let Some(downloads) = meta.downloads {
                    evidence_parts
                        .push(format!("{} has {:?} downloads", candidate, downloads));
                }
                if let Some(ref created) = meta.created {
                    evidence_parts
                        .push(format!("was first published {}", created));
                }
                if !evidence_parts.is_empty() {
                    message = format!("{} ({})", message, evidence_parts.join("; "));
                }
            }

            issues.push(make_issue(
                &dep_name,
                &candidate,
                check_type,
                &message,
                "Examine both packages and add the intended one to your allowed list.",
            ));
        }
    }

    // ---- Case variant check for case-sensitive registries ----
    if !case_insensitive {
        for dep in deps {
            if flagged.contains(&dep.name) {
                continue;
            }
            // On case-sensitive registries, check if the lowercased name exists on registry
            let dep_lower = dep.name.to_lowercase();
            if dep_lower != dep.name {
                let exists = match registry.exists(&dep_lower).await {
                    Ok(v) => v,
                    Err(_) => {
                        // Count toward the overall error budget (already checked above)
                        continue;
                    }
                };
                if exists && flagged.insert(dep.name.clone()) {
                    issues.push(make_issue(
                        &dep.name,
                        &dep_lower,
                        "case-variant",
                        &format!(
                            "'{}' differs from '{}' only in letter casing. \
                             On case-sensitive registries ({}) these resolve to different packages. \
                             An attacker could register the case variant.",
                            dep.name, dep_lower, ecosystem
                        ),
                        &format!(
                            "Use the exact casing '{}' in your manifest.",
                            dep_lower
                        ),
                    ));
                }
            }
        }
    }

    Ok(issues)
}

/// Generate cheap mutation candidates for a package name.
/// Used by the reverse-check in existence.rs to suggest corrections
/// for non-existent packages. Delegates to generate_mutations with a
/// neutral ecosystem to get the full set of candidates.
pub fn generate_candidates(name: &str) -> HashSet<String> {
    // Use "npm" as a neutral ecosystem (no separator suppression, includes all generators)
    generate_mutations(name, "npm")
}

fn make_issue(package: &str, popular: &str, check_type: &str, message: &str, fix: &str) -> Issue {
    Issue {
        package: package.to_string(),
        check: format!("similarity/{}", check_type),
        severity: Severity::Error,
        message: message.to_string(),
        fix: fix.to_string(),
        suggestion: Some(popular.to_string()),
        registry_url: None,
        source: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{PackageMetadata, RegistryExistence, RegistryMetadata};
    use async_trait::async_trait;

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
                    downloads: Some(50000),
                    has_install_scripts: false,
                    dependency_count: None,
                    previous_dependency_count: None,
                    current_publisher: None,
                    previous_publisher: None,
                }))
            } else {
                Ok(None)
            }
        }
    }

    fn dep(name: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: None,
            ecosystem: "npm".to_string(),
        }
    }

    fn dep_eco(name: &str, ecosystem: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: None,
            ecosystem: ecosystem.to_string(),
        }
    }

    // -- Repeated chars --

    #[tokio::test]
    async fn repeated_chars_caught() {
        // "expresss" -> mutation "express" exists on registry
        let registry = FakeRegistry::with(&["express"]);
        let deps = vec![dep("expresss")];
        let issues = check_similarity(&registry, &deps, "npm").await.unwrap();
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("repeated"));
        assert_eq!(issues[0].suggestion, Some("express".to_string()));
    }

    // -- Version suffix --

    #[tokio::test]
    async fn version_suffix_caught() {
        let registry = FakeRegistry::with(&["react"]);
        let deps = vec![dep("react2")];
        let issues = check_similarity(&registry, &deps, "npm").await.unwrap();
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("version-suffix"));
        assert_eq!(issues[0].suggestion, Some("react".to_string()));
    }

    // -- Adjacent swap --

    #[tokio::test]
    async fn adjacent_swap_caught() {
        let registry = FakeRegistry::with(&["requests"]);
        let deps = vec![dep_eco("reqeusts", "pypi")];
        let issues = check_similarity(&registry, &deps, "pypi").await.unwrap();
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("char-swap"));
        assert_eq!(issues[0].suggestion, Some("requests".to_string()));
    }

    // -- Extra char --

    #[tokio::test]
    async fn extra_char_caught() {
        // "expressx" -> delete 'x' -> "express" exists
        let registry = FakeRegistry::with(&["express"]);
        let deps = vec![dep("expressx")];
        let issues = check_similarity(&registry, &deps, "npm").await.unwrap();
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("extra-char"));
        assert_eq!(issues[0].suggestion, Some("express".to_string()));
    }

    // -- No match --

    #[tokio::test]
    async fn no_match_produces_no_issue() {
        let registry = FakeRegistry::with(&["react", "express"]);
        let deps = vec![dep("zzzzzzzzzzzzz")];
        let issues = check_similarity(&registry, &deps, "npm").await.unwrap();
        assert!(issues.is_empty());
    }

    // -- Any package catch (registry returns true for mutation) --

    #[tokio::test]
    async fn any_package_catch() {
        // Even a non-popular package: if mutation exists on registry, flag it
        let registry = FakeRegistry::with(&["my-lib"]);
        let deps = vec![dep("myy-lib")]; // repeated 'y' -> "my-lib"
        let issues = check_similarity(&registry, &deps, "npm").await.unwrap();
        assert!(!issues.is_empty());
    }

    // -- Intra-manifest --

    #[tokio::test]
    async fn intra_manifest_flags_both_present() {
        // Both "lodash" and "lodahs" in manifest (adjacent swap) -- flag without network
        let registry = FakeRegistry::empty();
        let deps = vec![dep("lodash"), dep("lodahs")];
        let issues = check_similarity(&registry, &deps, "npm").await.unwrap();
        assert!(!issues.is_empty());
        // One of them should be flagged
        assert!(
            issues.iter().any(|i| i.package == "lodahs" || i.package == "lodash"),
            "Expected intra-manifest flag"
        );
    }

    // -- PyPI separator suppression --

    #[tokio::test]
    async fn pypi_separator_suppressed() {
        // On PyPI, separator normalization is suppressed (PEP 503 normalizes)
        // So "python-dateutil" vs "python_dateutil" should NOT be flagged as separator-confusion
        let registry = FakeRegistry::with(&["python_dateutil"]);
        let deps = vec![dep_eco("python-dateutil", "pypi")];
        let issues = check_similarity(&registry, &deps, "pypi").await.unwrap();
        let sep_issues: Vec<_> = issues
            .iter()
            .filter(|i| i.check.contains("separator"))
            .collect();
        assert!(sep_issues.is_empty(), "PyPI should suppress separator-confusion");
    }

    // -- npm separator flagged --

    #[tokio::test]
    async fn npm_separator_flagged() {
        // On npm, separator variants ARE flagged
        let registry = FakeRegistry::with(&["socket.io"]);
        let deps = vec![dep("socket_io")];
        let issues = check_similarity(&registry, &deps, "npm").await.unwrap();
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("separator"));
    }

    // -- Scope squatting --

    #[tokio::test]
    async fn scope_squatting_flagged() {
        let registry = FakeRegistry::empty();
        let deps = vec![dep("@typos/lodash")];
        let issues = check_similarity(&registry, &deps, "npm").await.unwrap();
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("scope-squatting"));
        assert!(issues[0].message.contains("@typos"));
        assert!(issues[0].message.contains("@types"));
    }

    #[tokio::test]
    async fn scope_exact_match_no_flag() {
        let registry = FakeRegistry::empty();
        let deps = vec![dep("@types/lodash")];
        let issues = check_similarity(&registry, &deps, "npm").await.unwrap();
        let scope_issues: Vec<_> = issues
            .iter()
            .filter(|i| i.check.contains("scope-squatting"))
            .collect();
        assert!(scope_issues.is_empty());
    }

    // -- Case variant --

    #[tokio::test]
    async fn case_variant_flagged_on_case_sensitive_registry() {
        // Go is case-sensitive; "Github.com/spf13/cobra" differs from "github.com/spf13/cobra"
        let registry = FakeRegistry::with(&["github.com/spf13/cobra"]);
        let deps = vec![dep_eco("Github.com/spf13/cobra", "go")];
        let issues = check_similarity(&registry, &deps, "go").await.unwrap();
        assert!(
            issues.iter().any(|i| i.check.contains("case-variant")),
            "Expected case-variant issue on case-sensitive registry"
        );
    }

    #[tokio::test]
    async fn case_insensitive_registry_no_case_variant() {
        // npm is case-insensitive; "React" should not trigger case-variant
        let registry = FakeRegistry::with(&["react"]);
        let deps = vec![dep("React")];
        let issues = check_similarity(&registry, &deps, "npm").await.unwrap();
        let case_issues: Vec<_> = issues
            .iter()
            .filter(|i| i.check.contains("case-variant"))
            .collect();
        assert!(case_issues.is_empty());
    }

    // -- Deduplication --

    #[tokio::test]
    async fn no_duplicate_flags_for_same_package() {
        // "expresss" might match via repeated-chars AND delete-one -- should only report once
        let registry = FakeRegistry::with(&["express"]);
        let deps = vec![dep("expresss")];
        let issues = check_similarity(&registry, &deps, "npm").await.unwrap();
        let count = issues.iter().filter(|i| i.package == "expresss").count();
        assert_eq!(count, 1);
    }

    // -- Homoglyph --

    #[tokio::test]
    async fn homoglyph_caught() {
        // Cyrillic 'e' in "r\u{0435}quests" -> normalizes to "requests"
        let registry = FakeRegistry::with(&["requests"]);
        let deps = vec![dep_eco("r\u{0435}quests", "pypi")];
        let issues = check_similarity(&registry, &deps, "pypi").await.unwrap();
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
        assert!(is_case_insensitive("npm"));
        assert!(is_case_insensitive("pypi"));
        assert!(is_case_insensitive("cargo"));
        assert!(is_case_insensitive("dotnet"));
        assert!(is_case_insensitive("php"));
        assert!(!is_case_insensitive("go"));
        assert!(!is_case_insensitive("jvm"));
        assert!(!is_case_insensitive("ruby"));
    }

    #[test]
    fn test_extract_scope_npm() {
        assert_eq!(
            extract_scope("@types/lodash", "npm"),
            Some("@types".to_string())
        );
        assert_eq!(extract_scope("lodash", "npm"), None);
    }

    #[test]
    fn test_extract_scope_php() {
        assert_eq!(
            extract_scope("laravel/framework", "php"),
            Some("laravel".to_string())
        );
        assert_eq!(extract_scope("monolog", "php"), None);
    }

    #[test]
    fn test_extract_scope_go() {
        assert_eq!(
            extract_scope("github.com/google/protobuf", "go"),
            Some("github.com/google".to_string())
        );
    }

    #[test]
    fn test_extract_scope_jvm() {
        assert_eq!(
            extract_scope("com.google.guava:guava", "jvm"),
            Some("com.google".to_string())
        );
    }

    #[test]
    fn test_known_scopes_populated() {
        for eco in &["npm", "php", "go", "jvm"] {
            assert!(
                !known_scopes(eco).is_empty(),
                "known_scopes empty for {}",
                eco
            );
        }
        assert!(known_scopes("unknown").is_empty());
    }

    #[test]
    fn confused_form_pypi_py_vs_python() {
        let forms = apply_confused_forms("python-utils", "pypi");
        assert!(forms.contains(&"py-utils".to_string()));
        let forms = apply_confused_forms("py-utils", "pypi");
        assert!(forms.contains(&"python-utils".to_string()));
    }

    #[test]
    fn confused_form_go_github_gitlab() {
        let forms = apply_confused_forms("github.com/spf13/cobra", "go");
        assert!(forms.contains(&"gitlab.com/spf13/cobra".to_string()));
    }
}
