//! Mutation generators for typosquatting detection.
//!
//! Each generator produces candidate package names from a dependency name.
//! They are composed into a vector and iterated by `generate_mutations`.

use crate::Ecosystem;
use std::collections::HashSet;

/// A mutation generator produces candidate names from a dependency name.
/// Implementations are composed into a vector and iterated by generate_mutations.
pub trait MutationGenerator: Send + Sync {
    fn name(&self) -> &'static str;
    fn generate(&self, name: &str, ecosystem: Ecosystem) -> Vec<String>;
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

// -- Generator implementations -----------------------------------------------

struct SeparatorSwapGen;
impl MutationGenerator for SeparatorSwapGen {
    fn name(&self) -> &'static str { "separator-swap" }
    fn generate(&self, name: &str, ecosystem: Ecosystem) -> Vec<String> {
        if ecosystem == Ecosystem::PyPI { return vec![]; }
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
    fn name(&self) -> &'static str { "collapse-repeated" }
    fn generate(&self, name: &str, _ecosystem: Ecosystem) -> Vec<String> {
        collapse_one_repeated(&name.to_lowercase())
    }
}

struct VersionSuffixGen;
impl MutationGenerator for VersionSuffixGen {
    fn name(&self) -> &'static str { "version-suffix" }
    fn generate(&self, name: &str, _ecosystem: Ecosystem) -> Vec<String> {
        let lower = name.to_lowercase();
        let stripped = strip_version_suffix(&lower);
        if stripped != lower { vec![stripped] } else { vec![] }
    }
}

struct WordReorderGen;
impl MutationGenerator for WordReorderGen {
    fn name(&self) -> &'static str { "word-reorder" }
    fn generate(&self, name: &str, _ecosystem: Ecosystem) -> Vec<String> {
        word_reorderings(&name.to_lowercase())
    }
}

struct AdjacentSwapGen;
impl MutationGenerator for AdjacentSwapGen {
    fn name(&self) -> &'static str { "char-swap" }
    fn generate(&self, name: &str, _ecosystem: Ecosystem) -> Vec<String> {
        adjacent_swaps(&name.to_lowercase())
    }
}

struct DeleteOneCharGen;
impl MutationGenerator for DeleteOneCharGen {
    fn name(&self) -> &'static str { "extra-char" }
    fn generate(&self, name: &str, _ecosystem: Ecosystem) -> Vec<String> {
        delete_one_char(&name.to_lowercase()).into_iter().collect()
    }
}

struct HomoglyphGen;
impl MutationGenerator for HomoglyphGen {
    fn name(&self) -> &'static str { "homoglyph" }
    fn generate(&self, name: &str, _ecosystem: Ecosystem) -> Vec<String> {
        let (normalized, had_homoglyphs) = normalize_homoglyphs(name);
        if had_homoglyphs { vec![normalized.to_lowercase()] } else { vec![] }
    }
}

struct ConfusedFormsGen;
impl MutationGenerator for ConfusedFormsGen {
    fn name(&self) -> &'static str { "confused-forms" }
    fn generate(&self, name: &str, ecosystem: Ecosystem) -> Vec<String> {
        apply_confused_forms(name, ecosystem)
    }
}

// -- Helper functions --------------------------------------------------------

/// Ecosystem-specific confused forms: terms that are interchangeable
/// and commonly swapped by AI or humans.
fn confused_forms(ecosystem: Ecosystem) -> &'static [(&'static str, &'static str)] {
    match ecosystem {
        Ecosystem::PyPI => &[("python", "py"), ("python-", "py-"), ("python_", "py_")],
        Ecosystem::Go => &[
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
pub(super) fn normalize_homoglyphs(name: &str) -> (String, bool) {
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
pub(super) fn known_scopes(ecosystem: Ecosystem) -> &'static [&'static str] {
    match ecosystem {
        Ecosystem::Npm => &[
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
        Ecosystem::Php => &[
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
        Ecosystem::Go => &[
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
        Ecosystem::Jvm => &[
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
pub(super) fn extract_scope(name: &str, ecosystem: Ecosystem) -> Option<String> {
    match ecosystem {
        Ecosystem::Npm => {
            // @scope/package -> @scope
            if name.starts_with('@') {
                name.split('/').next().map(|s| s.to_string())
            } else {
                None
            }
        }
        Ecosystem::Php => {
            // vendor/package -> vendor
            name.split('/')
                .next()
                .filter(|_| name.contains('/'))
                .map(|s| s.to_string())
        }
        Ecosystem::Go => {
            // github.com/org/repo -> github.com/org
            let parts: Vec<&str> = name.splitn(3, '/').collect();
            if parts.len() >= 2 {
                Some(format!("{}/{}", parts[0], parts[1]))
            } else {
                None
            }
        }
        Ecosystem::Jvm => {
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

/// Normalize separators: strip `-`, `_`, `.` for comparison.
pub(super) fn normalize_separators(name: &str) -> String {
    name.chars()
        .filter(|c| *c != '-' && *c != '_' && *c != '.')
        .collect()
}

/// Generate variants with one repeated character removed at each position.
pub(super) fn collapse_one_repeated(name: &str) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut results = Vec::new();
    let mut i = 0;
    while i < chars.len().saturating_sub(1) {
        if chars[i] == chars[i + 1] {
            let mut variant: Vec<char> = Vec::with_capacity(chars.len() - 1);
            variant.extend_from_slice(&chars[..i]);
            variant.extend_from_slice(&chars[i + 1..]);
            let s: String = variant.into_iter().collect();
            if !results.contains(&s) {
                results.push(s);
            }
            while i < chars.len().saturating_sub(1) && chars[i] == chars[i + 1] {
                i += 1;
            }
        }
        i += 1;
    }
    results
}

/// Strip trailing version suffixes: "requests2" -> "requests", "lodash-4" -> "lodash"
pub(super) fn strip_version_suffix(name: &str) -> String {
    let trimmed = name.trim_end_matches(|c: char| c.is_ascii_digit());
    trimmed
        .trim_end_matches('-')
        .trim_end_matches('_')
        .to_string()
}

/// Generate word-reordered variants: "json-parse" -> "parse-json"
pub(super) fn word_reorderings(name: &str) -> Vec<String> {
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
    let mut results = Vec::new();
    permutations(&mut segments, 0, sep, &mut results);
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
pub(super) fn apply_confused_forms(name: &str, ecosystem: Ecosystem) -> Vec<String> {
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

/// Delete one character at each position.
pub(super) fn delete_one_char(name: &str) -> Vec<String> {
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

/// Swap adjacent characters.
pub(super) fn adjacent_swaps(name: &str) -> Vec<String> {
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
