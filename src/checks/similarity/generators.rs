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
/// Use `paranoid_generators()` for the full set including bitflip.
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
        Box::new(KeyboardProximityGen),
        Box::new(SegmentOverlapGen),
    ]
}

/// Returns all generators including expensive ones (bitflip).
/// Activated by --paranoid. Produces ~10x more mutations than default.
pub fn paranoid_generators() -> Vec<Box<dyn MutationGenerator>> {
    let mut gens = default_generators();
    gens.push(Box::new(BitflipGen));
    gens
}

// -- Generator implementations -----------------------------------------------

struct SeparatorSwapGen;
impl MutationGenerator for SeparatorSwapGen {
    fn name(&self) -> &'static str {
        "separator-swap"
    }
    fn generate(&self, name: &str, ecosystem: Ecosystem) -> Vec<String> {
        if ecosystem == Ecosystem::PyPI {
            return vec![];
        }
        let lower = name.to_lowercase();
        let mut results = Vec::new();
        let stripped = normalize_separators(&lower);
        if stripped != lower {
            results.push(stripped);
        }
        for &sep in &['-', '_', '.'] {
            let with_sep: String = lower
                .chars()
                .map(|c| {
                    if c == '-' || c == '_' || c == '.' {
                        sep
                    } else {
                        c
                    }
                })
                .collect();
            if with_sep != lower {
                results.push(with_sep);
            }
        }
        results
    }
}

struct CollapseRepeatedGen;
impl MutationGenerator for CollapseRepeatedGen {
    fn name(&self) -> &'static str {
        "collapse-repeated"
    }
    fn generate(&self, name: &str, _ecosystem: Ecosystem) -> Vec<String> {
        collapse_one_repeated(&name.to_lowercase())
    }
}

struct VersionSuffixGen;
impl MutationGenerator for VersionSuffixGen {
    fn name(&self) -> &'static str {
        "version-suffix"
    }
    fn generate(&self, name: &str, _ecosystem: Ecosystem) -> Vec<String> {
        let lower = name.to_lowercase();
        let stripped = strip_version_suffix(&lower);
        if stripped != lower {
            vec![stripped]
        } else {
            vec![]
        }
    }
}

struct WordReorderGen;
impl MutationGenerator for WordReorderGen {
    fn name(&self) -> &'static str {
        "word-reorder"
    }
    fn generate(&self, name: &str, _ecosystem: Ecosystem) -> Vec<String> {
        word_reorderings(&name.to_lowercase())
    }
}

struct AdjacentSwapGen;
impl MutationGenerator for AdjacentSwapGen {
    fn name(&self) -> &'static str {
        "char-swap"
    }
    fn generate(&self, name: &str, _ecosystem: Ecosystem) -> Vec<String> {
        adjacent_swaps(&name.to_lowercase())
    }
}

struct DeleteOneCharGen;
impl MutationGenerator for DeleteOneCharGen {
    fn name(&self) -> &'static str {
        "extra-char"
    }
    fn generate(&self, name: &str, _ecosystem: Ecosystem) -> Vec<String> {
        delete_one_char(&name.to_lowercase()).into_iter().collect()
    }
}

struct HomoglyphGen;
impl MutationGenerator for HomoglyphGen {
    fn name(&self) -> &'static str {
        "homoglyph"
    }
    fn generate(&self, name: &str, _ecosystem: Ecosystem) -> Vec<String> {
        let (normalized, had_homoglyphs) = normalize_homoglyphs(name);
        if had_homoglyphs {
            vec![normalized.to_lowercase()]
        } else {
            vec![]
        }
    }
}

struct ConfusedFormsGen;
impl MutationGenerator for ConfusedFormsGen {
    fn name(&self) -> &'static str {
        "confused-forms"
    }
    fn generate(&self, name: &str, ecosystem: Ecosystem) -> Vec<String> {
        apply_confused_forms(name, ecosystem)
    }
}

struct SegmentOverlapGen;
impl MutationGenerator for SegmentOverlapGen {
    fn name(&self) -> &'static str {
        "segment-overlap"
    }
    fn generate(&self, name: &str, ecosystem: Ecosystem) -> Vec<String> {
        segment_overlap_variants(&name.to_lowercase(), ecosystem)
    }
}

struct BitflipGen;
impl MutationGenerator for BitflipGen {
    fn name(&self) -> &'static str {
        "bitflip"
    }
    fn generate(&self, name: &str, _ecosystem: Ecosystem) -> Vec<String> {
        bitflip_variants(&name.to_lowercase())
    }
}

struct KeyboardProximityGen;
impl MutationGenerator for KeyboardProximityGen {
    fn name(&self) -> &'static str {
        "keyboard-proximity"
    }
    fn generate(&self, name: &str, _ecosystem: Ecosystem) -> Vec<String> {
        keyboard_proximity_variants(&name.to_lowercase())
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

/// Normalize a name by replacing Unicode confusables with ASCII equivalents.
/// Uses the full Unicode confusables table (445 entries) from confusables.rs.
pub(super) fn normalize_homoglyphs(name: &str) -> (String, bool) {
    super::confusables::normalize(name)
}

// -- Scope/namespace squatting detection ------------------------------------

/// Known-good scopes/namespaces per ecosystem.
pub(super) fn known_scopes(ecosystem: Ecosystem) -> &'static [&'static str] {
    match ecosystem {
        Ecosystem::Npm => &[
            // Build tools & frameworks
            "@types",
            "@babel",
            "@angular",
            "@vue",
            "@nuxt",
            "@nestjs",
            "@react-native",
            "@svelte",
            "@solidjs",
            "@qwik",
            "@nextjs",
            "@remix-run",
            "@astrojs",
            "@gatsbyjs",
            // UI libraries
            "@emotion",
            "@mui",
            "@chakra-ui",
            "@radix-ui",
            "@headlessui",
            "@shadcn",
            "@mantine",
            "@ant-design",
            // Testing
            "@testing-library",
            "@storybook",
            "@jest",
            "@playwright",
            "@vitest",
            "@cypress",
            // Linting & formatting
            "@typescript-eslint",
            "@eslint",
            "@prettier",
            // Bundlers
            "@rollup",
            "@vitejs",
            "@parcel",
            "@swc",
            "@esbuild",
            // State management
            "@reduxjs",
            "@tanstack",
            "@trpc",
            "@apollo",
            // Database & ORM
            "@prisma",
            "@drizzle-team",
            "@supabase",
            "@neon",
            // Cloud providers
            "@aws-sdk",
            "@azure",
            "@google-cloud",
            "@firebase",
            "@pulumi",
            "@terraform",
            // Hosting & edge
            "@vercel",
            "@netlify",
            "@cloudflare",
            "@fly",
            // DevOps & CI
            "@octokit",
            "@actions",
            "@github",
            "@gitlab",
            // Observability
            "@sentry",
            "@datadog",
            "@opentelemetry",
            "@grafana",
            // Protocols
            "@grpc",
            "@protobuf",
            "@bufbuild",
            "@connectrpc",
            // Auth
            "@auth",
            "@clerk",
            "@auth0",
            // Monorepo tools
            "@nx",
            "@lerna",
            "@changesets",
            "@turbo",
            // Package managers
            "@pnpm",
            "@yarnpkg",
            "@npmcli",
            // AI/ML
            "@huggingface",
            "@langchain",
            "@anthropic",
            // Other major orgs
            "@stripe",
            "@twilio",
            "@sendgrid",
            "@mapbox",
            "@elastic",
            "@mongodb",
            "@redis",
            "@hono",
            "@fastify",
            "@express",
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
            // Web frameworks
            "github.com/gin-gonic",
            "github.com/labstack",
            "github.com/gofiber",
            "github.com/gorilla",
            "github.com/go-chi",
            "github.com/julienschmidt",
            // CLI & config
            "github.com/spf13",
            "github.com/urfave",
            "github.com/alecthomas",
            // Testing
            "github.com/stretchr",
            "github.com/onsi",
            // Database
            "github.com/go-redis",
            "github.com/jackc",
            "github.com/go-sql-driver",
            "github.com/jmoiron",
            "github.com/go-gorm",
            // Logging
            "github.com/sirupsen",
            "github.com/rs",
            "github.com/uber-go",
            // HTTP
            "github.com/valyala",
            // Messaging
            "github.com/nats-io",
            "github.com/segmentio",
            "github.com/confluentinc",
            // Infrastructure
            "github.com/hashicorp",
            "github.com/prometheus",
            "github.com/grafana",
            "github.com/grpc",
            "github.com/envoyproxy",
            // Standard org scopes
            "github.com/golang",
            "github.com/google",
            "github.com/aws",
            "github.com/Azure",
            "github.com/kubernetes",
            "github.com/docker",
            "github.com/etcd-io",
            "github.com/cockroachdb",
            "github.com/containerd",
            "github.com/opencontainers",
            "github.com/cncf",
            "github.com/open-telemetry",
            // Module hosts
            "go.uber.org",
            "google.golang.org",
            "golang.org",
            "cloud.google.com",
            "go.opentelemetry.io",
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

/// Generate bitflip variants: flip each bit in each ASCII character.
/// Only flips bits that produce another printable ASCII letter/digit.
/// "express" → "dxpress" (e XOR 1 = d), "gxpress" (e XOR 2 = g), etc.
pub(super) fn bitflip_variants(name: &str) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut results = HashSet::new();
    for (i, &ch) in chars.iter().enumerate() {
        if !ch.is_ascii() {
            continue;
        }
        let byte = ch as u8;
        for bit in 0..8 {
            let flipped = byte ^ (1 << bit);
            let flipped_char = flipped as char;
            // Only keep if result is a valid package-name character
            if (flipped_char.is_ascii_alphanumeric() || flipped_char == '-' || flipped_char == '_')
                && flipped_char != ch
            {
                let mut variant = chars.clone();
                variant[i] = flipped_char;
                let s: String = variant.into_iter().collect();
                results.insert(s);
            }
        }
    }
    results.into_iter().collect()
}

/// QWERTY keyboard adjacency map for common package-name characters.
fn keyboard_neighbors() -> &'static [(char, &'static [char])] {
    &[
        ('q', &['w', 'a']),
        ('w', &['q', 'e', 'a', 's']),
        ('e', &['w', 'r', 's', 'd']),
        ('r', &['e', 't', 'd', 'f']),
        ('t', &['r', 'y', 'f', 'g']),
        ('y', &['t', 'u', 'g', 'h']),
        ('u', &['y', 'i', 'h', 'j']),
        ('i', &['u', 'o', 'j', 'k']),
        ('o', &['i', 'p', 'k', 'l']),
        ('p', &['o', 'l']),
        ('a', &['q', 'w', 's', 'z']),
        ('s', &['w', 'e', 'a', 'd', 'z', 'x']),
        ('d', &['e', 'r', 's', 'f', 'x', 'c']),
        ('f', &['r', 't', 'd', 'g', 'c', 'v']),
        ('g', &['t', 'y', 'f', 'h', 'v', 'b']),
        ('h', &['y', 'u', 'g', 'j', 'b', 'n']),
        ('j', &['u', 'i', 'h', 'k', 'n', 'm']),
        ('k', &['i', 'o', 'j', 'l', 'm']),
        ('l', &['o', 'p', 'k']),
        ('z', &['a', 's', 'x']),
        ('x', &['z', 's', 'd', 'c']),
        ('c', &['x', 'd', 'f', 'v']),
        ('v', &['c', 'f', 'g', 'b']),
        ('b', &['v', 'g', 'h', 'n']),
        ('n', &['b', 'h', 'j', 'm']),
        ('m', &['n', 'j', 'k']),
        ('1', &['2', 'q']),
        ('2', &['1', '3', 'q', 'w']),
        ('3', &['2', '4', 'w', 'e']),
        ('4', &['3', '5', 'e', 'r']),
        ('5', &['4', '6', 'r', 't']),
        ('6', &['5', '7', 't', 'y']),
        ('7', &['6', '8', 'y', 'u']),
        ('8', &['7', '9', 'u', 'i']),
        ('9', &['8', '0', 'i', 'o']),
        ('0', &['9', 'o', 'p']),
    ]
}

/// Check if dep name is a popular package name with extra segments (combo-squatting).
/// "react-hooks-utils" → checks if "react-hooks" is a top package.
/// "react" → no segments to remove, skipped.
/// Also checks if dep segments are a superset of a popular package's segments.
pub(super) fn segment_overlap_variants(name: &str, ecosystem: Ecosystem) -> Vec<String> {
    let top = super::popular::top_packages(ecosystem);
    if top.is_empty() {
        return vec![];
    }

    let separators = ['-', '_', '.'];
    let sep = separators
        .iter()
        .find(|&&s| name.contains(s))
        .copied()
        .unwrap_or('-');
    let segments: Vec<&str> = name.split(['-', '_', '.']).collect();

    if segments.len() < 2 {
        return vec![];
    }

    let mut results = Vec::new();

    // Strategy 1: remove one segment at a time and check if result is a top package
    for i in 0..segments.len() {
        let reduced: Vec<&str> = segments
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, s)| *s)
            .collect();
        let candidate = reduced.join(&sep.to_string());
        let candidate_normalized = candidate.replace(['_', '.'], "-");
        if top.iter().any(|&pkg| {
            let pkg_normalized = pkg.replace(['_', '.'], "-");
            pkg_normalized == candidate_normalized
        }) {
            results.push(candidate);
        }
    }

    results
}

/// Generate keyboard proximity variants: replace each character with its
/// QWERTY neighbors. "react" → "eeact", "rwact", "resct", etc.
pub(super) fn keyboard_proximity_variants(name: &str) -> Vec<String> {
    let neighbors = keyboard_neighbors();
    let chars: Vec<char> = name.chars().collect();
    let mut results = HashSet::new();
    for (i, &ch) in chars.iter().enumerate() {
        if let Some((_, adjacents)) = neighbors.iter().find(|(k, _)| *k == ch) {
            for &neighbor in *adjacents {
                let mut variant = chars.clone();
                variant[i] = neighbor;
                let s: String = variant.into_iter().collect();
                results.insert(s);
            }
        }
    }
    results.into_iter().collect()
}
