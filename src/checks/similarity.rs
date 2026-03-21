use crate::report::{Issue, Severity};
use crate::Dependency;
use std::collections::HashSet;

/// Placeholder popular package lists per ecosystem.
fn popular_packages(ecosystem: &str) -> &'static [&'static str] {
    match ecosystem {
        "npm" => &[
            "react", "express", "lodash", "axios", "webpack", "typescript",
            "next", "vue", "angular", "moment", "chalk", "commander",
            "debug", "uuid", "dotenv", "cors", "jsonwebtoken", "mongoose",
            "socket.io", "jest",
        ],
        "pypi" => &[
            "requests", "numpy", "pandas", "flask", "django", "pytest",
            "scipy", "matplotlib", "pillow", "sqlalchemy", "celery",
            "fastapi", "pydantic", "httpx", "uvicorn", "gunicorn",
            "boto3", "selenium", "scrapy", "beautifulsoup4",
        ],
        "cargo" => &[
            "serde", "tokio", "clap", "reqwest", "anyhow", "thiserror",
            "rand", "regex", "chrono", "hyper", "actix-web", "axum",
            "tracing", "log", "futures", "syn", "quote", "proc-macro2",
            "bytes", "tower",
        ],
        "go" => &[
            "github.com/gin-gonic/gin", "github.com/labstack/echo",
            "github.com/gofiber/fiber", "github.com/spf13/cobra",
            "github.com/spf13/viper", "go.uber.org/zap",
            "github.com/sirupsen/logrus", "gorm.io/gorm",
            "github.com/go-chi/chi", "github.com/gorilla/mux",
            "github.com/stretchr/testify", "github.com/go-redis/redis",
            "google.golang.org/grpc", "github.com/golang-jwt/jwt",
            "github.com/jackc/pgx", "github.com/nats-io/nats.go",
            "github.com/rs/zerolog", "github.com/valyala/fasthttp",
            "github.com/prometheus/client_golang", "github.com/hashicorp/consul",
        ],
        "ruby" => &[
            "rails", "puma", "sidekiq", "devise", "rspec", "rubocop",
            "faker", "nokogiri", "pg", "redis", "rack", "sinatra",
            "capybara", "bcrypt", "aws-sdk", "activerecord", "bundler",
            "rspec-rails", "factory_bot", "webpacker",
        ],
        "php" => &[
            "laravel/framework", "symfony/console", "guzzlehttp/guzzle",
            "phpunit/phpunit", "monolog/monolog", "doctrine/orm",
            "league/flysystem", "vlucas/phpdotenv", "predis/predis",
            "phpstan/phpstan", "symfony/http-foundation", "nikic/fast-route",
            "ramsey/uuid", "twig/twig", "carbon/carbon",
            "intervention/image", "spatie/laravel-permission",
            "filp/whoops", "mockery/mockery", "barryvdh/laravel-debugbar",
        ],
        "jvm" => &[
            "com.google.guava:guava", "org.springframework:spring-core",
            "junit:junit", "org.apache.commons:commons-lang3",
            "org.slf4j:slf4j-api", "ch.qos.logback:logback-classic",
            "com.fasterxml.jackson.core:jackson-databind",
            "org.projectlombok:lombok", "org.mockito:mockito-core",
            "io.netty:netty-all", "org.jetbrains.kotlin:kotlin-stdlib",
            "com.squareup.okhttp3:okhttp", "io.grpc:grpc-core",
            "org.apache.kafka:kafka-clients", "com.google.code.gson:gson",
            "org.hibernate:hibernate-core", "org.assertj:assertj-core",
            "io.micrometer:micrometer-core", "com.zaxxer:HikariCP",
            "org.apache.httpcomponents:httpclient",
        ],
        "dotnet" => &[
            "Newtonsoft.Json", "Microsoft.Extensions.DependencyInjection",
            "xunit", "Serilog", "AutoMapper", "MediatR",
            "FluentValidation", "Dapper", "Polly", "Moq",
            "Swashbuckle.AspNetCore", "StackExchange.Redis",
            "Microsoft.EntityFrameworkCore", "NUnit", "FluentAssertions",
            "Bogus", "Hangfire", "MassTransit",
            "Microsoft.Extensions.Logging", "Npgsql",
        ],
        _ => &[],
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

// ── Homoglyph detection ───────────────────────────────────────────

/// Map of common homoglyphs: (lookalike char, Latin equivalent).
fn homoglyph_map() -> &'static [(char, char)] {
    &[
        ('\u{0430}', 'a'), // Cyrillic а → Latin a
        ('\u{0435}', 'e'), // Cyrillic е → Latin e
        ('\u{043E}', 'o'), // Cyrillic о → Latin o
        ('\u{0440}', 'p'), // Cyrillic р → Latin p
        ('\u{0441}', 'c'), // Cyrillic с → Latin c
        ('\u{0443}', 'y'), // Cyrillic у → Latin y
        ('\u{0445}', 'x'), // Cyrillic х → Latin x
        ('\u{0455}', 's'), // Cyrillic ѕ → Latin s
        ('\u{0456}', 'i'), // Cyrillic і → Latin i
        ('\u{0458}', 'j'), // Cyrillic ј → Latin j
        ('\u{0501}', 'd'), // Cyrillic ԁ → Latin d
        ('\u{0261}', 'g'), // Latin ɡ → Latin g
        ('\u{2113}', 'l'), // Script ℓ → Latin l
        ('\u{FF10}', '0'), // Fullwidth 0
        ('\u{FF11}', '1'), // Fullwidth 1
        ('\u{2170}', 'i'), // Roman numeral ⅰ → Latin i
        ('\u{217C}', 'l'), // Roman numeral ⅼ → Latin l
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

// ── Scope/namespace squatting detection ────────────────────────────

/// Known-good scopes/namespaces per ecosystem.
fn known_scopes(ecosystem: &str) -> &'static [&'static str] {
    match ecosystem {
        "npm" => &[
            "@types", "@babel", "@angular", "@vue", "@nuxt", "@nestjs",
            "@react-native", "@emotion", "@mui", "@chakra-ui",
            "@testing-library", "@storybook", "@typescript-eslint",
            "@rollup", "@vitejs", "@svelte", "@tanstack",
            "@aws-sdk", "@azure", "@google-cloud", "@firebase",
            "@prisma", "@trpc", "@reduxjs", "@apollo",
            "@eslint", "@prettier", "@jest", "@playwright",
            "@vercel", "@netlify", "@cloudflare",
            "@octokit", "@actions", "@github",
            "@sentry", "@datadog",
            "@grpc", "@protobuf",
        ],
        "php" => &[
            "laravel", "symfony", "illuminate", "doctrine",
            "league", "guzzlehttp", "phpunit", "monolog",
            "spatie", "barryvdh", "filament", "livewire",
            "intervention", "predis", "ramsey", "vlucas",
            "phpstan", "mockery", "nikic", "twig",
            "psr", "composer", "sebastian",
        ],
        "go" => &[
            "github.com/gin-gonic", "github.com/labstack",
            "github.com/gofiber", "github.com/spf13",
            "github.com/stretchr", "github.com/gorilla",
            "github.com/go-chi", "github.com/go-redis",
            "github.com/sirupsen", "github.com/rs",
            "github.com/valyala", "github.com/jackc",
            "github.com/nats-io", "github.com/hashicorp",
            "github.com/prometheus", "github.com/grpc",
            "github.com/golang", "github.com/google",
            "github.com/aws", "github.com/Azure",
            "github.com/kubernetes", "github.com/docker",
            "github.com/etcd-io", "github.com/cockroachdb",
            "go.uber.org", "google.golang.org",
            "golang.org", "cloud.google.com",
        ],
        "jvm" => &[
            "com.google", "org.springframework", "org.apache",
            "io.netty", "com.fasterxml", "org.jetbrains",
            "com.squareup", "io.grpc", "org.slf4j",
            "ch.qos", "org.mockito", "org.assertj",
            "junit", "io.micrometer", "com.zaxxer",
            "org.hibernate", "org.projectlombok",
        ],
        _ => &[],
    }
}

/// Extract the scope/namespace from a package name for a given ecosystem.
fn extract_scope(name: &str, ecosystem: &str) -> Option<String> {
    match ecosystem {
        "npm" => {
            // @scope/package → @scope
            if name.starts_with('@') {
                name.split('/').next().map(|s| s.to_string())
            } else {
                None
            }
        }
        "php" => {
            // vendor/package → vendor
            name.split('/').next().filter(|_| name.contains('/')).map(|s| s.to_string())
        }
        "go" => {
            // github.com/org/repo → github.com/org
            let parts: Vec<&str> = name.splitn(3, '/').collect();
            if parts.len() >= 2 {
                Some(format!("{}/{}", parts[0], parts[1]))
            } else {
                None
            }
        }
        "jvm" => {
            // com.google.guava:guava → com.google
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

// ── Generative checks ──────────────────────────────────────────────
// Each function takes a dependency name and returns candidate names
// that would match a known package if this is a typosquat.

/// Normalize separators: strip `-`, `_`, `.` for comparison.
/// Catches: "python-dateutil" vs "pythondateutil"
fn normalize_separators(name: &str) -> String {
    name.chars().filter(|c| *c != '-' && *c != '_' && *c != '.').collect()
}

/// Generate variants with one repeated character removed at each position.
/// "expresss" → ["express"], "reeact" → ["react"], "llodash" → ["lodash"]
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

/// Strip trailing version suffixes: "requests2" → "requests", "lodash-4" → "lodash"
fn strip_version_suffix(name: &str) -> String {
    let trimmed = name.trim_end_matches(|c: char| c.is_ascii_digit());
    trimmed.trim_end_matches('-').trim_end_matches('_').to_string()
}

/// Generate word-reordered variants: "json-parse" → "parse-json"
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
    if segments.len() < 2 || segments.len() > 5 {
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
/// "python-dateutil" → "py-dateutil", "py-utils" → "python-utils"
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

/// Generate variants with one character inserted at each position.
/// "reqests" with every a-z inserted at every position → includes "requests"
/// This catches omitted-character typosquats where one letter was dropped.
fn insert_each_char(name: &str) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut results = HashSet::new();
    for pos in 0..=chars.len() {
        for c in b'a'..=b'z' {
            let mut variant = String::with_capacity(chars.len() + 1);
            for (i, &ch) in chars.iter().enumerate() {
                if i == pos {
                    variant.push(c as char);
                }
                variant.push(ch);
            }
            if pos == chars.len() {
                variant.push(c as char);
            }
            results.insert(variant);
        }
    }
    results.into_iter().collect()
}

/// Swap adjacent characters: "reqeust" → "request"
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

// ── Orchestration ──────────────────────────────────────────────────

fn is_case_insensitive(ecosystem: &str) -> bool {
    matches!(ecosystem, "npm" | "pypi" | "cargo" | "dotnet" | "php")
}

/// Max allowed Levenshtein distance, scaled by name length (fallback check).
fn max_distance(name_len: usize) -> usize {
    match name_len {
        0..=4 => 1,
        5..=8 => 2,
        _ => 3,
    }
}

/// Build a HashSet of popular package names (lowercased) for fast lookup.
fn build_corpus(popular: &[&str]) -> HashSet<String> {
    popular.iter().map(|p| p.to_lowercase()).collect()
}

/// Main entry point. Runs generative checks first, Levenshtein as fallback.
pub fn check_similarity(deps: &[Dependency], ecosystem: &str) -> Vec<Issue> {
    let popular = popular_packages(ecosystem);
    let case_insensitive = is_case_insensitive(ecosystem);
    let corpus = build_corpus(popular);
    let mut issues = Vec::new();
    let mut flagged: HashSet<String> = HashSet::new();

    for dep in deps {
        let dep_lower = dep.name.to_lowercase();

        // Exact match — safe, skip
        if corpus.contains(&dep_lower) && (case_insensitive || popular.contains(&dep.name.as_str())) {
            continue;
        }

        // On case-sensitive registries, flag case variants
        if !case_insensitive && corpus.contains(&dep_lower) {
            let original = popular.iter().find(|p| p.to_lowercase() == dep_lower).unwrap();
            issues.push(make_issue(
                &dep.name,
                original,
                "case-variant",
                &format!(
                    "'{}' differs from '{}' only in letter casing. On case-sensitive registries ({}) these resolve to different packages. An attacker could register the case variant.",
                    dep.name, original, ecosystem
                ),
                &format!("Use the exact casing '{}' in your manifest.", original),
            ));
            flagged.insert(dep.name.clone());
            continue;
        }

        // ── Scope/namespace squatting check ──
        if let Some(scope) = extract_scope(&dep.name, ecosystem) {
            let scopes = known_scopes(ecosystem);
            let scope_lower = scope.to_lowercase();
            let mut scope_flagged = false;
            for &known in scopes {
                let known_lower = known.to_lowercase();
                if scope_lower == known_lower {
                    // Exact match to a known scope — safe, skip this check
                    scope_flagged = false;
                    break;
                }
                let distance = strsim::levenshtein(&scope_lower, &known_lower);
                let threshold = max_distance(scope_lower.len());
                if distance > 0 && distance <= threshold {
                    if flagged.insert(dep.name.clone()) {
                        issues.push(make_issue(
                            &dep.name,
                            &dep.name, // no specific popular package to suggest
                            "scope-squatting",
                            &format!(
                                "Scope '{}' is {} character{} away from the known scope '{}'.\n      Scope squatting is a known supply chain attack vector.",
                                scope, distance, if distance == 1 { "" } else { "s" }, known
                            ),
                            &format!(
                                "If you meant '{}', fix the scope in your manifest.",
                                dep.name.replace(&scope, known)
                            ),
                        ));
                    }
                    scope_flagged = true;
                    break;
                }
            }
            if scope_flagged { continue; }
        }

        // ── Generative checks (specific, zero false positives) ──

        // 0. Homoglyph detection (zero false positives)
        let (normalized, had_homoglyphs) = normalize_homoglyphs(&dep.name);
        if had_homoglyphs {
            let norm_lower = normalized.to_lowercase();
            for &pop in popular {
                if norm_lower == pop.to_lowercase() {
                    if flagged.insert(dep.name.clone()) {
                        issues.push(make_issue(
                            &dep.name, pop, "homoglyph",
                            &format!(
                                "'{}' contains non-Latin characters that look identical to letters in '{}'. This is a homoglyph attack — the package name uses lookalike Unicode characters to impersonate a popular package.",
                                dep.name, pop
                            ),
                            &format!("Use the real package '{}' with standard Latin characters.", pop),
                        ));
                    }
                    break;
                }
            }
        }
        if flagged.contains(&dep.name) { continue; }

        // 1. Separator normalization
        let dep_normalized = normalize_separators(&dep_lower);
        for &pop in popular {
            let pop_normalized = normalize_separators(&pop.to_lowercase());
            if dep_normalized == pop_normalized && dep_lower != pop.to_lowercase() {
                if flagged.insert(dep.name.clone()) {
                    issues.push(make_issue(
                        &dep.name, pop, "separator-confusion",
                        &format!("'{}' matches '{}' after normalizing separators (-, _, .). These may resolve to different packages.", dep.name, pop),
                        &format!("Use the canonical name '{}' with the correct separators.", pop),
                    ));
                }
                break;
            }
        }
        if flagged.contains(&dep.name) { continue; }

        // 2. Collapsed repeated characters
        let collapsed_variants = collapse_one_repeated(&dep_lower);
        'repeated: for variant in &collapsed_variants {
            for &pop in popular {
                if variant == &pop.to_lowercase() {
                    if flagged.insert(dep.name.clone()) {
                        issues.push(make_issue(
                            &dep.name, pop, "repeated-chars",
                            &format!("'{}' matches '{}' after removing a repeated character. This is a common typosquatting pattern.", dep.name, pop),
                            &format!("Use '{}' — remove the repeated characters.", pop),
                        ));
                    }
                    break 'repeated;
                }
            }
        }
        if flagged.contains(&dep.name) { continue; }

        // 3. Version suffix stripping
        let dep_stripped = strip_version_suffix(&dep_lower);
        if dep_stripped != dep_lower {
            for &pop in popular {
                if dep_stripped == pop.to_lowercase() {
                    if flagged.insert(dep.name.clone()) {
                        issues.push(make_issue(
                            &dep.name, pop, "version-suffix",
                            &format!("'{}' looks like '{}' with a version suffix appended. An attacker could register the suffixed variant as a separate package.", dep.name, pop),
                            &format!("Use '{}' and specify the version in your manifest's version field, not the package name.", pop),
                        ));
                    }
                    break;
                }
            }
        }
        if flagged.contains(&dep.name) { continue; }

        // 4. Word reordering
        let reorderings = word_reorderings(&dep_lower);
        'reorder: for variant in &reorderings {
            for &pop in popular {
                if variant == &pop.to_lowercase() {
                    if flagged.insert(dep.name.clone()) {
                        issues.push(make_issue(
                            &dep.name, pop, "word-reorder",
                            &format!("'{}' is a reordering of '{}'. Word-swapped package names are a known typosquatting vector.", dep.name, pop),
                            &format!("Use '{}' — the segments are in the wrong order.", pop),
                        ));
                    }
                    break 'reorder;
                }
            }
        }
        if flagged.contains(&dep.name) { continue; }

        // 5. Adjacent character swaps
        let swaps = adjacent_swaps(&dep_lower);
        'swaps: for variant in &swaps {
            for &pop in popular {
                if variant == &pop.to_lowercase() {
                    if flagged.insert(dep.name.clone()) {
                        issues.push(make_issue(
                            &dep.name, pop, "char-swap",
                            &format!("'{}' matches '{}' with two adjacent characters swapped. This is a common typo and a known typosquatting pattern.", dep.name, pop),
                            &format!("Use '{}' — two characters are transposed.", pop),
                        ));
                    }
                    break 'swaps;
                }
            }
        }
        if flagged.contains(&dep.name) { continue; }

        // 6. Omitted character (one char dropped)
        let insertions = insert_each_char(&dep_lower);
        'omitted: for variant in &insertions {
            for &pop in popular {
                if variant == &pop.to_lowercase() {
                    if flagged.insert(dep.name.clone()) {
                        issues.push(make_issue(
                            &dep.name, pop, "omitted-char",
                            &format!("'{}' matches '{}' with one character inserted. A character may have been omitted — this is a common typosquatting pattern.", dep.name, pop),
                            &format!("Use '{}' — a character appears to be missing.", pop),
                        ));
                    }
                    break 'omitted;
                }
            }
        }
        if flagged.contains(&dep.name) { continue; }

        // 7. Ecosystem-specific confused forms
        let confused = apply_confused_forms(&dep.name, ecosystem);
        'confused: for variant in &confused {
            for &pop in popular {
                if variant == &pop.to_lowercase() {
                    if flagged.insert(dep.name.clone()) {
                        issues.push(make_issue(
                            &dep.name, pop, "confused-form",
                            &format!("'{}' is a confused form of '{}'. These are commonly interchanged but resolve to different packages.", dep.name, pop),
                            &format!("Use the canonical name '{}'.", pop),
                        ));
                    }
                    break 'confused;
                }
            }
        }
        if flagged.contains(&dep.name) { continue; }

        // ── Fallback: Levenshtein distance (catches novel mutations) ──
        let threshold = max_distance(dep_lower.len());
        for &pop in popular {
            let pop_lower = pop.to_lowercase();
            let distance = strsim::levenshtein(&dep_lower, &pop_lower);
            if distance > 0 && distance <= threshold {
                if flagged.insert(dep.name.clone()) {
                    issues.push(make_issue(
                        &dep.name, pop, "edit-distance",
                        &format!(
                            "'{}' is {} character{} away from '{}'. This could be a typosquat.",
                            dep.name, distance, if distance == 1 { "" } else { "s" }, pop
                        ),
                        &format!(
                            "If you meant '{}', fix the name. If '{}' is intentional, add it to the 'allowed' list.",
                            pop, dep.name
                        ),
                    ));
                }
                break;
            }
        }
    }

    issues
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(name: &str) -> Dependency {
        Dependency { name: name.to_string(), version: None, ecosystem: "npm".to_string() }
    }

    fn dep_eco(name: &str, ecosystem: &str) -> Dependency {
        Dependency { name: name.to_string(), version: None, ecosystem: ecosystem.to_string() }
    }

    // ── Exact match ──

    #[test]
    fn exact_match_produces_no_issue() {
        let deps = vec![dep("react")];
        let issues = check_similarity(&deps, "npm");
        assert!(issues.is_empty());
    }

    // ── Generative: separator normalization ──

    #[test]
    fn separator_confusion_hyphen_vs_underscore() {
        // "socket_io" should match "socket.io" after separator normalization
        let deps = vec![dep("socket_io")];
        let issues = check_similarity(&deps, "npm");
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("separator"));
        assert_eq!(issues[0].suggestion, Some("socket.io".to_string()));
    }

    #[test]
    fn separator_removed_entirely() {
        // "socketio" should match "socket.io"
        let deps = vec![dep("socketio")];
        let issues = check_similarity(&deps, "npm");
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("separator"));
    }

    // ── Generative: repeated characters ──

    #[test]
    fn repeated_chars_caught() {
        // "expresss" → "express"
        let deps = vec![dep("expresss")];
        let issues = check_similarity(&deps, "npm");
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("repeated"));
        assert_eq!(issues[0].suggestion, Some("express".to_string()));
    }

    #[test]
    fn repeated_chars_interior() {
        // "reeact" → "react"
        let deps = vec![dep("reeact")];
        let issues = check_similarity(&deps, "npm");
        assert!(!issues.is_empty());
        assert_eq!(issues[0].suggestion, Some("react".to_string()));
    }

    // ── Generative: version suffix ──

    #[test]
    fn version_suffix_caught() {
        // "react2" → "react"
        let deps = vec![dep("react2")];
        let issues = check_similarity(&deps, "npm");
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("version"));
        assert_eq!(issues[0].suggestion, Some("react".to_string()));
    }

    #[test]
    fn version_suffix_with_separator() {
        // "lodash-4" → "lodash"
        let deps = vec![dep("lodash-4")];
        let issues = check_similarity(&deps, "npm");
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("version"));
    }

    // ── Generative: word reordering ──

    #[test]
    fn word_reorder_caught() {
        // "bot-factory" should match "factory_bot" on Ruby
        let deps = vec![dep_eco("bot_factory", "ruby")];
        let issues = check_similarity(&deps, "ruby");
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("word-reorder"));
        assert_eq!(issues[0].suggestion, Some("factory_bot".to_string()));
    }

    // ── Generative: adjacent swaps ──

    #[test]
    fn adjacent_swap_caught() {
        // "reuqest" → swap e,u → "request" ... but "requests" is in pypi list
        // "reqeusts" → swap u,e → "requests"
        let deps = vec![dep_eco("reqeusts", "pypi")];
        let issues = check_similarity(&deps, "pypi");
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("char-swap"));
        assert_eq!(issues[0].suggestion, Some("requests".to_string()));
    }

    // ── Generative: confused forms ──

    #[test]
    fn confused_form_pypi_py_vs_python() {
        // Imagine "py-requests" should flag against "requests" via py- removal
        // Actually let's test: GuardDog swaps "python" <-> "py"
        // "python-flask" confused with "flask"? No, those are different lengths.
        // Better: confused_forms for pypi swaps "python" <-> "py"
        // So if we had "python-fastapi" it would produce "py-fastapi"
        // and if "py-fastapi" were popular it would match. But our popular list
        // has "fastapi" not "py-fastapi". This test validates the mechanism works.
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

    // ── Fallback: Levenshtein ──

    #[test]
    fn levenshtein_fallback_catches_novel_typo() {
        // "expresz" is edit distance 1 from "express", not caught by generative checks
        let deps = vec![dep("expresz")];
        let issues = check_similarity(&deps, "npm");
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("edit-distance"));
        assert_eq!(issues[0].suggestion, Some("express".to_string()));
    }

    #[test]
    fn levenshtein_short_name_threshold() {
        // "zzzz" — too far from anything, should not flag
        let deps = vec![dep("zzzz")];
        let issues = check_similarity(&deps, "npm");
        assert!(issues.is_empty());
    }

    // ── Case sensitivity ──

    #[test]
    fn case_insensitive_registry_skips_case_variant() {
        let deps = vec![dep("React")];
        let issues = check_similarity(&deps, "npm");
        assert!(issues.is_empty());
    }

    #[test]
    fn case_insensitive_registry_dotnet_skips_case_variant() {
        let deps = vec![dep_eco("newtonsoft.json", "dotnet")];
        let issues = check_similarity(&deps, "dotnet");
        assert!(issues.is_empty());
    }

    #[test]
    fn case_sensitive_registry_flags_case_variant_go() {
        let deps = vec![dep_eco("github.com/Gin-Gonic/Gin", "go")];
        let issues = check_similarity(&deps, "go");
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("case-variant"));
    }

    #[test]
    fn case_sensitive_registry_flags_case_variant_ruby() {
        let deps = vec![dep_eco("Rails", "ruby")];
        let issues = check_similarity(&deps, "ruby");
        assert!(!issues.is_empty());
        assert_eq!(issues[0].suggestion, Some("rails".to_string()));
    }

    #[test]
    fn case_sensitive_registry_flags_case_variant_jvm() {
        let deps = vec![dep_eco("Junit:Junit", "jvm")];
        let issues = check_similarity(&deps, "jvm");
        assert!(!issues.is_empty());
    }

    #[test]
    fn case_sensitive_registry_exact_match_no_issue() {
        let deps = vec![dep_eco("rails", "ruby")];
        let issues = check_similarity(&deps, "ruby");
        assert!(issues.is_empty());
    }

    // ── Helpers ──

    #[test]
    fn max_distance_thresholds() {
        assert_eq!(max_distance(0), 1);
        assert_eq!(max_distance(4), 1);
        assert_eq!(max_distance(5), 2);
        assert_eq!(max_distance(8), 2);
        assert_eq!(max_distance(9), 3);
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
    fn popular_packages_returns_entries_for_known_ecosystems() {
        for eco in &["npm", "pypi", "cargo", "go", "ruby", "php", "jvm", "dotnet"] {
            assert!(!popular_packages(eco).is_empty(), "empty for {}", eco);
        }
        assert!(popular_packages("unknown").is_empty());
    }

    #[test]
    fn unknown_ecosystem_returns_no_issues() {
        let deps = vec![dep("anything")];
        let issues = check_similarity(&deps, "unknown");
        assert!(issues.is_empty());
    }

    #[test]
    fn completely_unrelated_name_no_issue() {
        let deps = vec![dep("zzzzzzzzzzzzz")];
        let issues = check_similarity(&deps, "npm");
        assert!(issues.is_empty());
    }

    // ── Deduplication ──

    #[test]
    fn no_duplicate_flags_for_same_package() {
        // "expresss" would match repeated-chars AND levenshtein — should only report once
        let deps = vec![dep("expresss")];
        let issues = check_similarity(&deps, "npm");
        let count = issues.iter().filter(|i| i.package == "expresss").count();
        assert_eq!(count, 1);
    }

    // ── Unit tests for generative functions ──

    #[test]
    fn normalize_separators_works() {
        assert_eq!(normalize_separators("a-b_c.d"), "abcd");
        assert_eq!(normalize_separators("express"), "express");
    }

    #[test]
    fn collapse_one_repeated_works() {
        // "expresss" → remove one trailing s → "express"
        let variants = collapse_one_repeated("expresss");
        assert!(variants.contains(&"express".to_string()));

        // "reeact" → remove one e → "react"
        let variants = collapse_one_repeated("reeact");
        assert!(variants.contains(&"react".to_string()));

        // "llodash" → remove one l → "lodash"
        let variants = collapse_one_repeated("llodash");
        assert!(variants.contains(&"lodash".to_string()));

        // No repeated chars → empty
        let variants = collapse_one_repeated("react");
        assert!(variants.is_empty());

        // "express" has ss → produces "expres" (legitimate variant, won't match anything)
        let variants = collapse_one_repeated("express");
        assert!(variants.contains(&"expres".to_string()));
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

    // ── Omitted character ──

    #[test]
    fn omitted_char_generates_variants() {
        // "reqests" with 'u' inserted at position 3 → "requests"
        let variants = insert_each_char("reqests");
        assert!(variants.contains(&"requests".to_string()));
    }

    #[test]
    fn omitted_char_caught_in_check() {
        // "reqests" should match "requests" on pypi
        let deps = vec![dep_eco("reqests", "pypi")];
        let issues = check_similarity(&deps, "pypi");
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("omitted-char"));
        assert_eq!(issues[0].suggestion, Some("requests".to_string()));
    }

    #[test]
    fn omitted_char_not_flagged_for_exact_match() {
        let deps = vec![dep_eco("requests", "pypi")];
        let issues = check_similarity(&deps, "pypi");
        assert!(issues.is_empty());
    }

    // ── Homoglyph detection ──

    #[test]
    fn test_homoglyph_cyrillic_e() {
        // "r\u{0435}quests" — Cyrillic е instead of Latin e — should match "requests"
        let deps = vec![dep_eco("r\u{0435}quests", "pypi")];
        let issues = check_similarity(&deps, "pypi");
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("homoglyph"));
        assert_eq!(issues[0].suggestion, Some("requests".to_string()));
    }

    #[test]
    fn test_homoglyph_no_match() {
        // Pure ASCII name that doesn't match anything — should not trigger homoglyph
        let deps = vec![dep("my-safe-package")];
        let issues = check_similarity(&deps, "npm");
        let homoglyph_issues: Vec<_> = issues.iter().filter(|i| i.check.contains("homoglyph")).collect();
        assert!(homoglyph_issues.is_empty());
    }

    #[test]
    fn test_homoglyph_normalize_works() {
        // Verify normalization replaces Cyrillic chars with Latin equivalents
        let (normalized, replaced) = normalize_homoglyphs("r\u{0435}qu\u{0435}sts");
        assert_eq!(normalized, "requests");
        assert!(replaced);

        // Pure ASCII — no replacement
        let (normalized, replaced) = normalize_homoglyphs("requests");
        assert_eq!(normalized, "requests");
        assert!(!replaced);
    }

    // ── Scope/namespace squatting ──

    #[test]
    fn test_npm_scope_exact_match_no_flag() {
        // @types/lodash — known scope, should not flag scope-squatting
        let deps = vec![dep("@types/lodash")];
        let issues = check_similarity(&deps, "npm");
        let scope_issues: Vec<_> = issues.iter().filter(|i| i.check.contains("scope-squatting")).collect();
        assert!(scope_issues.is_empty());
    }

    #[test]
    fn test_npm_scope_squatting_flagged() {
        // @typos/lodash — scope '@typos' is distance 1 from '@types'
        let deps = vec![dep("@typos/lodash")];
        let issues = check_similarity(&deps, "npm");
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("scope-squatting"));
        assert!(issues[0].message.contains("@typos"));
        assert!(issues[0].message.contains("@types"));
    }

    #[test]
    fn test_npm_no_scope_no_flag() {
        // lodash — unscoped, scope-squatting check should not apply
        let deps = vec![dep("lodash")];
        let issues = check_similarity(&deps, "npm");
        let scope_issues: Vec<_> = issues.iter().filter(|i| i.check.contains("scope-squatting")).collect();
        assert!(scope_issues.is_empty());
    }

    #[test]
    fn test_php_vendor_squatting_flagged() {
        // larvael/framework — vendor 'larvael' is distance 2 from 'laravel'
        let deps = vec![dep_eco("larvael/framework", "php")];
        let issues = check_similarity(&deps, "php");
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("scope-squatting"));
        assert!(issues[0].message.contains("larvael"));
        assert!(issues[0].message.contains("laravel"));
    }

    #[test]
    fn test_go_org_squatting_flagged() {
        // github.com/gooogle/protobuf — org 'github.com/gooogle' is distance 1 from 'github.com/google'
        let deps = vec![dep_eco("github.com/gooogle/protobuf", "go")];
        let issues = check_similarity(&deps, "go");
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("scope-squatting"));
        assert!(issues[0].message.contains("github.com/gooogle"));
        assert!(issues[0].message.contains("github.com/google"));
    }

    #[test]
    fn test_jvm_group_squatting_flagged() {
        // com.gogle.guava:guava — group 'com.gogle' is distance 1 from 'com.google'
        let deps = vec![dep_eco("com.gogle.guava:guava", "jvm")];
        let issues = check_similarity(&deps, "jvm");
        assert!(!issues.is_empty());
        assert!(issues[0].check.contains("scope-squatting"));
        assert!(issues[0].message.contains("com.gogle"));
        assert!(issues[0].message.contains("com.google"));
    }

    #[test]
    fn test_extract_scope_npm() {
        assert_eq!(extract_scope("@types/lodash", "npm"), Some("@types".to_string()));
        assert_eq!(extract_scope("lodash", "npm"), None);
        assert_eq!(extract_scope("@babel/core", "npm"), Some("@babel".to_string()));
    }

    #[test]
    fn test_extract_scope_php() {
        assert_eq!(extract_scope("laravel/framework", "php"), Some("laravel".to_string()));
        assert_eq!(extract_scope("monolog", "php"), None);
    }

    #[test]
    fn test_extract_scope_go() {
        assert_eq!(extract_scope("github.com/google/protobuf", "go"), Some("github.com/google".to_string()));
        assert_eq!(extract_scope("go.uber.org/zap", "go"), Some("go.uber.org/zap".to_string()));
    }

    #[test]
    fn test_extract_scope_jvm() {
        assert_eq!(extract_scope("com.google.guava:guava", "jvm"), Some("com.google".to_string()));
        // "junit" has no dot-separated group, so no scope extracted
        assert_eq!(extract_scope("junit:junit", "jvm"), None);
    }

    #[test]
    fn test_known_scopes_populated() {
        for eco in &["npm", "php", "go", "jvm"] {
            assert!(!known_scopes(eco).is_empty(), "known_scopes empty for {}", eco);
        }
        assert!(known_scopes("unknown").is_empty());
    }
}
