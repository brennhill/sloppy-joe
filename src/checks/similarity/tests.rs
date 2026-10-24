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
async fn reject_oversized_names_before_mutations() {
    let registry = FakeRegistry::empty();
    for ecosystem in [Ecosystem::Npm, Ecosystem::PyPI, Ecosystem::Go] {
        let deps = vec![dep_eco(&"ab".repeat(1024), ecosystem)];
        let err = check_similarity(&registry, &deps, ecosystem)
            .await
            .expect_err("oversized names must not reach mutation generation");
        assert!(err.to_string().contains("Scan not supported"), "{err}");
    }
}

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
    let registry = FakeRegistry::with(&["requests"]);
    let deps = vec![dep_eco("Requests", Ecosystem::PyPI)];
    let issues = check_similarity(&registry, &deps, Ecosystem::PyPI)
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
    assert!(!is_case_insensitive(Ecosystem::Npm));
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
async fn popular_dependency_with_obscure_lookalike_is_not_high_confidence() {
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
    // The candidate "express" has 500 downloads (from FakeRegistry metadata)
    // while the dependency "expresss" has 50M. That is evidence the
    // candidate is the lookalike, not that the dependency is a squat.
    let messages: Vec<_> = issues.iter().map(|i| &i.message).collect();
    assert!(
        !issues.iter().any(|i| i.message.contains("HIGH CONFIDENCE")),
        "A popular dependency must not be called a high-confidence squat: {messages:?}"
    );
    assert!(
        issues.iter().any(|i| i.message.contains("LOW CONFIDENCE")),
        "Reverse disparity should be noted: {messages:?}"
    );
    assert!(issues.iter().all(|i| i.severity == Severity::Error));
}
