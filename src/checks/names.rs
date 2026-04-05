//! Check name constants. Every check name used in Issue construction
//! should reference a constant from here to prevent typos.

// -- Top-level checks --
pub const CANONICAL: &str = "canonical";
pub const EXISTENCE: &str = "existence";
pub const EXISTENCE_REGISTRY_UNREACHABLE: &str = "existence/registry-unreachable";

// -- Metadata signals --
pub const METADATA_VERSION_AGE: &str = "metadata/version-age";
pub const METADATA_NEW_PACKAGE: &str = "metadata/new-package";
pub const METADATA_LOW_DOWNLOADS: &str = "metadata/low-downloads";
pub const METADATA_INSTALL_SCRIPT_RISK: &str = "metadata/install-script-risk";
pub const METADATA_DEPENDENCY_EXPLOSION: &str = "metadata/dependency-explosion";
pub const METADATA_MAINTAINER_CHANGE: &str = "metadata/maintainer-change";
pub const METADATA_PUBLISHER_SCRIPT_COMBO: &str = "metadata/publisher-script-combo";
pub const METADATA_PARSE_FAILED: &str = "metadata/parse-failed";
pub const METADATA_NO_REPOSITORY: &str = "metadata/no-repository";

// -- Similarity --
pub const SIMILARITY_REGISTRY_UNREACHABLE: &str = "similarity/registry-unreachable";
pub const SIMILARITY_SCOPE_SQUATTING: &str = "similarity/scope-squatting";
pub const SIMILARITY_CASE_VARIANT: &str = "similarity/case-variant";
pub const SIMILARITY_SEPARATOR_SWAP: &str = "similarity/separator-swap";
pub const SIMILARITY_COLLAPSE_REPEATED: &str = "similarity/collapse-repeated";
pub const SIMILARITY_VERSION_SUFFIX: &str = "similarity/version-suffix";
pub const SIMILARITY_WORD_REORDER: &str = "similarity/word-reorder";
pub const SIMILARITY_CHAR_SWAP: &str = "similarity/char-swap";
pub const SIMILARITY_EXTRA_CHAR: &str = "similarity/extra-char";
pub const SIMILARITY_HOMOGLYPH: &str = "similarity/homoglyph";
pub const SIMILARITY_CONFUSED_FORMS: &str = "similarity/confused-forms";
pub const SIMILARITY_BITFLIP: &str = "similarity/bitflip";
pub const SIMILARITY_KEYBOARD_PROXIMITY: &str = "similarity/keyboard-proximity";
pub const SIMILARITY_SEGMENT_OVERLAP: &str = "similarity/segment-overlap";
pub const SIMILARITY_MUTATION_MATCH: &str = "similarity/mutation-match";

/// Map a generator name (from MutationGenerator::name()) to its check name constant.
pub fn similarity_check_name(generator_name: &str) -> &'static str {
    match generator_name {
        "separator-swap" => SIMILARITY_SEPARATOR_SWAP,
        "collapse-repeated" => SIMILARITY_COLLAPSE_REPEATED,
        "version-suffix" => SIMILARITY_VERSION_SUFFIX,
        "word-reorder" => SIMILARITY_WORD_REORDER,
        "char-swap" => SIMILARITY_CHAR_SWAP,
        "extra-char" => SIMILARITY_EXTRA_CHAR,
        "homoglyph" => SIMILARITY_HOMOGLYPH,
        "confused-forms" => SIMILARITY_CONFUSED_FORMS,
        "bitflip" => SIMILARITY_BITFLIP,
        "keyboard-proximity" => SIMILARITY_KEYBOARD_PROXIMITY,
        "segment-overlap" => SIMILARITY_SEGMENT_OVERLAP,
        "scope-squatting" => SIMILARITY_SCOPE_SQUATTING,
        "case-variant" => SIMILARITY_CASE_VARIANT,
        _ => SIMILARITY_MUTATION_MATCH,
    }
}

// -- Metadata --
pub const METADATA_REGISTRY_UNREACHABLE: &str = "metadata/registry-unreachable";

// -- Malicious --
pub const MALICIOUS_KNOWN_VULNERABILITY: &str = "malicious/known-vulnerability";
pub const MALICIOUS_REGISTRY_UNREACHABLE: &str = "malicious/registry-unreachable";

// -- Resolution --
pub const RESOLUTION_PARSE_FAILED: &str = "resolution/parse-failed";
pub const RESOLUTION_MISSING_LOCKFILE_ENTRY: &str = "resolution/missing-lockfile-entry";
pub const RESOLUTION_LOCKFILE_OUT_OF_SYNC: &str = "resolution/lockfile-out-of-sync";
pub const RESOLUTION_AMBIGUOUS: &str = "resolution/ambiguous";
pub const RESOLUTION_NO_EXACT_VERSION: &str = "resolution/no-exact-version";
pub const RESOLUTION_NO_TRUSTED_LOCKFILE: &str = "resolution/no-trusted-lockfile";
pub const RESOLUTION_NO_TRUSTED_LOCKFILE_SYNC: &str = "resolution/no-trusted-lockfile-sync";
pub const RESOLUTION_NPM_ALIAS: &str = "resolution/npm-alias";
pub const RESOLUTION_NO_TRUSTED_TRANSITIVE_COVERAGE: &str =
    "resolution/no-trusted-transitive-coverage";
pub const RESOLUTION_LOCAL_DEPENDENCY_SOURCE: &str = "resolution/local-dependency-source";
pub const RESOLUTION_UNTRUSTED_REGISTRY_SOURCE: &str = "resolution/untrusted-registry-source";
pub const RESOLUTION_SOURCE_MISMATCH: &str = "resolution/source-mismatch";
pub const RESOLUTION_UNUSED_DECLARED_SOURCE: &str = "resolution/unused-declared-source";
pub const RESOLUTION_UNTRUSTED_GIT_SOURCE: &str = "resolution/untrusted-git-source";
pub const RESOLUTION_BLOCKED_PROVENANCE_REWRITE: &str = "resolution/blocked-provenance-rewrite";
pub const RESOLUTION_REDUCED_CONFIDENCE_GIT: &str = "resolution/reduced-confidence-git";
pub const RESOLUTION_PYTHON_LEGACY_MANIFEST: &str = "resolution/python-legacy-manifest";
pub const CONFIG_LOCAL_OVERLAY_RELAXATION: &str = "config/local-overlay-relaxation";

#[cfg(test)]
mod tests {
    use super::*;

    // Collect all constants for validation tests
    fn all_constants() -> Vec<&'static str> {
        vec![
            CANONICAL,
            EXISTENCE,
            EXISTENCE_REGISTRY_UNREACHABLE,
            METADATA_VERSION_AGE,
            METADATA_NEW_PACKAGE,
            METADATA_LOW_DOWNLOADS,
            METADATA_INSTALL_SCRIPT_RISK,
            METADATA_DEPENDENCY_EXPLOSION,
            METADATA_MAINTAINER_CHANGE,
            METADATA_PUBLISHER_SCRIPT_COMBO,
            METADATA_PARSE_FAILED,
            METADATA_NO_REPOSITORY,
            SIMILARITY_REGISTRY_UNREACHABLE,
            SIMILARITY_SCOPE_SQUATTING,
            SIMILARITY_CASE_VARIANT,
            SIMILARITY_SEPARATOR_SWAP,
            SIMILARITY_COLLAPSE_REPEATED,
            SIMILARITY_VERSION_SUFFIX,
            SIMILARITY_WORD_REORDER,
            SIMILARITY_CHAR_SWAP,
            SIMILARITY_EXTRA_CHAR,
            SIMILARITY_HOMOGLYPH,
            SIMILARITY_CONFUSED_FORMS,
            SIMILARITY_BITFLIP,
            SIMILARITY_KEYBOARD_PROXIMITY,
            SIMILARITY_SEGMENT_OVERLAP,
            SIMILARITY_MUTATION_MATCH,
            METADATA_REGISTRY_UNREACHABLE,
            MALICIOUS_KNOWN_VULNERABILITY,
            MALICIOUS_REGISTRY_UNREACHABLE,
            RESOLUTION_PARSE_FAILED,
            RESOLUTION_MISSING_LOCKFILE_ENTRY,
            RESOLUTION_LOCKFILE_OUT_OF_SYNC,
            RESOLUTION_AMBIGUOUS,
            RESOLUTION_NO_EXACT_VERSION,
            RESOLUTION_NO_TRUSTED_LOCKFILE,
            RESOLUTION_NO_TRUSTED_LOCKFILE_SYNC,
            RESOLUTION_NPM_ALIAS,
            RESOLUTION_NO_TRUSTED_TRANSITIVE_COVERAGE,
            RESOLUTION_LOCAL_DEPENDENCY_SOURCE,
            RESOLUTION_UNTRUSTED_REGISTRY_SOURCE,
            RESOLUTION_SOURCE_MISMATCH,
            RESOLUTION_UNUSED_DECLARED_SOURCE,
            RESOLUTION_UNTRUSTED_GIT_SOURCE,
            RESOLUTION_BLOCKED_PROVENANCE_REWRITE,
            RESOLUTION_REDUCED_CONFIDENCE_GIT,
            RESOLUTION_PYTHON_LEGACY_MANIFEST,
            CONFIG_LOCAL_OVERLAY_RELAXATION,
        ]
    }

    #[test]
    fn all_constants_are_non_empty() {
        for name in all_constants() {
            assert!(!name.is_empty(), "Check name constant must not be empty");
        }
    }

    #[test]
    fn no_duplicate_constants() {
        let all = all_constants();
        let mut seen = std::collections::HashSet::new();
        for name in &all {
            assert!(seen.insert(name), "Duplicate check name: {}", name);
        }
    }

    #[test]
    fn similarity_check_name_maps_all_generators() {
        assert_eq!(similarity_check_name("homoglyph"), SIMILARITY_HOMOGLYPH);
        assert_eq!(similarity_check_name("char-swap"), SIMILARITY_CHAR_SWAP);
        assert_eq!(
            similarity_check_name("separator-swap"),
            SIMILARITY_SEPARATOR_SWAP
        );
        assert_eq!(
            similarity_check_name("collapse-repeated"),
            SIMILARITY_COLLAPSE_REPEATED
        );
        assert_eq!(
            similarity_check_name("version-suffix"),
            SIMILARITY_VERSION_SUFFIX
        );
        assert_eq!(
            similarity_check_name("word-reorder"),
            SIMILARITY_WORD_REORDER
        );
        assert_eq!(similarity_check_name("extra-char"), SIMILARITY_EXTRA_CHAR);
        assert_eq!(
            similarity_check_name("confused-forms"),
            SIMILARITY_CONFUSED_FORMS
        );
        assert_eq!(
            similarity_check_name("scope-squatting"),
            SIMILARITY_SCOPE_SQUATTING
        );
        assert_eq!(
            similarity_check_name("case-variant"),
            SIMILARITY_CASE_VARIANT
        );
        assert_eq!(similarity_check_name("unknown"), SIMILARITY_MUTATION_MATCH);
    }
}
