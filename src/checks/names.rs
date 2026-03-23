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
pub const METADATA_PARSE_FAILED: &str = "metadata/parse-failed";

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

#[cfg(test)]
mod tests {
    use super::*;

    // Collect all constants for validation tests
    fn all_constants() -> Vec<&'static str> {
        vec![
            CANONICAL, EXISTENCE, EXISTENCE_REGISTRY_UNREACHABLE,
            METADATA_VERSION_AGE, METADATA_NEW_PACKAGE, METADATA_LOW_DOWNLOADS,
            METADATA_INSTALL_SCRIPT_RISK, METADATA_DEPENDENCY_EXPLOSION,
            METADATA_MAINTAINER_CHANGE, METADATA_PARSE_FAILED,
            SIMILARITY_REGISTRY_UNREACHABLE, SIMILARITY_SCOPE_SQUATTING,
            SIMILARITY_CASE_VARIANT, SIMILARITY_SEPARATOR_SWAP,
            SIMILARITY_COLLAPSE_REPEATED, SIMILARITY_VERSION_SUFFIX,
            SIMILARITY_WORD_REORDER, SIMILARITY_CHAR_SWAP, SIMILARITY_EXTRA_CHAR,
            SIMILARITY_HOMOGLYPH, SIMILARITY_CONFUSED_FORMS,
            SIMILARITY_BITFLIP, SIMILARITY_KEYBOARD_PROXIMITY, SIMILARITY_MUTATION_MATCH,
            METADATA_REGISTRY_UNREACHABLE,
            MALICIOUS_KNOWN_VULNERABILITY, MALICIOUS_REGISTRY_UNREACHABLE,
            RESOLUTION_PARSE_FAILED, RESOLUTION_MISSING_LOCKFILE_ENTRY,
            RESOLUTION_LOCKFILE_OUT_OF_SYNC, RESOLUTION_AMBIGUOUS,
            RESOLUTION_NO_EXACT_VERSION,
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
        assert_eq!(similarity_check_name("separator-swap"), SIMILARITY_SEPARATOR_SWAP);
        assert_eq!(similarity_check_name("collapse-repeated"), SIMILARITY_COLLAPSE_REPEATED);
        assert_eq!(similarity_check_name("version-suffix"), SIMILARITY_VERSION_SUFFIX);
        assert_eq!(similarity_check_name("word-reorder"), SIMILARITY_WORD_REORDER);
        assert_eq!(similarity_check_name("extra-char"), SIMILARITY_EXTRA_CHAR);
        assert_eq!(similarity_check_name("confused-forms"), SIMILARITY_CONFUSED_FORMS);
        assert_eq!(similarity_check_name("scope-squatting"), SIMILARITY_SCOPE_SQUATTING);
        assert_eq!(similarity_check_name("case-variant"), SIMILARITY_CASE_VARIANT);
        assert_eq!(similarity_check_name("unknown"), SIMILARITY_MUTATION_MATCH);
    }
}
