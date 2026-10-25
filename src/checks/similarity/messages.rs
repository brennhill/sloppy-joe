use super::*;

/// Format a human-readable message for a match, given the generator name (from tagged mutations).
/// Replaces the old `classify_match` which re-ran all generators to determine the match type.
pub(crate) fn format_match_message(dep_name: &str, candidate: &str, generator: &str) -> String {
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
        "missing-char" => format!(
            "'{}' matches '{}' with one character missing. \
             A dropped character is a common typo and a known typosquatting pattern. \
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

pub(crate) fn is_suppressed(
    config: &crate::config::SloppyJoeConfig,
    ecosystem: Ecosystem,
    package: &str,
    candidate: &str,
    generator: &str,
) -> bool {
    config.is_similarity_exception(ecosystem.as_str(), package, candidate, generator)
}

/// Longest package name that is expanded into lookalike variants (npm's own limit is 214).
pub(crate) const MAX_SIMILARITY_NAME_CHARS: usize = 214;
