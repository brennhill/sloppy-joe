//! Dropped-character typosquats ("expres" for "express").
//!
//! The inverse mutation (insert every character at every position) would be
//! n x alphabet registry probes per name, so instead the dependency is compared
//! locally against known names: the built-in popular lists and the exact names
//! the repo config declares. Only names that are exactly one deletion away are
//! probed, so this adds at most one registry query per matching known name.

use super::*;

/// Shortest dependency name matched here. One deletion from a four-letter name
/// ("uuid" -> "uid", "jest" -> "jet") lands on many unrelated real packages.
pub(crate) const MIN_MISSING_CHAR_NAME_CHARS: usize = 4;

pub(super) struct MissingCharGen;
impl MutationGenerator for MissingCharGen {
    fn name(&self) -> &'static str {
        "missing-char"
    }
    fn generate(&self, name: &str, ecosystem: Ecosystem) -> Vec<String> {
        missing_char_targets(name, ecosystem, &[])
    }
}

/// Known names (popular list plus `additional_roots`) that `name` equals after
/// one character was dropped. A dependency that is itself a popular package is
/// never reported: it is the real package, not the squat.
pub(crate) fn missing_char_targets(
    name: &str,
    ecosystem: Ecosystem,
    additional_roots: &[String],
) -> Vec<String> {
    // PyPI treats -, _ and . as the same name (PEP 503).
    let canonical = |s: &str| {
        let lower = s.to_lowercase();
        if ecosystem == Ecosystem::PyPI {
            lower.replace(['_', '.'], "-")
        } else {
            lower
        }
    };
    let dep = canonical(name);
    if dep.chars().count() < MIN_MISSING_CHAR_NAME_CHARS {
        return Vec::new();
    }
    let popular = super::super::popular::top_packages(ecosystem);
    if popular.iter().any(|known| canonical(known) == dep) {
        return Vec::new();
    }
    let mut seen = HashSet::new();
    popular
        .iter()
        .copied()
        .chain(additional_roots.iter().map(String::as_str))
        .filter(|root| is_one_deletion_of(&dep, &canonical(root)))
        .map(str::to_lowercase)
        .filter(|root| seen.insert(root.clone()))
        .collect()
}

/// True when `short` is `long` with exactly one non-separator character removed. A dropped
/// separator ("crossenv" for "cross-env") is the separator-swap generator's finding.
fn is_one_deletion_of(short: &str, long: &str) -> bool {
    let short: Vec<char> = short.chars().collect();
    let long: Vec<char> = long.chars().collect();
    if long.len() != short.len() + 1 {
        return false;
    }
    let common = short.iter().zip(&long).take_while(|(a, b)| a == b).count();
    // Any other position that yields the same deletion holds the same character.
    !matches!(long[common], '-' | '_' | '.') && short[common..] == long[common + 1..]
}
