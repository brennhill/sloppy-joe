//! Which version of a package a projection checks: the newest version PyPI lists that every
//! collected specifier allows, as pip would pick without a lockfile.
//!
//! pip skips yanked versions unless a requirement pins one exactly (PEP 592) and prereleases
//! unless nothing else matches. When the specifiers cannot all be met, the newest version each
//! one allows is checked instead, so the projection never checks nothing.

use crate::parsers::python_version::specifier_contains;
use crate::registry::pypi_release::PypiVersionListing;
use pep440_rs::{Operator, Version, VersionSpecifier, VersionSpecifiers};
use std::collections::BTreeSet;

/// The versions to check for one package.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Choice {
    pub(super) versions: Vec<String>,
    /// Why the specifiers could not be met together, for a warning. `None` when they were.
    pub(super) conflict: Option<String>,
}

/// One collected specifier: its text and, when it is valid PEP 440, its clauses.
struct Requirement<'a> {
    raw: &'a str,
    clauses: Option<VersionSpecifiers>,
}

fn requirements(specs: &BTreeSet<String>) -> Vec<Requirement<'_>> {
    specs
        .iter()
        .map(|raw| raw.trim())
        // Pipenv writes `*` for "any version".
        .filter(|raw| !raw.is_empty() && *raw != "*")
        .map(|raw| Requirement {
            raw,
            clauses: raw.parse().ok(),
        })
        .collect()
}

fn allows(clauses: &VersionSpecifiers, version: &Version) -> bool {
    clauses
        .iter()
        .all(|clause| specifier_contains(clause, version))
}

fn pins(clause: &VersionSpecifier) -> bool {
    matches!(clause.operator(), Operator::Equal | Operator::ExactEqual)
}

/// The version an `==` pin names, when it satisfies every other specifier: no listing is needed
/// to choose it.
pub(super) fn exact_pin(specs: &BTreeSet<String>) -> Option<String> {
    let requirements = requirements(specs);
    if requirements.iter().any(|req| req.clauses.is_none()) {
        return None;
    }
    let pinned = requirements
        .iter()
        .filter_map(|req| req.clauses.as_ref())
        .flat_map(|clauses| clauses.iter())
        .find(|clause| *clause.operator() == Operator::Equal)?
        .version()
        .clone();
    requirements
        .iter()
        .filter_map(|req| req.clauses.as_ref())
        .all(|clauses| allows(clauses, &pinned))
        .then(|| pinned.to_string())
}

/// The newest listed version every set of `clauses` allows.
fn newest(
    listing: &[(Version, &PypiVersionListing)],
    clauses: &[&VersionSpecifiers],
) -> Option<String> {
    let pinned = clauses.iter().any(|clauses| clauses.iter().any(pins));
    let allowed = |prereleases: bool| {
        listing
            .iter()
            .filter(|(version, listed)| {
                (!listed.yanked || pinned)
                    && (prereleases || !version.any_prerelease())
                    && clauses.iter().all(|clauses| allows(clauses, version))
            })
            .max_by(|a, b| a.0.cmp(&b.0))
            .map(|(_, listed)| listed.version.clone())
    };
    allowed(false).or_else(|| allowed(true))
}

/// The versions to check for a package PyPI lists as `listing`, given every specifier collected
/// for it. Versions that are not valid PEP 440 are skipped, as pip skips them.
pub(super) fn choose(listing: &[PypiVersionListing], specs: &BTreeSet<String>) -> Choice {
    let parsed: Vec<(Version, &PypiVersionListing)> = listing
        .iter()
        .filter_map(|listed| Some((listed.version.parse().ok()?, listed)))
        .collect();
    let requirements = requirements(specs);
    let readable: Vec<&VersionSpecifiers> = requirements
        .iter()
        .filter_map(|req| req.clauses.as_ref())
        .collect();
    let unreadable: Vec<&str> = requirements
        .iter()
        .filter(|req| req.clauses.is_none())
        .map(|req| req.raw)
        .collect();
    let unreadable_note = (!unreadable.is_empty()).then(|| {
        format!(
            "specifiers {} are not valid PEP 440 and were ignored",
            quoted(unreadable.iter().copied())
        )
    });
    if let Some(version) = newest(&parsed, &readable) {
        return Choice {
            versions: vec![version],
            conflict: unreadable_note,
        };
    }
    let mut versions = Vec::new();
    for clauses in &readable {
        if let Some(version) = newest(&parsed, &[clauses])
            && !versions.contains(&version)
        {
            versions.push(version);
        }
    }
    let mut conflict = format!(
        "no published version satisfies every requirement on it ({})",
        quoted(requirements.iter().map(|req| req.raw))
    );
    if versions.is_empty() {
        conflict.push_str("; no version satisfies any of them, so none was checked");
    } else {
        conflict.push_str(&format!(
            "; checked the newest version each allows: {}",
            versions.join(", ")
        ));
    }
    if let Some(note) = unreadable_note {
        conflict.push_str(&format!("; {note}"));
    }
    Choice {
        versions,
        conflict: Some(conflict),
    }
}

fn quoted<'a>(items: impl Iterator<Item = &'a str>) -> String {
    items
        .map(|item| format!("'{}'", crate::report::sanitize_for_terminal(item)))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
#[path = "select_tests.rs"]
mod tests;
