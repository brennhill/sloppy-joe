//! Reading one `Requires-Dist` entry PyPI publishes for a release, and deciding whether pip could
//! install it. Markers are evaluated for every environment: one the evaluator cannot decide counts
//! as true. `extra == "..."` is decided by the extras requested of the package, or, when those
//! are unknown, by any extra the marker names.

use crate::parsers::python_scope::{
    PythonProfile, evaluate_marker_for_extras, evaluate_marker_for_profile_extras,
};
use anyhow::Result;
use std::collections::BTreeSet;

/// Which extras of a package are requested.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Extras {
    /// Exactly these (normalized; empty for none).
    Requested(BTreeSet<String>),
    /// Not known (the manifest parser does not record them): every extra counts.
    Any,
}

/// A requirement pip may install for the package that declares it.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Requirement {
    /// PEP 503 normalized name.
    pub(super) name: String,
    /// Specifier text, empty when unconstrained.
    pub(super) specifier: String,
    pub(super) extras: BTreeSet<String>,
}

/// `raw` as a requirement of `owner`, or `None` when its marker is false in every environment
/// for `extras`. An entry that is not a plain registry requirement (a direct URL, a local path,
/// an unreadable name) is an error: pip would install something the projection cannot model.
pub(super) fn applicable(
    raw: &str,
    owner: &str,
    extras: &Extras,
    profile: &PythonProfile,
) -> Result<Option<Requirement>> {
    let source = std::path::PathBuf::from(format!("PyPI metadata of {owner}"));
    let Some(scoped) = crate::parsers::requirements::parse_scoped_requirement_spec(raw, &source)?
    else {
        anyhow::bail!("empty requirement in PyPI metadata of {owner}");
    };
    if let Some(marker) = scoped.marker.as_deref() {
        let possible = match extras {
            Extras::Requested(active) => evaluate_marker_for_extras(marker, profile, active),
            Extras::Any => evaluate_marker_for_profile_extras(marker, profile),
        };
        // A marker the evaluator cannot read is undecided: the requirement stays.
        if possible.is_ok_and(|possible| !possible) {
            return Ok(None);
        }
    }
    Ok(Some(Requirement {
        name: scoped.dependency.name,
        specifier: scoped.dependency.version.unwrap_or_default(),
        extras: scoped.requested_extras,
    }))
}

#[cfg(test)]
#[path = "requires_tests.rs"]
mod tests;
