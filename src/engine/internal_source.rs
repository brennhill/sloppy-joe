//! Source proof for `internal` prefix matches.
//!
//! An `internal` prefix (`acme-*`) names a family of packages; it says nothing about where a
//! member is installed from. A public package that merely carries the prefix (dependency
//! confusion, or a hallucinated name an attacker registered) would otherwise skip existence,
//! similarity and metadata checks. A prefix match therefore keeps its internal treatment only
//! when the public registry the scan uses confirms the name is not published there, so the
//! installer can only be getting it from the internal source. A published name, or a lookup that
//! fails, blocks and the package is scanned like any other. Exact `internal` entries are
//! deliberate per-name decisions in out-of-repo config and are not looked up.

use crate::*;
use futures::stream::{self, StreamExt};

/// Dependencies split into the classification tiers, with the internal prefix matches that
/// could not be proven moved back into the checked tiers.
pub(crate) struct ProvenTiers {
    pub checkable: Vec<Dependency>,
    pub non_internal: Vec<Dependency>,
    pub internal: Vec<Dependency>,
    pub issues: Vec<Issue>,
}

/// Direct-dependency tiers for a scan in `opts`' mode. Fast mode is local-only and runs no
/// registry check on any package, so it classifies without the (networked) proof.
pub(crate) async fn classify_direct_deps(
    deps: &[Dependency],
    config: &config::SloppyJoeConfig,
    ecosystem: Ecosystem,
    registry: &dyn Registry,
    opts: &ScanOptions<'_>,
) -> ProvenTiers {
    if opts.scan_mode.runs_full_checks() {
        return classify_deps_with_source_proof(deps, config, ecosystem, registry, "direct").await;
    }
    let (checkable, non_internal, internal) = classify_deps(deps, config, ecosystem);
    ProvenTiers {
        checkable,
        non_internal,
        internal,
        issues: Vec::new(),
    }
}

/// `classify_deps`, then source proof for every internal prefix match. `source` is
/// `"direct"` or `"transitive"` and is recorded on the blocking issues.
pub(crate) async fn classify_deps_with_source_proof(
    deps: &[Dependency],
    config: &config::SloppyJoeConfig,
    ecosystem: Ecosystem,
    registry: &dyn Registry,
    source: &str,
) -> ProvenTiers {
    let (mut checkable, mut non_internal, internal) = classify_deps(deps, config, ecosystem);
    let eco = ecosystem.as_str();
    let outcomes: Vec<(Dependency, Option<Issue>)> = stream::iter(internal)
        .map(|dep| async move {
            let issue = unproven_issue(&dep, config, eco, registry).await;
            (dep, issue)
        })
        .buffered(ecosystem.similarity_concurrency())
        .collect()
        .await;
    let mut tiers = ProvenTiers {
        checkable: Vec::new(),
        non_internal: Vec::new(),
        internal: Vec::new(),
        issues: Vec::new(),
    };
    let mut reported = std::collections::HashSet::new();
    for (dep, issue) in outcomes {
        let Some(mut issue) = issue else {
            tiers.internal.push(dep);
            continue;
        };
        // One finding per name, however many locked versions carry it.
        if reported.insert(dep.package_name().to_string()) {
            issue.source = Some(source.to_string());
            tiers.issues.push(issue);
        }
        if !config.is_allowed(eco, dep.package_name()) {
            checkable.push(dep.clone());
        }
        non_internal.push(dep);
    }
    tiers.checkable = checkable;
    tiers.non_internal = non_internal;
    tiers
}

/// `None` when the dependency's internal treatment stands; otherwise the blocking issue.
async fn unproven_issue(
    dep: &Dependency,
    config: &config::SloppyJoeConfig,
    ecosystem: &str,
    registry: &dyn Registry,
) -> Option<Issue> {
    let config::InternalMatch::Prefix(pattern) =
        config.internal_match(ecosystem, dep.package_name())?
    else {
        return None;
    };
    let name = dep.package_name();
    let why = match registry.exists(name).await {
        Ok(false) => return None,
        Ok(true) => format!(
            "a package named '{name}' is published on the public {ecosystem} registry, so the installer may resolve the public package instead of yours"
        ),
        Err(error) => format!(
            "the public {ecosystem} registry could not be queried to confirm '{name}' is not published there ({error:#})"
        ),
    };
    Some(
        Issue::new(name, checks::names::RESOLUTION_INTERNAL_SOURCE_UNPROVEN, Severity::Error)
            .message(format!(
                "'{name}' matches the internal prefix '{pattern}', but nothing proves it comes from your internal source: {why}. It was scanned as an external package."
            ))
            .fix(format!(
                "If '{name}' is yours, confirm the public package with that name is too (or that your installer can never reach it), then list the exact name in `internal`. Otherwise remove the dependency."
            )),
    )
}
