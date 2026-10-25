//! Verification of a candidate lockfile: version preservation against the old lockfile, and the
//! full rescan. Both read the scanner's own parsed lockfile representation, so the fixer and the
//! scan cannot disagree about what a lockfile says.

use crate::ecosystems::fixer::{LockedPackage, Snapshot};
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// How the candidate differs from the old lockfile.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub(super) struct VersionDiff {
    pub(super) added: Vec<String>,
    pub(super) removed: Vec<String>,
    pub(super) unchanged: usize,
    /// Why the candidate may not be written; empty when it may.
    pub(super) violations: Vec<String>,
}

type Recorded = BTreeSet<(Option<String>, Option<String>)>;

fn by_identity(packages: &[LockedPackage]) -> BTreeMap<(String, String), Recorded> {
    let mut map: BTreeMap<(String, String), Recorded> = BTreeMap::new();
    for package in packages {
        map.entry((package.name.clone(), package.version.clone()))
            .or_default()
            .insert((package.integrity.clone(), package.source.clone()));
    }
    map
}

fn describe(recorded: &Recorded) -> String {
    recorded
        .iter()
        .map(|(integrity, source)| {
            format!(
                "integrity {}, source {}",
                integrity.as_deref().unwrap_or("<none>"),
                source.as_deref().unwrap_or("<none>")
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Whether the old lockfile lacked a direct dependency the manifest declares: the only case in
/// which the candidate may add packages.
fn lacked_direct_dependency(old: &Snapshot) -> bool {
    if !old.exists {
        return true;
    }
    old.direct.iter().any(|(name, version)| {
        !old.packages.iter().any(|package| {
            package.name == *name && version.as_ref().is_none_or(|v| package.version == *v)
        })
    })
}

/// Compare `candidate` with `old`. `reachable` is what the old lockfile's projects reach
/// (`None`: everything counts as reachable).
pub(super) fn compare(
    old: &Snapshot,
    reachable: Option<&HashSet<(String, String)>>,
    candidate: &Snapshot,
) -> VersionDiff {
    let old_map = by_identity(&old.packages);
    let new_map = by_identity(&candidate.packages);
    let mut diff = VersionDiff::default();
    for (key, recorded) in &old_map {
        let label = format!("{}@{}", key.0, key.1);
        match new_map.get(key) {
            Some(candidate_recorded) if candidate_recorded == recorded => diff.unchanged += 1,
            Some(candidate_recorded) => diff.violations.push(format!(
                "{label} changed: the lockfile recorded {}, the candidate records {}",
                describe(recorded),
                describe(candidate_recorded)
            )),
            None => {
                let still_reachable = reachable.is_none_or(|set| set.contains(key));
                let replacement: Vec<&String> = new_map
                    .keys()
                    .filter(|(name, _)| *name == key.0)
                    .map(|(_, version)| version)
                    .collect();
                if !replacement.is_empty() && still_reachable {
                    diff.violations.push(format!(
                        "{label} changed version: the candidate locks {}",
                        replacement
                            .iter()
                            .map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                } else if still_reachable {
                    diff.violations.push(format!(
                        "{label} was removed although the project still reaches it"
                    ));
                } else {
                    diff.removed.push(label);
                }
            }
        }
    }
    diff.added = new_map
        .keys()
        .filter(|key| !old_map.contains_key(*key))
        .map(|(name, version)| format!("{name}@{version}"))
        .collect();
    if !diff.added.is_empty() && !lacked_direct_dependency(old) {
        diff.violations.push(format!(
            "the candidate adds {} package(s) ({}) although the lockfile already recorded every direct dependency",
            diff.added.len(),
            preview(&diff.added)
        ));
    }
    diff
}

/// The first few entries of a list, for messages.
pub(super) fn preview(items: &[String]) -> String {
    const SHOWN: usize = 10;
    let mut text = items
        .iter()
        .take(SHOWN)
        .map(|item| crate::report::sanitize_for_terminal(item))
        .collect::<Vec<_>>()
        .join(", ");
    if items.len() > SHOWN {
        text.push_str(&format!(" and {} more", items.len() - SHOWN));
    }
    text
}

/// Runs the `check --full` scan on a candidate tree.
#[async_trait::async_trait]
pub(super) trait CandidateScanner: Sync {
    async fn scan(
        &self,
        root: &std::path::Path,
        project_type: Option<&str>,
        config: &crate::config::SloppyJoeConfig,
        cache_dir: &std::path::Path,
    ) -> anyhow::Result<crate::report::ScanReport>;
}

/// The real rescan: the full online scan, with a cache of its own and no cached results trusted.
pub(super) struct FullRescan;

#[async_trait::async_trait]
impl CandidateScanner for FullRescan {
    async fn scan(
        &self,
        root: &std::path::Path,
        project_type: Option<&str>,
        config: &crate::config::SloppyJoeConfig,
        cache_dir: &std::path::Path,
    ) -> anyhow::Result<crate::report::ScanReport> {
        let opts = crate::ScanOptions {
            scan_mode: crate::ScanMode::Full,
            no_cache: true,
            cache_dir: Some(cache_dir),
            skip_hash_check: true,
            ..Default::default()
        };
        crate::scan_with_config(root, project_type, config.clone(), &opts).await
    }
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
