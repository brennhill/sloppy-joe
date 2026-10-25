use super::*;

pub(crate) const ORPHAN_NAMES_LISTED: usize = 10;

/// Non-blocking warning for lockfile entries that nothing reaches. Only used
/// when reachability is certain, so the installer never installs them.
pub(crate) fn stale_orphan_entries_issue(
    lockfile_path: &Path,
    mut names: Vec<String>,
    installer: &str,
    remedy: &'static crate::remedy::Remedy,
) -> Issue {
    names.sort();
    names.dedup();
    let listed = names
        .iter()
        .take(ORPHAN_NAMES_LISTED)
        .map(|name| crate::report::sanitize_for_terminal(name))
        .collect::<Vec<_>>()
        .join(", ");
    let more = names.len().saturating_sub(ORPHAN_NAMES_LISTED);
    let more = if more > 0 {
        format!(" (and {more} more)")
    } else {
        String::new()
    };
    Issue::new(
        lockfile_path.display().to_string(),
        yarn::LOCKFILE_ORPHAN_ENTRIES,
        crate::report::Severity::Warning,
    )
    .message(format!(
        "Lockfile '{}' has {} stale entries that no dependency reaches: {}{}. {} does not install them, so they were not scanned.",
        lockfile_path.display(),
        names.len(),
        listed,
        more,
        installer
    ))
    .fix(format!(
        "Prune the stale entries. {}",
        remedy.sentence()
    ))
}

pub(crate) fn parse_failed_issue(lockfile: &str, detail: String) -> Issue {
    Issue::new("<lockfile>", crate::names::RESOLUTION_PARSE_FAILED, Severity::Error)
        .message(format!(
            "Could not parse '{}'. Exact lockfile resolution is unavailable, so version-sensitive checks cannot trust this project state. {}",
            lockfile, detail
        ))
        .fix(format!(
            "Repair or regenerate '{}', then rerun sloppy-joe.",
            lockfile
        ))
}

pub(crate) fn missing_entry_issue(dep: &Dependency, lockfile: &str) -> Issue {
    Issue::new(&dep.name, crate::names::RESOLUTION_MISSING_LOCKFILE_ENTRY, Severity::Error)
        .message(format!(
            "'{}' is declared in the manifest but was not found in '{}'. Exact version-sensitive checks cannot trust this lockfile state.",
            dep.name, lockfile
        ))
        .fix(match crate::remedy::for_missing_entry(lockfile) {
            Some(remedy) => format!(
                "Regenerate '{}' so it contains the direct dependency '{}'. {}",
                lockfile,
                dep.name,
                remedy.sentence()
            ),
            None => format!(
                "Regenerate '{}' so it contains the direct dependency '{}', then rerun sloppy-joe. `sloppy-joe fix-lockfile` shows the exact command.",
                lockfile, dep.name
            ),
        })
}

pub(crate) fn out_of_sync_issue(dep: &Dependency, resolved_version: &str) -> Issue {
    Issue::new(&dep.name, crate::names::RESOLUTION_LOCKFILE_OUT_OF_SYNC, Severity::Error)
        .message(format!(
            "'{}' is pinned to '{}' in the manifest but resolves to '{}' in the lockfile. Exact version-sensitive checks cannot trust this project state.",
            dep.name,
            dep.version.as_deref().unwrap_or(""),
            resolved_version
        ))
        .fix("Update the manifest or regenerate the lockfile so both describe the same direct dependency version.")
}

pub(crate) fn ambiguous_issue(dep: &Dependency) -> Issue {
    Issue::new(&dep.name, crate::names::RESOLUTION_AMBIGUOUS, Severity::Error)
        .message(format!(
            "'{}' resolves to multiple locked versions and the direct dependency version cannot be proven exactly from the manifest.",
            dep.name
        ))
        .fix("Pin an exact manifest version or regenerate the lockfile so the direct dependency version is unambiguous.")
}

pub(crate) fn no_trusted_lockfile_sync_issue(dep: &Dependency, lockfile: &str) -> Issue {
    Issue::new(
        &dep.name,
        crate::names::RESOLUTION_NO_TRUSTED_LOCKFILE_SYNC,
        Severity::Error,
    )
    .message(format!(
        "'{}' uses the non-exact requirement '{}' in the manifest, so sloppy-joe cannot prove that '{}' is synchronized to one exact reviewed direct dependency version.",
        dep.name,
        dep.version.as_deref().unwrap_or(""),
        lockfile
    ))
    .fix(format!(
        "Pin '{}' exactly in the manifest or regenerate '{}' after switching to an exact direct dependency requirement.",
        dep.name, lockfile
    ))
}
