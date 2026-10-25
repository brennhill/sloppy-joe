//! Direct dependencies of other environments. A Poetry or uv manifest dependency whose marker
//! is false for the scan target is installed elsewhere, so it is a direct dependency there: it
//! gets the canonical, similarity, existence and metadata checks, not the reduced transitive
//! set. The target's filtered list still chooses versions.
use super::*;
use std::collections::HashSet;

/// Move the locked packages that `coverage_roots` missing from `target_deps` resolve to out of
/// `transitive_deps` and into `gated_direct_deps`, with their locked versions recorded in the
/// resolution. A gated root the lockfile data does not carry (a reduced-confidence lock) is
/// checked from its manifest declaration instead, unless the target already checks that name.
pub(super) fn promote_gated_direct_deps(
    data: &mut lockfiles::LockfileData,
    coverage_roots: &[Dependency],
    target_deps: &[Dependency],
) {
    let gated: Vec<&Dependency> = coverage_roots
        .iter()
        .filter(|root| {
            !target_deps
                .iter()
                .any(|dep| dep.name == root.name && dep.version == root.version)
        })
        .collect();
    if gated.is_empty() {
        return;
    }
    let gated_names: HashSet<String> = gated.iter().map(|dep| normalized(dep)).collect();
    let (promoted, transitive): (Vec<_>, Vec<_>) = std::mem::take(&mut data.transitive_deps)
        .into_iter()
        .partition(|dep| gated_names.contains(&normalized(dep)));
    data.transitive_deps = transitive;

    let mut checked: HashSet<String> = target_deps.iter().map(normalized).collect();
    for dep in promoted {
        if let Some(version) = dep.version.clone() {
            data.resolution.exact_versions.insert(
                lockfiles::ResolutionKey::from(&dep),
                lockfiles::ResolvedVersion {
                    version,
                    source: lockfiles::ResolutionSource::Lockfile,
                },
            );
        }
        checked.insert(normalized(&dep));
        data.gated_direct_deps.push(dep);
    }
    let mut seen = HashSet::new();
    for root in gated {
        if checked.contains(&normalized(root))
            || !seen.insert((root.name.clone(), root.version.clone()))
        {
            continue;
        }
        lockfiles::add_manifest_exact_fallback(&mut data.resolution, root);
        data.gated_direct_deps.push(root.clone());
    }
}

fn normalized(dep: &Dependency) -> String {
    parsers::requirements::normalize_distribution_name(dep.package_name())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(name: &str, version: &str) -> Dependency {
        crate::test_helpers::dep_with(name, Some(version), crate::Ecosystem::PyPI)
    }

    fn names(deps: &[Dependency]) -> Vec<(String, Option<String>)> {
        deps.iter()
            .map(|dep| (dep.name.clone(), dep.version.clone()))
            .collect()
    }

    #[test]
    fn locked_gated_roots_move_from_transitive_to_direct_at_their_locked_version() {
        let mut data = lockfiles::LockfileData::reduced_confidence_from_manifest(&[]);
        data.transitive_deps = vec![dep("Win_Pkg", "1.2.0"), dep("urllib3", "2.0.0")];
        let target = [dep("six", "==1.17.0")];
        let roots = [dep("six", "==1.17.0"), dep("win-pkg", ">=1.0")];
        promote_gated_direct_deps(&mut data, &roots, &target);
        assert_eq!(
            names(&data.gated_direct_deps),
            [("Win_Pkg".to_string(), Some("1.2.0".to_string()))]
        );
        assert_eq!(
            names(&data.transitive_deps),
            [("urllib3".to_string(), Some("2.0.0".to_string()))]
        );
        assert_eq!(
            data.resolution.exact_version(&data.gated_direct_deps[0]),
            Some("1.2.0")
        );
    }

    #[test]
    fn an_unlocked_gated_root_is_checked_from_the_manifest() {
        let mut data = lockfiles::LockfileData::reduced_confidence_from_manifest(&[]);
        let target = [dep("six", "==1.17.0")];
        let roots = [dep("six", "==1.17.0"), dep("winpkg", "==1.0.0")];
        promote_gated_direct_deps(&mut data, &roots, &target);
        assert_eq!(
            names(&data.gated_direct_deps),
            [("winpkg".to_string(), Some("==1.0.0".to_string()))]
        );
        assert_eq!(
            data.resolution.exact_version(&data.gated_direct_deps[0]),
            Some("1.0.0")
        );
    }

    #[test]
    fn a_gated_root_the_target_already_checks_by_name_is_not_repeated() {
        // `numpy>=1; python_version < '3.12'` beside the target's `numpy==2.0`, which the lock
        // resolves to the same package: nothing is left to promote and nothing is duplicated.
        let mut data = lockfiles::LockfileData::reduced_confidence_from_manifest(&[]);
        let target = [dep("numpy", "==2.0")];
        let roots = [dep("numpy", "==2.0"), dep("numpy", ">=1")];
        promote_gated_direct_deps(&mut data, &roots, &target);
        assert!(data.gated_direct_deps.is_empty());
    }
}
