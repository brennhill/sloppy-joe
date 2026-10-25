use super::*;

fn package(name: &str, version: &str, integrity: &str) -> LockedPackage {
    LockedPackage {
        name: name.into(),
        version: version.into(),
        integrity: Some(integrity.into()),
        source: None,
    }
}

fn snapshot(packages: Vec<LockedPackage>, direct: &[&str]) -> Snapshot {
    Snapshot {
        exists: true,
        packages,
        reachable: None,
        direct: direct.iter().map(|name| (name.to_string(), None)).collect(),
    }
}

#[test]
fn an_unchanged_lockfile_passes() {
    let old = snapshot(vec![package("a", "1.0.0", "h1")], &["a"]);
    let diff = compare(&old, None, &old.clone());
    assert!(diff.violations.is_empty(), "{:?}", diff.violations);
    assert_eq!(diff.unchanged, 1);
}

#[test]
fn a_changed_version_is_refused() {
    let old = snapshot(vec![package("a", "1.0.0", "h1")], &["a"]);
    let new = snapshot(vec![package("a", "1.0.1", "h2")], &["a"]);
    let diff = compare(&old, None, &new);
    assert!(
        diff.violations.iter().any(|v| v.contains("a@1.0.0 changed version")),
        "{:?}",
        diff.violations
    );
}

#[test]
fn a_changed_integrity_or_source_is_refused() {
    let old = snapshot(vec![package("a", "1.0.0", "h1")], &["a"]);
    let new = snapshot(vec![package("a", "1.0.0", "evil")], &["a"]);
    assert!(compare(&old, None, &new).violations[0].contains("changed"));
    let mut moved = package("a", "1.0.0", "h1");
    moved.source = Some("https://evil.example/a.tgz".into());
    let new = snapshot(vec![moved], &["a"]);
    assert!(!compare(&old, None, &new).violations.is_empty());
}

#[test]
fn integrity_appearing_where_none_was_recorded_is_a_change() {
    let mut bare = package("a", "1.0.0", "h1");
    bare.integrity = None;
    let old = snapshot(vec![bare], &["a"]);
    let new = snapshot(vec![package("a", "1.0.0", "h1")], &["a"]);
    assert!(!compare(&old, None, &new).violations.is_empty());
}

#[test]
fn additions_need_a_direct_dependency_the_lockfile_lacked() {
    let old = snapshot(vec![package("a", "1.0.0", "h1")], &["a"]);
    let new = snapshot(
        vec![package("a", "1.0.0", "h1"), package("b", "2.0.0", "h2")],
        &["a"],
    );
    let diff = compare(&old, None, &new);
    assert!(diff.violations[0].contains("adds 1 package"), "{:?}", diff.violations);

    let old = snapshot(vec![package("a", "1.0.0", "h1")], &["a", "b"]);
    let diff = compare(&old, None, &new);
    assert!(diff.violations.is_empty(), "{:?}", diff.violations);
    assert_eq!(diff.added, vec!["b@2.0.0".to_string()]);
}

#[test]
fn without_an_old_lockfile_everything_is_added() {
    let old = Snapshot::default();
    let new = snapshot(vec![package("a", "1.0.0", "h1")], &["a"]);
    let diff = compare(&old, None, &new);
    assert!(diff.violations.is_empty());
    assert_eq!(diff.added.len(), 1);
}

#[test]
fn only_unreachable_packages_may_be_removed() {
    let old = snapshot(
        vec![package("a", "1.0.0", "h1"), package("orphan", "3.0.0", "h3")],
        &["a"],
    );
    let new = snapshot(vec![package("a", "1.0.0", "h1")], &["a"]);
    // Reachability unknown: every package counts as reachable.
    assert!(compare(&old, None, &new).violations[0].contains("orphan@3.0.0 was removed"));
    let reachable: HashSet<(String, String)> = [("a".to_string(), "1.0.0".to_string())].into();
    let diff = compare(&old, Some(&reachable), &new);
    assert!(diff.violations.is_empty(), "{:?}", diff.violations);
    assert_eq!(diff.removed, vec!["orphan@3.0.0".to_string()]);
}
