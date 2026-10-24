use super::AmbientInput as Row;
use super::*;
use Disposition::*;
use Scope::*;

fn tree(files: &[(&str, &str)]) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "sj-ambient-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    // A repository root bounds the ancestor walk to this fixture.
    std::fs::create_dir_all(root.join(".git")).unwrap();
    for (path, content) in files {
        let full = root.join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, content).unwrap();
    }
    std::fs::canonicalize(root).unwrap()
}

fn spec(dir: &Path, kind: ProjectInputKind) -> ProjectInputSpec {
    ProjectInputSpec {
        kind,
        manifest_path: dir.join("manifest"),
        lockfile_path_override: None,
        js_binding: None,
    }
}

fn never(_: &Path) -> Result<()> {
    anyhow::bail!("checker ran")
}

#[test]
fn glob_matching_is_case_insensitive_and_anchored() {
    assert!(glob_matches(".python-version", ".Python-Version"));
    assert!(glob_matches(".pnpmfile.*", ".pnpmfile.cjs"));
    assert!(glob_matches("*.gemspec", "My.GemSpec"));
    assert!(glob_matches("a*b*c", "aXXbYYc"));
    assert!(!glob_matches("a*b*c", "aXXbYY"));
    assert!(!glob_matches(".npmrc", "x.npmrc"));
    assert!(!glob_matches(".pnpmfile.*", ".pnpmfile"));
    assert!(glob_matches("*", "anything"));
}

#[test]
fn a_nested_pattern_matches_case_variants_at_every_segment() {
    let dir = tree(&[(".MVN/Settings.XML", "x")]);
    let found = matches(&dir, ".mvn/settings.xml").unwrap();
    assert_eq!(found.len(), 1);
    assert!(matches(&dir, ".mvn/toolchains.xml").unwrap().is_empty());
    assert!(matches(&dir.join("missing"), "x").unwrap().is_empty());
    // A file where the pattern wants a directory has no matches rather than an error.
    let dir = tree(&[(".mvn", "not a directory")]);
    assert!(matches(&dir, ".mvn/settings.xml").unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn a_symlink_matches_by_its_target_name() {
    let dir = tree(&[("real/.npmrc", "x")]);
    std::os::unix::fs::symlink(dir.join("real/.npmrc"), dir.join("innocent.txt")).unwrap();
    let found = matches(&dir, ".npmrc").unwrap();
    assert_eq!(found, vec![dir.join("innocent.txt")]);
}

#[test]
fn blocked_and_modeled_rows_block_when_the_file_exists() {
    let dir = tree(&[("a.txt", "x"), ("sub/b.txt", "x")]);
    let blocked = [Row::new("a.txt", ProjectDir, Blocked("why"))];
    let err = check(&blocked, &spec(&dir, ProjectInputKind::Npm), false)
        .unwrap_err()
        .to_string();
    assert!(err.contains("a.txt") && err.contains("why"), "{err}");

    let modeled = [Row::new("A.TXT", ProjectDir, Modeled(never))];
    let err = check(&modeled, &spec(&dir, ProjectInputKind::Npm), false)
        .unwrap_err()
        .to_string();
    assert!(err.contains("checker ran"), "{err}");

    let absent = [Row::new("c.txt", ProjectDir, Blocked("why"))];
    assert!(
        check(&absent, &spec(&dir, ProjectInputKind::Npm), false)
            .unwrap()
            .is_empty()
    );
    let elsewhere = [
        Row::new("a.txt", ProjectDir, ModeledElsewhere("somewhere")),
        Row::new("a.txt", ProjectDir, Irrelevant("harmless")),
    ];
    assert!(
        check(&elsewhere, &spec(&dir, ProjectInputKind::Npm), false)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn scope_and_kind_filters_apply() {
    let dir = tree(&[("up.txt", "x"), ("app/manifest", "x")]);
    let project = spec(&dir.join("app"), ProjectInputKind::Npm);
    let here_only = [Row::new("up.txt", ProjectDir, Blocked("why"))];
    assert!(check(&here_only, &project, false).unwrap().is_empty());
    let ancestors = [Row::new("up.txt", AncestorsToRepoRoot, Blocked("why"))];
    assert!(check(&ancestors, &project, false).is_err());
    // Another kind's row does not apply.
    let other = [
        Row::new("up.txt", AncestorsToRepoRoot, Blocked("why")).only(&[ProjectInputKind::Cargo])
    ];
    assert!(check(&other, &project, false).unwrap().is_empty());
}

fn index_with(dir: &Path, paths: &[&str]) {
    let mut bytes = b"DIRC\0\0\0\x02".to_vec();
    for path in paths {
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(0);
    }
    std::fs::write(dir.join(".git/index"), bytes).unwrap();
}

#[test]
fn blocked_if_tracked_follows_the_git_index() {
    let rows = [Row::new("v/f", ProjectDir, BlockedIfTracked("committed"))];

    let tracked = tree(&[("v/f", "x")]);
    index_with(&tracked, &["v/f"]);
    let err = check(&rows, &spec(&tracked, ProjectInputKind::Npm), false)
        .unwrap_err()
        .to_string();
    assert!(err.contains("Committed repository file"), "{err}");

    let untracked = tree(&[("v/f", "x")]);
    index_with(&untracked, &["other"]);
    assert!(
        check(&rows, &spec(&untracked, ProjectInputKind::Npm), true)
            .unwrap()
            .is_empty()
    );

    // No index: git cannot say. A warning, and an error under --ci.
    let unknown = tree(&[("v/f", "x")]);
    let soft = check(&rows, &spec(&unknown, ProjectInputKind::Npm), false).unwrap();
    assert_eq!(soft.len(), 1);
    assert_eq!(soft[0].severity, Severity::Warning);
    let hard = check(&rows, &spec(&unknown, ProjectInputKind::Npm), true).unwrap();
    assert_eq!(hard[0].severity, Severity::Error);

    let absent = tree(&[]);
    assert!(
        check(&rows, &spec(&absent, ProjectInputKind::Npm), true)
            .unwrap()
            .is_empty()
    );
}
