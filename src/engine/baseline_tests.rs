//! `--base-ref`: dependencies added since a git ref, read from a real repository.

use super::*;
use crate::checks::steering::dependency_key;
use crate::engine::with_new_dependencies;
use crate::project::ParsedProject;
use crate::{config, unbound_project_inputs_with_config};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn repo() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sj-baseline-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    run(&dir, &["init", "-q", "-b", "main"]);
    dir
}

fn run(dir: &std::path::Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .status()
        .expect("git is required for baseline tests");
    assert!(status.success(), "git {args:?}");
}

fn commit(dir: &std::path::Path, requirements: &str) {
    std::fs::write(dir.join("requirements.txt"), requirements).unwrap();
    run(dir, &["add", "requirements.txt"]);
    run(dir, &["commit", "-q", "-m", "c"]);
}

fn project(dir: &std::path::Path) -> (ProjectInputSpec, Vec<Dependency>) {
    let specs =
        unbound_project_inputs_with_config(dir, None, &config::SloppyJoeConfig::default()).unwrap();
    let spec = specs
        .into_iter()
        .next()
        .expect("requirements.txt is discovered");
    let deps = ecosystems::for_kind(spec.kind)
        .parse_manifest(dir, &spec)
        .unwrap();
    (spec, deps)
}

fn names(keys: &std::collections::HashSet<String>) -> Vec<String> {
    let mut v: Vec<_> = keys.iter().cloned().collect();
    v.sort();
    v
}

#[test]
fn dependency_added_after_the_ref_is_new() {
    let dir = repo();
    commit(&dir, "requests==2.31.0\n");
    std::fs::write(
        dir.join("requirements.txt"),
        "requests==2.31.0\nsklearn==1.0\n",
    )
    .unwrap();
    let (spec, deps) = project(&dir);
    let keys = new_dependency_keys(&spec, &deps, "HEAD").unwrap();
    assert_eq!(names(&keys), ["pypi:sklearn"]);
}

#[test]
fn version_bumps_and_spelling_changes_are_not_new() {
    let dir = repo();
    commit(&dir, "Flask_Login==0.5.0\n");
    std::fs::write(dir.join("requirements.txt"), "flask-login==0.6.0\n").unwrap();
    let (spec, deps) = project(&dir);
    assert!(
        new_dependency_keys(&spec, &deps, "HEAD")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_manifest_absent_at_the_ref_makes_everything_new() {
    let dir = repo();
    std::fs::write(dir.join("README"), "x").unwrap();
    run(&dir, &["add", "README"]);
    run(&dir, &["commit", "-q", "-m", "c"]);
    std::fs::write(dir.join("requirements.txt"), "requests==2.31.0\n").unwrap();
    let (spec, deps) = project(&dir);
    let keys = new_dependency_keys(&spec, &deps, "HEAD").unwrap();
    assert_eq!(keys.len(), deps.len());
    assert!(keys.contains(&dependency_key(&deps[0])));
}

const OID: &str = "0123456789abcdef0123456789abcdef01234567";

fn answer(ok: bool, stdout: &[u8], stderr: &str) -> Result<GitOutput> {
    Ok(GitOutput {
        ok,
        stdout: stdout.to_vec(),
        stderr: stderr.as_bytes().to_vec(),
    })
}

/// A git that resolves the ref and answers `ls-tree` and `cat-file` as given, recording the
/// subcommands it was asked to run.
fn fake_git<'a>(
    tree: &'static [u8],
    blob: (bool, &'static [u8], &'static str),
    calls: &'a mut Vec<Vec<String>>,
) -> impl FnMut(&[&str]) -> Result<GitOutput> + 'a {
    move |args: &[&str]| {
        calls.push(args.iter().map(|a| a.to_string()).collect());
        match args[0] {
            "rev-parse" => answer(true, format!("{OID}\n").as_bytes(), ""),
            "ls-tree" => answer(true, tree, ""),
            "cat-file" => answer(blob.0, blob.1, blob.2),
            other => panic!("unexpected git {other}"),
        }
    }
}

#[test]
fn absence_is_read_from_the_tree_not_from_gits_message_text() {
    // Git 2.34 (Ubuntu 22.04) says "fatal: Not a valid object name HEAD:requirements.txt" for a
    // path missing at the ref; no message text may decide that the manifest is absent.
    let mut calls = Vec::new();
    let blob = (
        false,
        &b""[..],
        "fatal: Not a valid object name HEAD:requirements.txt",
    );
    let found = manifest_at_ref_with(
        &mut fake_git(b"", blob, &mut calls),
        "HEAD",
        "requirements.txt",
    )
    .unwrap();
    assert!(found.is_none());
    assert!(calls.iter().all(|c| c[0] != "cat-file"), "{calls:?}");
    let ls_tree = calls.iter().find(|c| c[0] == "ls-tree").unwrap();
    assert_eq!(
        ls_tree,
        &[
            "ls-tree",
            "-z",
            "--full-tree",
            "--name-only",
            &format!("{OID}^{{commit}}"),
            "--",
            "requirements.txt"
        ]
    );
}

#[test]
fn a_manifest_listed_in_the_tree_is_read_from_the_resolved_commit() {
    let mut calls = Vec::new();
    let tree = b"sub/requirements.txt\0";
    let mut git = fake_git(tree, (true, b"requests\n", ""), &mut calls);
    let found = manifest_at_ref_with(&mut git, "origin/main", "sub/requirements.txt").unwrap();
    drop(git);
    assert_eq!(found.as_deref(), Some(&b"requests\n"[..]));
    // Both reads name the commit rev-parse resolved, so a ref moving in between cannot mix trees.
    let cat = calls.iter().find(|c| c[0] == "cat-file").unwrap();
    assert_eq!(
        cat,
        &["cat-file", "blob", &format!("{OID}:sub/requirements.txt")]
    );
}

#[test]
fn a_listed_manifest_git_cannot_read_is_an_error() {
    let mut calls = Vec::new();
    let blob = (false, &b""[..], "fatal: does not exist");
    let mut git = fake_git(b"requirements.txt\0", blob, &mut calls);
    assert!(manifest_at_ref_with(&mut git, "HEAD", "requirements.txt").is_err());
}

#[test]
fn a_tree_listing_naming_another_path_is_an_error() {
    let mut calls = Vec::new();
    let mut git = fake_git(b"other.txt\0", (true, b"x", ""), &mut calls);
    assert!(manifest_at_ref_with(&mut git, "HEAD", "requirements.txt").is_err());
}

#[test]
fn a_failing_tree_listing_is_an_error() {
    let mut git = |args: &[&str]| match args[0] {
        "rev-parse" => answer(true, format!("{OID}\n").as_bytes(), ""),
        _ => answer(false, b"", "fatal: something unexpected"),
    };
    assert!(manifest_at_ref_with(&mut git, "HEAD", "requirements.txt").is_err());
}

#[cfg(unix)] // Windows file names cannot hold `:`, `*`, `"` or a tab.
#[test]
fn paths_that_need_quoting_or_look_like_pathspec_magic_are_read_literally() {
    let dir = repo();
    let names = [
        "a b/requirements.txt",
        "caf\u{e9}/requirements.txt",
        ":(glob)x/requirements.txt",
        "*/requirements.txt",
        "q\"uote/requirements.txt",
        "tab\tdir/requirements.txt",
    ];
    for (index, name) in names.iter().enumerate() {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, format!("pkg{index}==1.0\n")).unwrap();
    }
    run(&dir, &["add", "-A"]);
    run(&dir, &["commit", "-q", "-m", "c"]);
    for (index, name) in names.iter().enumerate() {
        let bytes = manifest_at_ref(&dir, "HEAD", name).unwrap();
        assert_eq!(
            bytes.as_deref(),
            Some(format!("pkg{index}==1.0\n").as_bytes()),
            "{name}"
        );
    }
    // A glob must not match the files above, and a missing file beside them is absent.
    for absent in [
        "?/requirements.txt",
        "a b/other.txt",
        "nested/dir/requirements.txt",
    ] {
        assert!(
            manifest_at_ref(&dir, "HEAD", absent).unwrap().is_none(),
            "{absent}"
        );
    }
}

#[test]
fn a_directory_where_the_manifest_should_be_is_an_error() {
    let dir = repo();
    std::fs::create_dir_all(dir.join("requirements.txt")).unwrap();
    std::fs::write(dir.join("requirements.txt/x"), "x").unwrap();
    run(&dir, &["add", "-A"]);
    run(&dir, &["commit", "-q", "-m", "c"]);
    assert!(manifest_at_ref(&dir, "HEAD", "requirements.txt").is_err());
}

#[test]
fn an_unresolvable_ref_is_a_configuration_error() {
    let dir = repo();
    commit(&dir, "requests==2.31.0\n");
    let (spec, deps) = project(&dir);
    let error = new_dependency_keys(&spec, &deps, "no-such-branch").unwrap_err();
    assert!(matches!(error, BaselineError::Unusable(_)));
}

#[test]
fn git_runs_in_the_c_locale_with_literal_pathspecs() {
    let command = git_command(std::path::Path::new("."), &["status"]);
    let envs: std::collections::HashMap<_, _> = command
        .get_envs()
        .map(|(key, value)| (key.to_owned(), value.map(|v| v.to_owned())))
        .collect();
    for (key, value) in [
        ("LC_ALL", "C"),
        ("LANGUAGE", "C"),
        ("GIT_LITERAL_PATHSPECS", "1"),
    ] {
        assert_eq!(
            envs.get(std::ffi::OsStr::new(key)),
            Some(&Some(std::ffi::OsString::from(value))),
            "{key} must be {value}"
        );
    }
}

#[test]
fn refs_that_look_like_options_are_refused_before_git_runs() {
    for bad in ["--output=/tmp/x", "-n", "", "a b", "HEAD;rm", "x\ny"] {
        assert!(validate_ref(bad).is_err(), "{bad:?}");
    }
    for good in ["HEAD", "origin/main", "v1.2.3", "HEAD~2", "feature/a-b_c.d"] {
        assert!(validate_ref(good).is_ok(), "{good:?}");
    }
}

#[test]
fn outside_a_repository_is_a_configuration_error() {
    let dir = std::env::temp_dir().join(format!("sj-baseline-norepo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("requirements.txt"), "requests==2.31.0\n").unwrap();
    let (spec, deps) = project(&dir);
    // A temp dir can sit inside a repository on some machines; only assert the error kind
    // when no ancestor repository exists.
    if crate::cache::find_git_root(&dir).ok().flatten().is_none() {
        assert!(matches!(
            new_dependency_keys(&spec, &deps, "HEAD").unwrap_err(),
            BaselineError::Unusable(_)
        ));
    }
}

fn parsed(spec: ProjectInputSpec, deps: Vec<Dependency>) -> ParsedProject {
    ParsedProject {
        spec,
        deps,
        python_root_extras: crate::parsers::python_scope::PythonRootExtras::new(),
        unlocked_tooling: false,
        package_indexes: Vec::new(),
    }
}

#[test]
fn scan_options_carry_the_new_dependencies_for_the_project() {
    let dir = repo();
    commit(&dir, "requests==2.31.0\n");
    std::fs::write(dir.join("requirements.txt"), "requests==2.31.0\ncv2==1.0\n").unwrap();
    let (spec, deps) = project(&dir);
    let opts = crate::ScanOptions {
        base_ref: Some("HEAD".into()),
        ..Default::default()
    };
    let mut issues = Vec::new();
    let project_opts = with_new_dependencies(&parsed(spec, deps), &opts, &mut issues);
    assert!(issues.is_empty());
    assert_eq!(names(&project_opts.new_dependencies), ["pypi:cv2"]);
}

#[test]
fn an_unusable_ref_blocks_the_scan_instead_of_skipping_the_signal() {
    let dir = repo();
    commit(&dir, "requests==2.31.0\n");
    let (spec, deps) = project(&dir);
    let opts = crate::ScanOptions {
        base_ref: Some("no-such-branch".into()),
        ..Default::default()
    };
    let mut issues = Vec::new();
    let project_opts = with_new_dependencies(&parsed(spec, deps), &opts, &mut issues);
    assert!(project_opts.new_dependencies.is_empty());
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].check, "steering/baseline-unavailable");
    assert_eq!(issues[0].severity, crate::report::Severity::Error);
}

#[test]
fn without_a_base_ref_nothing_is_computed_or_reported() {
    let dir = repo();
    commit(&dir, "requests==2.31.0\n");
    let (spec, deps) = project(&dir);
    let mut issues = Vec::new();
    let project_opts = with_new_dependencies(
        &parsed(spec, deps),
        &crate::ScanOptions::default(),
        &mut issues,
    );
    assert!(issues.is_empty() && project_opts.new_dependencies.is_empty());
}
