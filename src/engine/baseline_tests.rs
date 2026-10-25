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

#[test]
fn an_unresolvable_ref_is_a_configuration_error() {
    let dir = repo();
    commit(&dir, "requests==2.31.0\n");
    let (spec, deps) = project(&dir);
    let error = new_dependency_keys(&spec, &deps, "no-such-branch").unwrap_err();
    assert!(matches!(error, BaselineError::Unusable(_)));
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
