//! Cache files feed security decisions (OSV results, similarity results, scan
//! fingerprints). A cache directory inside the scanned repository would let
//! committed files forge those results, so it must be rejected.
use super::*;
use std::ffi::OsString;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir() -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-cache-boundary-{}-{}", std::process::id(), id));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_npm_project(dir: &std::path::Path) {
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"app","dependencies":{"react":"18.3.1"}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("package-lock.json"), r#"{"lockfileVersion":3,"packages":{"":{"dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1","resolved":"https://registry.npmjs.org/react/-/react-18.3.1.tgz","integrity":"sha512-demo"}}}"#).unwrap();
}

async fn fast_scan(project: &std::path::Path, cache_dir: &std::path::Path) -> Result<ScanReport> {
    scan_with_source_full_options(
        project,
        Some("npm"),
        None,
        &ScanOptions {
            scan_mode: ScanMode::Fast,
            cache_dir: Some(cache_dir),
            ..Default::default()
        },
    )
    .await
}

#[tokio::test]
async fn cache_dir_inside_git_repository_is_rejected() {
    let root = unique_dir();
    let repo = root.join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::create_dir_all(repo.join("app")).unwrap();
    write_npm_project(&repo.join("app"));
    for cache_dir in [
        repo.join(".sloppy-cache"),
        repo.join("app/.cache/sloppy-joe"),
        repo.clone(),
    ] {
        std::fs::create_dir_all(&cache_dir).unwrap();
        let error = fast_scan(&repo.join("app"), &cache_dir)
            .await
            .expect_err("a cache directory inside the repository must block the scan");
        assert!(
            error.to_string().contains("outside the project"),
            "{error:#}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn nonexistent_cache_dir_inside_repository_is_rejected() {
    let root = unique_dir();
    let repo = root.join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    write_npm_project(&repo);
    let error = fast_scan(&repo, &repo.join("not/yet/created"))
        .await
        .expect_err("a not-yet-created in-repo cache must be rejected");
    assert!(
        error.to_string().contains("outside the project"),
        "{error:#}"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn cache_dir_inside_non_git_scan_root_is_rejected() {
    let root = unique_dir();
    write_npm_project(&root);
    let error = fast_scan(&root, &root.join(".cache"))
        .await
        .expect_err("a cache directory inside the scan root must block the scan");
    assert!(
        error.to_string().contains("outside the project"),
        "{error:#}"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn symlinked_cache_dir_resolving_into_repository_is_rejected() {
    let root = unique_dir();
    let repo = root.join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    std::fs::create_dir_all(repo.join("forged")).unwrap();
    write_npm_project(&repo);
    let link = root.join("cache-link");
    std::os::unix::fs::symlink(repo.join("forged"), &link).unwrap();
    let error = fast_scan(&repo, &link)
        .await
        .expect_err("a symlinked cache directory pointing into the repo must be rejected");
    assert!(
        error.to_string().contains("outside the project"),
        "{error:#}"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn parent_dir_components_below_missing_directories_cannot_escape_the_check() {
    let root = unique_dir();
    let repo = root.join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    write_npm_project(&repo);
    // `missing/..` cannot be canonicalized; it must not be compared lexically.
    let sneaky = root.join("missing").join("..").join("repo").join(".cache");
    assert!(fast_scan(&repo, &sneaky).await.is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn cache_dir_outside_repository_is_accepted() {
    let root = unique_dir();
    let repo = root.join("repo");
    std::fs::create_dir_all(repo.join(".git")).unwrap();
    write_npm_project(&repo);
    let cache_dir = root.join("cache");
    fast_scan(&repo, &cache_dir)
        .await
        .expect("an external cache directory must be accepted");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn relative_xdg_cache_home_is_ignored() {
    let env = |name: &str| -> Option<OsString> {
        match name {
            "XDG_CACHE_HOME" => Some("relative/cache".into()),
            "HOME" => Some("/home/user".into()),
            _ => None,
        }
    };
    let dir = cache::user_cache_dir_from(env);
    assert!(dir.is_absolute(), "{}", dir.display());
    assert!(!dir.starts_with("relative"), "{}", dir.display());
    assert!(dir.starts_with("/home/user"), "{}", dir.display());
}

#[test]
fn empty_xdg_cache_home_is_ignored() {
    let env = |name: &str| -> Option<OsString> {
        match name {
            "XDG_CACHE_HOME" => Some("".into()),
            "HOME" => Some("/home/user".into()),
            _ => None,
        }
    };
    assert!(cache::user_cache_dir_from(env).starts_with("/home/user"));
}

#[test]
fn absolute_xdg_cache_home_is_used() {
    let env = |name: &str| -> Option<OsString> {
        match name {
            "XDG_CACHE_HOME" => Some("/var/cache/me".into()),
            "HOME" => Some("/home/user".into()),
            _ => None,
        }
    };
    assert_eq!(
        cache::user_cache_dir_from(env),
        std::path::PathBuf::from("/var/cache/me")
    );
}

#[test]
fn relative_home_is_ignored() {
    let env = |name: &str| -> Option<OsString> {
        match name {
            "HOME" => Some("relative-home".into()),
            _ => None,
        }
    };
    assert!(cache::user_cache_dir_from(env).is_absolute());
}
