use super::*;

fn index(version: u8, paths: &[&str]) -> Vec<u8> {
    let mut bytes = b"DIRC\0\0\0".to_vec();
    bytes.push(version);
    for path in paths {
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(0);
    }
    bytes
}

fn repo(index_bytes: Option<Vec<u8>>) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sj-gitindex-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    if let Some(bytes) = index_bytes {
        std::fs::write(dir.join(".git/index"), bytes).unwrap();
    }
    dir
}

#[test]
fn a_path_in_the_index_is_tracked_and_one_missing_is_not() {
    let dir = repo(Some(index(2, &["a.txt", "sub/.venv/pyvenv.cfg"])));
    std::fs::create_dir_all(dir.join("sub/.venv")).unwrap();
    std::fs::create_dir_all(dir.join(".venv")).unwrap();
    assert_eq!(is_git_tracked(&dir.join("a.txt")), IndexState::Tracked);
    assert_eq!(
        is_git_tracked(&dir.join("sub/.venv/pyvenv.cfg")),
        IndexState::Tracked
    );
    assert_eq!(is_git_tracked(&dir.join("b.txt")), IndexState::Untracked);
}

#[test]
fn a_longer_tracked_path_ending_the_same_way_counts_as_tracked() {
    // The documented over-approximation: errs toward Tracked, never toward Untracked.
    let dir = repo(Some(index(2, &["sub/.venv/pyvenv.cfg"])));
    std::fs::create_dir_all(dir.join(".venv")).unwrap();
    assert_eq!(
        is_git_tracked(&dir.join(".venv/pyvenv.cfg")),
        IndexState::Tracked
    );
}

#[test]
fn an_unreadable_index_or_missing_repository_is_undecidable() {
    assert_eq!(
        is_git_tracked(&repo(None).join("a.txt")),
        IndexState::Undecidable
    );
    assert_eq!(
        is_git_tracked(&repo(Some(index(4, &["a.txt"]))).join("a.txt")),
        IndexState::Undecidable
    );
    assert_eq!(
        is_git_tracked(&repo(Some(b"nope".to_vec())).join("a.txt")),
        IndexState::Undecidable
    );
}

#[test]
fn a_gitdir_pointer_file_is_followed() {
    let dir = repo(None);
    std::fs::remove_dir_all(dir.join(".git")).unwrap();
    let real = dir.join("real-git");
    std::fs::create_dir_all(&real).unwrap();
    std::fs::write(real.join("index"), index(2, &["a.txt"])).unwrap();
    std::fs::write(dir.join(".git"), "gitdir: real-git\n").unwrap();
    assert_eq!(is_git_tracked(&dir.join("a.txt")), IndexState::Tracked);
}
