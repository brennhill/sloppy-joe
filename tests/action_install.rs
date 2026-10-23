//! The GitHub Action installs the release binary while the working directory
//! is the (possibly untrusted) PR checkout. Files committed there must never be
//! installed or put on PATH, and the archive must match its published SHA-256.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/install-action-binary.sh")
}

fn unique_dir() -> PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sj-action-{}-{}", std::process::id(), id));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn have(tool: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {tool}")])
        .output()
        .is_ok_and(|o| o.status.success())
}

fn sha256(path: &Path) -> String {
    let out = Command::new("sh")
        .arg("-c")
        .arg(r#"if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi"#)
        .arg("sh")
        .arg(path)
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap()[..64].to_string()
}

/// Build a fake release directory with a flat Windows-style zip (as cargo-dist
/// publishes) and its `.sha256` file. Returns (release dir, archive name).
fn fake_windows_release(root: &Path, checksum_override: Option<&str>) -> (PathBuf, String) {
    let release = root.join("release");
    let staging = root.join("staging");
    std::fs::create_dir_all(&release).unwrap();
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(staging.join("sloppy-joe.exe"), "genuine-release-binary").unwrap();
    let archive = "sloppy-joe-x86_64-pc-windows-msvc.zip".to_string();
    let status = Command::new("zip")
        .arg("-q")
        .arg(release.join(&archive))
        .arg("sloppy-joe.exe")
        .current_dir(&staging)
        .status()
        .unwrap();
    assert!(status.success());
    let digest = checksum_override
        .map(str::to_string)
        .unwrap_or_else(|| sha256(&release.join(&archive)));
    std::fs::write(
        release.join(format!("{archive}.sha256")),
        format!("{digest} *{archive}\n\n"),
    )
    .unwrap();
    (release, archive)
}

/// A PR checkout that plants files where the old install step looked.
fn hostile_checkout(root: &Path) -> PathBuf {
    let checkout = root.join("checkout");
    let planted = checkout.join("sloppy-joe-x86_64-pc-windows-msvc");
    std::fs::create_dir_all(&planted).unwrap();
    std::fs::write(planted.join("sloppy-joe"), "attacker-binary").unwrap();
    std::fs::write(checkout.join("sloppy-joe.exe"), "attacker-binary").unwrap();
    std::fs::write(checkout.join("sloppy-joe"), "attacker-binary").unwrap();
    checkout
}

fn run(checkout: &Path, release: &Path, archive: &str, root: &Path) -> std::process::Output {
    let github_path = root.join("github_path");
    std::fs::write(&github_path, "").unwrap();
    let runner_temp = root.join("runner-temp");
    std::fs::create_dir_all(&runner_temp).unwrap();
    Command::new("bash")
        .arg(script())
        .arg(format!("file://{}/{archive}", release.display()))
        .arg(archive)
        .arg("x86_64-pc-windows-msvc")
        .arg("zip")
        .current_dir(checkout)
        .env("GITHUB_PATH", &github_path)
        .env("RUNNER_TEMP", &runner_temp)
        .output()
        .unwrap()
}

#[test]
fn install_ignores_binaries_committed_to_the_checkout() {
    if !have("zip") || !have("unzip") {
        eprintln!("zip/unzip unavailable; skipping action install test");
        return;
    }
    let root = unique_dir();
    let (release, archive) = fake_windows_release(&root, None);
    let checkout = hostile_checkout(&root);
    let out = run(&checkout, &release, &archive, &root);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let path_entries = std::fs::read_to_string(root.join("github_path")).unwrap();
    let entries: Vec<_> = path_entries.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(entries.len(), 1, "{path_entries}");
    let bin_dir = std::fs::canonicalize(entries[0]).unwrap();
    let checkout = std::fs::canonicalize(&checkout).unwrap();
    assert!(
        !bin_dir.starts_with(&checkout),
        "the checkout must never be put on PATH: {}",
        bin_dir.display()
    );
    let installed = std::fs::read_to_string(bin_dir.join("sloppy-joe.exe")).unwrap();
    assert_eq!(installed, "genuine-release-binary");
    // Nothing is extracted into, or moved out of, the checkout.
    assert_eq!(
        std::fs::read_to_string(checkout.join("sloppy-joe.exe")).unwrap(),
        "attacker-binary"
    );
    assert!(!checkout.join(&archive).exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn install_rejects_archive_with_mismatched_checksum() {
    if !have("zip") || !have("unzip") {
        eprintln!("zip/unzip unavailable; skipping action install test");
        return;
    }
    let root = unique_dir();
    let (release, archive) = fake_windows_release(&root, Some(&"0".repeat(64)));
    let checkout = hostile_checkout(&root);
    let out = run(&checkout, &release, &archive, &root);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("checksum")
            || String::from_utf8_lossy(&out.stderr).contains("checksum")
    );
    assert_eq!(
        std::fs::read_to_string(root.join("github_path")).unwrap(),
        ""
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn install_fails_closed_when_checksum_file_is_missing_or_malformed() {
    if !have("zip") || !have("unzip") {
        eprintln!("zip/unzip unavailable; skipping action install test");
        return;
    }
    let root = unique_dir();
    let (release, archive) = fake_windows_release(&root, Some("not-a-digest"));
    let checkout = hostile_checkout(&root);
    assert!(!run(&checkout, &release, &archive, &root).status.success());
    std::fs::remove_file(release.join(format!("{archive}.sha256"))).unwrap();
    assert!(!run(&checkout, &release, &archive, &root).status.success());
    std::fs::remove_dir_all(root).unwrap();
}
