//! Regression tests for red-team finding RT19: cache contents were trusted without an owner or
//! integrity check, so a hand-edited `osv-cache.json` with empty advisories cleared packages.

use super::integrity::{self, hmac_sha256, key_dir_from, load_or_create_key, mac_path};
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir() -> PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir =
        std::env::temp_dir().join(format!("sj-cache-integrity-{}-{}", std::process::id(), id));
    std::fs::create_dir_all(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
struct Entry {
    timestamp: u64,
    vuln_ids: Vec<String>,
}

fn fresh(vulns: &[&str]) -> Entry {
    Entry {
        timestamp: now_epoch(),
        vuln_ids: vulns.iter().map(|v| v.to_string()).collect(),
    }
}

fn read(path: &Path) -> Option<Entry> {
    read_json_cache::<Entry>(path, 3600, |e| e.timestamp)
}

#[test]
fn cache_written_by_sloppy_joe_is_trusted() {
    let dir = unique_dir();
    let path = dir.join("osv-cache.json");
    let entry = fresh(&["GHSA-1"]);
    atomic_write_json(&path, &entry);
    assert!(
        mac_path(&path).exists(),
        "every write records its integrity"
    );
    assert_eq!(read(&path), Some(entry));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hand_edited_cache_is_discarded() {
    let dir = unique_dir();
    let path = dir.join("osv-cache.json");
    atomic_write_json(&path, &fresh(&["GHSA-1"]));
    // Same owner, same 0600 mode, only the advisories emptied.
    std::fs::write(&path, serde_json::to_string(&fresh(&[])).unwrap()).unwrap();
    assert_eq!(read(&path), None, "an edited cache must never be trusted");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cache_without_integrity_record_is_discarded() {
    let dir = unique_dir();
    let path = dir.join("osv-cache.json");
    std::fs::write(&path, serde_json::to_string(&fresh(&[])).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(
        read(&path),
        None,
        "a planted cache file must never be trusted"
    );
    assert!(read_trusted_json::<Entry>(&path).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn integrity_record_does_not_transfer_to_another_cache_file() {
    let dir = unique_dir();
    let original = dir.join("similarity-npm.json");
    let swapped = dir.join("osv-cache.json");
    atomic_write_json(&original, &fresh(&[]));
    std::fs::copy(&original, &swapped).unwrap();
    std::fs::copy(mac_path(&original), mac_path(&swapped)).unwrap();
    assert_eq!(read(&swapped), None);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rewriting_the_cache_refreshes_its_record() {
    let dir = unique_dir();
    let path = dir.join("osv-cache.json");
    atomic_write_json(&path, &fresh(&["GHSA-1"]));
    let entry = fresh(&["GHSA-2"]);
    atomic_write_json(&path, &entry);
    assert_eq!(read(&path), Some(entry));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn missing_cache_is_not_an_error() {
    let dir = unique_dir();
    assert_eq!(
        read_trusted_json::<Entry>(&dir.join("absent.json")),
        Ok(None)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn group_or_world_writable_cache_file_is_discarded() {
    use std::os::unix::fs::PermissionsExt;
    let dir = unique_dir();
    let path = dir.join("osv-cache.json");
    atomic_write_json(&path, &fresh(&[]));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(read(&path), None);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn cache_in_a_directory_others_can_write_is_discarded() {
    use std::os::unix::fs::PermissionsExt;
    let dir = unique_dir();
    let path = dir.join("osv-cache.json");
    atomic_write_json(&path, &fresh(&[]));
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(read(&path), None);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn ownership_check_accepts_own_files_and_rejects_symlinks() {
    let dir = unique_dir();
    let real = dir.join("real.json");
    std::fs::write(&real, "{}").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(integrity::check_owner(&real).is_ok());
    let link = dir.join("link.json");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(integrity::check_owner(&link).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn integrity_key_is_created_private_and_reused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = unique_dir();
    let path = dir.join("nested").join("cache-integrity.key");
    let first = load_or_create_key(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(load_or_create_key(&path).unwrap(), first);
    assert_ne!(first, [0u8; 32]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn integrity_key_readable_by_others_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = unique_dir();
    let path = dir.join("cache-integrity.key");
    std::fs::write(&path, [7u8; 32]).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_or_create_key(&path).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn integrity_key_of_the_wrong_length_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = unique_dir();
    let path = dir.join("cache-integrity.key");
    std::fs::write(&path, b"short").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load_or_create_key(&path).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn integrity_key_lives_in_the_config_directory_not_a_cache_directory() {
    let dir = key_dir_from(|name| match name {
        "XDG_CONFIG_HOME" => Some("/cfg".into()),
        "XDG_CACHE_HOME" => Some("/cache".into()),
        "HOME" => Some("/home/u".into()),
        _ => None,
    })
    .unwrap();
    assert_eq!(dir, PathBuf::from("/cfg/sloppy-joe"));
    // A relative XDG_CONFIG_HOME would resolve inside the scanned repository.
    let dir = key_dir_from(|name| match name {
        "XDG_CONFIG_HOME" => Some("relative".into()),
        "HOME" => Some("/home/u".into()),
        _ => None,
    })
    .unwrap();
    assert!(dir.starts_with("/home/u"), "{}", dir.display());
    assert!(!dir.starts_with(user_cache_dir_from(|name| match name {
        "HOME" => Some("/home/u".into()),
        _ => None,
    })));
}

#[test]
fn hmac_sha256_matches_rfc_4231_test_case_2() {
    let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}
