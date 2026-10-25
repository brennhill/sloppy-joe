//! Ownership and integrity checks for cache files.
//!
//! Cache files decide scan outcomes (an OSV entry with no advisories clears a package), so a
//! cache entry is trusted only when:
//! - the file and its directory belong to the current user and are not group/world-writable
//!   (another account cannot have written or replaced it), and
//! - a sidecar `<file>.mac` holds the HMAC-SHA256 of the file's bytes under a per-user key kept
//!   in the user's config directory, outside every cache directory. A hand-edited cache, or one
//!   restored from somewhere else (a shared or CI cache artifact), fails the check.
//!
//! A file that fails either check is discarded: the caller refetches, never trusts it. Code
//! running as the same user can read the key, so this does not defend against that user; it
//! stops other accounts, copied-in caches, and edits that bypass sloppy-joe.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const KEY_LEN: usize = 32;
const KEY_FILE: &str = "cache-integrity.key";
const MAC_EXTENSION: &str = "mac";

/// The sidecar that holds `path`'s MAC.
pub(super) fn mac_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(MAC_EXTENSION);
    path.with_file_name(name)
}

/// Why a cache file is not trusted, or `Ok` when it is.
pub(super) fn verify(path: &Path, content: &[u8]) -> Result<(), String> {
    check_owner(path)?;
    if let Some(parent) = path.parent() {
        check_owner(parent)?;
    }
    let key = key().ok_or("no cache integrity key is available")?;
    let mac_file = mac_path(path);
    check_owner(&mac_file)?;
    let recorded = std::fs::read_to_string(&mac_file)
        .map_err(|e| format!("integrity record {} unreadable: {e}", mac_file.display()))?;
    if !constant_time_eq(
        recorded.trim().as_bytes(),
        mac_hex(&key, path, content).as_bytes(),
    ) {
        return Err("contents do not match their integrity record".to_string());
    }
    Ok(())
}

/// The sidecar contents for `content` written at `path`, if a key is available.
pub(super) fn seal(path: &Path, content: &[u8]) -> Option<String> {
    Some(mac_hex(&key()?, path, content))
}

/// MAC over the file name and bytes, so one cache file cannot be substituted for another.
fn mac_hex(key: &[u8; KEY_LEN], path: &Path, content: &[u8]) -> String {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let mut message = Vec::with_capacity(name.len() + 1 + content.len());
    message.extend_from_slice(name.as_bytes());
    message.push(0);
    message.extend_from_slice(content);
    hmac_sha256(key, &message)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// HMAC-SHA256 (RFC 2104) with a key no longer than the block size.
pub(super) fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut padded = [0u8; BLOCK];
    padded[..key.len()].copy_from_slice(key);
    let pad = |byte: u8| padded.iter().map(|k| k ^ byte).collect::<Vec<u8>>();
    let inner = Sha256::new()
        .chain_update(pad(0x36))
        .chain_update(message)
        .finalize();
    Sha256::new()
        .chain_update(pad(0x5c))
        .chain_update(inner)
        .finalize()
        .into()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Owned by the current user, not a symlink, and not writable by group or others.
#[cfg(unix)]
pub(super) fn check_owner(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("{} unreadable: {e}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!("{} is a symlink", path.display()));
    }
    let euid = current_uid().ok_or("the current user id could not be determined")?;
    if meta.uid() != euid {
        return Err(format!(
            "{} is owned by uid {}, not the current user ({euid})",
            path.display(),
            meta.uid()
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{} is writable by group or others (mode {:o})",
            path.display(),
            meta.mode() & 0o7777
        ));
    }
    Ok(())
}

/// The effective user id, read from a file this process creates (the crate forbids `unsafe`, so
/// `geteuid` is not called directly). `None` if no probe file can be created: then nothing is
/// trusted.
#[cfg(unix)]
fn current_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    static UID: OnceLock<Option<u32>> = OnceLock::new();
    *UID.get_or_init(|| {
        let probe = std::env::temp_dir().join(format!(
            "sloppy-joe-uid-probe-{}-{}",
            std::process::id(),
            super::now_nanos()
        ));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)
            .ok()?;
        let uid = file.metadata().ok().map(|meta| meta.uid());
        let _ = std::fs::remove_file(&probe);
        uid
    })
}

#[cfg(not(unix))]
pub(super) fn check_owner(path: &Path) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("{} unreadable: {e}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!("{} is a symlink", path.display()));
    }
    Ok(())
}

/// The per-user key, loaded or created once per process. `None` disables cache trust (every
/// read is discarded and refetched) and is reported once.
fn key() -> Option<[u8; KEY_LEN]> {
    static KEY: OnceLock<Option<[u8; KEY_LEN]>> = OnceLock::new();
    *KEY.get_or_init(|| {
        let loaded = key_path().and_then(|path| load_or_create_key(&path));
        match loaded {
            Ok(key) => Some(key),
            Err(reason) => {
                eprintln!(
                    "Cache integrity key unavailable ({}); cached results will not be trusted and are fetched fresh.",
                    crate::report::sanitize_for_terminal(&reason)
                );
                None
            }
        }
    })
}

/// The key lives in the user's config directory, never under a cache directory, so a cache
/// directory copied from elsewhere cannot carry a key that validates it.
fn key_path() -> Result<PathBuf, String> {
    #[cfg(test)]
    {
        Ok(std::env::temp_dir()
            .join(format!("sloppy-joe-test-key-{}", std::process::id()))
            .join(KEY_FILE))
    }
    #[cfg(not(test))]
    {
        key_dir_from(|name| std::env::var_os(name)).map(|dir| dir.join(KEY_FILE))
    }
}

/// `$XDG_CONFIG_HOME/sloppy-joe`, else the platform config directory. Relative values are
/// ignored: they would resolve against the scanned repository.
pub(super) fn key_dir_from(
    env: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<PathBuf, String> {
    let env = |name: &str| env(name).filter(|value| Path::new(value).is_absolute());
    if let Some(xdg) = env("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(xdg).join("sloppy-joe"));
    }
    #[cfg(target_os = "windows")]
    if let Some(appdata) = env("APPDATA") {
        return Ok(PathBuf::from(appdata).join("sloppy-joe"));
    }
    let home = env("HOME").ok_or("HOME is not set to an absolute path")?;
    let home = PathBuf::from(home);
    if cfg!(target_os = "macos") {
        return Ok(home
            .join("Library")
            .join("Application Support")
            .join("sloppy-joe"));
    }
    Ok(home.join(".config").join("sloppy-joe"))
}

pub(super) fn load_or_create_key(path: &Path) -> Result<[u8; KEY_LEN], String> {
    if std::fs::symlink_metadata(path).is_err() {
        create_key(path)?;
    }
    check_owner(path)?;
    check_private(path)?;
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    bytes
        .try_into()
        .map_err(|_| format!("{} is not a {KEY_LEN}-byte key", path.display()))
}

/// Readable only by its owner.
#[cfg(unix)]
fn check_private(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let mode = std::fs::metadata(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "{} is readable by group or others (mode {:o})",
            path.display(),
            mode & 0o7777
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn create_key(path: &Path) -> Result<(), String> {
    use std::io::Write;
    let dir = path.parent().ok_or("key path has no directory")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let key = random_key()?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => file
            .write_all(&key)
            .map_err(|e| format!("{}: {e}", path.display())),
        // Another process created it first; the caller validates and reads that one.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

#[cfg(unix)]
fn random_key() -> Result<[u8; KEY_LEN], String> {
    use std::io::Read;
    let mut key = [0u8; KEY_LEN];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut key))
        .map_err(|e| format!("no system randomness: {e}"))?;
    Ok(key)
}

#[cfg(not(unix))]
fn random_key() -> Result<[u8; KEY_LEN], String> {
    Err("no supported system randomness source on this platform".to_string())
}
