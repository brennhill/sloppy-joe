//! Writing a verified candidate into the working tree: the previous file is kept as
//! `<name>.sloppy-joe.bak`, and every replacement is a rename of a fully written temporary file,
//! so a reader never sees half a lockfile.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// `<name>.sloppy-joe.bak` beside `path`.
pub(super) fn backup_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!("{name}.sloppy-joe.bak"))
}

fn temporary_path(path: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!(
        ".{name}.sloppy-joe-tmp-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Replace `path` with `content` atomically, keeping the permissions of the file it replaces.
pub(super) fn atomic_replace(path: &Path, content: &[u8]) -> Result<()> {
    crate::cache::ensure_no_symlink(path)?;
    let permissions = std::fs::metadata(path).ok().map(|m| m.permissions());
    let tmp = temporary_path(path);
    let written = (|| -> Result<()> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .with_context(|| format!("could not create {}", tmp.display()))?;
        file.write_all(content)?;
        file.sync_all()?;
        if let Some(permissions) = permissions {
            std::fs::set_permissions(&tmp, permissions)?;
        }
        std::fs::rename(&tmp, path)
            .with_context(|| format!("could not replace {}", path.display()))?;
        Ok(())
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// Keep the current `path` as its backup (when it exists), then write `content` in its place.
/// Returns the backup path when one was made.
pub(super) fn replace_with_backup(path: &Path, content: &[u8]) -> Result<Option<PathBuf>> {
    let backup = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => {
            let backup = backup_path(path);
            let old = std::fs::read(path)
                .with_context(|| format!("could not read {}", path.display()))?;
            atomic_replace(&backup, &old)?;
            Some(backup)
        }
        Ok(_) => anyhow::bail!("{} is not a regular file; not replacing it", path.display()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(err).with_context(|| format!("could not inspect {}", path.display())),
    };
    atomic_replace(path, content)?;
    Ok(backup)
}

/// Remove `path` by renaming it to its backup.
pub(super) fn remove_with_backup(path: &Path) -> Result<PathBuf> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("could not inspect {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("{} is not a regular file; not removing it", path.display());
    }
    let backup = backup_path(path);
    crate::cache::ensure_no_symlink(&backup)?;
    std::fs::rename(path, &backup)
        .with_context(|| format!("could not move {} aside", path.display()))?;
    Ok(backup)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "sj-fix-write-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn replacing_keeps_the_previous_file_as_backup() {
        let dir = dir();
        let lock = dir.join("pnpm-lock.yaml");
        std::fs::write(&lock, "old").unwrap();
        let backup = replace_with_backup(&lock, b"new").unwrap().unwrap();
        assert_eq!(backup, dir.join("pnpm-lock.yaml.sloppy-joe.bak"));
        assert_eq!(std::fs::read_to_string(&lock).unwrap(), "new");
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "old");
        let leftovers: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().collect();
        assert_eq!(leftovers.len(), 2, "no temporary file is left behind");
    }

    #[test]
    fn writing_a_new_lockfile_makes_no_backup() {
        let dir = dir();
        let lock = dir.join("Cargo.lock");
        assert!(replace_with_backup(&lock, b"new").unwrap().is_none());
        assert_eq!(std::fs::read_to_string(&lock).unwrap(), "new");
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_target_or_backup_is_refused() {
        let dir = dir();
        let outside = dir.join("outside");
        std::fs::write(&outside, "keep").unwrap();
        let lock = dir.join("package-lock.json");
        std::os::unix::fs::symlink(&outside, &lock).unwrap();
        assert!(replace_with_backup(&lock, b"new").is_err());
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");

        let real = dir.join("yarn.lock");
        std::fs::write(&real, "old").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("yarn.lock.sloppy-joe.bak")).unwrap();
        assert!(replace_with_backup(&real, b"new").is_err());
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "old");
    }

    #[test]
    fn removing_moves_the_file_to_its_backup() {
        let dir = dir();
        let child = dir.join("package-lock.json");
        std::fs::write(&child, "shadow").unwrap();
        let backup = remove_with_backup(&child).unwrap();
        assert!(!child.exists());
        assert_eq!(std::fs::read_to_string(backup).unwrap(), "shadow");
    }
}
