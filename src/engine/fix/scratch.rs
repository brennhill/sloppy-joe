//! The private scratch directory `fix-lockfile` runs a tool in. Created fresh with mode 0700,
//! never reused, and removed when the value is dropped, on every exit path.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub(super) struct Scratch {
    root: PathBuf,
}

impl Scratch {
    /// A new, empty directory under `parent` that did not exist before.
    pub(super) fn create(parent: &Path) -> Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        let root = parent.join(format!(
            "sloppy-joe-fix-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        // `create`, not `create_all`: an existing path (planted or left over) is an error.
        builder
            .create(&root)
            .with_context(|| format!("could not create scratch directory {}", root.display()))?;
        let scratch = Self { root };
        let metadata = std::fs::symlink_metadata(&scratch.root)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            anyhow::bail!("scratch directory {} is not a plain directory", scratch.root.display());
        }
        for dir in ["home", "tmp", "work", "verify", "cache"] {
            std::fs::create_dir(scratch.root.join(dir))?;
        }
        Ok(scratch)
    }

    #[cfg(test)]
    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    /// `HOME` and every cache and config directory of the tool.
    pub(super) fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    pub(super) fn tmp(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// The copy the tool runs in.
    pub(super) fn work(&self) -> PathBuf {
        self.root.join("work")
    }

    /// The candidate tree that is verified: the original inputs with the tool's outputs.
    pub(super) fn verify(&self) -> PathBuf {
        self.root.join("verify")
    }

    /// Cache directory of the rescan, so it neither reads nor writes the user's cache.
    pub(super) fn cache(&self) -> PathBuf {
        self.root.join("cache")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if std::fs::remove_dir_all(&self.root).is_ok() {
            return;
        }
        // Tools leave read-only files (Go's module cache); make the tree writable and retry.
        make_writable(&self.root);
        if let Err(err) = std::fs::remove_dir_all(&self.root) {
            eprintln!(
                "Warning: could not remove fix-lockfile scratch directory {}: {err}",
                self.root.display()
            );
        }
    }
}

fn make_writable(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(metadata) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if metadata.is_dir() {
                make_writable(&path);
            } else if !metadata.file_type().is_symlink() {
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Copy the regular file `from` to `to`, creating parents. Symlinks and special files are refused:
/// the scratch copy holds file contents only.
pub(super) fn copy_file(from: &Path, to: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(from)
        .with_context(|| format!("could not inspect {}", from.display()))?;
    if !metadata.is_file() {
        anyhow::bail!(
            "{} is not a regular file, so it is not copied into the scratch directory",
            from.display()
        );
    }
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(from, to)
        .with_context(|| format!("could not copy {} into the scratch directory", from.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parent() -> PathBuf {
        std::env::temp_dir()
    }

    #[test]
    fn scratch_is_private_fresh_and_removed_on_drop() {
        let scratch = Scratch::create(&parent()).unwrap();
        let root = scratch.root().to_path_buf();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
        for dir in [scratch.home(), scratch.work(), scratch.verify(), scratch.cache()] {
            assert!(dir.is_dir());
        }
        std::fs::write(scratch.work().join("f"), "x").unwrap();
        drop(scratch);
        assert!(!root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn read_only_trees_are_removed_too() {
        use std::os::unix::fs::PermissionsExt;
        let scratch = Scratch::create(&parent()).unwrap();
        let root = scratch.root().to_path_buf();
        let nested = scratch.home().join("mod/cache");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("f"), "x").unwrap();
        std::fs::set_permissions(nested.join("f"), std::fs::Permissions::from_mode(0o400))
            .unwrap();
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o500)).unwrap();
        drop(scratch);
        assert!(!root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_not_copied() {
        let scratch = Scratch::create(&parent()).unwrap();
        let target = scratch.tmp().join("target");
        std::fs::write(&target, "secret").unwrap();
        let link = scratch.tmp().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(copy_file(&link, &scratch.work().join("copy")).is_err());
        copy_file(&target, &scratch.work().join("a/b/copy")).unwrap();
        assert!(scratch.work().join("a/b/copy").is_file());
    }
}
