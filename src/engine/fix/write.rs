//! Writing a verified candidate into the working tree as one all-or-nothing change.
//!
//! 1. Check every path before touching anything: a target must be a regular file or absent, and
//!    its backup `<name>.sloppy-joe.bak` must not exist at all (file, directory or symlink). An
//!    existing backup is never overwritten: the write is refused and names it.
//! 2. Stage: create each backup and each fully written temporary file with `create_new`, so a
//!    path planted after the check is still refused rather than followed or clobbered.
//! 3. Commit: remove the files the fix deletes, then rename each temporary file over its target,
//!    so a reader never sees half a lockfile.
//!
//! A failure at any step undoes the steps before it, so the tree is left as it was.

use anyhow::{Context, Result};
use std::fs::Permissions;
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

/// Create `path`, which must not exist, holding `content`. A partly written file is removed.
fn create_new_file(path: &Path, content: &[u8], permissions: Option<&Permissions>) -> Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("could not create {}", path.display()))?;
    let written = (|| -> std::io::Result<()> {
        file.write_all(content)?;
        file.sync_all()?;
        if let Some(permissions) = permissions {
            std::fs::set_permissions(path, permissions.clone())?;
        }
        Ok(())
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(path);
    }
    written.with_context(|| format!("could not write {}", path.display()))
}

/// Put `content` at `path` (present or not) through a temporary file and a rename.
fn replace_via_temporary(path: &Path, content: &[u8], permissions: &Permissions) -> Result<()> {
    let tmp = temporary_path(path);
    create_new_file(&tmp, content, Some(permissions))?;
    std::fs::rename(&tmp, path).map_err(|err| {
        let _ = std::fs::remove_file(&tmp);
        anyhow::Error::new(err).context(format!("could not replace {}", path.display()))
    })
}

/// A file the change replaces or removes, as it was before.
struct Previous {
    content: Vec<u8>,
    permissions: Permissions,
    backup: PathBuf,
}

/// One path the change touches.
struct Target<'a> {
    path: &'a Path,
    /// The new content; `None` removes the file.
    content: Option<&'a [u8]>,
    previous: Option<Previous>,
}

/// The current regular file at `path`, `None` when absent; anything else is refused.
fn inspect(path: &Path) -> Result<Option<(Vec<u8>, Permissions)>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("could not inspect {}", path.display()));
        }
    };
    if !metadata.is_file() {
        anyhow::bail!("{} is not a regular file; not replacing it", path.display());
    }
    let content =
        std::fs::read(path).with_context(|| format!("could not read {}", path.display()))?;
    Ok(Some((content, metadata.permissions())))
}

/// Refuse a backup path that already exists in any form.
fn ensure_absent(backup: &Path) -> Result<()> {
    match std::fs::symlink_metadata(backup) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("could not inspect {}", backup.display())),
        Ok(metadata) => {
            let kind = if metadata.file_type().is_symlink() {
                " (as a symlink)"
            } else {
                ""
            };
            anyhow::bail!(
                "{} already exists{kind}; fix-lockfile never overwrites a backup: move or remove it and run fix-lockfile again",
                backup.display()
            )
        }
    }
}

fn target<'a>(path: &'a Path, content: Option<&'a [u8]>) -> Result<Target<'a>> {
    let previous = match inspect(path)? {
        Some((content, permissions)) => {
            let backup = backup_path(path);
            ensure_absent(&backup)?;
            Some(Previous {
                content,
                permissions,
                backup,
            })
        }
        None if content.is_none() => {
            anyhow::bail!("{} does not exist; nothing to remove", path.display())
        }
        None => None,
    };
    Ok(Target {
        path,
        content,
        previous,
    })
}

/// Step 1: every target and backup path, checked before anything changes.
fn check<'a>(writes: &'a [(PathBuf, Vec<u8>)], removals: &'a [PathBuf]) -> Result<Vec<Target<'a>>> {
    let mut targets = Vec::new();
    for (path, content) in writes {
        targets.push(target(path, Some(content))?);
    }
    for path in removals {
        targets.push(target(path, None)?);
    }
    let mut seen = std::collections::HashSet::new();
    for path in targets.iter().flat_map(|t| {
        std::iter::once(t.path.to_path_buf()).chain(t.previous.as_ref().map(|p| p.backup.clone()))
    }) {
        if !seen.insert(path.clone()) {
            anyhow::bail!("{} is touched twice by one fix", path.display());
        }
    }
    Ok(targets)
}

/// What to undo when a later step fails, newest last.
enum Undo {
    Remove(PathBuf),
    Restore(PathBuf, Vec<u8>, Permissions),
}

#[derive(Default)]
struct Journal(Vec<Undo>);

impl Journal {
    /// Undo every recorded step, newest first; returns what could not be undone.
    fn rollback(&mut self) -> Vec<String> {
        let mut failures = Vec::new();
        while let Some(step) = self.0.pop() {
            let undone = match &step {
                Undo::Remove(path) => match std::fs::remove_file(path) {
                    Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
                        Err(anyhow::Error::new(err).context(format!("remove {}", path.display())))
                    }
                    _ => Ok(()),
                },
                Undo::Restore(path, content, permissions) => {
                    replace_via_temporary(path, content, permissions)
                }
            };
            if let Err(err) = undone {
                failures.push(format!("{err:#}"));
            }
        }
        failures
    }
}

/// Steps 2 and 3. Returns the backups made.
fn stage_and_commit(targets: &[Target<'_>], journal: &mut Journal) -> Result<Vec<PathBuf>> {
    let mut backups = Vec::new();
    for previous in targets.iter().filter_map(|t| t.previous.as_ref()) {
        create_new_file(
            &previous.backup,
            &previous.content,
            Some(&previous.permissions),
        )?;
        journal.0.push(Undo::Remove(previous.backup.clone()));
        backups.push(previous.backup.clone());
    }
    let mut staged = Vec::new();
    for target in targets {
        let Some(content) = target.content else {
            continue;
        };
        let tmp = temporary_path(target.path);
        let permissions = target.previous.as_ref().map(|p| &p.permissions);
        create_new_file(&tmp, content, permissions)?;
        journal.0.push(Undo::Remove(tmp.clone()));
        staged.push((target, tmp));
    }
    for target in targets.iter().filter(|t| t.content.is_none()) {
        std::fs::remove_file(target.path)
            .with_context(|| format!("could not move {} aside", target.path.display()))?;
        journal.0.push(undo_for(target));
    }
    for (target, tmp) in staged {
        std::fs::rename(&tmp, target.path)
            .with_context(|| format!("could not replace {}", target.path.display()))?;
        journal.0.push(undo_for(target));
    }
    Ok(backups)
}

/// How to put `target.path` back as it was.
fn undo_for(target: &Target<'_>) -> Undo {
    match &target.previous {
        Some(previous) => Undo::Restore(
            target.path.to_path_buf(),
            previous.content.clone(),
            previous.permissions.clone(),
        ),
        None => Undo::Remove(target.path.to_path_buf()),
    }
}

/// Write each of `writes` and remove each of `removals`, keeping every previous file as its
/// backup, all or nothing. Returns the backups made.
pub(super) fn apply_changes(
    writes: &[(PathBuf, Vec<u8>)],
    removals: &[PathBuf],
) -> Result<Vec<PathBuf>> {
    let targets = check(writes, removals).context("nothing in the project was changed")?;
    let mut journal = Journal::default();
    stage_and_commit(&targets, &mut journal).map_err(|err| {
        let failures = journal.rollback();
        if failures.is_empty() {
            err.context("the change was undone; nothing in the project was changed")
        } else {
            err.context(format!(
                "the change could not be fully undone ({}); check the project tree",
                failures.join("; ")
            ))
        }
    })
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

    /// Every entry directly under `dir` with its bytes, or its link target for a symlink.
    fn listing(dir: &Path) -> Vec<(String, String)> {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|entry| {
                let path = entry.path();
                let content = match std::fs::read_link(&path) {
                    Ok(target) => format!("-> {}", target.display()),
                    Err(_) => String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into(),
                };
                (entry.file_name().to_string_lossy().into_owned(), content)
            })
            .collect();
        entries.sort();
        entries
    }

    fn write(path: &Path, content: &str) -> Vec<(PathBuf, Vec<u8>)> {
        vec![(path.to_path_buf(), content.as_bytes().to_vec())]
    }

    #[test]
    fn replacing_keeps_the_previous_file_as_backup() {
        let dir = dir();
        let lock = dir.join("pnpm-lock.yaml");
        std::fs::write(&lock, "old").unwrap();
        let backups = apply_changes(&write(&lock, "new"), &[]).unwrap();
        assert_eq!(backups, vec![dir.join("pnpm-lock.yaml.sloppy-joe.bak")]);
        assert_eq!(std::fs::read_to_string(&lock).unwrap(), "new");
        assert_eq!(std::fs::read_to_string(&backups[0]).unwrap(), "old");
        assert_eq!(listing(&dir).len(), 2, "no temporary file is left behind");
    }

    #[cfg(unix)]
    #[test]
    fn the_replacement_and_backup_keep_the_previous_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = dir();
        let lock = dir.join("Cargo.lock");
        std::fs::write(&lock, "old").unwrap();
        std::fs::set_permissions(&lock, Permissions::from_mode(0o640)).unwrap();
        let backups = apply_changes(&write(&lock, "new"), &[]).unwrap();
        for path in [&lock, &backups[0]] {
            let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o640, "{}", path.display());
        }
    }

    #[test]
    fn writing_a_new_lockfile_makes_no_backup() {
        let dir = dir();
        let lock = dir.join("Cargo.lock");
        assert!(apply_changes(&write(&lock, "new"), &[]).unwrap().is_empty());
        assert_eq!(std::fs::read_to_string(&lock).unwrap(), "new");
    }

    #[test]
    fn an_existing_backup_is_refused_and_named() {
        let dir = dir();
        let lock = dir.join("yarn.lock");
        std::fs::write(&lock, "old").unwrap();
        std::fs::write(dir.join("yarn.lock.sloppy-joe.bak"), "earlier").unwrap();
        let before = listing(&dir);
        let error = format!(
            "{:#}",
            apply_changes(&write(&lock, "new"), &[]).unwrap_err()
        );
        assert!(
            error.contains("yarn.lock.sloppy-joe.bak already exists"),
            "{error}"
        );
        assert!(
            error.contains("nothing in the project was changed"),
            "{error}"
        );
        assert_eq!(listing(&dir), before);

        let child = dir.join("yarn.lock");
        let error = format!("{:#}", apply_changes(&[], &[child]).unwrap_err());
        assert!(error.contains("already exists"), "{error}");
        assert_eq!(listing(&dir), before);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_target_or_backup_is_refused() {
        let dir = dir();
        let outside = dir.join("outside");
        std::fs::write(&outside, "keep").unwrap();
        let lock = dir.join("package-lock.json");
        std::os::unix::fs::symlink(&outside, &lock).unwrap();
        assert!(apply_changes(&write(&lock, "new"), &[]).is_err());
        assert!(apply_changes(&[], std::slice::from_ref(&lock)).is_err());
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");

        let real = dir.join("yarn.lock");
        std::fs::write(&real, "old").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("yarn.lock.sloppy-joe.bak")).unwrap();
        assert!(apply_changes(&write(&real, "new"), &[]).is_err());
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "old");
    }

    #[cfg(unix)]
    #[test]
    fn a_planted_backup_symlink_for_a_removal_leaves_every_file_in_place() {
        let dir = dir();
        let outside = dir.join("outside");
        std::fs::write(&outside, "keep").unwrap();
        let lockb = dir.join("bun.lockb");
        std::fs::write(&lockb, "binary").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("bun.lockb.sloppy-joe.bak")).unwrap();
        let before = listing(&dir);
        let error = apply_changes(&write(&dir.join("bun.lock"), "text"), &[lockb]).unwrap_err();
        let error = format!("{error:#}");
        assert!(error.contains("bun.lockb.sloppy-joe.bak"), "{error}");
        assert!(error.contains("symlink"), "{error}");
        assert_eq!(listing(&dir), before, "bun.lock is not written");
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "keep");
    }

    #[test]
    fn a_failure_while_staging_undoes_the_backups_already_made() {
        let dir = dir();
        let lockb = dir.join("bun.lockb");
        std::fs::write(&lockb, "binary").unwrap();
        let before = listing(&dir);
        // The new file's directory does not exist, so its temporary file cannot be created
        // after the removal's backup was.
        let unwritable = dir.join("missing").join("bun.lock");
        let error = apply_changes(&write(&unwritable, "text"), &[lockb]).unwrap_err();
        assert!(format!("{error:#}").contains("undone"), "{error:#}");
        assert_eq!(listing(&dir), before);
    }

    #[test]
    fn removing_moves_the_file_to_its_backup() {
        let dir = dir();
        let child = dir.join("package-lock.json");
        std::fs::write(&child, "shadow").unwrap();
        let backups = apply_changes(&[], std::slice::from_ref(&child)).unwrap();
        assert!(!child.exists());
        assert_eq!(std::fs::read_to_string(&backups[0]).unwrap(), "shadow");
    }

    #[test]
    fn a_write_and_a_removal_happen_together() {
        let dir = dir();
        let lockb = dir.join("bun.lockb");
        std::fs::write(&lockb, "binary").unwrap();
        let lock = dir.join("bun.lock");
        let backups = apply_changes(&write(&lock, "text"), std::slice::from_ref(&lockb)).unwrap();
        assert_eq!(backups, vec![dir.join("bun.lockb.sloppy-joe.bak")]);
        assert_eq!(
            listing(&dir),
            vec![
                ("bun.lock".to_string(), "text".to_string()),
                ("bun.lockb.sloppy-joe.bak".to_string(), "binary".to_string()),
            ]
        );
    }

    #[test]
    fn rollback_restores_replaced_and_removed_files() {
        let dir = dir();
        let replaced = dir.join("a.lock");
        let removed = dir.join("b.lock");
        let created = dir.join("c.lock");
        std::fs::write(&replaced, "new").unwrap();
        std::fs::write(&created, "new").unwrap();
        let permissions = std::fs::metadata(&replaced).unwrap().permissions();
        let mut journal = Journal(vec![
            Undo::Restore(removed.clone(), b"old b".to_vec(), permissions.clone()),
            Undo::Restore(replaced.clone(), b"old a".to_vec(), permissions),
            Undo::Remove(created.clone()),
        ]);
        assert!(journal.rollback().is_empty());
        assert_eq!(
            listing(&dir),
            vec![
                ("a.lock".to_string(), "old a".to_string()),
                ("b.lock".to_string(), "old b".to_string()),
            ]
        );
    }
}
