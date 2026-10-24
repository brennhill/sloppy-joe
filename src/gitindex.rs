//! Whether git tracks a path, read from `.git/index` without running git. A file that a pull
//! request commits is repository code; the same file in a developer's own checkout (usually
//! git-ignored) is the developer's, so some checks only apply to tracked files.

use std::path::{Path, PathBuf};

/// What the index says about a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndexState {
    Tracked,
    Untracked,
    /// No repository, or an index that cannot be searched reliably (unsupported version,
    /// oversized, unreadable). Callers fail closed on this.
    Undecidable,
}

const MAX_INDEX_BYTES: u64 = 256 * 1024 * 1024;

/// Whether git tracks `path`. The match is a substring search of the index for the path relative
/// to the repository root, so a longer tracked path that merely ends the same way also counts:
/// the answer errs toward `Tracked`, never toward `Untracked`.
pub(crate) fn is_git_tracked(path: &Path) -> IndexState {
    let Some(name) = path.file_name() else {
        return IndexState::Undecidable;
    };
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let Ok(parent) = std::fs::canonicalize(parent.unwrap_or(Path::new("."))) else {
        return IndexState::Undecidable;
    };
    let Ok(Some(root)) = crate::cache::find_git_root(&parent) else {
        return IndexState::Undecidable;
    };
    let Ok(relative) = parent.join(name).strip_prefix(&root).map(Path::to_path_buf) else {
        return IndexState::Undecidable;
    };
    let needle = relative.to_string_lossy().replace('\\', "/");
    search_index(&root, needle.as_bytes())
}

fn git_dir(root: &Path) -> Option<PathBuf> {
    let dot_git = root.join(".git");
    if dot_git.is_dir() {
        return Some(dot_git);
    }
    // Worktrees and submodules: `.git` is a file holding `gitdir: <path>`.
    let pointer = crate::untrusted::read_text(
        &dot_git,
        crate::untrusted::Format::Text,
        crate::fsutil::MAX_MANIFEST_BYTES,
    )
    .ok()?;
    let target = Path::new(pointer.trim().strip_prefix("gitdir:")?.trim()).to_path_buf();
    Some(if target.is_absolute() {
        target
    } else {
        root.join(target)
    })
}

fn search_index(root: &Path, needle: &[u8]) -> IndexState {
    let Some(index_path) = git_dir(root).map(|dir| dir.join("index")) else {
        return IndexState::Undecidable;
    };
    let Ok(index) = crate::fsutil::read_bytes_limited(&index_path, MAX_INDEX_BYTES) else {
        return IndexState::Undecidable;
    };
    // Versions 2 and 3 store full paths; version 4 compresses prefixes and cannot be searched.
    if index.get(..4) != Some(b"DIRC") || !matches!(index.get(7), Some(2 | 3)) {
        return IndexState::Undecidable;
    }
    if index.windows(needle.len()).any(|window| window == needle) {
        IndexState::Tracked
    } else {
        IndexState::Untracked
    }
}

#[cfg(test)]
mod tests;
