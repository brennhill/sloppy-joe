//! Repository files a package manager reads without being told to, declared as data.
//!
//! Each plugin lists the files (and directories) its tools consult beside a project or in the
//! directories above it, and what the scan does about each. One generic walk applies the table, so
//! "which files can steer this install?" has an answer in the tree and a new row cannot be added
//! without saying what it means. The walk names no ecosystem.

use super::*;
use anyhow::bail;

/// Where a tool looks for the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    /// The project directory only.
    ProjectDir,
    /// The project directory and every parent up to the repository root (to the filesystem root
    /// when there is no repository, which only widens what is checked).
    AncestorsToRepoRoot,
}

/// What the scan does when the file is present.
#[derive(Clone, Copy)]
pub(crate) enum Disposition {
    /// The checker runs on the matched path; its error blocks the project.
    Modeled(fn(&Path) -> Result<()>),
    /// A check that needs more context than a path (a parsed manifest, the operator's
    /// `config_key_allow`) already runs elsewhere; the text names it. The conformance suite
    /// still proves that a bad file of this kind blocks.
    #[allow(dead_code)] // the text is read by the conformance suite and by people
    ModeledElsewhere(&'static str),
    /// Presence alone blocks the project; the text says why.
    Blocked(&'static str),
    /// Blocks when git tracks the file (a pull request commits it), is silent when git does not,
    /// and when git cannot say it warns, or blocks in `--ci`.
    BlockedIfTracked(&'static str),
    /// The file cannot change what is installed; the text says why.
    #[allow(dead_code)] // the text is read by the conformance suite and by people
    Irrelevant(&'static str),
}

pub(crate) struct AmbientInput {
    /// Path relative to the scope directory. Segments match case-insensitively; `*` inside a
    /// segment matches any run of characters.
    pub(crate) pattern: &'static str,
    /// Project kinds the row applies to; empty means every kind of the plugin.
    pub(crate) kinds: &'static [ProjectInputKind],
    pub(crate) scope: Scope,
    pub(crate) disposition: Disposition,
}

impl AmbientInput {
    pub(crate) const fn new(pattern: &'static str, scope: Scope, disposition: Disposition) -> Self {
        Self {
            pattern,
            kinds: &[],
            scope,
            disposition,
        }
    }

    pub(crate) const fn only(mut self, kinds: &'static [ProjectInputKind]) -> Self {
        self.kinds = kinds;
        self
    }

    fn applies_to(&self, kind: ProjectInputKind) -> bool {
        self.kinds.is_empty() || self.kinds.contains(&kind)
    }
}

/// Apply `inputs` to one project. An error blocks it; the issues are warnings.
pub(crate) fn check(
    inputs: &[AmbientInput],
    spec: &ProjectInputSpec,
    strict: bool,
) -> Result<Vec<Issue>> {
    let project_dir = std::fs::canonicalize(spec.project_dir())?;
    let ancestors = ancestor_dirs(&project_dir)?;
    let mut issues = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for input in inputs.iter().filter(|input| input.applies_to(spec.kind)) {
        let dirs = match input.scope {
            Scope::ProjectDir => std::slice::from_ref(&project_dir),
            Scope::AncestorsToRepoRoot => ancestors.as_slice(),
        };
        for dir in dirs {
            for path in matches(dir, input.pattern)? {
                if seen.insert((input.pattern, path.clone())) {
                    issues.extend(apply(&input.disposition, &path, strict)?);
                }
            }
        }
    }
    Ok(issues)
}

fn ancestor_dirs(project_dir: &Path) -> Result<Vec<PathBuf>> {
    let boundary = cache::find_git_root(project_dir).map_err(anyhow::Error::msg)?;
    let mut dirs = Vec::new();
    for ancestor in project_dir.ancestors() {
        dirs.push(ancestor.to_path_buf());
        if boundary.as_deref() == Some(ancestor) {
            break;
        }
    }
    Ok(dirs)
}

fn apply(disposition: &Disposition, path: &Path, strict: bool) -> Result<Vec<Issue>> {
    match disposition {
        Disposition::Modeled(checker) => checker(path).map(|()| Vec::new()),
        Disposition::ModeledElsewhere(_) | Disposition::Irrelevant(_) => Ok(Vec::new()),
        Disposition::Blocked(reason) => bail!(
            "Unsupported repository file {}: {reason}",
            path.display()
        ),
        Disposition::BlockedIfTracked(reason) => match gitindex::is_git_tracked(path) {
            gitindex::IndexState::Untracked => Ok(Vec::new()),
            gitindex::IndexState::Tracked => bail!(
                "Committed repository file {}: {reason}",
                path.display()
            ),
            gitindex::IndexState::Undecidable => Ok(vec![
                Issue::new(
                    path.display().to_string(),
                    checks::names::RESOLUTION_AMBIENT_INPUT_UNDECIDABLE,
                    if strict {
                        Severity::Error
                    } else {
                        Severity::Warning
                    },
                )
                .message(format!(
                    "{} exists and sloppy-joe cannot tell whether git tracks it; if it is committed: {reason}",
                    path.display()
                ))
                .fix("Make sure the file is not committed (add it to .gitignore). Blocks in --ci."),
            ]),
        },
    }
}

/// Paths under `dir` that match `pattern`, found by listing directories so that a case variant
/// and a symlink whose target has the right name both count. A directory that does not exist has
/// no matches; one that exists and cannot be listed blocks.
pub(crate) fn matches(dir: &Path, pattern: &str) -> Result<Vec<PathBuf>> {
    let mut current = vec![dir.to_path_buf()];
    let segments: Vec<&str> = pattern.split('/').collect();
    for (index, segment) in segments.iter().enumerate() {
        let last = index + 1 == segments.len();
        let mut next = Vec::new();
        for parent in &current {
            for entry in list_dir(parent)? {
                if !segment_matches(segment, &entry) {
                    continue;
                }
                if last || entry.is_dir() {
                    next.push(entry);
                }
            }
        }
        current = next;
    }
    Ok(current)
}

fn list_dir(dir: &Path) -> Result<Vec<PathBuf>> {
    let reader = match std::fs::read_dir(dir) {
        Ok(reader) => reader,
        Err(err) if matches!(err.kind(), std::io::ErrorKind::NotFound) => return Ok(Vec::new()),
        Err(err) if dir.is_file() || err.kind() == std::io::ErrorKind::NotADirectory => {
            return Ok(Vec::new());
        }
        Err(err) => bail!("Failed to list {}: {err}", dir.display()),
    };
    reader
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|err| anyhow::anyhow!("Failed to list {}: {err}", dir.display()))
        })
        .collect()
}

/// An entry matches by its own name, or, when it is a symlink, by the name of its target.
fn segment_matches(segment: &str, entry: &Path) -> bool {
    let name_matches = |path: &Path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| glob_matches(segment, name))
    };
    if name_matches(entry) {
        return true;
    }
    std::fs::symlink_metadata(entry).is_ok_and(|meta| meta.file_type().is_symlink())
        && std::fs::canonicalize(entry).is_ok_and(|target| name_matches(&target))
}

fn glob_matches(pattern: &str, name: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let name = name.to_lowercase();
    let mut pieces = pattern.split('*');
    let first = pieces.next().unwrap_or_default();
    let Some(mut rest) = name.strip_prefix(first) else {
        return false;
    };
    let tail: Vec<&str> = pieces.collect();
    let Some((last, middle)) = tail.split_last() else {
        return rest.is_empty();
    };
    for piece in middle {
        match rest.find(piece) {
            Some(at) => rest = &rest[at + piece.len()..],
            None => return false,
        }
    }
    rest.ends_with(last)
}

#[cfg(test)]
#[path = "ambient/tests.rs"]
mod tests;
