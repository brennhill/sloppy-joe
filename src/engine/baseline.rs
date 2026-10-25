//! Dependencies a project declares now that it did not declare at a git ref
//! (`--base-ref`). A dependency an AI assistant just added is the one most
//! likely to be a guessed name, so it gets extra scrutiny (see
//! `checks::steering`).
//!
//! The manifest at the ref is read with `git cat-file` (plumbing: no pager,
//! no textconv, no hooks) and parsed by the project's own manifest parser from
//! a private temporary directory. Only the manifest file is restored, so a
//! manifest that needs siblings (`-r other.txt`) cannot be compared.

use crate::checks::steering::dependency_key;
use crate::{Dependency, ProjectInputSpec, ecosystems};
use anyhow::{Result, anyhow, bail};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Why no baseline could be compared, so callers can pick a severity.
#[derive(Debug)]
pub(crate) enum BaselineError {
    /// The ref, repository or git itself is unusable: a configuration error.
    Unusable(anyhow::Error),
    /// The manifest at the ref could not be parsed in isolation.
    Unparsed(anyhow::Error),
}

/// A ref git can resolve; anything that could be read as an option is refused.
pub(crate) fn validate_ref(base_ref: &str) -> Result<()> {
    let ok = !base_ref.is_empty()
        && base_ref.len() <= 200
        && !base_ref.starts_with('-')
        && base_ref
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/@^~-".contains(&b));
    if !ok {
        bail!("--base-ref {base_ref:?} is not a plain git ref");
    }
    Ok(())
}

/// The git invocation. Its messages are forced into the C locale because `manifest_at_ref`
/// classifies them by their English text; a localised git would otherwise turn "file absent at
/// the ref" into a blocking error.
fn git_command(root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C")
        .env("LANGUAGE", "C")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE");
    command
}

fn git(root: &Path, args: &[&str]) -> Result<std::process::Output> {
    git_command(root, args)
        .output()
        .map_err(|e| anyhow!("could not run git: {e}"))
}

/// The manifest's bytes at `base_ref`; `None` when the file did not exist there.
fn manifest_at_ref(root: &Path, base_ref: &str, relative: &str) -> Result<Option<Vec<u8>>> {
    let commit = format!("{base_ref}^{{commit}}");
    let verified = git(root, &["rev-parse", "--verify", "--quiet", &commit])?;
    if !verified.status.success() {
        bail!(
            "git cannot resolve --base-ref {base_ref:?} to a commit (a shallow clone may lack it)"
        );
    }
    let object = format!("{base_ref}:{relative}");
    let blob = git(root, &["cat-file", "blob", &object])?;
    if blob.status.success() {
        if blob.stdout.len() as u64 > crate::fsutil::MAX_MANIFEST_BYTES {
            bail!("{relative} at {base_ref} is larger than the manifest size limit");
        }
        return Ok(Some(blob.stdout));
    }
    let stderr = String::from_utf8_lossy(&blob.stderr);
    if stderr.contains("does not exist") || stderr.contains("exists on disk, but not in") {
        return Ok(None);
    }
    bail!(
        "git could not read {relative} at {base_ref}: {}",
        stderr.trim()
    )
}

struct TempDir(PathBuf);

impl TempDir {
    fn create() -> Result<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path =
            std::env::temp_dir().join(format!("sloppy-joe-base-{}-{nanos}", std::process::id()));
        std::fs::create_dir(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self(path))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn baseline_keys(
    spec: &ProjectInputSpec,
    base_ref: &str,
) -> Result<Option<HashSet<String>>, BaselineError> {
    let manifest = spec
        .manifest_path
        .canonicalize()
        .map_err(|e| BaselineError::Unusable(e.into()))?;
    let parent = manifest
        .parent()
        .ok_or_else(|| BaselineError::Unusable(anyhow!("manifest has no directory")))?;
    let root = crate::cache::find_git_root(parent)
        .map_err(|e| BaselineError::Unusable(anyhow!(e)))?
        .ok_or_else(|| BaselineError::Unusable(anyhow!("--base-ref needs a git repository")))?;
    let relative = manifest
        .strip_prefix(&root)
        .map_err(|e| BaselineError::Unusable(e.into()))?
        .to_string_lossy()
        .replace('\\', "/");
    let Some(bytes) =
        manifest_at_ref(&root, base_ref, &relative).map_err(BaselineError::Unusable)?
    else {
        return Ok(None);
    };
    let dir = TempDir::create().map_err(BaselineError::Unusable)?;
    let file_name = manifest
        .file_name()
        .ok_or_else(|| BaselineError::Unusable(anyhow!("manifest has no file name")))?;
    let restored = dir.0.join(file_name);
    std::fs::write(&restored, bytes).map_err(|e| BaselineError::Unusable(e.into()))?;
    let mut baseline_spec = spec.clone();
    baseline_spec.manifest_path = restored;
    baseline_spec.lockfile_path_override = None;
    baseline_spec.js_binding = None;
    let deps = ecosystems::for_kind(spec.kind)
        .parse_manifest(&dir.0, &baseline_spec)
        .map_err(BaselineError::Unparsed)?;
    Ok(Some(deps.iter().map(dependency_key).collect()))
}

/// Keys of `current` dependencies that the manifest did not declare at
/// `base_ref`. A manifest that did not exist at the ref makes all of them new.
pub(crate) fn new_dependency_keys(
    spec: &ProjectInputSpec,
    current: &[Dependency],
    base_ref: &str,
) -> Result<HashSet<String>, BaselineError> {
    validate_ref(base_ref).map_err(BaselineError::Unusable)?;
    let baseline = baseline_keys(spec, base_ref)?;
    Ok(current
        .iter()
        .map(dependency_key)
        .filter(|key| baseline.as_ref().is_none_or(|known| !known.contains(key)))
        .collect())
}

#[cfg(test)]
#[path = "baseline_tests.rs"]
mod tests;
