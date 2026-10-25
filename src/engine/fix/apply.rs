//! `--write`: put a verified candidate into the working tree.

use super::Refusal;
use super::execute::Layout;
use super::report::ProjectFix;
use super::write::{remove_with_backup, replace_with_backup};
use crate::ecosystems::fixer::Recipe;
use std::path::PathBuf;

/// The bytes of each file the fix replaces or removes, as they were copied into the scratch tree.
pub(super) struct Originals(Vec<(PathBuf, Option<Vec<u8>>)>);

impl Originals {
    pub(super) fn capture(layout: &Layout, recipe: &Recipe) -> Result<Self, Refusal> {
        let mut files = Vec::new();
        for path in recipe.outputs.iter().chain(&recipe.deletions) {
            let content = match std::fs::read(path) {
                Ok(bytes) => Some(bytes),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => return Err(format!("could not read {}: {err}", path.display())),
            };
            // The copy the tool started from must be these bytes.
            if recipe.outputs.contains(path) && content.is_some() {
                let copied = std::fs::read(layout.in_work(path)?).ok();
                if copied != content {
                    return Err(format!("{} changed while it was copied", path.display()));
                }
            }
            files.push((path.clone(), content));
        }
        Ok(Self(files))
    }

    /// Refuse when a file changed in the working tree since the fix started: writing would
    /// discard that change.
    fn ensure_unchanged(&self) -> Result<(), Refusal> {
        for (path, before) in &self.0 {
            let now = match std::fs::read(path) {
                Ok(bytes) => Some(bytes),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => return Err(format!("could not read {}: {err}", path.display())),
            };
            if &now != before {
                return Err(format!(
                    "{} changed while fix-lockfile ran; nothing was written",
                    path.display()
                ));
            }
        }
        Ok(())
    }
}

pub(super) fn write_candidate(
    layout: &Layout,
    recipe: &Recipe,
    originals: &Originals,
    project: &mut ProjectFix,
) -> Result<(), Refusal> {
    originals.ensure_unchanged()?;
    let mut candidates = Vec::new();
    for output in &recipe.outputs {
        let produced = layout.in_verify(output)?;
        let bytes = std::fs::read(&produced)
            .map_err(|err| format!("could not read the candidate {}: {err}", produced.display()))?;
        candidates.push((output, bytes));
    }
    for (output, bytes) in candidates {
        let backup = replace_with_backup(output, &bytes).map_err(|err| format!("{err:#}"))?;
        project.written.push(output.display().to_string());
        project
            .backups
            .extend(backup.map(|path| path.display().to_string()));
    }
    for deletion in &recipe.deletions {
        let backup = remove_with_backup(deletion).map_err(|err| format!("{err:#}"))?;
        project.removed.push(deletion.display().to_string());
        project.backups.push(backup.display().to_string());
    }
    Ok(())
}
