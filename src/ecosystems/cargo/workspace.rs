//! Workspace member discovery for projects that directory discovery may have skipped.
//!
//! `ignore_dirs` hides directories such as `.planning` from the walk, but Cargo builds every
//! `[workspace] members` entry wherever it lives, so a member under an ignored directory must still
//! be scanned.

use super::*;

/// Whether `name` matches a path segment pattern with `*` wildcards (Cargo's members globs).
fn segment_matches(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((head, tail)) => {
            name.starts_with(head)
                && (0..=name.len() - head.len()).any(|skip| {
                    name.is_char_boundary(head.len() + skip)
                        && segment_matches(tail, &name[head.len() + skip..])
                })
        }
    }
}

/// Directories matching a `members` pattern, relative to `base`. Patterns with glob syntax other
/// than `*` cannot be expanded faithfully, so they fail closed.
fn expand_pattern(base: &Path, pattern: &str) -> Result<Vec<PathBuf>> {
    if pattern.contains(['?', '[', '{']) {
        anyhow::bail!(
            "Unsupported Cargo workspace members pattern '{}' in {}: only `*` wildcards can be expanded, so the members cannot be scanned",
            crate::report::sanitize_for_terminal(pattern),
            base.display()
        );
    }
    let mut current = vec![base.to_path_buf()];
    for segment in pattern.split('/').filter(|s| !s.is_empty() && *s != ".") {
        let mut next = Vec::new();
        for dir in &current {
            if segment.contains('*') {
                let Ok(entries) = std::fs::read_dir(dir) else {
                    continue;
                };
                for entry in entries {
                    let entry = entry?;
                    let name = entry.file_name().to_string_lossy().to_string();
                    if segment_matches(segment, &name) && entry.path().is_dir() {
                        next.push(entry.path());
                    }
                }
            } else {
                next.push(dir.join(segment));
            }
        }
        current = next;
    }
    current.sort();
    Ok(current)
}

/// Manifests of the workspace members declared by `manifest` that live inside `scan_root`.
pub(super) fn workspace_member_manifests(
    scan_root: &Path,
    manifest: &parsers::cargo_toml::CargoManifest,
) -> Result<Vec<PathBuf>> {
    if !manifest.has_workspace {
        return Ok(Vec::new());
    }
    let base = manifest
        .manifest_path
        .parent()
        .expect("Cargo.toml should always have a parent directory");
    let root = std::fs::canonicalize(scan_root)?;
    let excluded: std::collections::HashSet<PathBuf> = manifest
        .workspace_exclude
        .iter()
        .flat_map(|pattern| expand_pattern(base, pattern).unwrap_or_default())
        .filter_map(|dir| std::fs::canonicalize(dir).ok())
        .collect();
    let mut members = Vec::new();
    for pattern in &manifest.workspace_members {
        for dir in expand_pattern(base, pattern)? {
            let member_manifest = dir.join("Cargo.toml");
            let Ok(canonical) = std::fs::canonicalize(&dir) else {
                continue;
            };
            if !canonical.starts_with(&root)
                || excluded.contains(&canonical)
                || !parsers::path_detected(&member_manifest)?
            {
                continue;
            }
            members.push(canonical.join("Cargo.toml"));
        }
    }
    Ok(members)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "sj-cargo-ws-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        for (path, content) in files {
            let full = root.join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, content).unwrap();
        }
        std::fs::canonicalize(root).unwrap()
    }

    const MEMBER: &str = "[package]\nname = \"m\"\nversion = \"0.1.0\"\n";

    fn members_of(root: &Path) -> Result<Vec<PathBuf>> {
        let manifest = parsers::cargo_toml::parse_manifest_file(&root.join("Cargo.toml"))?;
        workspace_member_manifests(root, &manifest)
    }

    #[test]
    fn members_in_ignored_directories_and_globs_are_found() {
        let root = tree(&[
            (
                "Cargo.toml",
                "[workspace]\nmembers = [\".planning/m\", \"crates/*\"]\nexclude = [\"crates/skip\"]\n",
            ),
            (".planning/m/Cargo.toml", MEMBER),
            ("crates/a/Cargo.toml", MEMBER),
            ("crates/skip/Cargo.toml", MEMBER),
        ]);
        let found = members_of(&root).unwrap();
        assert_eq!(
            found,
            vec![
                root.join(".planning/m/Cargo.toml"),
                root.join("crates/a/Cargo.toml")
            ]
        );
    }

    #[test]
    fn members_outside_the_scan_root_and_unsupported_globs() {
        let root = tree(&[
            ("ws/Cargo.toml", "[workspace]\nmembers = [\"../outside\"]\n"),
            ("outside/Cargo.toml", MEMBER),
        ]);
        let ws = root.join("ws");
        let manifest = parsers::cargo_toml::parse_manifest_file(&ws.join("Cargo.toml")).unwrap();
        assert!(
            workspace_member_manifests(&ws, &manifest)
                .unwrap()
                .is_empty()
        );

        let root = tree(&[("Cargo.toml", "[workspace]\nmembers = [\"crates/[ab]\"]\n")]);
        assert!(members_of(&root).is_err());
    }
}
