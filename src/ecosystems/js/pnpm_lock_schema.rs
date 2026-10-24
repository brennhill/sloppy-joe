//! The closed schema of a `pnpm-lock.yaml` `packages` and `snapshots` entry. A key pnpm does not
//! write blocks: pnpm may honour a field the scanner does not model, and the lock would no longer
//! describe what is installed. An operator can allow one more exact key through
//! `config_key_allow` (file id `pnpm-lock.yaml`). The `resolution` table is already closed by the
//! provenance check. See docs/specs/verification-and-schemas.md, criterion 4.

use crate::config_surface::{
    AppliedAllow, KeyAllow, KeyRule, Surface, ValueRule::*, check_json, rule,
};
use anyhow::{Context, Result};
use std::path::Path;

const ALLOW: &[KeyRule] = &[
    rule("resolution", Any),
    rule("name", Str),
    rule("version", Str),
    rule("id", Str),
    rule("engines", Any),
    rule("cpu", Any),
    rule("os", Any),
    rule("libc", Any),
    rule("deprecated", Str),
    rule("hasBin", Bool),
    rule("prepare", Bool),
    rule("requiresBuild", Bool),
    rule("patched", Bool),
    rule("dev", Bool),
    rule("optional", Bool),
    rule("bundledDependencies", Any),
    rule("bundleDependencies", Any),
    rule("dependencies", Any),
    rule("optionalDependencies", Any),
    rule("peerDependencies", Any),
    rule("peerDependenciesMeta", Any),
    rule("transitivePeerDependencies", Any),
];

const PNPM_LOCK_ENTRY: Surface = Surface {
    id: "pnpm-lock.yaml",
    subject: "pnpm lockfile entry key",
    why: "pnpm may honour a field the scanner does not model, so the lock would no longer describe what is installed",
    allow: ALLOW,
    deny: &[],
    deny_under: &[],
    scope: &[],
};

pub(crate) fn check_entry_keys(
    lockfile: &serde_yaml::Value,
    lockfile_path: &Path,
    allows: &[KeyAllow],
) -> Result<Vec<AppliedAllow>> {
    let mut applied = Vec::new();
    for section in ["packages", "snapshots"] {
        let Some(entries) = lockfile.get(section).and_then(|value| value.as_mapping()) else {
            continue;
        };
        for (key, entry) in entries {
            let name = key.as_str().unwrap_or("");
            if !entry.is_mapping() {
                continue;
            }
            let json = serde_json::to_value(entry)
                .with_context(|| format!("Cannot inspect {}", lockfile_path.display()))?;
            applied.extend(
                check_json(&PNPM_LOCK_ENTRY, &json, lockfile_path, allows).with_context(|| {
                    format!(
                        "lockfile {section} entry '{}'",
                        crate::report::sanitize_for_terminal(name)
                    )
                })?,
            );
        }
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_surface::KNOWN_SURFACES;

    fn run(text: &str, allows: &[KeyAllow]) -> Result<usize> {
        let value: serde_yaml::Value = serde_yaml::from_str(text).unwrap();
        check_entry_keys(&value, Path::new("pnpm-lock.yaml"), allows).map(|a| a.len())
    }

    const CURRENT: &str = "lockfileVersion: '9.0'\npackages:\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-x}\n    engines: {node: '>=0.10'}\n    hasBin: true\nsnapshots:\n  left-pad@1.3.0:\n    dependencies:\n      a: 1.0.0\n";

    #[test]
    fn surface_id_is_known() {
        assert!(KNOWN_SURFACES.contains(&PNPM_LOCK_ENTRY.id));
    }

    #[test]
    fn current_entries_pass() {
        assert_eq!(run(CURRENT, &[]).unwrap(), 0);
    }

    #[test]
    fn unknown_key_blocks_in_packages_and_snapshots() {
        let packages = CURRENT.replace("hasBin: true", "hasBin: true\n    registry: x");
        let err = format!("{:#}", run(&packages, &[]).unwrap_err());
        assert!(
            err.contains("packages") && err.contains("left-pad@1.3.0") && err.contains("registry"),
            "{err}"
        );
        let snapshots = format!("{CURRENT}    tarballOverride: x\n");
        assert!(run(&snapshots, &[]).is_err());
    }

    #[test]
    fn key_allow_passes() {
        let lock = CURRENT.replace("hasBin: true", "hasBin: true\n    newField: 1");
        let allow = KeyAllow {
            file: "pnpm-lock.yaml".into(),
            key: "newField".into(),
        };
        assert_eq!(run(&lock, &[allow]).unwrap(), 1);
    }
}
