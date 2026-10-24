//! The closed schema of a `Cargo.lock` `[[package]]` entry. A key Cargo does not write blocks:
//! Cargo may honour a field the scanner does not model, and the lock would no longer describe what
//! is built. An operator can allow one more exact key through `config_key_allow` (file id
//! `Cargo.lock`). See docs/specs/verification-and-schemas.md, criterion 4.

use crate::config_surface::{
    AppliedAllow, KeyAllow, KeyRule, Surface, ValueRule::*, check_toml, rule,
};
use anyhow::{Context, Result};
use std::path::Path;

const ALLOW: &[KeyRule] = &[
    rule("name", Str),
    rule("version", Str),
    rule("source", Str),
    rule("checksum", Str),
    rule("dependencies", Any),
    // Written by Cargo before 1.51 and still read.
    rule("replace", Str),
];

const CARGO_LOCK_ENTRY: Surface = Surface {
    id: "Cargo.lock",
    subject: "Cargo.lock entry key",
    why: "Cargo may honour a field the scanner does not model, so the lock would no longer describe what is built",
    allow: ALLOW,
    deny: &[],
    deny_under: &[],
    scope: &[],
};

/// Check every `[[package]]` entry against the closed schema.
pub(crate) fn check_entry_keys(
    lockfile: &toml::Value,
    lockfile_path: &Path,
    allows: &[KeyAllow],
) -> Result<Vec<AppliedAllow>> {
    let mut applied = Vec::new();
    for entry in super::cargo_lockfile_entries(lockfile) {
        let name = entry
            .get("name")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        applied.extend(
            check_toml(
                &CARGO_LOCK_ENTRY,
                &toml::Value::Table(entry.clone()),
                lockfile_path,
                allows,
            )
            .with_context(|| {
                format!(
                    "lockfile entry '{}'",
                    crate::report::sanitize_for_terminal(name)
                )
            })?,
        );
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_surface::KNOWN_SURFACES;

    fn run(text: &str, allows: &[KeyAllow]) -> Result<usize> {
        let value: toml::Value = toml::from_str(text).unwrap();
        check_entry_keys(&value, Path::new("Cargo.lock"), allows).map(|applied| applied.len())
    }

    const CURRENT: &str = r#"
version = 4

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"
dependencies = ["serde_derive"]

[[package]]
name = "app"
version = "0.1.0"
"#;

    #[test]
    fn surface_id_is_known() {
        assert!(KNOWN_SURFACES.contains(&CARGO_LOCK_ENTRY.id));
    }

    #[test]
    fn current_entries_pass() {
        assert_eq!(run(CURRENT, &[]).unwrap(), 0);
    }

    #[test]
    fn unknown_key_blocks_naming_entry_and_key() {
        let lock = format!(
            "{CURRENT}\n[[package]]\nname = \"x\"\nversion = \"1.0.0\"\nmirror = \"https://evil.test\"\n"
        );
        let err = format!("{:#}", run(&lock, &[]).unwrap_err());
        assert!(err.contains("'x'") && err.contains("mirror"), "{err}");
    }

    #[test]
    fn key_allow_passes() {
        let lock =
            format!("{CURRENT}\n[[package]]\nname = \"x\"\nversion = \"1.0.0\"\nnewField = 1\n");
        let allow = KeyAllow {
            file: "Cargo.lock".into(),
            key: "newField".into(),
        };
        assert_eq!(run(&lock, &[allow]).unwrap(), 1);
        assert!(run(&lock, &[]).is_err());
    }
}
