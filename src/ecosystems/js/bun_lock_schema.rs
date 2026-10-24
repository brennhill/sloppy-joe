//! The closed schema of a `bun.lock` package entry: a tuple of at most four elements
//! (descriptor, registry, metadata, integrity) whose metadata object may only hold the keys Bun
//! writes. An extra tuple element or metadata key blocks: Bun may honour a field the scanner does
//! not model, and the lock would no longer describe what is installed. An operator can allow one
//! more exact metadata key through `config_key_allow` (file id `bun.lock`); the tuple length is
//! fixed. See docs/specs/verification-and-schemas.md, criterion 4.

use crate::config_surface::{
    AppliedAllow, KeyAllow, KeyRule, Surface, ValueRule::*, check_json, rule,
};
use anyhow::{Context, Result, bail};
use std::path::Path;

const ALLOW: &[KeyRule] = &[
    rule("dependencies", Any),
    rule("devDependencies", Any),
    rule("optionalDependencies", Any),
    rule("peerDependencies", Any),
    rule("optionalPeers", Any),
    rule("bin", Any),
    rule("os", Any),
    rule("cpu", Any),
    rule("libc", Any),
    rule("bundled", Any),
    rule("name", Str),
    rule("version", Str),
];

const BUN_LOCK_ENTRY: Surface = Surface {
    id: "bun.lock",
    subject: "bun.lock entry key",
    why: "Bun may honour a field the scanner does not model, so the lock would no longer describe what is installed",
    allow: ALLOW,
    deny: &[],
    deny_under: &[],
    scope: &[],
};

const MAX_TUPLE: usize = 4;

pub(crate) fn check_entry_keys(
    lockfile: &serde_json::Value,
    lockfile_path: &Path,
    allows: &[KeyAllow],
) -> Result<Vec<AppliedAllow>> {
    let mut applied = Vec::new();
    let Some(packages) = lockfile.get("packages").and_then(|value| value.as_object()) else {
        return Ok(applied);
    };
    for (key, entry) in packages {
        let Some(tuple) = entry.as_array() else {
            continue; // the provenance check rejects a non-array entry
        };
        let shown = crate::report::sanitize_for_terminal(key);
        if tuple.len() > MAX_TUPLE {
            bail!(
                "Unsupported bun.lock package '{shown}' in {}: {} tuple elements, Bun writes at most {MAX_TUPLE}; an extra element may change what is installed.",
                lockfile_path.display(),
                tuple.len()
            );
        }
        for element in tuple.iter().filter(|element| element.is_object()) {
            applied.extend(
                check_json(&BUN_LOCK_ENTRY, element, lockfile_path, allows)
                    .with_context(|| format!("lockfile entry '{shown}'"))?,
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
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        check_entry_keys(&value, Path::new("bun.lock"), allows).map(|a| a.len())
    }

    const CURRENT: &str = r#"{"lockfileVersion":1,"packages":{"left-pad":["left-pad@1.3.0","",{"dependencies":{"a":"^1"},"bin":{"x":"y"}},"sha512-x"],"app":["app@workspace:."]}}"#;

    #[test]
    fn surface_id_is_known() {
        assert!(KNOWN_SURFACES.contains(&BUN_LOCK_ENTRY.id));
    }

    #[test]
    fn current_entries_pass() {
        assert_eq!(run(CURRENT, &[]).unwrap(), 0);
    }

    #[test]
    fn unknown_metadata_key_blocks_and_can_be_allowed() {
        let lock = CURRENT.replace(
            r#""bin":{"x":"y"}"#,
            r#""bin":{"x":"y"},"registry":"https://evil.test""#,
        );
        let err = format!("{:#}", run(&lock, &[]).unwrap_err());
        assert!(
            err.contains("left-pad") && err.contains("registry"),
            "{err}"
        );
        let allow = KeyAllow {
            file: "bun.lock".into(),
            key: "registry".into(),
        };
        assert_eq!(run(&lock, &[allow]).unwrap(), 1);
    }

    #[test]
    fn extra_tuple_element_blocks_even_with_allows() {
        let lock = CURRENT.replace(r#""sha512-x"]"#, r#""sha512-x","https://evil.test/x.tgz"]"#);
        let err = format!("{:#}", run(&lock, &[]).unwrap_err());
        assert!(err.contains("tuple elements"), "{err}");
    }
}
