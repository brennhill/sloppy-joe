//! The closed schema of an npm lockfile entry (`package-lock.json`, `npm-shrinkwrap.json`). An
//! entry key that is not listed blocks: npm may honour a field the scanner does not model, and the
//! lock would no longer describe what is installed. An operator can allow one more exact key
//! through `config_key_allow` (file id `package-lock.json`). See
//! docs/specs/verification-and-schemas.md, criterion 4.
//!
//! Listed are the keys npm's arborist writes (v2/v3 `packages` entries) plus the v1 `dependencies`
//! entry keys; values are opaque here because the provenance checks read the ones that matter.

use crate::config_surface::{
    AppliedAllow, KeyAllow, KeyRule, Surface, ValueRule::*, check_json, rule,
};
use anyhow::{Context, Result};
use std::path::Path;

const ALLOW: &[KeyRule] = &[
    rule("name", Str),
    rule("version", Str),
    rule("resolved", Str),
    rule("integrity", Str),
    rule("link", Any),
    rule("dev", Any),
    rule("optional", Any),
    rule("devOptional", Any),
    rule("peer", Any),
    rule("inBundle", Any),
    rule("bundled", Any),
    rule("extraneous", Any),
    rule("ideallyInert", Any),
    rule("hasInstallScript", Any),
    rule("hasShrinkwrap", Any),
    rule("bin", Any),
    rule("license", Any),
    rule("engines", Any),
    rule("os", Any),
    rule("cpu", Any),
    rule("libc", Any),
    rule("funding", Any),
    rule("deprecated", Any),
    rule("workspaces", Any),
    rule("dependencies", Any),
    rule("devDependencies", Any),
    rule("optionalDependencies", Any),
    rule("peerDependencies", Any),
    rule("peerDependenciesMeta", Any),
    rule("bundleDependencies", Any),
    rule("bundledDependencies", Any),
    // lockfileVersion 1 only
    rule("requires", Any),
    rule("from", Any),
];

const NPM_LOCK_ENTRY: Surface = Surface {
    id: "package-lock.json",
    subject: "npm lockfile entry key",
    why: "npm may honour a field the scanner does not model, so the lock would no longer describe what is installed",
    allow: ALLOW,
    deny: &[],
    deny_under: &[],
    scope: &[],
};

/// Check every entry of `packages` (and, for lockfileVersion 1, `dependencies`, recursively)
/// against the closed schema.
pub(crate) fn check_entry_keys(
    lockfile: &serde_json::Value,
    lockfile_path: &Path,
    allows: &[KeyAllow],
) -> Result<Vec<AppliedAllow>> {
    let mut applied = Vec::new();
    if let Some(packages) = lockfile.get("packages").and_then(|value| value.as_object()) {
        for (key, entry) in packages {
            check_entry(key, entry, lockfile_path, allows, &mut applied)?;
        }
    }
    if let Some(dependencies) = lockfile
        .get("dependencies")
        .and_then(|value| value.as_object())
    {
        check_dependencies(dependencies, lockfile_path, allows, &mut applied)?;
    }
    Ok(applied)
}

fn check_dependencies(
    dependencies: &serde_json::Map<String, serde_json::Value>,
    lockfile_path: &Path,
    allows: &[KeyAllow],
    applied: &mut Vec<AppliedAllow>,
) -> Result<()> {
    for (name, entry) in dependencies {
        check_entry(name, entry, lockfile_path, allows, applied)?;
        if let Some(nested) = entry
            .get("dependencies")
            .and_then(|value| value.as_object())
        {
            check_dependencies(nested, lockfile_path, allows, applied)?;
        }
    }
    Ok(())
}

fn check_entry(
    name: &str,
    entry: &serde_json::Value,
    lockfile_path: &Path,
    allows: &[KeyAllow],
    applied: &mut Vec<AppliedAllow>,
) -> Result<()> {
    // Non-object entries are rejected by the provenance checks with their own message.
    if !entry.is_object() {
        return Ok(());
    }
    applied.extend(
        check_json(&NPM_LOCK_ENTRY, entry, lockfile_path, allows).with_context(|| {
            format!(
                "lockfile entry '{}'",
                crate::report::sanitize_for_terminal(name)
            )
        })?,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_surface::KNOWN_SURFACES;

    fn run(text: &str, allows: &[KeyAllow]) -> Result<usize> {
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        check_entry_keys(&value, Path::new("package-lock.json"), allows)
            .map(|applied| applied.len())
    }

    fn allow(key: &str) -> KeyAllow {
        KeyAllow {
            file: "package-lock.json".into(),
            key: key.into(),
        }
    }

    const CURRENT: &str = r#"{"lockfileVersion":3,"packages":{
        "":{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}},
        "node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz","integrity":"sha512-x","dev":true,"engines":{"node":">=0.10"},"funding":{"url":"x"},"license":"MIT"}}}"#;

    #[test]
    fn surface_id_is_known() {
        assert!(KNOWN_SURFACES.contains(&NPM_LOCK_ENTRY.id));
    }

    #[test]
    fn current_npm_entries_pass() {
        assert_eq!(run(CURRENT, &[]).unwrap(), 0);
    }

    #[test]
    fn unknown_key_in_packages_entry_blocks_naming_entry_and_key() {
        let lock = CURRENT.replace(
            r#""license":"MIT""#,
            r#""license":"MIT","mirrors":["https://evil.test"]"#,
        );
        let err = format!("{:#}", run(&lock, &[]).unwrap_err());
        assert!(err.contains("node_modules/left-pad"), "{err}");
        assert!(err.contains("mirrors"), "{err}");
    }

    #[test]
    fn key_allow_passes_and_reports() {
        let lock = CURRENT.replace(r#""license":"MIT""#, r#""license":"MIT","newField":1"#);
        assert_eq!(run(&lock, &[allow("newField")]).unwrap(), 1);
        assert!(run(&lock, &[allow("otherField")]).is_err());
    }

    #[test]
    fn unknown_key_in_v1_nested_dependency_blocks() {
        let lock = r#"{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"1.0.0","registry":"x"}}}}}"#;
        let err = format!("{:#}", run(lock, &[]).unwrap_err());
        assert!(err.contains("registry"), "{err}");
    }

    #[test]
    fn case_variant_key_does_not_pass() {
        let lock = CURRENT.replace(r#""license":"MIT""#, r#""Resolved":"https://evil.test""#);
        assert!(run(&lock, &[]).is_err());
    }
}
