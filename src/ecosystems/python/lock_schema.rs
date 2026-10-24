//! Closed schemas for one entry of `uv.lock`, `poetry.lock` and `Pipfile.lock`. A key the tool
//! does not write blocks: the tool may honour a field the scanner does not model, and the lock
//! would no longer describe what is installed. An operator can allow one more exact key through
//! `config_key_allow` (file ids `uv.lock`, `poetry.lock`, `Pipfile.lock`). Source and hash fields
//! are checked by the provenance validators; here their values are opaque. See
//! docs/specs/verification-and-schemas.md, criterion 4.

use crate::config_surface::{
    AppliedAllow, KeyAllow, KeyRule, Surface, ValueRule::*, check_json, check_toml, rule,
};
use anyhow::{Context, Result};
use std::path::Path;

const UV_ALLOW: &[KeyRule] = &[
    rule("name", Str),
    rule("version", Str),
    rule("source", Any),
    rule("dependencies", Any),
    rule("optional-dependencies", Any),
    rule("dev-dependencies", Any),
    rule("sdist", Any),
    rule("wheels", Any),
    rule("metadata", Any),
    rule("resolution-markers", Any),
];

const POETRY_ALLOW: &[KeyRule] = &[
    rule("name", Str),
    rule("version", Str),
    rule("description", Str),
    rule("optional", Bool),
    rule("develop", Bool),
    rule("category", Str),
    rule("python-versions", Str),
    rule("groups", Any),
    rule("markers", Any),
    rule("files", Any),
    rule("dependencies", Any),
    rule("extras", Any),
    rule("source", Any),
];

const PIPFILE_ALLOW: &[KeyRule] = &[
    rule("version", Str),
    rule("hashes", Any),
    rule("index", Str),
    rule("markers", Str),
    rule("extras", Any),
    rule("git", Str),
    rule("ref", Str),
    rule("editable", Bool),
    rule("path", Str),
    rule("file", Str),
    rule("subdirectory", Str),
    rule("sys_platform", Str),
    rule("platform_machine", Str),
    rule("platform_python_implementation", Str),
    rule("platform_release", Str),
    rule("platform_system", Str),
    rule("platform_version", Str),
    rule("python_full_version", Str),
    rule("python_version", Str),
    rule("implementation_name", Str),
    rule("implementation_version", Str),
    rule("os_name", Str),
];

const fn surface(id: &'static str, allow: &'static [KeyRule]) -> Surface {
    Surface {
        id,
        subject: "lockfile entry key",
        why: "the tool may honour a field the scanner does not model, so the lock would no longer describe what is installed",
        allow,
        deny: &[],
        deny_under: &[],
        scope: &[],
    }
}

const UV_LOCK_ENTRY: Surface = surface("uv.lock", UV_ALLOW);
const POETRY_LOCK_ENTRY: Surface = surface("poetry.lock", POETRY_ALLOW);
const PIPFILE_LOCK_ENTRY: Surface = surface("Pipfile.lock", PIPFILE_ALLOW);

fn named<T>(name: &str, result: Result<T>) -> Result<T> {
    result.with_context(|| {
        format!(
            "lockfile entry '{}'",
            crate::report::sanitize_for_terminal(name)
        )
    })
}

fn check_toml_packages(
    surface: &Surface,
    lockfile: &toml::Value,
    path: &Path,
    allows: &[KeyAllow],
) -> Result<Vec<AppliedAllow>> {
    let mut applied = Vec::new();
    let packages = lockfile.get("package").and_then(|value| value.as_array());
    for entry in packages
        .into_iter()
        .flatten()
        .filter(|entry| entry.is_table())
    {
        let name = entry
            .get("name")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        applied.extend(named(name, check_toml(surface, entry, path, allows))?);
    }
    Ok(applied)
}

pub(crate) fn check_uv_entries(
    lockfile: &toml::Value,
    path: &Path,
    allows: &[KeyAllow],
) -> Result<Vec<AppliedAllow>> {
    check_toml_packages(&UV_LOCK_ENTRY, lockfile, path, allows)
}

pub(crate) fn check_poetry_entries(
    lockfile: &toml::Value,
    path: &Path,
    allows: &[KeyAllow],
) -> Result<Vec<AppliedAllow>> {
    check_toml_packages(&POETRY_LOCK_ENTRY, lockfile, path, allows)
}

/// `default` and `develop` map package names to entries.
pub(crate) fn check_pipfile_entries(
    lockfile: &serde_json::Value,
    path: &Path,
    allows: &[KeyAllow],
) -> Result<Vec<AppliedAllow>> {
    let mut applied = Vec::new();
    for section in ["default", "develop"] {
        let entries = lockfile.get(section).and_then(|value| value.as_object());
        for (name, entry) in entries.into_iter().flatten().filter(|(_, e)| e.is_object()) {
            applied.extend(named(
                name,
                check_json(&PIPFILE_LOCK_ENTRY, entry, path, allows),
            )?);
        }
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_surface::KNOWN_SURFACES;

    fn allow(file: &str, key: &str) -> KeyAllow {
        KeyAllow {
            file: file.into(),
            key: key.into(),
        }
    }

    #[test]
    fn surface_ids_are_known() {
        for id in [
            UV_LOCK_ENTRY.id,
            POETRY_LOCK_ENTRY.id,
            PIPFILE_LOCK_ENTRY.id,
        ] {
            assert!(KNOWN_SURFACES.contains(&id), "{id}");
        }
    }

    #[test]
    fn uv_entries() {
        let ok: toml::Value = toml::from_str(
            "version = 1\n[[package]]\nname = \"a\"\nversion = \"1\"\nsource = { registry = \"https://pypi.org/simple\" }\nwheels = []\n",
        )
        .unwrap();
        assert!(
            check_uv_entries(&ok, Path::new("uv.lock"), &[])
                .unwrap()
                .is_empty()
        );
        let bad: toml::Value = toml::from_str(
            "[[package]]\nname = \"a\"\nversion = \"1\"\nextra-index = \"https://evil.test\"\n",
        )
        .unwrap();
        let err = format!(
            "{:#}",
            check_uv_entries(&bad, Path::new("uv.lock"), &[]).unwrap_err()
        );
        assert!(err.contains("'a'") && err.contains("extra-index"), "{err}");
        let allows = [allow("uv.lock", "extra-index")];
        assert_eq!(
            check_uv_entries(&bad, Path::new("uv.lock"), &allows)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn poetry_entries() {
        let ok: toml::Value = toml::from_str(
            "[[package]]\nname = \"a\"\nversion = \"1\"\ndescription = \"d\"\noptional = false\npython-versions = \">=3\"\nfiles = []\n[package.dependencies]\nb = \">=1\"\n",
        )
        .unwrap();
        assert!(
            check_poetry_entries(&ok, Path::new("poetry.lock"), &[])
                .unwrap()
                .is_empty()
        );
        let bad: toml::Value =
            toml::from_str("[[package]]\nname = \"a\"\nversion = \"1\"\nindex-url = \"x\"\n")
                .unwrap();
        assert!(check_poetry_entries(&bad, Path::new("poetry.lock"), &[]).is_err());
    }

    #[test]
    fn pipfile_entries() {
        let ok: serde_json::Value = serde_json::from_str(
            r#"{"_meta":{},"default":{"a":{"version":"==1","hashes":["sha256:x"],"index":"pypi","markers":"python_version >= '3'"}},"develop":{}}"#,
        )
        .unwrap();
        assert!(
            check_pipfile_entries(&ok, Path::new("Pipfile.lock"), &[])
                .unwrap()
                .is_empty()
        );
        let bad: serde_json::Value = serde_json::from_str(
            r#"{"default":{"a":{"version":"==1","find-links":"https://evil.test"}}}"#,
        )
        .unwrap();
        let err = format!(
            "{:#}",
            check_pipfile_entries(&bad, Path::new("Pipfile.lock"), &[]).unwrap_err()
        );
        assert!(err.contains("find-links") && err.contains("'a'"), "{err}");
        let allows = [allow("Pipfile.lock", "find-links")];
        assert_eq!(
            check_pipfile_entries(&bad, Path::new("Pipfile.lock"), &allows)
                .unwrap()
                .len(),
            1
        );
    }
}
