//! The closed schema of a `yarn.lock` entry (classic and Berry). A property Yarn does not write
//! blocks: Yarn may honour a field the scanner does not model, and the lock would no longer
//! describe what is installed. An operator can allow one more exact key through
//! `config_key_allow` (file id `yarn.lock`). The Berry `__metadata` header is not an entry. See
//! docs/specs/verification-and-schemas.md, criterion 4.

use crate::config_surface::{
    AppliedAllow, KeyAllow, KeyRule, Surface, ValueRule::*, check_json, rule,
};
use crate::lockfiles::yarn::ParsedYarnLock;
use anyhow::{Context, Result};

const ALLOW: &[KeyRule] = &[
    rule("version", Any),
    rule("resolved", Any),
    rule("integrity", Any),
    rule("resolution", Any),
    rule("checksum", Any),
    rule("languageName", Any),
    rule("linkType", Any),
    rule("dependencies", Any),
    rule("optionalDependencies", Any),
    rule("peerDependencies", Any),
    rule("dependenciesMeta", Any),
    rule("peerDependenciesMeta", Any),
    rule("bin", Any),
    rule("conditions", Any),
];

const YARN_LOCK_ENTRY: Surface = Surface {
    id: "yarn.lock",
    subject: "yarn.lock entry key",
    why: "Yarn may honour a field the scanner does not model, so the lock would no longer describe what is installed",
    allow: ALLOW,
    deny: &[],
    deny_under: &[],
    scope: &[],
};

pub(crate) fn check_entry_keys(
    parsed: &ParsedYarnLock,
    allows: &[KeyAllow],
) -> Result<Vec<AppliedAllow>> {
    let mut applied = Vec::new();
    for entry in &parsed.entries {
        if entry.selectors.len() == 1 && entry.selectors[0] == "__metadata" {
            continue;
        }
        let object = entry
            .keys
            .iter()
            .map(|key| (key.clone(), serde_json::Value::Null))
            .collect::<serde_json::Map<_, _>>();
        applied.extend(
            check_json(
                &YARN_LOCK_ENTRY,
                &serde_json::Value::Object(object),
                &parsed.path,
                allows,
            )
            .with_context(|| {
                format!(
                    "lockfile entry '{}'",
                    crate::report::sanitize_for_terminal(&entry.selectors.join(", "))
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

    fn parse(text: &str) -> ParsedYarnLock {
        crate::lockfiles::yarn::parse_lockfile(
            text,
            std::path::PathBuf::from("yarn.lock"),
            std::path::Path::new("."),
        )
        .unwrap()
    }

    const CLASSIC: &str = "# yarn lockfile v1\n\n\nleft-pad@^1.3.0:\n  version \"1.3.0\"\n  resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#abc\"\n  integrity sha512-x\n  dependencies:\n    a \"^1.0.0\"\n";
    const BERRY: &str = "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\"left-pad@npm:^1.3.0\":\n  version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  checksum: abc/def\n  languageName: node\n  linkType: hard\n";

    #[test]
    fn surface_id_is_known() {
        assert!(KNOWN_SURFACES.contains(&YARN_LOCK_ENTRY.id));
    }

    #[test]
    fn current_entries_pass() {
        assert!(check_entry_keys(&parse(CLASSIC), &[]).unwrap().is_empty());
        assert!(check_entry_keys(&parse(BERRY), &[]).unwrap().is_empty());
    }

    #[test]
    fn unknown_property_or_section_blocks() {
        let property = parse(&format!("{CLASSIC}  registry \"https://evil.test\"\n"));
        let err = format!("{:#}", check_entry_keys(&property, &[]).unwrap_err());
        assert!(
            err.contains("left-pad@^1.3.0") && err.contains("registry"),
            "{err}"
        );
        let section = parse(&format!("{CLASSIC}  mirrors:\n    a \"b\"\n"));
        assert!(check_entry_keys(&section, &[]).is_err());
    }

    #[test]
    fn key_allow_passes() {
        let parsed = parse(&format!("{CLASSIC}  newField \"x\"\n"));
        let allow = KeyAllow {
            file: "yarn.lock".into(),
            key: "newField".into(),
        };
        assert_eq!(check_entry_keys(&parsed, &[allow]).unwrap().len(), 1);
    }
}
