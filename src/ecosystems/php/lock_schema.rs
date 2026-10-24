//! The closed schema of a `composer.lock` package entry. An entry key Composer's lock dumper does
//! not write blocks: Composer may honour a field the scanner does not model, and the lock would no
//! longer describe what is installed. An operator can allow one more exact key through
//! `config_key_allow` (file id `composer.lock`). `transport-options` changes how a package is
//! downloaded and is never allowed. See docs/specs/verification-and-schemas.md, criterion 4.

use crate::config_surface::{
    AppliedAllow, KeyAllow, KeyRule, Surface, ValueRule::*, check_json, rule,
};
use anyhow::{Context, Result};
use std::path::Path;

const ALLOW: &[KeyRule] = &[
    rule("name", Str),
    rule("version", Str),
    rule("version_normalized", Str),
    rule("source", Any),
    rule("dist", Any),
    rule("require", Any),
    rule("require-dev", Any),
    rule("conflict", Any),
    rule("replace", Any),
    rule("provide", Any),
    rule("suggest", Any),
    rule("type", Str),
    rule("extra", Any),
    rule("installation-source", Str),
    rule("autoload", Any),
    rule("autoload-dev", Any),
    rule("notification-url", Str),
    rule("license", Any),
    rule("authors", Any),
    rule("description", Str),
    rule("homepage", Str),
    rule("keywords", Any),
    rule("support", Any),
    rule("funding", Any),
    rule("time", Str),
    rule("bin", Any),
    rule("include-path", Any),
    rule("target-dir", Str),
    rule("abandoned", Any),
    rule("default-branch", Bool),
    rule("php-ext", Any),
    rule("archive", Any),
    rule("scripts", Any),
    rule("scripts-descriptions", Any),
];

const COMPOSER_LOCK_ENTRY: Surface = Surface {
    id: "composer.lock",
    subject: "composer.lock entry key",
    why: "Composer may honour a field the scanner does not model, so the lock would no longer describe what is installed",
    allow: ALLOW,
    deny: &["transport-options"],
    deny_under: &[],
    scope: &[],
};

/// Check every entry of `packages` and `packages-dev` against the closed schema.
pub(crate) fn check_entry_keys(
    lockfile: &serde_json::Value,
    lockfile_path: &Path,
    allows: &[KeyAllow],
) -> Result<Vec<AppliedAllow>> {
    let mut applied = Vec::new();
    for section in ["packages", "packages-dev"] {
        let Some(entries) = lockfile.get(section).and_then(|value| value.as_array()) else {
            continue;
        };
        for entry in entries.iter().filter(|entry| entry.is_object()) {
            let name = entry
                .get("name")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            applied.extend(
                check_json(&COMPOSER_LOCK_ENTRY, entry, lockfile_path, allows).with_context(
                    || {
                        format!(
                            "lockfile entry '{}'",
                            crate::report::sanitize_for_terminal(name)
                        )
                    },
                )?,
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
        check_entry_keys(&value, Path::new("composer.lock"), allows).map(|applied| applied.len())
    }

    fn allow(key: &str) -> KeyAllow {
        KeyAllow {
            file: "composer.lock".into(),
            key: key.into(),
        }
    }

    const CURRENT: &str = r#"{"packages":[{"name":"monolog/monolog","version":"3.0.0","source":{"type":"git","url":"https://github.com/Seldaek/monolog.git","reference":"a"},"dist":{"type":"zip","url":"https://api.github.com/repos/Seldaek/monolog/zipball/a","reference":"a","shasum":""},"require":{"php":">=8.1"},"type":"library","autoload":{"psr-4":{"Monolog\\":"src"}},"notification-url":"https://packagist.org/downloads/","license":["MIT"],"time":"2022-01-01T00:00:00+00:00"}],"packages-dev":[]}"#;

    #[test]
    fn surface_id_is_known() {
        assert!(KNOWN_SURFACES.contains(&COMPOSER_LOCK_ENTRY.id));
    }

    #[test]
    fn current_entries_pass() {
        assert_eq!(run(CURRENT, &[]).unwrap(), 0);
    }

    #[test]
    fn unknown_key_blocks_naming_entry_and_key() {
        let lock = CURRENT.replace(
            r#""type":"library""#,
            r#""type":"library","repositories":[{"type":"composer","url":"https://evil.test"}]"#,
        );
        let err = format!("{:#}", run(&lock, &[]).unwrap_err());
        assert!(
            err.contains("monolog/monolog") && err.contains("repositories"),
            "{err}"
        );
    }

    #[test]
    fn key_allow_passes_but_never_for_transport_options() {
        let lock = CURRENT.replace(r#""type":"library""#, r#""type":"library","newField":1"#);
        assert_eq!(run(&lock, &[allow("newField")]).unwrap(), 1);
        let lock = CURRENT.replace(
            r#""type":"library""#,
            r#""type":"library","transport-options":{}"#,
        );
        assert!(run(&lock, &[allow("transport-options")]).is_err());
    }
}
