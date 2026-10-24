//! The allowlist for uv settings: `[tool.uv]` in `pyproject.toml` and `uv.toml`, in the project
//! directory or any parent up to the repository root. Anything not listed blocks; an operator can
//! allow one more exact key through `config_key_allow` (file id `uv`).
//!
//! Decisions (uv settings reference):
//! - **Denied** (never allowable): settings that redirect where uv resolves from (`index-url`,
//!   `extra-index-url`, `find-links`, `no-index`, `index`, `index-strategy`, `default-index`,
//!   `torch-backend`), download and run an interpreter (`python-install-mirror`,
//!   `pypy-install-mirror`, `python-downloads-json-url`, `pip.python`), reuse an unhashed cache
//!   (`cache-dir`: uv installs unpacked cache contents without re-hashing) or add build
//!   requirements that `uv.lock` does not record (`extra-build-dependencies`). The denied keys
//!   also apply inside `[pip]`.
//! - **Allowed**: dependency metadata that the project scan or `uv.lock` already covers
//!   (`sources`, `workspace`, constraints, overrides, groups, environments, conflicts), resolver
//!   and installer behavior that only chooses among locked, hash-verified artifacts, and build
//!   toggles. Lock hashes still vouch for every downloaded artifact.
//! - **Everything else** (for example `keyring-provider`, which runs a `keyring` executable,
//!   `dependency-metadata`, `publish-url`, `build-backend`) is unknown: blocked unless allowed.

use crate::config_surface::{KeyRule, Surface, ValueRule::*, rule};

const ALLOW: &[KeyRule] = &[
    rule("required-version", Str),
    rule("managed", Bool),
    rule("package", Bool),
    rule("default-groups", Any),
    rule("dev-dependencies", Any),
    rule("constraint-dependencies", Any),
    rule("override-dependencies", Any),
    rule("build-constraint-dependencies", Any),
    rule("exclude-dependencies", Any),
    rule("environments", Any),
    rule("required-environments", Any),
    rule("conflicts", Any),
    rule("sources", Any),
    rule("workspace", Any),
    rule("exclude-newer", Str),
    rule("resolution", OneOf(&["highest", "lowest", "lowest-direct"])),
    rule("prerelease", Str),
    rule("fork-strategy", Str),
    rule("no-binary", Bool),
    rule("no-binary-package", Any),
    rule("no-build", Bool),
    rule("no-build-package", Any),
    rule("no-build-isolation", Bool),
    rule("no-build-isolation-package", Any),
    rule("no-sources", Bool),
    rule("upgrade", Bool),
    rule("upgrade-package", Any),
    rule("reinstall", Bool),
    rule("reinstall-package", Any),
    rule("refresh", Bool),
    rule("refresh-package", Any),
    rule("no-cache", Bool),
    rule(
        "link-mode",
        OneOf(&["clone", "copy", "hardlink", "symlink"]),
    ),
    rule("compile-bytecode", Bool),
    rule("config-settings", Any),
    rule("config-settings-package", Any),
    rule("native-tls", Bool),
    rule("allow-insecure-host", Any),
    rule("offline", Bool),
    rule("preview", Bool),
    rule("python-preference", Str),
    rule("python-downloads", OneOf(&["automatic", "manual", "never"])),
    rule("cache-keys", Any),
    rule("concurrent-builds", Any),
    rule("concurrent-downloads", Any),
    rule("concurrent-installs", Any),
    rule("trusted-publishing", Str),
    rule("add-bounds", Str),
    rule("pip.python-version", Str),
    rule("pip.python-platform", Str),
    rule("pip.system", Bool),
    rule("pip.break-system-packages", Bool),
    rule("pip.require-hashes", Bool),
    rule("pip.verify-hashes", Bool),
    rule("pip.generate-hashes", Bool),
    rule("pip.universal", Bool),
    rule("pip.strict", Bool),
    rule("pip.no-deps", Bool),
    rule("pip.resolution", Str),
    rule("pip.prerelease", Str),
    rule("pip.fork-strategy", Str),
    rule("pip.exclude-newer", Str),
    rule("pip.no-binary", Any),
    rule("pip.only-binary", Any),
    rule("pip.no-build", Bool),
    rule("pip.no-build-isolation", Bool),
    rule("pip.no-build-isolation-package", Any),
    rule("pip.link-mode", Str),
    rule("pip.compile-bytecode", Bool),
    rule("pip.native-tls", Bool),
    rule("pip.extra", Any),
    rule("pip.all-extras", Bool),
    rule("pip.group", Any),
    rule("pip.annotation-style", Str),
    rule("pip.no-header", Bool),
    rule("pip.no-emit-package", Any),
    rule("pip.config-settings", Any),
    rule("pip.no-sources", Bool),
    rule("pip.offline", Bool),
];

pub(super) const UV: Surface = Surface {
    id: "uv",
    subject: "uv setting",
    why: "it can redirect package resolution to an index or directory that cannot be verified, download and run an interpreter, or install from an unhashed cache or unlocked build requirements",
    allow: ALLOW,
    deny: &[
        "index-url",
        "extra-index-url",
        "find-links",
        "no-index",
        "index",
        "index-strategy",
        "default-index",
        "torch-backend",
        "python-install-mirror",
        "pypy-install-mirror",
        "python-downloads-json-url",
        "cache-dir",
        "extra-build-dependencies",
        "pip.python",
    ],
    deny_under: &["pip"],
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_surface::{KNOWN_SURFACES, check_toml};

    fn run(text: &str, allows: &[crate::config_surface::KeyAllow]) -> anyhow::Result<usize> {
        let value: toml::Value = text.parse().unwrap();
        check_toml(&UV, &value, std::path::Path::new("uv.toml"), allows).map(|a| a.len())
    }

    #[test]
    fn the_surface_id_is_known() {
        assert!(KNOWN_SURFACES.contains(&UV.id));
    }

    #[test]
    fn safe_settings_pass() {
        let text = "required-version = \">=0.5\"\nnative-tls = true\nsources = { a = { workspace = true } }\n[pip]\nrequire-hashes = true\npython-version = \"3.12\"\n";
        assert_eq!(run(text, &[]).unwrap(), 0);
    }

    #[test]
    fn redirecting_and_executing_settings_block_even_when_allowed() {
        for key in [
            "index-url = \"https://x/simple\"",
            "extra-index-url = [\"https://x/simple\"]",
            "find-links = [\"./w\"]",
            "no-index = true",
            "index-strategy = \"unsafe-best-match\"",
            "default-index = \"https://x\"",
            "torch-backend = \"auto\"",
            "python-install-mirror = \"https://x\"",
            "pypy-install-mirror = \"https://x\"",
            "python-downloads-json-url = \"https://x\"",
            "cache-dir = \"./c\"",
            "extra-build-dependencies = { a = [\"b\"] }",
            "[pip]\nindex-url = \"https://x/simple\"",
            "[pip]\npython = \"./py\"",
        ] {
            assert!(run(key, &[]).is_err(), "{key}");
            let name = key.split([' ', '=']).next().unwrap().to_string();
            let allow = crate::config_surface::KeyAllow {
                file: "uv".into(),
                key: name,
            };
            assert!(run(key, &[allow]).is_err(), "allowed: {key}");
        }
    }

    #[test]
    fn an_unlisted_setting_blocks_until_the_operator_allows_that_exact_key() {
        let err = run("keyring-provider = \"subprocess\"\n", &[])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Unsupported uv setting 'keyring-provider'"),
            "{err}"
        );
        let allow = crate::config_surface::KeyAllow {
            file: "uv".into(),
            key: "keyring-provider".into(),
        };
        assert_eq!(
            run("keyring-provider = \"subprocess\"\n", &[allow]).unwrap(),
            1
        );
    }
}
