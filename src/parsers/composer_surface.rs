//! The allowlist for the `config` object of `composer.json`. Anything not listed blocks; an
//! operator can allow one more exact key through `config_key_allow` (file id `composer.json`).
//!
//! Decisions:
//! - **Denied** (never allowable): keys that move Composer's caches (it installs a cached archive
//!   without re-hashing when the lock's `shasum` is empty: `cache-dir`, `cache-files-dir`,
//!   `cache-repo-dir`, `cache-vcs-dir`, `data-dir`), change the trust store (`cafile`, `capath`)
//!   or redirect where it fetches from (`github-domains`, `gitlab-domains`, `github-protocols`).
//! - **Value-restricted**: `disable-tls` may only be `false` and `secure-http` only `true`.
//! - **Allowed**: autoloader and sorting switches, `platform` simulation, install preferences,
//!   timeouts and the `vendor-dir`/`bin-dir` locations (the lock still vouches for what is
//!   installed there); `allow-plugins` is allowed here and vetted separately for blanket trust.
//! - **Everything else** (credentials such as `http-basic`, `github-oauth` or `bearer`, `audit`,
//!   `gitlab-protocol`, ...) is unknown: blocked unless allowed.

use crate::config_surface::{KeyRule, Surface, ValueRule::*, rule};

const ALLOW: &[KeyRule] = &[
    rule("allow-plugins", Any),
    rule("sort-packages", Bool),
    rule("optimize-autoloader", Bool),
    rule("classmap-authoritative", Bool),
    rule("apcu-autoloader", Bool),
    rule("apcu-autoloader-prefix", Str),
    rule("autoloader-suffix", Str),
    rule("prepend-autoloader", Bool),
    rule("platform", Any),
    rule("platform-check", Any),
    rule("preferred-install", Any),
    rule("process-timeout", Any),
    rule("discard-changes", Any),
    rule("vendor-dir", Str),
    rule("bin-dir", Str),
    rule("bin-compat", Str),
    rule("use-github-api", Bool),
    rule("use-parent-dir", Any),
    rule("lock", Bool),
    rule("htaccess-protect", Bool),
    rule("notify-on-install", Bool),
    rule("github-expose-hostname", Bool),
    rule("archive-format", Str),
    rule("archive-dir", Str),
    rule("disable-tls", BoolIs(false)),
    rule("secure-http", BoolIs(true)),
];

pub(super) const COMPOSER_CONFIG: Surface = Surface {
    id: "composer.json",
    subject: "Composer config",
    why: "it moves caches or changes how packages are fetched or authenticated, so the scanned lock no longer describes what is installed",
    allow: ALLOW,
    deny: &[
        "cache-dir",
        "cache-files-dir",
        "cache-repo-dir",
        "cache-vcs-dir",
        "data-dir",
        "cafile",
        "capath",
        "github-domains",
        "gitlab-domains",
        "github-protocols",
    ],
    deny_under: &[],
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_surface::{KNOWN_SURFACES, KeyAllow, check_json};

    fn run(text: &str, allows: &[KeyAllow]) -> anyhow::Result<usize> {
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        check_json(
            &COMPOSER_CONFIG,
            &value,
            std::path::Path::new("composer.json"),
            allows,
        )
        .map(|applied| applied.len())
    }

    fn allow(key: &str) -> KeyAllow {
        KeyAllow {
            file: "composer.json".into(),
            key: key.into(),
        }
    }

    #[test]
    fn the_surface_id_is_known() {
        assert!(KNOWN_SURFACES.contains(&COMPOSER_CONFIG.id));
    }

    #[test]
    fn safe_keys_pass() {
        let text = r#"{"sort-packages": true, "optimize-autoloader": true, "platform": {"php": "8.2"}, "disable-tls": false, "secure-http": true, "vendor-dir": "v"}"#;
        assert_eq!(run(text, &[]).unwrap(), 0);
    }

    #[test]
    fn denied_and_weakened_keys_block_even_when_allowed() {
        for (text, key) in [
            (r#"{"cache-dir": "x"}"#, "cache-dir"),
            (r#"{"data-dir": "x"}"#, "data-dir"),
            (r#"{"cafile": "ca.pem"}"#, "cafile"),
            (r#"{"github-domains": ["e"]}"#, "github-domains"),
            (r#"{"disable-tls": true}"#, "disable-tls"),
            (r#"{"secure-http": false}"#, "secure-http"),
        ] {
            assert!(run(text, &[]).is_err(), "{text}");
            assert!(run(text, &[allow(key)]).is_err(), "allowed: {text}");
        }
    }

    #[test]
    fn an_unlisted_key_blocks_until_the_operator_allows_that_exact_key() {
        let text = r#"{"github-oauth": {"github.com": "token"}}"#;
        let err = run(text, &[]).unwrap_err().to_string();
        assert!(
            err.contains("Unsupported Composer config 'github-oauth.github.com'"),
            "{err}"
        );
        assert_eq!(run(text, &[allow("github-oauth.github.com")]).unwrap(), 1);
    }
}
