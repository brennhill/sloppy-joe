//! The allowlist for `.cargo/config.toml` / `.cargo/config` in the repository (and the host-local
//! Cargo home). Anything not listed blocks; the operator can allow one exact leaf key through
//! `config_key_allow` (file id `cargo-config`).
//!
//! Decisions:
//! - **Denied** (never allowable): settings that pull in more config (`include`), run a program
//!   (`build.rustc*`, `target.*.linker`/`runner`/`ar`, `doc.browser`, credential providers),
//!   proxy or re-trust the fetch (`http.proxy`, `http.cainfo`, `http.ssl-version`,
//!   `http.check-revoke`, `net.git-fetch-with-cli`).
//! - **Value-restricted**: `rustflags`/`rustdocflags` (build and per target) may only hold plain
//!   flags, and `[env]` may only set inert names; both are judged as whole values.
//! - **Allowed**: the provenance tables the scan models itself (`paths`, `source`, `patch`,
//!   `registries.*.index`, `registry.default`), aliases, profiles, lints, build job and target
//!   selection, network retry/timeout tuning, terminal and `cargo new` preferences.
//! - **Everything else** (target build-script override tables, credentials, ...) is unknown.

use super::program_settings::{env_table_is_inert, flags_are_plain};
use crate::config_surface::{
    AppliedAllow, KeyAllow, KeyRule, Surface, ValueRule::*, check_toml, rule,
};
use anyhow::Result;
use std::path::Path;

const ALLOW: &[KeyRule] = &[
    rule("paths", Any),
    rule("source", Any),
    rule("patch", Any),
    rule("replace", Any),
    rule("alias", Any),
    rule("profile", Any),
    rule("lints", Any),
    rule("registries.*.index", Any),
    rule("registry.default", Any),
    rule("build.jobs", Any),
    rule("build.target", Any),
    rule("build.target-dir", Str),
    rule("build.incremental", Bool),
    rule("build.pipelining", Bool),
    rule("build.dep-info-basedir", Str),
    rule(
        "build.rustflags",
        ValueWhere(
            flags_are_plain,
            "plain compiler flags that load or run nothing",
        ),
    ),
    rule(
        "build.rustdocflags",
        ValueWhere(
            flags_are_plain,
            "plain rustdoc flags that load or run nothing",
        ),
    ),
    rule(
        "target.*.rustflags",
        ValueWhere(
            flags_are_plain,
            "plain compiler flags that load or run nothing",
        ),
    ),
    rule(
        "target.*.rustdocflags",
        ValueWhere(
            flags_are_plain,
            "plain rustdoc flags that load or run nothing",
        ),
    ),
    rule(
        "env",
        ValueWhere(
            env_table_is_inert,
            "inert variables (RUST_BACKTRACE, RUST_LIB_BACKTRACE, RUST_LOG)",
        ),
    ),
    rule("http.timeout", Any),
    rule("http.multiplexing", Bool),
    rule("http.user-agent", Str),
    rule("http.low-speed-limit", Any),
    rule("http.debug", Bool),
    rule("net.retry", Any),
    rule("net.offline", Bool),
    rule("cargo-new", Any),
    rule("term", Any),
    rule("resolver", Any),
    rule("future-incompat-report", Any),
    rule("cache", Any),
    rule("install.root", Str),
];

pub(super) const CARGO_CONFIG: Surface = Surface {
    id: "cargo-config",
    subject: "Cargo config setting",
    why: "it runs a program, loads more config, proxies or re-trusts the fetch, or otherwise changes how crates are fetched or built in a way the scan cannot verify; remove it from the repository's Cargo config and set it in the environment instead",
    allow: ALLOW,
    deny: &[
        "include",
        "credential-alias",
        "http.proxy",
        "http.cainfo",
        "http.ssl-version",
        "http.check-revoke",
        "net.git-fetch-with-cli",
        "build.rustc",
        "build.rustdoc",
        "build.rustc-wrapper",
        "build.rustc-workspace-wrapper",
        "registry.credential-provider",
        "registry.global-credential-providers",
        "registries.*.credential-provider",
        "target.*.linker",
        "target.*.runner",
        "target.*.ar",
        "doc.browser",
    ],
    deny_under: &[],
    scope: &[],
};

/// Check a parsed Cargo config against the table; the applied operator allows come back.
pub(super) fn check(
    value: &toml::Value,
    config_path: &Path,
    allows: &[KeyAllow],
) -> Result<Vec<AppliedAllow>> {
    check_toml(&CARGO_CONFIG, value, config_path, allows)
}

#[cfg(test)]
mod tests;
