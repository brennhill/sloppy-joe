//! `nuget.config` policy for .NET projects: an allowlist of the elements and settings a
//! repo-committed NuGet config may use. `dotnet restore` honors a `nuget.config` in the project
//! directory or any parent, so a feed other than nuget.org, a package folder, a trust anchor or a
//! proxy there redirects or re-trusts every package. An unlisted entry blocks unless the
//! operator lists it in `config_key_allow` (file id `nuget.config`).
//!
//! Entries are flat keys: `<element>` for every element, `source` (value: feed URL) for each
//! `<add>` under `<packageSources>`, `config:<key>` for `<add>` under `<config>`, and
//! `<section>:<key>` for the other `<add>` settings, all lower-cased.
//!
//! Decisions:
//! - **Denied**: `<fallbackPackageFolders>`, `<trustedSigners>`, `<auditSources>`, the package
//!   folder keys (`globalPackagesFolder`, `repositoryPath`) wherever they appear and the proxy
//!   keys; a package source other than nuget.org; `signatureValidationMode` other than `require`.
//! - **Allowed**: package source mapping, disabled sources, `<clear/>`/`<remove/>`, restore and
//!   package-management preferences, `dependencyVersion`.
use super::csproj::{extract_attr, strip_xml_comments};
use crate::config_surface::{AppliedAllow, KeyAllow, Surface, ValueRule::*, check_flat, rule};
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

const NUGET_ORG_FEED: &str = "https://api.nuget.org/v3/index.json";

/// `<add key=..>` settings that move where restore reads or writes packages: a repo-committed
/// folder then supplies packages with their recorded hash metadata.
const FOLDER_KEYS: &[&str] = &["globalpackagesfolder", "repositorypath"];

fn is_nuget_org(value: &str) -> bool {
    value.trim() == NUGET_ORG_FEED
}

const NUGET_CONFIG: Surface = Surface {
    id: "nuget.config",
    subject: "NuGet config entry",
    why: "it changes where restore reads packages from, which feeds, signers or proxies it trusts, so the scanned lockfile no longer describes what is installed",
    allow: &[
        rule("=<configuration>", Any),
        rule("=<packagesources>", Any),
        rule("=<config>", Any),
        rule("=<packagesourcemapping>", Any),
        rule("=<packagesource>", Any),
        rule("=<package>", Any),
        rule("=<disabledpackagesources>", Any),
        rule("=<packagerestore>", Any),
        rule("=<bindingredirects>", Any),
        rule("=<packagemanagement>", Any),
        rule("=<solution>", Any),
        rule("=<clear>", Any),
        rule("=<remove>", Any),
        rule("=<add>", Any),
        rule("=source", StrWhere(is_nuget_org, "the nuget.org v3 feed")),
        rule("config:dependencyversion", Any),
        rule("config:signaturevalidationmode", OneOf(&["require"])),
        rule("disabledpackagesources:*", Any),
        rule("packagerestore:*", Any),
        rule("bindingredirects:*", Any),
        rule("packagemanagement:*", Any),
        rule("solution:*", Any),
    ],
    deny: &[
        "=<fallbackpackagefolders>",
        "=<trustedsigners>",
        "=<auditsources>",
        "config:globalpackagesfolder",
        "config:repositorypath",
        "config:http_proxy",
        "config:https_proxy",
        "config:no_proxy",
    ],
    deny_under: &[],
    scope: &[],
};

/// The flat entries of a NuGet config document (comments already stripped).
fn config_entries(content: &str) -> Vec<(String, Value)> {
    let mut entries = Vec::new();
    let mut open: Vec<String> = Vec::new();
    for tag in content.split('<').skip(1) {
        if tag.starts_with(['?', '!']) {
            continue;
        }
        if let Some(closing) = tag.strip_prefix('/') {
            let name = closing.split('>').next().unwrap_or_default().trim();
            if open
                .last()
                .is_some_and(|last| last.eq_ignore_ascii_case(name))
            {
                open.pop();
            }
            continue;
        }
        let attrs = tag.split('>').next().unwrap_or_default();
        let name = attrs
            .split(|c: char| c.is_whitespace() || c == '/')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let self_closing = attrs.trim_end().ends_with('/');
        entries.push((format!("<{name}>"), Value::String(String::new())));
        if name == "add" {
            let section = open.last().cloned().unwrap_or_default();
            let key = extract_attr(attrs, "key")
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            let value = extract_attr(attrs, "value").unwrap_or_default();
            let entry = if section == "packagesources" {
                "source".to_string()
            } else if section == "config" || FOLDER_KEYS.contains(&key.as_str()) {
                format!("config:{key}")
            } else {
                format!("{section}:{key}")
            };
            entries.push((entry, Value::String(value)));
        }
        if !self_closing {
            open.push(name);
        }
    }
    entries
}

/// `dotnet restore` honors a `nuget.config` in the project directory or any parent; check the
/// ones in `dir` against the allowlist.
pub(super) fn reject_untrusted_nuget_config(
    dir: &Path,
    csproj: &Path,
    allows: &[KeyAllow],
) -> Result<Vec<AppliedAllow>> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    let mut applied = Vec::new();
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .to_string_lossy()
            .eq_ignore_ascii_case("nuget.config")
        {
            continue;
        }
        let path = entry.path();
        let content = crate::untrusted::read_text(
            &path,
            crate::untrusted::Format::Xml,
            super::MAX_MANIFEST_BYTES,
        )?;
        let content = strip_xml_comments(&content);
        applied.extend(
            check_flat(&NUGET_CONFIG, &config_entries(&content), &path, allows)
                .map_err(|err| anyhow::anyhow!("{err} (applies to {})", csproj.display()))?,
        );
    }
    Ok(applied)
}

#[cfg(test)]
mod tests;
