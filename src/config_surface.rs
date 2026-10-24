//! Allowlist tables for repo-controlled config files that steer a package manager (uv settings,
//! `poetry.toml`, Composer `config`, ...). A key the table does not list blocks: a setting nobody
//! has classified may fetch from, cache in or execute something the lockfile never vouched for.
//! See docs/specs/untrusted-input-hardening.md, criterion A.
//!
//! Three outcomes for a key:
//! - **denied** (`Surface::deny`): known to redirect, cache or execute. Always blocks.
//! - **allowed** (`Surface::allow`, with a value rule): passes.
//! - **unknown**: blocks, unless the out-of-repo scanner config lists the exact file and key in
//!   `config_key_allow`; the allow is then reported as a warning.
//!
//! An allow never overrides a denied key or a value that fails its rule.

use crate::report::{Issue, Severity};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// What a listed key's value may be.
#[derive(Clone, Copy)]
pub(crate) enum ValueRule {
    /// Any value, including a whole nested table (opaque to this check).
    Any,
    Bool,
    BoolIs(bool),
    Str,
    OneOf(&'static [&'static str]),
}

/// A key path (dotted; `*` matches one segment) and the values it may hold. A path that is a
/// proper prefix of another rule's path needs no rule of its own.
#[derive(Debug)]
pub(crate) struct KeyRule {
    pub path: &'static str,
    pub value: ValueRule,
}

impl std::fmt::Debug for ValueRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValueRule::Any => write!(f, "any"),
            ValueRule::Bool => write!(f, "bool"),
            ValueRule::BoolIs(value) => write!(f, "{value}"),
            ValueRule::Str => write!(f, "string"),
            ValueRule::OneOf(values) => write!(f, "one of {values:?}"),
        }
    }
}

pub(crate) const fn rule(path: &'static str, value: ValueRule) -> KeyRule {
    KeyRule { path, value }
}

/// One config file (or table) a package manager reads from the repository.
pub(crate) struct Surface {
    /// Name used in `config_key_allow` and in messages; must be listed in [`KNOWN_SURFACES`].
    pub id: &'static str,
    /// What a key is called in messages, e.g. "uv setting".
    pub subject: &'static str,
    /// Why unlisted keys are refused.
    pub why: &'static str,
    pub allow: &'static [KeyRule],
    /// Key paths (prefix match, `*` wildcard) that always block and cannot be allowed by config.
    pub deny: &'static [&'static str],
    /// Sub-tables in which the `deny` paths also apply (for example uv's `pip`).
    pub deny_under: &'static [&'static str],
}

/// Surface ids a `config_key_allow` entry may name.
pub const KNOWN_SURFACES: &[&str] = &["uv", "poetry.toml", "composer.json"];

/// One entry of the scanner config's `config_key_allow`: permit one exact key on one surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyAllow {
    pub file: String,
    pub key: String,
}

impl KeyAllow {
    /// Problems with this entry; empty when it is acceptable.
    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if !KNOWN_SURFACES.contains(&self.file.as_str()) {
            problems.push(format!(
                "config_key_allow names unknown file '{}'. Valid: {}",
                self.file,
                KNOWN_SURFACES.join(", ")
            ));
        }
        if self.key.is_empty() || self.key.split('.').any(str::is_empty) {
            problems.push(format!(
                "config_key_allow key '{}' for '{}' must be a dotted key path with no empty segment",
                self.key, self.file
            ));
        }
        if self.key.contains('*') {
            problems.push(format!(
                "config_key_allow key '{}' for '{}' must be exact; wildcards are not allowed",
                self.key, self.file
            ));
        }
        problems
    }
}

/// A key that blocked by default and was permitted by `config_key_allow`.
#[derive(Debug, Clone)]
pub(crate) struct AppliedAllow {
    surface: &'static str,
    key: String,
    source: PathBuf,
}

impl AppliedAllow {
    pub(crate) fn to_issue(&self) -> Issue {
        Issue::new(
            self.source.display().to_string(),
            crate::names::CONFIG_KEY_ALLOWED,
            Severity::Warning,
        )
        .message(format!(
            "{} setting '{}' in {} is not on the built-in allowlist; config_key_allow permits it, so the scan does not check what it changes.",
            self.surface,
            crate::report::sanitize_for_terminal(&self.key),
            self.source.display()
        ))
        .fix("Review the setting; remove the config_key_allow entry once it is no longer needed.")
    }
}

pub(crate) fn issues(applied: &[AppliedAllow]) -> Vec<Issue> {
    applied.iter().map(AppliedAllow::to_issue).collect()
}

/// Check a parsed TOML document (the table at its root) against `surface`.
pub(crate) fn check_toml(
    surface: &Surface,
    root: &toml::Value,
    source: &Path,
    allows: &[KeyAllow],
) -> Result<Vec<AppliedAllow>> {
    let json = serde_json::to_value(root)
        .map_err(|err| anyhow::anyhow!("Cannot inspect {}: {err}", source.display()))?;
    check_json(surface, &json, source, allows)
}

/// Check a parsed JSON object against `surface`.
pub(crate) fn check_json(
    surface: &Surface,
    root: &Value,
    source: &Path,
    allows: &[KeyAllow],
) -> Result<Vec<AppliedAllow>> {
    let Some(table) = root.as_object() else {
        bail!(
            "Unsupported {} in {}: expected a table of settings",
            surface.subject,
            source.display()
        );
    };
    let mut walk = Walk {
        surface,
        source,
        allows,
        applied: Vec::new(),
    };
    let mut path = Vec::new();
    walk.visit_table(table, &mut path)?;
    Ok(walk.applied)
}

struct Walk<'a> {
    surface: &'a Surface,
    source: &'a Path,
    allows: &'a [KeyAllow],
    applied: Vec<AppliedAllow>,
}

fn segments_match(pattern: &[&str], path: &[String], whole: bool) -> bool {
    if pattern.len() > path.len() || (whole && pattern.len() != path.len()) {
        return false;
    }
    pattern
        .iter()
        .zip(path)
        .all(|(want, have)| *want == "*" || want == have)
}

/// Whether `path` names a table that a longer rule path descends into.
fn is_proper_prefix(path: &[String], pattern: &[&str]) -> bool {
    path.len() < pattern.len()
        && path
            .iter()
            .zip(pattern)
            .all(|(have, want)| *want == "*" || want == have)
}

impl Walk<'_> {
    fn visit_table(
        &mut self,
        table: &serde_json::Map<String, Value>,
        path: &mut Vec<String>,
    ) -> Result<()> {
        for (key, node) in table {
            path.push(key.clone());
            let outcome = self.visit(node, path);
            path.pop();
            outcome?;
        }
        Ok(())
    }

    fn visit(&mut self, node: &Value, path: &mut Vec<String>) -> Result<()> {
        if self.denied(path) {
            return Err(self.refusal(path, self.surface.why));
        }
        if let Some(rule) = self
            .surface
            .allow
            .iter()
            .find(|rule| segments_match(&rule.path.split('.').collect::<Vec<_>>(), path, true))
        {
            return self.check_value(rule, node, path);
        }
        let leads_to_a_rule = self
            .surface
            .allow
            .iter()
            .any(|rule| is_proper_prefix(path, &rule.path.split('.').collect::<Vec<_>>()));
        if leads_to_a_rule && let Some(table) = node.as_object() {
            return self.visit_table(table, path);
        }
        // An unlisted table is judged key by key, so an operator allow names the exact setting
        // rather than a whole table.
        if let Some(table) = node.as_object()
            && !table.is_empty()
        {
            return self.visit_table(table, path);
        }
        self.unknown(path)
    }

    fn denied(&self, path: &[String]) -> bool {
        self.surface.deny.iter().any(|deny| {
            let parts: Vec<&str> = deny.split('.').collect();
            segments_match(&parts, path, false)
                || self.surface.deny_under.iter().any(|under| {
                    let nested: Vec<&str> = under.split('.').chain(parts.iter().copied()).collect();
                    segments_match(&nested, path, false)
                })
        })
    }

    fn check_value(&self, rule: &KeyRule, node: &Value, path: &[String]) -> Result<()> {
        let fits = match rule.value {
            ValueRule::Any => true,
            ValueRule::Bool => node.is_boolean(),
            ValueRule::BoolIs(want) => node.as_bool() == Some(want),
            ValueRule::Str => node.is_string(),
            ValueRule::OneOf(values) => node.as_str().is_some_and(|text| values.contains(&text)),
        };
        if fits {
            return Ok(());
        }
        Err(self.refusal(
            path,
            &format!(
                "its value must be {:?}; other values change what the package manager installs",
                rule.value
            ),
        ))
    }

    fn unknown(&mut self, path: &[String]) -> Result<()> {
        let key = path.join(".");
        if self
            .allows
            .iter()
            .any(|allow| allow.file == self.surface.id && allow.key == key)
        {
            self.applied.push(AppliedAllow {
                surface: self.surface.id,
                key,
                source: self.source.to_path_buf(),
            });
            return Ok(());
        }
        Err(self.refusal(
            path,
            &format!(
                "it is not on the allowlist for this file ({}). To permit it, add {{\"file\": \"{}\", \"key\": \"{}\"}} to config_key_allow in the scanner config",
                self.surface.why, self.surface.id, key
            ),
        ))
    }

    fn refusal(&self, path: &[String], reason: &str) -> anyhow::Error {
        anyhow::anyhow!(
            "Unsupported {} '{}' in {}: {}",
            self.surface.subject,
            crate::report::sanitize_for_terminal(&path.join(".")),
            self.source.display(),
            reason
        )
    }
}

#[cfg(test)]
mod tests;
