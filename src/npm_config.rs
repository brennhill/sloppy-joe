//! Project-local npm routing. Private package identities must never use public registries.
use crate::config_surface::{DeferredKey, Surface, ValueRule::*, check_flat_deferred, rule};
use anyhow::{Result, bail};
use std::collections::BTreeMap;
use std::path::Path;

/// Route name for the unscoped `registry=` key in `trusted_registries.npm`.
pub(crate) const DEFAULT_ROUTE: &str = "default";

fn valid_scope(scope: &str) -> bool {
    scope.starts_with('@')
        && scope.len() > 1
        && !scope.contains('/')
        && crate::ecosystem::validate_package_name(&format!("{scope}/package"))
}

/// Validate a `trusted_registries.npm` route name: `default` or `@scope`.
pub(crate) fn valid_route_name(name: &str) -> bool {
    name == DEFAULT_ROUTE || valid_scope(name)
}

/// Normalize an npm registry URL as written in `.npmrc` or out-of-repo config.
/// A `${NAME}` placeholder may occupy a whole path segment and becomes `*`.
/// Returns None for anything other than a credential-free HTTPS base URL.
pub(crate) fn normalize_registry_url(value: &str) -> Option<String> {
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
        .unwrap_or(value);
    // Unset CI project IDs can occupy a whole path segment; no secret expansion is needed.
    let mut segments = Vec::new();
    for segment in value.split('/') {
        if segment.starts_with("${") && segment.ends_with('}') && segment.len() > 3 {
            segments.push("*");
        } else if segment.contains(['$', '{', '}', '*']) {
            return None;
        } else {
            segments.push(segment);
        }
    }
    let url = reqwest::Url::parse(&segments.join("/")).ok()?;
    if url.scheme() != "https"
        || url.host_str().is_none_or(|host| host.contains('*'))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    Some(format!("{}/", url.as_str().trim_end_matches('/')))
}

const TRUE_FALSE: &[&str] = &["true", "false"];

/// `.npmrc` settings other than registry routing and credentials. Denied: anything that moves
/// the cache, prefix, store or config files, adds trust anchors, proxies traffic, runs a shell
/// or hook, or turns off integrity (`package-lock=false`) or TLS checks (`strict-ssl=false`).
const NPMRC: Surface = Surface {
    id: ".npmrc",
    subject: "npm setting",
    why: "it moves caches or config files, changes trust or proxying, runs a hook or weakens integrity or TLS checks, so the scanned lockfile no longer describes what is installed",
    allow: &[
        rule("always-auth", OneOf(TRUE_FALSE)),
        rule("strict-ssl", OneOf(&["true"])),
        rule("package-lock", OneOf(&["true"])),
        rule("audit", OneOf(TRUE_FALSE)),
        rule(
            "audit-level",
            OneOf(&["low", "moderate", "high", "critical"]),
        ),
        rule("fund", OneOf(TRUE_FALSE)),
        rule("ignore-scripts", OneOf(TRUE_FALSE)),
        rule("save-exact", OneOf(TRUE_FALSE)),
        rule("save-prefix", OneOf(&["^", "~", ""])),
        rule("engine-strict", OneOf(TRUE_FALSE)),
        rule("legacy-peer-deps", OneOf(TRUE_FALSE)),
        rule("auto-install-peers", OneOf(TRUE_FALSE)),
        rule("strict-peer-dependencies", OneOf(TRUE_FALSE)),
        rule("loglevel", Str),
        rule("progress", OneOf(TRUE_FALSE)),
        rule("update-notifier", OneOf(TRUE_FALSE)),
        rule("node-linker", OneOf(&["isolated", "hoisted", "pnp"])),
    ],
    deny: &[
        "cache",
        "prefix",
        "globalconfig",
        "userconfig",
        "=ca",
        "cafile",
        "=cert",
        "=key",
        "proxy",
        "https-proxy",
        "noproxy",
        "local-address",
        "store-dir",
        "virtual-store-dir",
        "global-dir",
        "state-dir",
        "pnpmfile",
        "global-pnpmfile",
        "script-shell",
        "=shell",
        "node-options",
        "node-gyp",
        "=tmp",
        "init-module",
        "=git",
        "replace-registry-host",
        "registry",
    ],
    deny_under: &[],
    scope: &[],
};

/// Routing read from `.npmrc` (and, in the second field, settings that the operator's
/// `config_key_allow` still has to settle).
#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct NpmRegistries(
    pub(crate) BTreeMap<String, String>,
    pub(crate) Vec<DeferredKey>,
);

impl NpmRegistries {
    pub(crate) fn read(&mut self, path: &Path) -> Result<()> {
        let content = crate::fsutil::read_file_limited(path, crate::fsutil::MAX_MANIFEST_BYTES)?;
        crate::fsutil::reject_unmodeled_line_breaks(&content, path)?;
        let mut other_settings: Vec<(String, serde_json::Value)> = Vec::new();
        for (line_number, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(['#', ';']) {
                continue;
            }
            let invalid = || {
                anyhow::anyhow!(
                    "Unsupported npm configuration in '{}' at line {} (values redacted)",
                    path.display(),
                    line_number + 1
                )
            };
            let (key, value) = line.split_once('=').ok_or_else(invalid)?;
            let key = key.trim();
            // Credentials are never expanded, retained, or sent by the scanner.
            if key.starts_with("//")
                && key.rsplit_once(':').is_some_and(|(_, field)| {
                    matches!(
                        field,
                        "_authToken"
                            | "_auth"
                            | "username"
                            | "_password"
                            | "email"
                            | "certfile"
                            | "keyfile"
                    )
                })
            {
                continue;
            }
            let scope = if key == "registry" {
                ""
            } else if let Some(scope) = key.strip_suffix(":registry") {
                if !valid_scope(scope) {
                    return Err(invalid());
                }
                scope
            } else {
                // Judged against the allowlist below; an unlisted key blocks once the operator's
                // `config_key_allow` is known.
                other_settings.push((
                    key.to_string(),
                    serde_json::Value::String(value.trim().to_string()),
                ));
                continue;
            };
            let value = normalize_registry_url(value.trim()).ok_or_else(invalid)?;
            self.0.insert(scope.to_string(), value);
        }
        self.1
            .extend(check_flat_deferred(&NPMRC, &other_settings, path)?);
        Ok(())
    }

    pub(crate) fn private_registry(&self, package: &str) -> Option<&str> {
        self.private_route(package).map(|(_, registry)| registry)
    }

    /// The `.npmrc` route (`"default"` or `"@scope"`) and normalized registry
    /// URL that redirect `package` away from the public npm registry, if any.
    pub(crate) fn private_route(&self, package: &str) -> Option<(&str, &str)> {
        let scope = package.split_once('/').map(|(scope, _)| scope);
        let (route, registry) = scope
            .and_then(|scope| self.0.get_key_value(scope))
            .or_else(|| self.0.get_key_value(""))?;
        let route = if route.is_empty() {
            DEFAULT_ROUTE
        } else {
            route.as_str()
        };
        (registry != "https://registry.npmjs.org/").then_some((route, registry.as_str()))
    }

    pub(crate) fn matches_private_source(&self, package: &str, resolved: &str) -> bool {
        let Some(registry) = self.private_registry(package) else {
            return false;
        };
        let Ok(expected) = reqwest::Url::parse(registry) else {
            return false;
        };
        let Ok(actual) = reqwest::Url::parse(resolved) else {
            return false;
        };
        if actual.origin() != expected.origin()
            || !actual.username().is_empty()
            || actual.password().is_some()
            || actual.query().is_some()
            || actual.fragment().is_some()
        {
            return false;
        }
        let expected = expected.path().trim_end_matches('/').split('/');
        let mut actual = actual.path().split('/');
        expected.into_iter().all(|segment| {
            actual
                .next()
                .is_some_and(|part| segment == part || segment == "*" && !part.is_empty())
        })
    }

    pub(crate) fn validate_manager(&self, manager: &str, path: &Path) -> Result<()> {
        if !matches!(manager, "npm" | "pnpm")
            && self
                .0
                .values()
                .any(|url| url != "https://registry.npmjs.org/")
        {
            bail!(
                "Scan not supported: private .npmrc routing for {manager} in '{}'; npm and pnpm lockfiles are supported",
                path.display()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod line_break_tests {
    use super::*;

    #[test]
    fn a_registry_hidden_behind_a_carriage_return_is_not_skipped() {
        let dir = std::env::temp_dir().join(format!("sj-npmrc-cr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(".npmrc");
        std::fs::write(&path, "# team config\rregistry=https://evil.example.com/\n").unwrap();
        assert!(NpmRegistries::default().read(&path).is_err());
        std::fs::write(
            &path,
            "# team config\r\nregistry=https://registry.npmjs.org/\n",
        )
        .unwrap();
        assert!(NpmRegistries::default().read(&path).is_ok());
    }
}
