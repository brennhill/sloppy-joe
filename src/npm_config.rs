//! Project-local npm routing. Private package identities must never use public registries.
use anyhow::{Result, bail};
use std::collections::BTreeMap;
use std::path::Path;

/// Route name for the unscoped `registry=` key in `trusted_registries.npm`.
pub(crate) const DEFAULT_ROUTE: &str = "default";

fn valid_scope(scope: &str) -> bool {
    scope.starts_with('@')
        && scope.len() > 1
        && !scope.contains('/')
        && crate::registry::validate_package_name(&format!("{scope}/package"))
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

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct NpmRegistries(pub(crate) BTreeMap<String, String>);

impl NpmRegistries {
    pub(crate) fn read(&mut self, path: &Path) -> Result<()> {
        let content = crate::parsers::read_file_limited(path, crate::parsers::MAX_MANIFEST_BYTES)?;
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
            } else if matches!(
                key,
                "always-auth"
                    | "strict-ssl"
                    | "audit"
                    | "fund"
                    | "ignore-scripts"
                    | "save-exact"
                    | "engine-strict"
            ) {
                continue;
            } else {
                return Err(invalid());
            };
            let value = normalize_registry_url(value.trim()).ok_or_else(invalid)?;
            self.0.insert(scope.to_string(), value);
        }
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
