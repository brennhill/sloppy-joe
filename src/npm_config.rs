//! Project-local npm routing. Private package identities must never use public registries.
use anyhow::{Result, bail};
use std::collections::BTreeMap;
use std::path::Path;

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
                if !scope.starts_with('@')
                    || !crate::registry::validate_package_name(&format!("{scope}/package"))
                {
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
            let value = value.trim();
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
                    return Err(invalid());
                } else {
                    segments.push(segment);
                }
            }
            let value = segments.join("/");
            let url = reqwest::Url::parse(&value).map_err(|_| invalid())?;
            if url.scheme() != "https"
                || url.host_str().is_none_or(|host| host.contains('*'))
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(invalid());
            }
            self.0.insert(
                scope.to_string(),
                format!("{}/", url.as_str().trim_end_matches('/')),
            );
        }
        Ok(())
    }

    pub(crate) fn private_registry(&self, package: &str) -> Option<&str> {
        let scope = package.split_once('/').map(|(scope, _)| scope);
        let registry = scope
            .and_then(|scope| self.0.get(scope))
            .or_else(|| self.0.get(""))?;
        (registry != "https://registry.npmjs.org/").then_some(registry.as_str())
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
        if manager != "npm"
            && self
                .0
                .values()
                .any(|url| url != "https://registry.npmjs.org/")
        {
            bail!(
                "Scan not supported: private .npmrc routing for {manager} in '{}'; npm package-lock.json and npm-shrinkwrap.json are supported",
                path.display()
            );
        }
        Ok(())
    }
}
