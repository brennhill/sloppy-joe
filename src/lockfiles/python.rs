use crate::Dependency;
use anyhow::Result;
use std::path::Path;

#[cfg(test)]
use super::add_manifest_exact_fallbacks;
use super::{
    ResolutionKey, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, missing_entry_issue, out_of_sync_issue,
};

/// Resolve versions from a pre-parsed poetry.lock TOML value.
pub(super) fn resolve_from_value(
    parsed: &toml::Value,
    deps: &[Dependency],
) -> Result<ResolutionResult> {
    let packages = extract_packages(parsed);
    let mut result = ResolutionResult::default();

    for dep in deps {
        // PEP 503 normalize: lowercase, replace [-_.] with -
        let normalized = normalize_name(&dep.name);
        match packages
            .iter()
            .find(|(n, _)| normalize_name(n) == normalized)
        {
            Some((_, version)) => {
                if let Some(exact_manifest) = dep.exact_version()
                    && exact_manifest != *version
                {
                    result.issues.push(out_of_sync_issue(dep, version));
                    add_manifest_exact_fallback(&mut result, dep);
                    continue;
                }
                result.exact_versions.insert(
                    ResolutionKey::from(dep),
                    ResolvedVersion {
                        version: version.clone(),
                        source: ResolutionSource::Lockfile,
                    },
                );
            }
            None => {
                result.issues.push(missing_entry_issue(dep, "poetry.lock"));
                add_manifest_exact_fallback(&mut result, dep);
            }
        }
    }

    Ok(result)
}

/// Parse all packages from a pre-parsed poetry.lock TOML value.
pub(super) fn parse_all_from_value(parsed: &toml::Value) -> Result<Vec<Dependency>> {
    Ok(extract_packages(parsed)
        .into_iter()
        .map(|(name, version)| Dependency {
            name,
            version: Some(version),
            ecosystem: crate::Ecosystem::PyPI,
        })
        .collect())
}

/// Read poetry.lock if it exists, return parsed TOML value.
pub(super) fn read_lockfile(project_dir: &Path) -> Option<toml::Value> {
    let path = project_dir.join("poetry.lock");
    if !path.exists() {
        return None;
    }
    let content =
        crate::parsers::read_file_limited(&path, crate::parsers::MAX_MANIFEST_BYTES).ok()?;
    toml::from_str(&content).ok()
}

/// Resolve from disk (used by resolve_versions test API).
#[cfg(test)]
pub(super) fn resolve(project_dir: &Path, deps: &[Dependency]) -> Result<ResolutionResult> {
    let Some(parsed) = read_lockfile(project_dir) else {
        let mut result = ResolutionResult::default();
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };
    resolve_from_value(&parsed, deps)
}

/// PEP 503 normalization: lowercase, replace [-_.] with single hyphen.
fn normalize_name(name: &str) -> String {
    let lower = name.to_lowercase();
    let mut result = String::with_capacity(lower.len());
    let mut last_was_sep = false;
    for ch in lower.chars() {
        if ch == '-' || ch == '_' || ch == '.' {
            if !last_was_sep {
                result.push('-');
                last_was_sep = true;
            }
        } else {
            result.push(ch);
            last_was_sep = false;
        }
    }
    result
}

/// Extract (name, version) pairs from poetry.lock TOML.
/// Format: `[[package]]` array of tables with `name` and `version` keys.
fn extract_packages(parsed: &toml::Value) -> Vec<(String, String)> {
    let Some(packages) = parsed.get("package").and_then(|v| v.as_array()) else {
        return vec![];
    };

    packages
        .iter()
        .filter_map(|pkg| {
            let name = pkg.get("name")?.as_str()?;
            let version = pkg.get("version")?.as_str()?;
            Some((name.to_string(), version.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const POETRY_LOCK: &str = r#"
[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."

[[package]]
name = "urllib3"
version = "2.1.0"
description = "HTTP library with thread-safe connection pooling"

[[package]]
name = "certifi"
version = "2023.11.17"
description = "Python package for providing Mozilla's CA Bundle."

[metadata]
lock-version = "2.0"
python-versions = "^3.8"
"#;

    fn dep(name: &str, version: Option<&str>) -> Dependency {
        crate::test_helpers::dep_with(name, version, crate::Ecosystem::PyPI)
    }

    #[test]
    fn extract_packages_works() {
        let parsed: toml::Value = toml::from_str(POETRY_LOCK).unwrap();
        let packages = extract_packages(&parsed);
        assert_eq!(packages.len(), 3);
        assert!(
            packages
                .iter()
                .any(|(n, v)| n == "requests" && v == "2.31.0")
        );
        assert!(packages.iter().any(|(n, v)| n == "urllib3" && v == "2.1.0"));
        assert!(
            packages
                .iter()
                .any(|(n, v)| n == "certifi" && v == "2023.11.17")
        );
    }

    #[test]
    fn resolve_finds_version() {
        let parsed: toml::Value = toml::from_str(POETRY_LOCK).unwrap();
        let deps = vec![dep("requests", Some("==2.31.0")), dep("urllib3", None)];
        let result = resolve_from_value(&parsed, &deps).unwrap();
        assert_eq!(result.exact_version(&deps[0]), Some("2.31.0"));
        assert_eq!(result.exact_version(&deps[1]), Some("2.1.0"));
        assert!(result.issues.is_empty());
    }

    #[test]
    fn resolve_pep503_normalized() {
        // poetry.lock has "requests" but dep might be "Requests" or "requests_lib"
        let parsed: toml::Value = toml::from_str(POETRY_LOCK).unwrap();
        let deps = vec![dep("Requests", None)];
        let result = resolve_from_value(&parsed, &deps).unwrap();
        assert_eq!(result.exact_version(&deps[0]), Some("2.31.0"));
    }

    #[test]
    fn resolve_missing_dep_reports_issue() {
        let parsed: toml::Value = toml::from_str(POETRY_LOCK).unwrap();
        let deps = vec![dep("nonexistent-pkg", None)];
        let result = resolve_from_value(&parsed, &deps).unwrap();
        assert!(result.exact_version(&deps[0]).is_none());
        assert!(!result.issues.is_empty());
        assert!(result.issues[0].check.contains("missing"));
    }

    #[test]
    fn parse_all_extracts_transitive() {
        let parsed: toml::Value = toml::from_str(POETRY_LOCK).unwrap();
        let all = parse_all_from_value(&parsed).unwrap();
        assert_eq!(all.len(), 3);
        let names: Vec<&str> = all.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"urllib3"));
        assert!(names.contains(&"certifi"));
    }

    #[test]
    fn normalize_name_pep503() {
        assert_eq!(normalize_name("Requests"), "requests");
        assert_eq!(normalize_name("my_package"), "my-package");
        assert_eq!(normalize_name("my.package"), "my-package");
        assert_eq!(normalize_name("My__Package"), "my-package");
    }
}
