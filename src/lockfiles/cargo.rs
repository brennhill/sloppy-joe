use crate::Dependency;
use anyhow::Result;
use std::collections::HashMap;
#[cfg(test)]
use std::path::Path;

use super::{
    ResolutionKey, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, add_manifest_exact_fallbacks, ambiguous_issue,
    missing_entry_issue, out_of_sync_issue, parse_failed_issue,
};

/// Read + parse + resolve in one step (used by resolve_versions test API).
#[cfg(test)]
pub(super) fn resolve(project_dir: &Path, deps: &[Dependency]) -> Result<ResolutionResult> {
    let path = project_dir.join("Cargo.lock");
    if !crate::parsers::path_detected(&path)? {
        let mut result = ResolutionResult::default();
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    }

    let content = crate::parsers::read_file_limited(&path, crate::parsers::MAX_MANIFEST_BYTES)?;
    let parsed: toml::Value = match toml::from_str(&content) {
        Ok(parsed) => parsed,
        Err(err) => {
            let mut result = ResolutionResult::default();
            result
                .issues
                .push(parse_failed_issue("Cargo.lock", err.to_string()));
            add_manifest_exact_fallbacks(&mut result, deps);
            return Ok(result);
        }
    };

    resolve_from_value(&parsed, deps)
}

/// Resolve versions from a pre-parsed Cargo.lock TOML value.
pub(super) fn resolve_from_value(
    parsed: &toml::Value,
    deps: &[Dependency],
) -> Result<ResolutionResult> {
    let Some(packages) = parsed.get("package").and_then(|value| value.as_array()) else {
        let mut result = ResolutionResult::default();
        result.issues.push(parse_failed_issue(
            "Cargo.lock",
            "lockfile did not contain a package array".to_string(),
        ));
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };

    let mut versions_by_name: HashMap<String, Vec<String>> = HashMap::new();
    for package in packages {
        let Some(table) = package.as_table() else {
            continue;
        };
        let Some(name) = table.get("name").and_then(|value| value.as_str()) else {
            continue;
        };
        if name.contains("..") || name.contains('\0') {
            continue;
        }
        let Some(version) = table.get("version").and_then(|value| value.as_str()) else {
            continue;
        };
        versions_by_name
            .entry(name.to_string())
            .or_default()
            .push(version.to_string());
    }

    let mut result = ResolutionResult::default();
    for dep in deps {
        let Some(versions) = versions_by_name.get(&dep.name) else {
            result.issues.push(missing_entry_issue(dep, "Cargo.lock"));
            add_manifest_exact_fallback(&mut result, dep);
            continue;
        };

        if versions.len() == 1 {
            let version = &versions[0];
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
            continue;
        }

        // Try exact_version first (manifest with = prefix),
        // then fall back to raw version string (lockfile-extracted versions
        // like "0.52.0" don't have = prefix but ARE exact).
        let exact = dep
            .exact_version()
            .or_else(|| dep.version.clone())
            .filter(|v| versions.iter().any(|lv| lv == v));

        if let Some(matched) = exact {
            result.exact_versions.insert(
                ResolutionKey::from(dep),
                ResolvedVersion {
                    version: matched,
                    source: ResolutionSource::Lockfile,
                },
            );
        } else if let Some(exact_manifest) = dep.exact_version() {
            result
                .issues
                .push(out_of_sync_issue(dep, &versions.join(", ")));
            add_manifest_exact_fallback(&mut result, dep);
            let _ = exact_manifest; // used for the branch condition
        } else {
            result.issues.push(ambiguous_issue(dep));
        }
    }

    Ok(result)
}

/// Parse ALL cargo deps from a lockfile string (for tests).
#[cfg(test)]
pub fn parse_all(lockfile_content: &str) -> Result<Vec<Dependency>> {
    let parsed: toml::Value = toml::from_str(lockfile_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse Cargo.lock: {}", e))?;
    parse_all_from_value(&parsed)
}

/// Parse ALL cargo deps from a pre-parsed TOML value.
pub(super) fn parse_all_from_value(parsed: &toml::Value) -> Result<Vec<Dependency>> {
    let Some(packages) = parsed.get("package").and_then(|v| v.as_array()) else {
        anyhow::bail!("Cargo.lock has no package array");
    };

    let mut deps = Vec::new();
    for package in packages {
        let Some(table) = package.as_table() else {
            continue;
        };
        if table.get("source").and_then(|v| v.as_str()).is_none() {
            continue;
        }
        let Some(name) = table.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        if name.contains("..") || name.contains('\0') {
            continue;
        }
        let version = table
            .get("version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        deps.push(Dependency {
            name: name.to_string(),
            version,
            ecosystem: crate::Ecosystem::Cargo,
            actual_name: None,
        });
    }

    Ok(deps)
}

#[cfg(test)]
mod tests {
    use super::parse_all;

    #[test]
    fn parse_all_skips_workspace_root_package_without_source() {
        let lockfile = r#"
[[package]]
name = "demo-app"
version = "0.1.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

        let deps = parse_all(lockfile).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "serde");
    }
}
