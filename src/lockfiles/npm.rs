use crate::Dependency;
use anyhow::Result;
use std::path::Path;

use super::{
    add_manifest_exact_fallback, add_manifest_exact_fallbacks, first_existing,
    missing_entry_issue, out_of_sync_issue, parse_failed_issue, ResolutionKey, ResolutionResult,
    ResolutionSource, ResolvedVersion,
};

/// Read + parse + resolve in one step (used by resolve_versions public API).
pub(super) fn resolve(project_dir: &Path, deps: &[Dependency]) -> Result<ResolutionResult> {
    let Some(path) = first_existing(project_dir, &["package-lock.json", "npm-shrinkwrap.json"])
    else {
        let mut result = ResolutionResult::default();
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("package-lock.json")
        .to_string();
    let content = crate::parsers::read_file_limited(&path, crate::parsers::MAX_MANIFEST_BYTES)?;
    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(parsed) => parsed,
        Err(err) => {
            let mut result = ResolutionResult::default();
            result
                .issues
                .push(parse_failed_issue(&file_name, err.to_string()));
            add_manifest_exact_fallbacks(&mut result, deps);
            return Ok(result);
        }
    };

    resolve_from_value(&parsed, deps, &file_name)
}

/// Resolve versions from a pre-parsed npm lockfile JSON value.
pub(super) fn resolve_from_value(
    parsed: &serde_json::Value,
    deps: &[Dependency],
    file_name: &str,
) -> Result<ResolutionResult> {
    let packages = parsed.get("packages").and_then(|value| value.as_object());
    let dependencies = parsed
        .get("dependencies")
        .and_then(|value| value.as_object());
    if packages.is_none() && dependencies.is_none() {
        let mut result = ResolutionResult::default();
        result.issues.push(parse_failed_issue(
            file_name,
            "lockfile did not contain a supported packages or dependencies section".to_string(),
        ));
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    }

    let mut result = ResolutionResult::default();
    for dep in deps {
        let resolved = packages
            .and_then(|packages| {
                packages
                    .get(&format!("node_modules/{}", dep.name))
                    .and_then(|entry| entry.get("version"))
                    .and_then(|value| value.as_str())
            })
            .or_else(|| {
                dependencies.and_then(|dependencies| {
                    dependencies
                        .get(&dep.name)
                        .and_then(|entry| entry.get("version"))
                        .and_then(|value| value.as_str())
                })
            });

        match resolved {
            Some(version) => {
                if let Some(exact_manifest) = dep.exact_version()
                    && exact_manifest != version
                {
                    result.issues.push(out_of_sync_issue(dep, version));
                    add_manifest_exact_fallback(&mut result, dep);
                    continue;
                }
                result.exact_versions.insert(
                    ResolutionKey::from(dep),
                    ResolvedVersion {
                        version: version.to_string(),
                        source: ResolutionSource::Lockfile,
                    },
                );
            }
            None => {
                result.issues.push(missing_entry_issue(dep, file_name));
                add_manifest_exact_fallback(&mut result, dep);
            }
        }
    }

    Ok(result)
}

/// Parse ALL npm deps from a lockfile string (for tests).
#[cfg(test)]
pub fn parse_all(lockfile_content: &str) -> Result<Vec<Dependency>> {
    let parsed: serde_json::Value = serde_json::from_str(lockfile_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse npm lockfile: {}", e))?;
    parse_all_from_value(&parsed)
}

/// Parse ALL npm deps from a pre-parsed JSON value.
pub(super) fn parse_all_from_value(parsed: &serde_json::Value) -> Result<Vec<Dependency>> {
    let mut deps = Vec::new();
    if let Some(packages) = parsed.get("packages").and_then(|v| v.as_object()) {
        for (key, entry) in packages {
            if key.is_empty() {
                continue;
            }
            let name = key
                .rsplit_once("node_modules/")
                .map(|(_, name)| name)
                .unwrap_or(key);
            if name.is_empty() {
                continue;
            }
            if !crate::registry::validate_package_name(name) {
                continue;
            }
            let version = entry
                .get("version")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            deps.push(Dependency {
                name: name.to_string(),
                version,
                ecosystem: crate::Ecosystem::Npm,
            });
        }
    } else if let Some(dependencies) = parsed.get("dependencies").and_then(|v| v.as_object()) {
        for (name, entry) in dependencies {
            let version = entry
                .get("version")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            deps.push(Dependency {
                name: name.clone(),
                version,
                ecosystem: crate::Ecosystem::Npm,
            });
        }
    } else {
        anyhow::bail!("npm lockfile has no packages or dependencies section");
    }

    Ok(deps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_all_skips_invalid_package_names() {
        let lockfile = r#"{
            "packages": {
                "": { "name": "root" },
                "node_modules/react": { "version": "18.2.0" },
                "node_modules/../etc/passwd": { "version": "1.0.0" },
                "node_modules/evil\u0000pkg": { "version": "1.0.0" },
                "node_modules/good-pkg": { "version": "2.0.0" }
            }
        }"#;
        let deps = parse_all(lockfile).unwrap();
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"react"));
        assert!(names.contains(&"good-pkg"));
        assert!(!names.iter().any(|n| n.contains("..")), "path traversal name should be filtered");
        assert!(!names.iter().any(|n| n.contains('\0')), "null byte name should be filtered");
        assert_eq!(deps.len(), 2);
    }
}
