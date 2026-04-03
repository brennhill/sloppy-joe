use crate::Dependency;
use anyhow::Result;
#[cfg(test)]
use std::path::Path;

#[cfg(test)]
use super::first_existing;
use super::{
    ResolutionKey, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, add_manifest_exact_fallbacks, missing_entry_issue,
    out_of_sync_issue, parse_failed_issue,
};

/// Read + parse + resolve in one step (used by resolve_versions test API).
#[cfg(test)]
pub(super) fn resolve(project_dir: &Path, deps: &[Dependency]) -> Result<ResolutionResult> {
    let Some(path) = first_existing(project_dir, &["npm-shrinkwrap.json", "package-lock.json"])
    else {
        let mut result = ResolutionResult::default();
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("npm-shrinkwrap.json")
        .to_string();
    let content = crate::parsers::read_file_limited(&path, crate::parsers::MAX_MANIFEST_BYTES)?;
    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(parsed) => parsed,
        Err(err) => {
            let mut result = ResolutionResult::default();
            result.push_issue(parse_failed_issue(&file_name, err.to_string()));
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
        result.push_issue(parse_failed_issue(
            file_name,
            "lockfile did not contain a supported packages or dependencies section".to_string(),
        ));
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    }

    let mut result = ResolutionResult::default();
    for dep in deps {
        let package_entry = packages.and_then(|packages| {
            packages
                .get(&format!("node_modules/{}", dep.name))
                .and_then(|entry| entry.as_object())
        });
        let dependency_entry = dependencies.and_then(|dependencies| {
            dependencies
                .get(&dep.name)
                .and_then(|entry| entry.as_object())
        });

        let resolved = if packages.is_some() {
            if !entry_matches_dependency(dep, package_entry) {
                result.push_issue_for(dep, missing_entry_issue(dep, file_name));
                add_manifest_exact_fallback(&mut result, dep);
                continue;
            }
            package_entry
                .and_then(|entry| entry.get("version"))
                .and_then(|value| value.as_str())
        } else {
            if !entry_matches_dependency(dep, dependency_entry) {
                result.push_issue_for(dep, missing_entry_issue(dep, file_name));
                add_manifest_exact_fallback(&mut result, dep);
                continue;
            }
            dependency_entry
                .and_then(|entry| entry.get("version"))
                .and_then(|value| value.as_str())
        };

        match resolved {
            Some(version) => {
                if let Some(exact_manifest) = dep.exact_version()
                    && exact_manifest != version
                {
                    result.push_issue_for(dep, out_of_sync_issue(dep, version));
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
                result.push_issue_for(dep, missing_entry_issue(dep, file_name));
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
    parse_dependencies_from_value(parsed, None)
}

pub(super) fn parse_transitive_from_value(
    parsed: &serde_json::Value,
    direct_deps: &[Dependency],
) -> Result<Vec<Dependency>> {
    let direct_root_paths = direct_deps
        .iter()
        .map(|dep| format!("node_modules/{}", dep.name))
        .collect::<std::collections::HashSet<_>>();
    parse_dependencies_from_value(parsed, Some(&direct_root_paths))
}

fn parse_dependencies_from_value(
    parsed: &serde_json::Value,
    direct_root_paths: Option<&std::collections::HashSet<String>>,
) -> Result<Vec<Dependency>> {
    let mut deps = Vec::new();
    if let Some(packages) = parsed.get("packages").and_then(|v| v.as_object()) {
        for (key, entry) in packages {
            if key.is_empty() {
                continue;
            }
            if !key.contains("node_modules/") {
                continue;
            }
            if direct_root_paths.is_some_and(|paths| paths.contains(key)) {
                continue;
            }
            if entry
                .get("link")
                .and_then(|value| value.as_bool())
                .unwrap_or(false)
            {
                continue;
            }
            let name = entry
                .get("name")
                .and_then(|value| value.as_str())
                .or_else(|| key.rsplit_once("node_modules/").map(|(_, name)| name))
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
                actual_name: None,
            });
        }
    } else if let Some(dependencies) = parsed.get("dependencies").and_then(|v| v.as_object()) {
        collect_v1_dependencies(dependencies, direct_root_paths, 0, &mut deps);
    } else {
        anyhow::bail!("npm lockfile has no packages or dependencies section");
    }

    Ok(deps)
}

fn collect_v1_dependencies(
    dependencies: &serde_json::Map<String, serde_json::Value>,
    direct_root_paths: Option<&std::collections::HashSet<String>>,
    depth: usize,
    deps: &mut Vec<Dependency>,
) {
    for (name, entry) in dependencies {
        let is_direct_root = depth == 0
            && direct_root_paths
                .is_some_and(|paths| paths.contains(&format!("node_modules/{name}")));
        if !is_direct_root {
            let version = entry
                .get("version")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            deps.push(Dependency {
                name: entry
                    .get("name")
                    .and_then(|value| value.as_str())
                    .unwrap_or(name)
                    .to_string(),
                version,
                ecosystem: crate::Ecosystem::Npm,
                actual_name: None,
            });
        }

        if let Some(nested) = entry
            .get("dependencies")
            .and_then(|value| value.as_object())
        {
            collect_v1_dependencies(nested, None, depth + 1, deps);
        }
    }
}

fn entry_matches_dependency(
    dep: &Dependency,
    entry: Option<&serde_json::Map<String, serde_json::Value>>,
) -> bool {
    let expected = dep.actual_name.as_deref().unwrap_or(dep.name.as_str());
    let Some(entry) = entry else {
        return true;
    };
    entry
        .get("name")
        .and_then(|value| value.as_str())
        .map(|actual| actual == expected)
        .unwrap_or(true)
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
        assert!(
            !names.iter().any(|n| n.contains("..")),
            "path traversal name should be filtered"
        );
        assert!(
            !names.iter().any(|n| n.contains('\0')),
            "null byte name should be filtered"
        );
        assert_eq!(deps.len(), 2);
    }
}
