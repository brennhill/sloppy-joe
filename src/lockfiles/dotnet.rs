use crate::Dependency;
use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;

#[cfg(test)]
use super::add_manifest_exact_fallbacks;
use super::{
    ResolutionKey, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, ambiguous_issue, missing_entry_issue, out_of_sync_issue,
};

pub(super) fn resolve_from_value(
    parsed: &serde_json::Value,
    deps: &[Dependency],
) -> Result<ResolutionResult> {
    let packages = extract_packages(parsed);
    let mut versions_by_name: HashMap<String, Vec<String>> = HashMap::new();

    for (name, version) in packages {
        versions_by_name
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(version);
    }

    for versions in versions_by_name.values_mut() {
        versions.sort();
        versions.dedup();
    }

    let mut result = ResolutionResult::default();
    for dep in deps {
        let Some(versions) = versions_by_name.get(&dep.name.to_ascii_lowercase()) else {
            result
                .issues
                .push(missing_entry_issue(dep, "packages.lock.json"));
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

        let exact = dep
            .exact_version()
            .or_else(|| dep.version.clone())
            .filter(|version| versions.iter().any(|candidate| candidate == version));

        if let Some(version) = exact {
            result.exact_versions.insert(
                ResolutionKey::from(dep),
                ResolvedVersion {
                    version,
                    source: ResolutionSource::Lockfile,
                },
            );
        } else if dep.exact_version().is_some() {
            result
                .issues
                .push(out_of_sync_issue(dep, &versions.join(", ")));
            add_manifest_exact_fallback(&mut result, dep);
        } else {
            result.issues.push(ambiguous_issue(dep));
        }
    }

    Ok(result)
}

pub(super) fn parse_all_from_value(parsed: &serde_json::Value) -> Result<Vec<Dependency>> {
    Ok(extract_packages(parsed)
        .into_iter()
        .map(|(name, version)| Dependency {
            name,
            version: Some(version),
            ecosystem: crate::Ecosystem::Dotnet,
            actual_name: None,
        })
        .collect())
}

pub(super) fn read_lockfile(project_dir: &Path) -> Result<Option<serde_json::Value>> {
    let path = project_dir.join("packages.lock.json");
    if !crate::parsers::path_detected(&path)? {
        return Ok(None);
    }
    let content = crate::parsers::read_file_limited(&path, crate::parsers::MAX_MANIFEST_BYTES)?;
    let parsed = serde_json::from_str(&content)
        .map_err(|err| anyhow::anyhow!("Failed to parse {}: {}", path.display(), err))?;
    Ok(Some(parsed))
}

#[cfg(test)]
pub(super) fn resolve(project_dir: &Path, deps: &[Dependency]) -> Result<ResolutionResult> {
    let Some(parsed) = read_lockfile(project_dir)? else {
        let mut result = ResolutionResult::default();
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };
    resolve_from_value(&parsed, deps)
}

fn extract_packages(parsed: &serde_json::Value) -> Vec<(String, String)> {
    let Some(targets) = parsed
        .get("dependencies")
        .and_then(|value| value.as_object())
    else {
        return Vec::new();
    };

    let mut packages = Vec::new();
    for target in targets.values() {
        let Some(entries) = target.as_object() else {
            continue;
        };

        for (name, entry) in entries {
            if !crate::registry::validate_package_name(name) {
                continue;
            }
            let Some(resolved) = entry.get("resolved").and_then(|value| value.as_str()) else {
                continue;
            };
            packages.push((name.to_string(), resolved.to_string()));
        }
    }

    packages
}
