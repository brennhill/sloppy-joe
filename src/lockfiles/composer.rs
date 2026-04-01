use crate::Dependency;
use anyhow::Result;
use std::path::Path;

#[cfg(test)]
use super::add_manifest_exact_fallbacks;
use super::{
    ResolutionKey, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, missing_entry_issue, out_of_sync_issue,
};

pub(super) fn resolve_from_value(
    parsed: &serde_json::Value,
    deps: &[Dependency],
) -> Result<ResolutionResult> {
    let packages = extract_packages(parsed);
    let mut result = ResolutionResult::default();

    for dep in deps {
        match packages.iter().find(|(name, _)| name == &dep.name) {
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
                result
                    .issues
                    .push(missing_entry_issue(dep, "composer.lock"));
                add_manifest_exact_fallback(&mut result, dep);
            }
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
            ecosystem: crate::Ecosystem::Php,
        })
        .collect())
}

pub(super) fn read_lockfile(project_dir: &Path) -> Option<serde_json::Value> {
    let path = project_dir.join("composer.lock");
    if !crate::parsers::path_detected(&path).ok()? {
        return None;
    }
    let content =
        crate::parsers::read_file_limited(&path, crate::parsers::MAX_MANIFEST_BYTES).ok()?;
    serde_json::from_str(&content).ok()
}

#[cfg(test)]
pub(super) fn resolve(project_dir: &Path, deps: &[Dependency]) -> Result<ResolutionResult> {
    let Some(parsed) = read_lockfile(project_dir) else {
        let mut result = ResolutionResult::default();
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };
    resolve_from_value(&parsed, deps)
}

fn extract_packages(parsed: &serde_json::Value) -> Vec<(String, String)> {
    let mut packages = Vec::new();

    for section in ["packages", "packages-dev"] {
        let Some(entries) = parsed.get(section).and_then(|value| value.as_array()) else {
            continue;
        };

        for entry in entries {
            let Some(name) = entry.get("name").and_then(|value| value.as_str()) else {
                continue;
            };
            if !crate::registry::validate_package_name(name) {
                continue;
            }
            let Some(version) = entry.get("version").and_then(|value| value.as_str()) else {
                continue;
            };
            packages.push((name.to_string(), version.to_string()));
        }
    }

    packages
}
