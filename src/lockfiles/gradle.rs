use crate::Dependency;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[cfg(test)]
use super::add_manifest_exact_fallbacks;
use super::{
    ResolutionKey, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, ambiguous_issue, missing_entry_issue, out_of_sync_issue,
};

pub(super) fn resolve_from_content(content: &str, deps: &[Dependency]) -> Result<ResolutionResult> {
    let versions = parse_versions(content);
    let mut result = ResolutionResult::default();

    for dep in deps {
        let Some(candidates) = versions.get(&dep.name) else {
            result
                .issues
                .push(missing_entry_issue(dep, "gradle.lockfile"));
            add_manifest_exact_fallback(&mut result, dep);
            continue;
        };

        if candidates.len() == 1 {
            let version = &candidates[0];
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
            .filter(|version| candidates.iter().any(|candidate| candidate == version));

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
                .push(out_of_sync_issue(dep, &candidates.join(", ")));
            add_manifest_exact_fallback(&mut result, dep);
        } else {
            result.issues.push(ambiguous_issue(dep));
        }
    }

    Ok(result)
}

pub(super) fn parse_all_from_content(content: &str) -> Result<Vec<Dependency>> {
    Ok(parse_entries(content)
        .into_iter()
        .map(|(name, version)| Dependency {
            name,
            version: Some(version),
            ecosystem: crate::Ecosystem::Jvm,
            actual_name: None,
        })
        .collect())
}

pub(super) fn read_lockfile(project_dir: &Path) -> Result<Option<String>> {
    let path = project_dir.join("gradle.lockfile");
    if !crate::parsers::path_detected(&path)? {
        return Ok(None);
    }
    crate::parsers::read_file_limited(&path, crate::parsers::MAX_MANIFEST_BYTES).map(Some)
}

#[cfg(test)]
pub(super) fn resolve(project_dir: &Path, deps: &[Dependency]) -> Result<ResolutionResult> {
    let Some(content) = read_lockfile(project_dir)? else {
        let mut result = ResolutionResult::default();
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };
    resolve_from_content(&content, deps)
}

fn parse_versions(content: &str) -> HashMap<String, Vec<String>> {
    let mut versions: HashMap<String, HashSet<String>> = HashMap::new();

    for (name, version) in parse_entries(content) {
        versions.entry(name).or_default().insert(version);
    }

    versions
        .into_iter()
        .map(|(name, versions)| {
            let mut versions: Vec<String> = versions.into_iter().collect();
            versions.sort();
            (name, versions)
        })
        .collect()
}

fn parse_entries(content: &str) -> Vec<(String, String)> {
    let mut entries = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let coords = line.split_once('=').map(|(left, _)| left).unwrap_or(line);
        if coords == "empty" {
            continue;
        }

        let mut parts = coords.splitn(3, ':');
        let Some(group) = parts.next() else {
            continue;
        };
        let Some(artifact) = parts.next() else {
            continue;
        };
        let Some(version) = parts.next() else {
            continue;
        };

        let name = format!("{}:{}", group, artifact);
        if !crate::registry::validate_package_name(&name) {
            continue;
        }

        entries.push((name, version.to_string()));
    }

    entries
}
