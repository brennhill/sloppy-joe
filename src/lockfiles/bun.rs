use crate::Dependency;
use anyhow::Result;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

use super::{
    ResolutionKey, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, add_manifest_exact_fallbacks, missing_entry_issue,
    out_of_sync_issue, parse_failed_issue,
};

pub(super) fn resolve_from_value(
    parsed: &serde_json::Value,
    deps: &[Dependency],
    importer_key: &str,
) -> Result<ResolutionResult> {
    let Some(workspaces) = parsed.get("workspaces").and_then(|value| value.as_object()) else {
        let mut result = ResolutionResult::default();
        result.push_issue(parse_failed_issue(
            "bun.lock",
            "lockfile did not contain a workspaces section".to_string(),
        ));
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };
    let Some(importer) = workspaces.get(importer_key) else {
        let mut result = ResolutionResult::default();
        result.push_issue(parse_failed_issue(
            "bun.lock",
            format!("lockfile did not contain workspace '{}'", importer_key),
        ));
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };

    let Some(packages) = parsed.get("packages").and_then(|value| value.as_object()) else {
        let mut result = ResolutionResult::default();
        result.push_issue(parse_failed_issue(
            "bun.lock",
            "lockfile did not contain a packages section".to_string(),
        ));
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };

    let prefix = importer_scope(importer, importer_key);
    let mut result = ResolutionResult::default();
    for dep in deps {
        let Some(specifier) = importer_dependency_specifier(importer, &dep.name) else {
            result.push_issue_for(dep, missing_entry_issue(dep, "bun.lock"));
            add_manifest_exact_fallback(&mut result, dep);
            continue;
        };

        let resolved = match resolve_package_ref(
            packages,
            &prefix,
            &dep.name,
            dep.package_name(),
            specifier,
        ) {
            Some((_, version)) => version,
            None => {
                result.push_issue_for(
                    dep,
                    parse_failed_issue(
                        "bun.lock",
                        format!(
                            "lockfile could not prove the Bun package entry for '{}' with specifier '{}'",
                            dep.package_name(),
                            specifier
                        ),
                    ),
                );
                add_manifest_exact_fallback(&mut result, dep);
                continue;
            }
        };

        if let Some(exact_manifest) = dep.exact_version()
            && exact_manifest != resolved
        {
            result.push_issue_for(dep, out_of_sync_issue(dep, &resolved));
            add_manifest_exact_fallback(&mut result, dep);
            continue;
        }

        if expected_bun_specifier(dep)
            .as_deref()
            .is_some_and(|expected| expected != specifier)
        {
            result.push_issue_for(dep, out_of_sync_issue(dep, &resolved));
            add_manifest_exact_fallback(&mut result, dep);
            continue;
        }

        result.exact_versions.insert(
            ResolutionKey::from(dep),
            ResolvedVersion {
                version: resolved,
                source: ResolutionSource::Lockfile,
            },
        );
    }

    Ok(result)
}

pub(super) fn parse_all_from_value(parsed: &serde_json::Value) -> Result<Vec<Dependency>> {
    let Some(packages) = parsed.get("packages").and_then(|value| value.as_object()) else {
        return Ok(vec![]);
    };
    let mut deps = Vec::new();
    for value in packages.values() {
        let Some(descriptor) = bun_package_descriptor(value) else {
            continue;
        };
        let Some((name, version)) = bun_descriptor_parts(descriptor) else {
            continue;
        };
        if !crate::ecosystem::validate_package_name(name) {
            anyhow::bail!(
                "bun.lock package '{}' has an invalid package name.",
                crate::report::sanitize_for_terminal(name)
            );
        }
        deps.push(Dependency {
            name: name.to_string(),
            version: Some(version.to_string()),
            ecosystem: crate::Ecosystem::Npm,
            actual_name: None,
        });
    }
    Ok(deps)
}

pub(super) fn parse_all_from_value_for_importer(
    parsed: &serde_json::Value,
    importer_key: &str,
) -> Result<Vec<Dependency>> {
    let Some(workspaces) = parsed.get("workspaces").and_then(|value| value.as_object()) else {
        return Ok(vec![]);
    };
    let Some(importer) = workspaces.get(importer_key) else {
        return Ok(vec![]);
    };
    let Some(packages) = parsed.get("packages").and_then(|value| value.as_object()) else {
        return Ok(vec![]);
    };

    let mut keys = reachable_package_keys(
        packages,
        &importer_scope(importer, importer_key),
        importer_dependency_entries(importer),
    );

    // The root importer also owns any package entry no workspace reaches, so
    // an orphan entry can never sit in the lockfile unscanned. Without a root
    // workspace nobody owns them, so every importer scans them (fail closed).
    if importer_key.is_empty() || !workspaces.contains_key("") {
        let mut reachable_from_any = HashSet::new();
        for (workspace_key, workspace) in workspaces {
            reachable_from_any.extend(reachable_package_keys(
                packages,
                &importer_scope(workspace, workspace_key),
                importer_dependency_entries(workspace),
            ));
        }
        let orphan_roots = packages
            .keys()
            .filter(|key| !reachable_from_any.contains(*key))
            .cloned()
            .collect::<Vec<_>>();
        keys.extend(walk_package_keys(packages, orphan_roots));
    }

    let mut ordered = keys.into_iter().collect::<Vec<_>>();
    ordered.sort();
    let mut deps = Vec::new();
    for package_key in ordered {
        let Some(value) = packages.get(&package_key) else {
            continue;
        };
        let Some(descriptor) = bun_package_descriptor(value) else {
            continue;
        };
        let Some((name, version)) = bun_descriptor_parts(descriptor) else {
            continue;
        };
        if !crate::ecosystem::validate_package_name(name) {
            anyhow::bail!(
                "bun.lock package '{}' has an invalid package name '{}'.",
                crate::report::sanitize_for_terminal(&package_key),
                crate::report::sanitize_for_terminal(name)
            );
        }
        deps.push(Dependency {
            name: name.to_string(),
            version: Some(version.to_string()),
            ecosystem: crate::Ecosystem::Npm,
            actual_name: None,
        });
    }

    Ok(deps)
}

/// The nested scope an importer's own dependencies resolve from first: a
/// workspace member's entries are nested under its package name (`app/dep`),
/// the root's are top-level.
fn importer_scope(importer: &serde_json::Value, importer_key: &str) -> String {
    if importer_key.is_empty() {
        return String::new();
    }
    importer
        .get("name")
        .and_then(|value| value.as_str())
        .filter(|name| split_package_key(name).is_some_and(|segments| segments.len() == 1))
        .unwrap_or_default()
        .to_string()
}

/// Package keys reachable from an importer's declared dependency edges.
fn reachable_package_keys(
    packages: &serde_json::Map<String, serde_json::Value>,
    scope: &str,
    roots: Vec<(String, String)>,
) -> HashSet<String> {
    let start = roots
        .into_iter()
        .filter_map(|(dep_name, specifier)| {
            let target_name = bun_specifier_package_name(&dep_name, &specifier);
            resolve_package_ref(packages, scope, &dep_name, &target_name, &specifier)
                .map(|(key, _)| key)
        })
        .collect();
    walk_package_keys(packages, start)
}

/// Breadth-first closure over package dependency edges starting at `start`.
fn walk_package_keys(
    packages: &serde_json::Map<String, serde_json::Value>,
    start: Vec<String>,
) -> HashSet<String> {
    let mut seen_keys = HashSet::new();
    let mut queue = VecDeque::from(start);
    while let Some(package_key) = queue.pop_front() {
        if !seen_keys.insert(package_key.clone()) {
            continue;
        }
        let Some(value) = packages.get(&package_key) else {
            continue;
        };
        for (child_name, child_specifier) in bun_dependency_entries(value) {
            let target_name = bun_specifier_package_name(&child_name, &child_specifier);
            // A package's own dependencies resolve from its nested
            // node_modules first (`parent/child`), then up the tree.
            if let Some((child_key, _)) = resolve_package_ref(
                packages,
                &package_key,
                &child_name,
                &target_name,
                &child_specifier,
            ) {
                queue.push_back(child_key);
            }
        }
    }
    seen_keys
}

fn importer_dependency_specifier<'a>(
    importer: &'a serde_json::Value,
    dep_name: &str,
) -> Option<&'a str> {
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let specifier = importer
            .get(section)
            .and_then(|value| value.get(dep_name))
            .and_then(|value| value.as_str());
        if specifier.is_some() {
            return specifier;
        }
    }
    None
}

fn importer_dependency_entries(importer: &serde_json::Value) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let Some(values) = importer.get(section).and_then(|value| value.as_object()) else {
            continue;
        };
        for (name, value) in values {
            if let Some(specifier) = value.as_str() {
                entries.push((name.to_string(), specifier.to_string()));
            }
        }
    }
    entries
}

/// Every dependency edge a Bun package entry can install. Optional and peer
/// edges are installed by Bun just like regular ones, so they must be walked
/// (matching the pnpm and Yarn walkers).
pub(crate) fn bun_dependency_entries(value: &serde_json::Value) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let Some(meta) = value.as_array().and_then(|parts| parts.get(2)) else {
        return entries;
    };
    for section in ["dependencies", "optionalDependencies", "peerDependencies"] {
        let Some(deps) = meta.get(section).and_then(|deps| deps.as_object()) else {
            continue;
        };
        for (name, specifier) in deps {
            if let Some(specifier) = specifier.as_str() {
                entries.push((name.to_string(), specifier.to_string()));
            }
        }
    }
    entries
}

/// Split a `packages` key into its package-name segments (`a/@s/b` ->
/// `["a", "@s/b"]`). None for malformed keys (empty or dangling segments).
pub(crate) fn split_package_key(key: &str) -> Option<Vec<&str>> {
    let mut segments = Vec::new();
    let mut rest = key;
    while !rest.is_empty() {
        let end = if rest.starts_with('@') {
            let slash = rest.find('/')?;
            rest[slash + 1..]
                .find('/')
                .map(|next| slash + 1 + next)
                .unwrap_or(rest.len())
        } else {
            rest.find('/').unwrap_or(rest.len())
        };
        let segment = &rest[..end];
        if segment.is_empty() || segment.ends_with('/') || segment == "@" {
            return None;
        }
        if segment.starts_with('@') && segment.split('/').any(str::is_empty) {
            return None;
        }
        segments.push(segment);
        rest = &rest[end..];
        if let Some(stripped) = rest.strip_prefix('/') {
            if stripped.is_empty() {
                return None;
            }
            rest = stripped;
        }
    }
    (!segments.is_empty()).then_some(segments)
}

/// The key Bun installs `dep_name` from when required inside `scope`: the
/// nearest `scope/dep_name`, walking up the nested node_modules chain, then
/// the top-level `dep_name`.
fn nearest_package_key<'a>(
    packages: &'a serde_json::Map<String, serde_json::Value>,
    scope: &str,
    dep_name: &str,
) -> Option<&'a String> {
    let mut segments = split_package_key(scope).unwrap_or_default();
    loop {
        let candidate = if segments.is_empty() {
            dep_name.to_string()
        } else {
            format!("{}/{}", segments.join("/"), dep_name)
        };
        if let Some((key, _)) = packages.get_key_value(&candidate) {
            return Some(key);
        }
        segments.pop()?;
    }
}

fn resolve_package_ref(
    packages: &serde_json::Map<String, serde_json::Value>,
    scope: &str,
    manifest_key: &str,
    package_name: &str,
    specifier: &str,
) -> Option<(String, String)> {
    if let Some(key) = nearest_package_key(packages, scope, manifest_key)
        && let Some(descriptor) = bun_package_descriptor(&packages[key])
        && let Some((name, version)) = bun_descriptor_parts(descriptor)
        && name == package_name
    {
        return Some((key.clone(), version.to_string()));
    }

    if let Some(exact) = crate::version::exact_version(specifier, crate::Ecosystem::Npm) {
        let mut matches = packages
            .iter()
            .filter_map(|(key, value)| {
                let descriptor = bun_package_descriptor(value)?;
                let (name, version) = bun_descriptor_parts(descriptor)?;
                (name == package_name && version == exact)
                    .then_some((key.clone(), version.to_string()))
            })
            .collect::<Vec<_>>();
        if matches.len() == 1 {
            return matches.pop();
        }
    }

    let mut matches = packages
        .iter()
        .filter_map(|(key, value)| {
            let descriptor = bun_package_descriptor(value)?;
            let (name, version) = bun_descriptor_parts(descriptor)?;
            (name == package_name).then_some((key.clone(), version.to_string()))
        })
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        return matches.pop();
    }

    None
}

fn expected_bun_specifier(dep: &Dependency) -> Option<String> {
    let requested = dep.version.as_deref()?;
    if let Some(actual_name) = dep.actual_name.as_deref() {
        return Some(format!("npm:{actual_name}@{requested}"));
    }
    Some(requested.to_string())
}

pub(crate) fn validate_provenance(parsed: &serde_json::Value, lockfile_path: &Path) -> Result<()> {
    let allowed_alias_targets = bun_alias_targets(parsed);
    let Some(packages) = parsed.get("packages").and_then(|value| value.as_object()) else {
        return Ok(());
    };

    for (key, value) in packages {
        let Some(parts) = value.as_array() else {
            anyhow::bail!(
                "Broken lockfile '{}': Bun package '{}' was not an array.",
                lockfile_path.display(),
                key
            );
        };
        let Some(descriptor) = parts.first().and_then(|value| value.as_str()) else {
            anyhow::bail!(
                "Broken lockfile '{}': Bun package '{}' is missing its descriptor.",
                lockfile_path.display(),
                key
            );
        };
        if descriptor.contains("@workspace:")
            || descriptor.contains("@file:")
            || descriptor.contains("@link:")
        {
            continue;
        }

        let Some((package_name, _version)) = bun_descriptor_parts(descriptor) else {
            anyhow::bail!(
                "Required lockfile '{}' contains unsupported Bun package descriptor '{}'.",
                lockfile_path.display(),
                crate::report::sanitize_for_terminal(descriptor)
            );
        };
        // Nested keys (`parent/child`) install `child` inside `parent`'s
        // node_modules; the installed identity is the last segment.
        let Some(installed_name) = split_package_key(key).and_then(|segments| {
            segments
                .iter()
                .all(|segment| crate::ecosystem::validate_package_name(segment))
                .then(|| segments.last().copied())
                .flatten()
        }) else {
            anyhow::bail!(
                "Required lockfile '{}' has malformed Bun package key '{}'.",
                lockfile_path.display(),
                crate::report::sanitize_for_terminal(key)
            );
        };
        if installed_name != package_name
            && allowed_alias_targets
                .get(installed_name)
                .is_none_or(|actual| actual != package_name)
        {
            anyhow::bail!(
                "Required lockfile '{}' package '{}' claims to resolve '{}'. Bun package entries must match the installed package identity exactly or be explicitly referenced as npm aliases.",
                lockfile_path.display(),
                key,
                package_name
            );
        }

        // Slot 1 is the registry tarball location; empty means the default registry.
        let location = parts
            .get(1)
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Broken lockfile '{}': Bun package '{}' has no registry location.",
                    lockfile_path.display(),
                    key
                )
            })?;
        if !location.is_empty() && !location.starts_with("https://registry.npmjs.org/") {
            anyhow::bail!(
                "Required lockfile '{}' package '{}' resolves from '{}', which is not the public npm registry. sloppy-joe only trusts Bun entries resolved from registry.npmjs.org.",
                lockfile_path.display(),
                key,
                crate::report::sanitize_for_terminal(location)
            );
        }

        let integrity = parts
            .get(3)
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Required lockfile '{}' package '{}' is missing integrity metadata. sloppy-joe only trusts Bun registry entries with explicit integrity hashes.",
                    lockfile_path.display(),
                    key
                )
            })?;
        if !integrity.contains('-') {
            anyhow::bail!(
                "Required lockfile '{}' package '{}' has malformed integrity metadata '{}'.",
                lockfile_path.display(),
                key,
                crate::report::sanitize_for_terminal(integrity)
            );
        }
    }

    Ok(())
}

fn bun_alias_targets(parsed: &serde_json::Value) -> HashMap<String, String> {
    let mut aliases = HashMap::new();

    if let Some(workspaces) = parsed.get("workspaces").and_then(|value| value.as_object()) {
        for workspace in workspaces.values() {
            for (name, specifier) in importer_dependency_entries(workspace) {
                if let Some((actual, _)) =
                    split_npm_package_and_spec(specifier.strip_prefix("npm:").unwrap_or(""))
                {
                    aliases.insert(name, actual.to_string());
                }
            }
        }
    }

    if let Some(packages) = parsed.get("packages").and_then(|value| value.as_object()) {
        for package in packages.values() {
            for (name, specifier) in bun_dependency_entries(package) {
                if let Some((actual, _)) =
                    split_npm_package_and_spec(specifier.strip_prefix("npm:").unwrap_or(""))
                {
                    aliases.insert(name, actual.to_string());
                }
            }
        }
    }

    aliases
}

fn bun_specifier_package_name(manifest_name: &str, specifier: &str) -> String {
    if let Some(alias_spec) = specifier.strip_prefix("npm:")
        && let Some((actual_name, _)) = split_npm_package_and_spec(alias_spec)
    {
        return actual_name.to_string();
    }
    manifest_name.to_string()
}

fn split_npm_package_and_spec(spec: &str) -> Option<(&str, &str)> {
    if spec.is_empty() {
        return None;
    }
    if let Some(stripped) = spec.strip_prefix('@') {
        let slash = stripped.find('/')?;
        let after_scope = 1 + slash + 1;
        let version_at = spec[after_scope..].rfind('@')?;
        let split = after_scope + version_at;
        let (name, version) = spec.split_at(split);
        return Some((name, version.trim_start_matches('@')));
    }
    let split = spec.rfind('@')?;
    let (name, version) = spec.split_at(split);
    Some((name, version.trim_start_matches('@')))
}

/// A `packages` entry that Bun installs from the local filesystem rather than a
/// registry (`name@workspace:path`, `name@file:path`, `name@link:path`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct BunLocalPackage<'a> {
    pub(crate) key: &'a str,
    pub(crate) name: &'a str,
    pub(crate) protocol: &'static str,
    pub(crate) target: &'a str,
}

/// Every local (workspace:/file:/link:) package entry in a Bun lockfile,
/// regardless of whether the manifest declares it directly. Callers must prove
/// each target is a scanned local project.
pub(crate) fn local_package_entries(parsed: &serde_json::Value) -> Vec<BunLocalPackage<'_>> {
    let Some(packages) = parsed.get("packages").and_then(|value| value.as_object()) else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    for (key, value) in packages {
        let Some(descriptor) = bun_package_descriptor(value) else {
            continue;
        };
        let descriptor = descriptor.trim();
        // Mirror the `contains` checks that exempt these entries from registry
        // provenance: any marker anywhere makes the entry local. Prefer a
        // marker after a leading scope '@' so "@scope/name@file:x" keeps its
        // name; a marker only at position 0 yields an empty name, which the
        // caller rejects.
        let mut matches = ["workspace:", "file:", "link:"]
            .into_iter()
            .flat_map(|protocol| {
                let marker_len = protocol.len() + 1;
                descriptor
                    .match_indices(&format!("@{protocol}"))
                    .map(move |(pos, _)| (pos, protocol, marker_len))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        matches.sort_by_key(|(pos, _, _)| *pos);
        let found = matches
            .iter()
            .find(|(pos, _, _)| *pos > 0)
            .or_else(|| matches.first())
            .copied();
        let Some((pos, protocol, marker_len)) = found else {
            continue;
        };
        entries.push(BunLocalPackage {
            key: key.as_str(),
            name: &descriptor[..pos],
            protocol,
            target: &descriptor[pos + marker_len..],
        });
    }
    entries
}

fn bun_package_descriptor(value: &serde_json::Value) -> Option<&str> {
    value.as_array()?.first()?.as_str()
}

fn bun_descriptor_parts(descriptor: &str) -> Option<(&str, &str)> {
    let descriptor = descriptor.trim();
    if descriptor.is_empty()
        || descriptor.contains("@workspace:")
        || descriptor.contains("@file:")
        || descriptor.contains("@link:")
    {
        return None;
    }
    if let Some(stripped) = descriptor.strip_prefix('@') {
        let slash = stripped.find('/')?;
        let after_scope = 1 + slash + 1;
        let version_at = descriptor[after_scope..].rfind('@')?;
        let split = after_scope + version_at;
        let (name, version) = descriptor.split_at(split);
        return Some((name, version.trim_start_matches('@')));
    }
    let split = descriptor.rfind('@')?;
    let (name, version) = descriptor.split_at(split);
    Some((name, version.trim_start_matches('@')))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_all_reads_scoped_and_unscoped_packages() {
        let parsed: serde_json::Value = json5::from_str(
            r#"{
  "packages": {
    "react": ["react@18.3.1"],
    "@scope/pkg": ["@scope/pkg@1.2.3"],
    "web": ["web@workspace:apps/web"],
  },
}"#,
        )
        .unwrap();
        let deps = parse_all_from_value(&parsed).unwrap();
        let names = deps.iter().map(|dep| dep.name.as_str()).collect::<Vec<_>>();
        assert!(names.contains(&"react"));
        assert!(names.contains(&"@scope/pkg"));
        assert!(!names.contains(&"web"));
    }
}
