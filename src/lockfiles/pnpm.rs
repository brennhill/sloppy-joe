use crate::Dependency;
use anyhow::Result;
use std::collections::{HashSet, VecDeque};
use std::path::Path;

use super::{
    ResolutionKey, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, add_manifest_exact_fallbacks, missing_entry_issue,
    out_of_sync_issue, parse_failed_issue,
};

pub(super) fn resolve_from_value(
    parsed: &serde_yaml::Value,
    deps: &[Dependency],
    importer_key: &str,
) -> Result<ResolutionResult> {
    let Some(importers) = parsed.get("importers").and_then(|value| value.as_mapping()) else {
        let mut result = ResolutionResult::default();
        result.push_issue(parse_failed_issue(
            "pnpm-lock.yaml",
            "lockfile did not contain an importers section".to_string(),
        ));
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };
    let Some(importer) = importers.get(importer_key) else {
        let mut result = ResolutionResult::default();
        result.push_issue(parse_failed_issue(
            "pnpm-lock.yaml",
            format!("lockfile did not contain importer '{}'", importer_key),
        ));
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };

    let mut result = ResolutionResult::default();
    for dep in deps {
        let Some(reference) = importer_dependency_reference(importer, &dep.name) else {
            result.push_issue_for(dep, missing_entry_issue(dep, "pnpm-lock.yaml"));
            add_manifest_exact_fallback(&mut result, dep);
            continue;
        };
        let Some(version) = normalized_pnpm_reference(reference, dep.package_name()) else {
            result.push_issue_for(dep, missing_entry_issue(dep, "pnpm-lock.yaml"));
            add_manifest_exact_fallback(&mut result, dep);
            continue;
        };
        if let Some(exact_manifest) = dep.exact_version()
            && exact_manifest != version
        {
            result.push_issue_for(dep, out_of_sync_issue(dep, &version));
            add_manifest_exact_fallback(&mut result, dep);
            continue;
        }
        result.exact_versions.insert(
            ResolutionKey::from(dep),
            ResolvedVersion {
                version,
                source: ResolutionSource::Lockfile,
            },
        );
    }

    Ok(result)
}

pub(super) fn parse_all_from_value(parsed: &serde_yaml::Value) -> Result<Vec<Dependency>> {
    let Some(packages) = parsed.get("packages").and_then(|value| value.as_mapping()) else {
        return Ok(vec![]);
    };
    let mut deps = Vec::new();
    for (key, _value) in packages {
        let Some(key) = key.as_str() else {
            continue;
        };
        let Some((name, version)) = pnpm_package_key_parts(key) else {
            continue;
        };
        if !crate::registry::validate_package_name(name) {
            continue;
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
    parsed: &serde_yaml::Value,
    importer_key: &str,
) -> Result<Vec<Dependency>> {
    let Some(importer) = parsed
        .get("importers")
        .and_then(|value| value.get(importer_key))
    else {
        return Ok(vec![]);
    };

    let mut deps = Vec::new();
    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();

    for (name, reference) in importer_dependency_entries(importer) {
        let Some((package_name, version)) = normalized_pnpm_dependency(&name, &reference) else {
            continue;
        };
        queue.push_back((package_name, version));
    }

    while let Some((name, version)) = queue.pop_front() {
        if !seen.insert((name.clone(), version.clone())) {
            continue;
        }
        if crate::registry::validate_package_name(&name) {
            deps.push(Dependency {
                name: name.clone(),
                version: Some(version.clone()),
                ecosystem: crate::Ecosystem::Npm,
                actual_name: None,
            });
        }
        for (child_name, child_reference) in package_dependency_entries(parsed, &name, &version) {
            if let Some((child_package_name, child_version)) =
                normalized_pnpm_dependency(&child_name, &child_reference)
            {
                queue.push_back((child_package_name, child_version));
            }
        }
    }

    Ok(deps)
}

fn importer_dependency_reference<'a>(
    importer: &'a serde_yaml::Value,
    dep_name: &str,
) -> Option<&'a str> {
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let version = importer
            .get(section)
            .and_then(|value| value.get(dep_name))
            .and_then(|value| value.get("version"))
            .and_then(|value| value.as_str());
        if version.is_some() {
            return version;
        }
    }
    None
}

fn importer_dependency_entries(importer: &serde_yaml::Value) -> Vec<(String, String)> {
    dependency_entries_from_sections(importer)
}

fn package_dependency_entries(
    parsed: &serde_yaml::Value,
    package_name: &str,
    version: &str,
) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let sections = ["dependencies", "optionalDependencies", "peerDependencies"];

    if let Some(snapshots) = parsed.get("snapshots").and_then(|value| value.as_mapping()) {
        for (key, value) in snapshots {
            let Some(key) = key.as_str() else {
                continue;
            };
            if pnpm_package_key_parts(key) != Some((package_name, version)) {
                continue;
            }
            entries.extend(dependency_entries_from_sections_with_values(
                value, &sections,
            ));
        }
    }

    if let Some(packages) = parsed.get("packages").and_then(|value| value.as_mapping()) {
        for (key, value) in packages {
            let Some(key) = key.as_str() else {
                continue;
            };
            if pnpm_package_key_parts(key) != Some((package_name, version)) {
                continue;
            }
            entries.extend(dependency_entries_from_sections_with_values(
                value, &sections,
            ));
        }
    }

    entries
}

fn dependency_entries_from_sections(value: &serde_yaml::Value) -> Vec<(String, String)> {
    let sections = [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ];
    dependency_entries_from_sections_with_values(value, &sections)
}

fn dependency_entries_from_sections_with_values(
    value: &serde_yaml::Value,
    sections: &[&str],
) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    for section in sections {
        let Some(mapping) = value.get(*section).and_then(|section| section.as_mapping()) else {
            continue;
        };
        for (name, raw) in mapping {
            let Some(name) = name.as_str() else {
                continue;
            };
            if let Some(version) = raw
                .get("version")
                .and_then(|value| value.as_str())
                .or_else(|| raw.as_str())
            {
                entries.push((name.to_string(), version.to_string()));
            }
        }
    }
    entries
}

fn normalized_pnpm_reference(reference: &str, fallback_name: &str) -> Option<String> {
    let reference = reference.trim();
    if reference.is_empty()
        || reference.starts_with("link:")
        || reference.starts_with("file:")
        || reference.starts_with("workspace:")
    {
        return None;
    }
    let base = reference.split('(').next().unwrap_or(reference).trim();
    if let Some(alias_spec) = base.strip_prefix("npm:") {
        let (actual_name, version) = split_npm_package_and_spec(alias_spec)?;
        return (actual_name == fallback_name).then_some(version.to_string());
    }
    if let Some((name, version)) = pnpm_package_key_parts(base)
        && name == fallback_name
    {
        return Some(version.to_string());
    }
    Some(base.to_string())
}

fn normalized_pnpm_dependency(name: &str, reference: &str) -> Option<(String, String)> {
    let reference = reference.trim();
    if reference.is_empty()
        || reference.starts_with("link:")
        || reference.starts_with("file:")
        || reference.starts_with("workspace:")
    {
        return None;
    }
    let base = reference.split('(').next().unwrap_or(reference).trim();
    if let Some(alias_spec) = base.strip_prefix("npm:")
        && let Some((actual_name, version)) = split_npm_package_and_spec(alias_spec)
    {
        return Some((actual_name.to_string(), version.to_string()));
    }
    if let Some((package_name, version)) = pnpm_package_key_parts(base) {
        return Some((package_name.to_string(), version.to_string()));
    }
    Some((name.to_string(), base.to_string()))
}

pub(crate) fn validate_provenance(parsed: &serde_yaml::Value, lockfile_path: &Path) -> Result<()> {
    let Some(packages) = parsed.get("packages").and_then(|value| value.as_mapping()) else {
        return Ok(());
    };

    for (key, value) in packages {
        let Some(key) = key.as_str() else {
            anyhow::bail!(
                "Broken lockfile '{}': pnpm package keys must be strings.",
                lockfile_path.display()
            );
        };
        if key.starts_with("link:") || key.starts_with("file:") {
            continue;
        }
        let Some((package_name, version)) = pnpm_package_key_parts(key) else {
            anyhow::bail!(
                "Required lockfile '{}' contains unsupported pnpm package key '{}'.",
                lockfile_path.display(),
                crate::report::sanitize_for_terminal(key)
            );
        };
        let Some(resolution) = value.get("resolution").and_then(|value| value.as_mapping()) else {
            anyhow::bail!(
                "Required lockfile '{}' package '{}' is missing a resolution section.",
                lockfile_path.display(),
                key
            );
        };

        let integrity = resolution
            .get("integrity")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Required lockfile '{}' package '{}' is missing integrity metadata. sloppy-joe only trusts pnpm registry entries with explicit integrity hashes.",
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

        if let Some(tarball) = resolution
            .get("tarball")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            validate_pnpm_tarball_identity(package_name, version, tarball, lockfile_path)?;
        }
    }

    Ok(())
}

fn validate_pnpm_tarball_identity(
    package_name: &str,
    version: &str,
    tarball: &str,
    lockfile_path: &Path,
) -> Result<()> {
    let Some(path) = pnpm_tarball_path(tarball) else {
        anyhow::bail!(
            "Required lockfile '{}' package '{}' has untrusted tarball source '{}'. sloppy-joe only trusts npm registry tarball URLs in pnpm-lock.yaml.",
            lockfile_path.display(),
            package_name,
            crate::report::sanitize_for_terminal(tarball)
        );
    };

    if !expected_npm_registry_tarball_paths(package_name, version)
        .iter()
        .any(|expected| expected == path)
    {
        anyhow::bail!(
            "Required lockfile '{}' package '{}' resolves to '{}', which does not match the locked package identity '{}' at version '{}'.",
            lockfile_path.display(),
            package_name,
            crate::report::sanitize_for_terminal(tarball),
            package_name,
            version
        );
    }

    Ok(())
}

fn pnpm_tarball_path(tarball: &str) -> Option<&str> {
    let tarball = tarball.trim();
    let tarball = tarball
        .split_once('#')
        .map(|(path, _)| path)
        .unwrap_or(tarball);
    if let Some(without_scheme) = tarball.strip_prefix("https://") {
        let without_host = without_scheme
            .strip_prefix("registry.npmjs.org/")
            .or_else(|| without_scheme.strip_prefix("registry.yarnpkg.com/"))?;
        return Some(without_host);
    }
    tarball.strip_prefix('/')
}

fn expected_npm_registry_tarball_paths(package_name: &str, version: &str) -> Vec<String> {
    if let Some((scope, leaf)) = package_name.split_once('/')
        && let Some(scope_name) = scope.strip_prefix('@')
    {
        let filename = format!("{leaf}-{version}.tgz");
        return vec![
            format!("{package_name}/-/{filename}"),
            format!("%40{scope_name}%2F{leaf}/-/{filename}"),
            format!("%40{scope_name}%2f{leaf}/-/{filename}"),
        ];
    }

    vec![format!("{package_name}/-/{}-{version}.tgz", package_name)]
}

fn split_npm_package_and_spec(spec: &str) -> Option<(&str, &str)> {
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

fn pnpm_package_key_parts(key: &str) -> Option<(&str, &str)> {
    let base = key.split('(').next().unwrap_or(key).trim();
    if base.is_empty() || base.starts_with("link:") || base.starts_with("file:") {
        return None;
    }
    if let Some(stripped) = base.strip_prefix('@') {
        let slash = stripped.find('/')?;
        let after_scope = 1 + slash + 1;
        let version_at = base[after_scope..].rfind('@')?;
        let split = after_scope + version_at;
        let (name, version) = base.split_at(split);
        return Some((name, version.trim_start_matches('@')));
    }
    let split = base.rfind('@')?;
    let (name, version) = base.split_at(split);
    Some((name, version.trim_start_matches('@')))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_all_reads_scoped_and_unscoped_packages() {
        let parsed: serde_yaml::Value = serde_yaml::from_str(
            r#"
packages:
  react@18.3.1:
    resolution:
      integrity: sha512-react
  '@scope/pkg@1.2.3':
    resolution:
      integrity: sha512-scope
  react-dom@19.0.0(react@19.0.0):
    resolution:
      integrity: sha512-dom
"#,
        )
        .unwrap();
        let deps = parse_all_from_value(&parsed).unwrap();
        let names = deps.iter().map(|dep| dep.name.as_str()).collect::<Vec<_>>();
        assert!(names.contains(&"react"));
        assert!(names.contains(&"@scope/pkg"));
        assert!(names.contains(&"react-dom"));
    }
}
