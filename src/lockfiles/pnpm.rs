use crate::Dependency;
use anyhow::Result;
use std::collections::{HashSet, VecDeque};
use std::path::Path;

use super::{
    ResolutionKey, ResolutionMode, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, add_manifest_exact_fallbacks, missing_entry_issue,
    out_of_sync_issue, parse_failed_issue,
};

pub(super) fn resolve_from_value(
    parsed: &serde_yaml::Value,
    deps: &[Dependency],
    importer_key: &str,
    mode: ResolutionMode,
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
    // Transitives are not importer entries; they are proven by the lockfile
    // recording exactly that name@version.
    let locked = match mode {
        ResolutionMode::Transitive => {
            let mut locked = locked_package_identities(parsed)?.0;
            locked.extend(env_package_identities(parsed));
            locked
        }
        ResolutionMode::Direct => HashSet::new(),
    };
    for dep in deps {
        if let Some(version) = dep.version.as_deref()
            && locked.contains(&(dep.name.clone(), version.to_string()))
        {
            result.exact_versions.insert(
                ResolutionKey::from(dep),
                ResolvedVersion {
                    version: version.to_string(),
                    source: ResolutionSource::Lockfile,
                },
            );
            continue;
        }
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
    let mut deps = dependencies_for(env_package_identities(parsed));
    let Some(packages) = parsed.get("packages").and_then(|value| value.as_mapping()) else {
        return Ok(deps);
    };
    for (key, _value) in packages {
        let Some(key) = key.as_str() else {
            continue;
        };
        let Some((name, version)) = pnpm_package_key_parts(key) else {
            continue;
        };
        if !crate::ecosystem::validate_package_name(name) {
            anyhow::bail!(
                "pnpm-lock.yaml package '{}' has an invalid package name '{}'.",
                crate::report::sanitize_for_terminal(key),
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

#[cfg(test)]
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
    let walk = walk_from_importers(parsed, [importer])?;
    Ok(dependencies_for(walk.reachable))
}

/// Dependencies to scan for one importer, plus lockfile-level issues.
///
/// The importer scans what its own dependencies reach. Entries no importer
/// reaches are owned by the root importer (`.`), or by every importer when
/// the lockfile has no root importer. For a standalone lockfile (one importer)
/// whose graph resolves completely they are stale and never installed, so
/// they are flagged instead of scanned; otherwise they are scanned (fail
/// closed) so a walker gap can never hide an installed package.
pub(crate) fn parse_for_importer_with_orphans(
    parsed: &serde_yaml::Value,
    importer_key: &str,
    lockfile_path: &Path,
) -> Result<(Vec<Dependency>, Vec<crate::report::Issue>)> {
    let Some(importers) = parsed.get("importers").and_then(|value| value.as_mapping()) else {
        return Ok((vec![], vec![]));
    };
    let Some(importer) = parsed
        .get("importers")
        .and_then(|value| value.get(importer_key))
    else {
        return Ok((vec![], vec![]));
    };
    let own = walk_from_importers(parsed, [importer])?;
    let owns_orphans = importer_key == "."
        || parsed
            .get("importers")
            .and_then(|value| value.get("."))
            .is_none();
    if !owns_orphans {
        return Ok((dependencies_for(own.reachable), vec![]));
    }

    let global = walk_from_importers(parsed, importers.values())?;
    let (entries, unattributable) = locked_package_identities(parsed)?;
    let orphans = entries
        .into_iter()
        .filter(|identity| !global.reachable.contains(identity))
        .collect::<HashSet<_>>();
    // Only a standalone root importer can prove an entry is never installed.
    let certain = importer_key == "."
        && importers.len() == 1
        && !own.unresolved_edge
        && !global.unresolved_edge
        && !unattributable;

    let mut scan = own.reachable;
    // pnpm's own locked packages (earlier lockfile documents) are installed for
    // the whole workspace, so the root owns them.
    scan.extend(env_package_identities(parsed));
    let mut issues = Vec::new();
    if !orphans.is_empty() {
        if certain {
            issues.push(super::stale_orphan_entries_issue(
                lockfile_path,
                orphans
                    .iter()
                    .map(|(name, version)| format!("{name}@{version}"))
                    .collect(),
                "pnpm",
                "Run `pnpm install` to prune the stale entries from pnpm-lock.yaml, then commit the result.",
            ));
        } else {
            scan.extend(orphans);
        }
    }
    Ok((dependencies_for(scan), issues))
}

/// Packages of pnpm's own lockfile documents, carried by
/// [`super::PNPM_ENV_PACKAGES_KEY`] (already validated as registry packages).
fn env_package_identities(parsed: &serde_yaml::Value) -> HashSet<(String, String)> {
    parsed
        .get(super::PNPM_ENV_PACKAGES_KEY)
        .and_then(|value| value.as_sequence())
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.as_str())
        .filter_map(pnpm_package_key_parts)
        .map(|(name, version)| (name.to_string(), version.to_string()))
        .collect()
}

struct PnpmWalk {
    reachable: HashSet<(String, String)>,
    /// A dependency edge pointed at a package the lockfile does not record.
    unresolved_edge: bool,
}

fn walk_from_importers<'a>(
    parsed: &serde_yaml::Value,
    importers: impl IntoIterator<Item = &'a serde_yaml::Value>,
) -> Result<PnpmWalk> {
    let (known, _) = locked_package_identities(parsed)?;
    let mut queue = VecDeque::new();
    for importer in importers {
        for (name, reference) in importer_dependency_entries(importer) {
            if let Some(dependency) = normalized_pnpm_dependency(&name, &reference) {
                queue.push_back(dependency);
            }
        }
    }

    let mut reachable = HashSet::new();
    let mut unresolved_edge = false;
    while let Some((name, version)) = queue.pop_front() {
        if reachable.contains(&(name.clone(), version.clone())) {
            continue;
        }
        if !crate::ecosystem::validate_package_name(&name) {
            anyhow::bail!(
                "pnpm-lock.yaml dependency '{}@{}' has an invalid package name.",
                crate::report::sanitize_for_terminal(&name),
                crate::report::sanitize_for_terminal(&version)
            );
        }
        if !known.contains(&(name.clone(), version.clone())) {
            unresolved_edge = true;
        }
        for (child_name, child_reference) in package_dependency_entries(parsed, &name, &version) {
            if let Some(child) = normalized_pnpm_dependency(&child_name, &child_reference) {
                queue.push_back(child);
            }
        }
        reachable.insert((name, version));
    }
    Ok(PnpmWalk {
        reachable,
        unresolved_edge,
    })
}

/// Every (name, version) recorded under `packages` or `snapshots`, and whether
/// any key could not be attributed to a package. Invalid names block.
fn locked_package_identities(
    parsed: &serde_yaml::Value,
) -> Result<(HashSet<(String, String)>, bool)> {
    let mut identities = HashSet::new();
    let mut unattributable = false;
    for section in ["packages", "snapshots"] {
        let Some(entries) = parsed.get(section).and_then(|value| value.as_mapping()) else {
            continue;
        };
        for key in entries.keys() {
            let Some((name, version)) = key.as_str().and_then(pnpm_package_key_parts) else {
                unattributable = true;
                continue;
            };
            if !crate::ecosystem::validate_package_name(name) {
                anyhow::bail!(
                    "pnpm-lock.yaml package '{}' has an invalid package name '{}'.",
                    crate::report::sanitize_for_terminal(key.as_str().unwrap_or_default()),
                    crate::report::sanitize_for_terminal(name)
                );
            }
            identities.insert((name.to_string(), version.to_string()));
        }
    }
    Ok((identities, unattributable))
}

fn dependencies_for(identities: HashSet<(String, String)>) -> Vec<Dependency> {
    // Local `file:` / `link:` packages are repository source, not registry packages.
    let mut ordered = identities
        .into_iter()
        .filter(|(_, version)| !version.starts_with("file:") && !version.starts_with("link:"))
        .collect::<Vec<_>>();
    ordered.sort();
    ordered
        .into_iter()
        .map(|(name, version)| Dependency {
            name,
            version: Some(version),
            ecosystem: crate::Ecosystem::Npm,
            actual_name: None,
        })
        .collect()
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
    if let Some((name, version)) = pnpm_package_key_parts(base) {
        // pnpm installs whatever package the importer names under the declared name; a
        // different package is an alias written only in the lockfile and cannot be verified.
        return (name == fallback_name).then_some(version.to_string());
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

/// pnpm reads the lockfile with js-yaml, which expands `<<` merge keys; serde_yaml does not,
/// so a merged dependency edge would be invisible here. pnpm never writes `<<`.
fn reject_yaml_merge_keys(value: &serde_yaml::Value, lockfile_path: &Path) -> Result<()> {
    match value {
        serde_yaml::Value::Mapping(mapping) => {
            for (key, inner) in mapping {
                if key.as_str() == Some("<<") {
                    anyhow::bail!(
                        "Broken lockfile '{}': YAML merge keys ('<<') are not supported. pnpm expands them but sloppy-joe would not see the merged entries. Fix: regenerate the lockfile with pnpm install.",
                        lockfile_path.display()
                    );
                }
                reject_yaml_merge_keys(inner, lockfile_path)?;
            }
            Ok(())
        }
        serde_yaml::Value::Sequence(items) => items
            .iter()
            .try_for_each(|item| reject_yaml_merge_keys(item, lockfile_path)),
        _ => Ok(()),
    }
}

pub(crate) fn validate_provenance(
    parsed: &serde_yaml::Value,
    lockfile_path: &Path,
    registries: &crate::npm_config::NpmRegistries,
) -> Result<()> {
    reject_yaml_merge_keys(parsed, lockfile_path)?;
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

        // An in-repo directory package (`name@file:dir`, `type: directory`) is
        // source in this repository, not a registry artifact: it has no
        // integrity hash and is scanned as the project it is.
        if let Some(directory) = local_directory_resolution(resolution) {
            let key_matches = version.strip_prefix("file:") == Some(directory);
            if !key_matches {
                anyhow::bail!(
                    "Required lockfile '{}' package '{}' is a local directory package whose path '{}' does not match its lockfile key.",
                    lockfile_path.display(),
                    key,
                    crate::report::sanitize_for_terminal(directory)
                );
            }
            continue;
        }

        // pnpm fetches a `type: git`, `binary`, `variations` or escaping `directory` resolution
        // from wherever it points, whatever integrity string rides along; only a plain
        // registry tarball (integrity, optional tarball) is modeled.
        if let Some(extra) = resolution
            .keys()
            .filter_map(|key| key.as_str())
            .find(|key| !matches!(*key, "integrity" | "tarball"))
        {
            anyhow::bail!(
                "Required lockfile '{}' package '{}' has an unsupported resolution field '{}' (a git, binary, variations or out-of-repo directory source); sloppy-joe only trusts registry tarball resolutions.",
                lockfile_path.display(),
                key,
                crate::report::sanitize_for_terminal(extra)
            );
        }

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
            && !registries.matches_private_source(package_name, tarball)
        {
            validate_pnpm_tarball_identity(package_name, version, tarball, lockfile_path)?;
        }
    }

    Ok(())
}

/// `{directory: <relative path>, type: directory}` with a path that stays
/// inside the repository.
fn local_directory_resolution(resolution: &serde_yaml::Mapping) -> Option<&str> {
    if resolution.get("type").and_then(|value| value.as_str()) != Some("directory") {
        return None;
    }
    let directory = resolution
        .get("directory")
        .and_then(|value| value.as_str())?;
    let escapes = directory.starts_with('/')
        || directory.contains('\\')
        || directory.split('/').any(|part| part == "..");
    (!directory.is_empty() && !escapes).then_some(directory)
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
            crate::config::redact_url_for_display(tarball)
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
            crate::config::redact_url_for_display(tarball),
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

pub(super) fn pnpm_package_key_parts(key: &str) -> Option<(&str, &str)> {
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

#[cfg(test)]
mod alias_tests {
    use super::*;

    #[test]
    fn an_importer_reference_naming_another_package_is_not_the_declared_one() {
        assert_eq!(
            normalized_pnpm_reference("7.0.0", "is-number"),
            Some("7.0.0".to_string())
        );
        assert_eq!(
            normalized_pnpm_reference("is-number@7.0.0", "is-number"),
            Some("7.0.0".to_string())
        );
        assert_eq!(normalized_pnpm_reference("ms@2.1.3", "is-number"), None);
        assert_eq!(normalized_pnpm_reference("npm:ms@2.1.3", "is-number"), None);
        assert_eq!(
            normalized_pnpm_reference("@scope/x@1.0.0", "@scope/y"),
            None
        );
    }
}

#[cfg(test)]
mod resolution_kind_tests {
    use super::*;

    fn check(resolution: &str) -> Result<()> {
        let lock = format!(
            "lockfileVersion: '9.0'\npackages:\n  left-pad@1.3.0:\n    resolution: {resolution}\n"
        );
        let parsed: serde_yaml::Value = serde_yaml::from_str(&lock).unwrap();
        validate_provenance(
            &parsed,
            Path::new("pnpm-lock.yaml"),
            &crate::npm_config::NpmRegistries::default(),
        )
    }

    #[test]
    fn git_binary_and_escaping_directory_resolutions_block_even_with_integrity() {
        for resolution in [
            "{integrity: sha512-AAAA, type: git, repo: 'https://evil.example/x.git', commit: abc}",
            "{integrity: sha512-AAAA, type: binary, url: 'https://evil.example/x.tgz'}",
            "{integrity: sha512-AAAA, type: variations, variants: []}",
            "{integrity: sha512-AAAA, type: directory, directory: ../../outside}",
        ] {
            assert!(check(resolution).is_err(), "{resolution}");
        }
        assert!(check("{integrity: sha512-AAAA}").is_ok());
    }
}
