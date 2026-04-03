use crate::Dependency;
use anyhow::Result;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use super::{
    ResolutionKey, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, missing_entry_issue, out_of_sync_issue, parse_failed_issue,
};

#[derive(Debug, Clone)]
pub(crate) struct ParsedYarnLock {
    pub(crate) path: PathBuf,
    entries: Vec<YarnLockEntry>,
    by_selector: HashMap<String, usize>,
}

#[derive(Debug, Clone)]
pub(crate) struct YarnLockEntry {
    pub(crate) selectors: Vec<String>,
    pub(crate) version: Option<String>,
    pub(crate) resolved: Option<String>,
    pub(crate) resolution: Option<String>,
    pub(crate) checksum: Option<String>,
    pub(crate) integrity: Option<String>,
    pub(crate) link_type: Option<String>,
    pub(crate) sections: HashMap<String, BTreeMap<String, String>>,
}

pub(crate) fn parse_lockfile(
    content: &str,
    path: PathBuf,
    _project_dir: &Path,
) -> Result<ParsedYarnLock> {
    let mut entries = Vec::new();
    let mut by_selector = HashMap::new();
    let lines = content.lines().collect::<Vec<_>>();
    let mut index = 0usize;

    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            index += 1;
            continue;
        }
        if line.starts_with(' ') {
            anyhow::bail!(
                "Broken lockfile '{}': unexpected indentation before entry header on line {}.",
                path.display(),
                index + 1
            );
        }
        let Some(header) = trimmed.strip_suffix(':') else {
            anyhow::bail!(
                "Broken lockfile '{}': expected an entry header ending with ':' on line {}.",
                path.display(),
                index + 1
            );
        };
        let selectors = split_selectors(header);
        if selectors.is_empty() {
            anyhow::bail!(
                "Broken lockfile '{}': entry on line {} did not contain any selectors.",
                path.display(),
                index + 1
            );
        }

        index += 1;
        let mut version = None;
        let mut resolved = None;
        let mut resolution = None;
        let mut checksum = None;
        let mut integrity = None;
        let mut link_type = None;
        let mut sections = HashMap::new();

        while index < lines.len() {
            let line = lines[index];
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                index += 1;
                continue;
            }
            if !line.starts_with("  ") {
                break;
            }
            let body = &line[2..];
            if let Some(section_name) = body.trim_end().strip_suffix(':') {
                index += 1;
                let mut section = BTreeMap::new();
                while index < lines.len() {
                    let line = lines[index];
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        index += 1;
                        continue;
                    }
                    if !line.starts_with("    ") {
                        break;
                    }
                    let (name, value) = parse_property_line(&line[4..]).ok_or_else(|| {
                        anyhow::anyhow!(
                            "Broken lockfile '{}': invalid nested property on line {}.",
                            path.display(),
                            index + 1
                        )
                    })?;
                    section.insert(name, normalize_yarn_value(&value));
                    index += 1;
                }
                sections.insert(section_name.trim().to_string(), section);
                continue;
            }

            let (key, value) = parse_property_line(body).ok_or_else(|| {
                anyhow::anyhow!(
                    "Broken lockfile '{}': invalid property on line {}.",
                    path.display(),
                    index + 1
                )
            })?;
            let value = normalize_yarn_value(&value);
            match key.as_str() {
                "version" => version = Some(value),
                "resolved" => resolved = Some(value),
                "resolution" => resolution = Some(value),
                "checksum" => checksum = Some(value),
                "integrity" => integrity = Some(value),
                "linkType" => link_type = Some(value),
                _ => {}
            }
            index += 1;
        }

        let entry = YarnLockEntry {
            selectors: selectors.clone(),
            version,
            resolved,
            resolution,
            checksum,
            integrity,
            link_type,
            sections,
        };
        let entry_index = entries.len();
        for selector in selectors {
            by_selector.insert(selector, entry_index);
        }
        entries.push(entry);
    }

    Ok(ParsedYarnLock {
        path,
        entries,
        by_selector,
    })
}

pub(super) fn resolve_from_parsed(
    parsed: &ParsedYarnLock,
    deps: &[Dependency],
) -> Result<ResolutionResult> {
    let mut result = ResolutionResult::default();

    for dep in deps {
        let Some(entry) = parsed.entry_for_dependency(dep) else {
            result.push_issue_for(dep, missing_entry_issue(dep, "yarn.lock"));
            add_manifest_exact_fallback(&mut result, dep);
            continue;
        };
        let Some(version) = &entry.version else {
            result.push_issue_for(
                dep,
                parse_failed_issue(
                    "yarn.lock",
                    format!(
                        "entry '{}' is missing its resolved version",
                        entry
                            .selectors
                            .first()
                            .cloned()
                            .unwrap_or_else(|| "<unknown>".to_string())
                    ),
                ),
            );
            add_manifest_exact_fallback(&mut result, dep);
            continue;
        };
        if let Some(exact_manifest) = dep.exact_version()
            && exact_manifest != *version
        {
            result.push_issue_for(dep, out_of_sync_issue(dep, version));
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

    Ok(result)
}

pub(super) fn parse_all_from_parsed(parsed: &ParsedYarnLock) -> Result<Vec<Dependency>> {
    let mut deps = Vec::new();
    for entry in &parsed.entries {
        let Some(version) = &entry.version else {
            continue;
        };
        let Some((name, source)) = entry
            .selectors
            .iter()
            .find_map(|selector| selector_package_name_and_source(selector))
        else {
            continue;
        };
        if source != "registry" || !crate::registry::validate_package_name(name) {
            continue;
        }
        deps.push(Dependency {
            name: name.to_string(),
            version: Some(version.clone()),
            ecosystem: crate::Ecosystem::Npm,
            actual_name: None,
        });
    }
    Ok(deps)
}

pub(super) fn parse_all_from_parsed_for_project(
    parsed: &ParsedYarnLock,
    direct_deps: &[Dependency],
) -> Result<Vec<Dependency>> {
    let mut deps = Vec::new();
    let mut seen_entries = HashSet::new();
    let mut seen_packages = HashSet::new();
    let mut queue = VecDeque::new();

    for dep in direct_deps {
        if let Some(index) = parsed.entry_index_for_dependency(dep) {
            queue.push_back(index);
        }
    }

    while let Some(index) = queue.pop_front() {
        if !seen_entries.insert(index) {
            continue;
        }
        let Some(entry) = parsed.entries.get(index) else {
            continue;
        };
        let Some(version) = &entry.version else {
            continue;
        };
        let Some((name, source)) = entry
            .selectors
            .iter()
            .find_map(|selector| selector_package_name_and_source(selector))
        else {
            continue;
        };
        if source == "registry"
            && crate::registry::validate_package_name(name)
            && seen_packages.insert((name.to_string(), version.clone()))
        {
            deps.push(Dependency {
                name: name.to_string(),
                version: Some(version.clone()),
                ecosystem: crate::Ecosystem::Npm,
                actual_name: None,
            });
        }

        for section in ["dependencies", "optionalDependencies", "peerDependencies"] {
            let Some(entries) = entry.sections.get(section) else {
                continue;
            };
            for (dep_name, specifier) in entries {
                for selector in manifest_selectors(dep_name, specifier) {
                    if let Some(next) = parsed.by_selector.get(&selector) {
                        queue.push_back(*next);
                        break;
                    }
                }
            }
        }
    }

    Ok(deps)
}

pub(crate) fn validate_manifest_consistency(
    parsed: &ParsedYarnLock,
    manifest: &serde_json::Value,
    package_entry_key: &str,
    project_name: &str,
) -> Result<()> {
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let manifest_entries = manifest
            .get(section)
            .and_then(|value| value.as_object())
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|(name, value)| {
                        value.as_str().map(|spec| (name.clone(), spec.to_string()))
                    })
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();

        if let Some(workspace_entry) = parsed.workspace_entry(project_name, package_entry_key) {
            let lock_entries = workspace_entry
                .sections
                .get(section)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|(name, value)| {
                    let normalized = if manifest_entries
                        .get(&name)
                        .is_some_and(|requested| requested.starts_with("npm:"))
                    {
                        value
                    } else {
                        value.trim_start_matches("npm:").to_string()
                    };
                    (name, normalized)
                })
                .collect::<BTreeMap<_, _>>();
            if manifest_entries != lock_entries {
                anyhow::bail!(
                    "Required lockfile '{}' is out of sync with package.json: workspace '{}' does not match its '{}' declarations. Regenerate yarn.lock so it matches the manifest exactly.",
                    parsed.path.display(),
                    if package_entry_key.is_empty() {
                        "<root>"
                    } else {
                        package_entry_key
                    },
                    section
                );
            }
        }

        for (name, requested) in manifest_entries {
            if requested.starts_with("workspace:")
                || requested.starts_with("file:")
                || requested.starts_with("link:")
            {
                continue;
            }
            if !manifest_selectors(&name, &requested)
                .into_iter()
                .any(|selector| parsed.by_selector.contains_key(&selector))
            {
                anyhow::bail!(
                    "Required lockfile '{}' is out of sync with package.json: '{}'@'{}' is missing from yarn.lock.",
                    parsed.path.display(),
                    name,
                    requested
                );
            }
        }
    }

    Ok(())
}

pub(crate) fn validate_provenance(parsed: &ParsedYarnLock) -> Result<()> {
    for entry in &parsed.entries {
        let Some((name, source)) = entry
            .selectors
            .iter()
            .find_map(|selector| selector_package_name_and_source(selector))
        else {
            continue;
        };
        match source {
            "workspace" => {
                if entry.link_type.as_deref() == Some("hard") {
                    anyhow::bail!(
                        "Required lockfile '{}' entry '{}' claims to be a workspace dependency, but linkType was hard instead of soft.",
                        parsed.path.display(),
                        entry.selectors.join(", ")
                    );
                }
            }
            "registry" => {
                let Some(version) = entry.version.as_deref() else {
                    anyhow::bail!(
                        "Required lockfile '{}' entry '{}' is missing its resolved version.",
                        parsed.path.display(),
                        entry.selectors.join(", ")
                    );
                };
                if let Some(resolution) = &entry.resolution {
                    let checksum = entry
                        .checksum
                        .as_deref()
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "Required lockfile '{}' entry '{}' is missing checksum metadata. sloppy-joe only trusts Yarn Berry registry entries with explicit artifact checksums.",
                                parsed.path.display(),
                                entry.selectors.join(", ")
                            )
                        })?;
                    validate_yarn_berry_resolution_identity(
                        name,
                        version,
                        resolution,
                        parsed.path.as_path(),
                    )?;
                    if !checksum.contains('/') {
                        anyhow::bail!(
                            "Required lockfile '{}' entry '{}' has malformed checksum metadata '{}'.",
                            parsed.path.display(),
                            entry.selectors.join(", "),
                            crate::report::sanitize_for_terminal(checksum)
                        );
                    }
                } else if let Some(resolved) = &entry.resolved {
                    let Some(integrity) = &entry.integrity else {
                        anyhow::bail!(
                            "Required lockfile '{}' entry '{}' is missing integrity metadata. sloppy-joe only trusts Yarn classic registry entries with explicit tarball provenance.",
                            parsed.path.display(),
                            entry.selectors.join(", ")
                        );
                    };
                    validate_yarn_classic_resolved_identity(
                        name,
                        version,
                        resolved,
                        integrity,
                        parsed.path.as_path(),
                    )?;
                } else {
                    anyhow::bail!(
                        "Required lockfile '{}' entry '{}' is missing explicit provenance metadata.",
                        parsed.path.display(),
                        entry.selectors.join(", ")
                    );
                }
            }
            protocol => {
                anyhow::bail!(
                    "Required lockfile '{}' contains unsupported Yarn dependency source '{}' in entry '{}'.",
                    parsed.path.display(),
                    protocol,
                    entry.selectors.join(", ")
                );
            }
        }
    }

    Ok(())
}

pub(crate) fn validate_workspace_target(
    parsed: &ParsedYarnLock,
    dep_name: &str,
    relative_target: &str,
) -> Result<()> {
    let selector = format!("{dep_name}@workspace:{relative_target}");
    if parsed.by_selector.contains_key(&selector) {
        return Ok(());
    }
    anyhow::bail!(
        "Required lockfile '{}' is out of sync with package.json: local Yarn workspace dependency '{}' is missing selector '{}'.",
        parsed.path.display(),
        dep_name,
        selector
    );
}

fn split_selectors(header: &str) -> Vec<String> {
    let header = header.trim().trim_matches('"').trim_matches('\'');
    header
        .split(',')
        .map(|selector| selector.trim().trim_matches('"').trim_matches('\''))
        .filter(|selector| !selector.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_property_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    let whitespace = line.find(char::is_whitespace);
    let colon = line.find(':');
    match (colon, whitespace) {
        (Some(colon), Some(whitespace)) if colon < whitespace => {
            let (key, value) = line.split_at(colon);
            Some((
                key.trim().trim_matches('"').trim_matches('\'').to_string(),
                value[1..].trim().to_string(),
            ))
        }
        (Some(colon), None) => {
            let (key, value) = line.split_at(colon);
            Some((
                key.trim().trim_matches('"').trim_matches('\'').to_string(),
                value[1..].trim().to_string(),
            ))
        }
        _ => {
            let split = whitespace?;
            let (key, value) = line.split_at(split);
            Some((
                key.trim().trim_matches('"').trim_matches('\'').to_string(),
                value.trim().to_string(),
            ))
        }
    }
}

fn normalize_yarn_value(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

fn validate_yarn_berry_resolution_identity(
    package_name: &str,
    version: &str,
    resolution: &str,
    lockfile_path: &Path,
) -> Result<()> {
    let expected = format!("{package_name}@npm:{version}");
    if resolution.trim() != expected {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' resolves to '{}', which does not match the locked package identity '{}' at version '{}'.",
            lockfile_path.display(),
            package_name,
            crate::report::sanitize_for_terminal(resolution),
            package_name,
            version
        );
    }

    Ok(())
}

fn validate_yarn_classic_resolved_identity(
    package_name: &str,
    version: &str,
    resolved: &str,
    integrity: &str,
    lockfile_path: &Path,
) -> Result<()> {
    let Some(path) = yarn_registry_tarball_path(resolved) else {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' has untrusted resolved source '{}'. sloppy-joe only trusts Yarn classic registry tarball URLs with explicit package identity.",
            lockfile_path.display(),
            package_name,
            crate::report::sanitize_for_terminal(resolved)
        );
    };

    if !expected_yarn_registry_tarball_paths(package_name, version)
        .iter()
        .any(|expected| expected == path)
    {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' resolves to '{}', which does not match the locked package identity '{}' at version '{}'.",
            lockfile_path.display(),
            package_name,
            crate::report::sanitize_for_terminal(resolved),
            package_name,
            version
        );
    }

    let integrity = integrity.trim();
    if integrity.is_empty() {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' is missing integrity metadata. sloppy-joe only trusts Yarn classic registry entries with explicit tarball provenance.",
            lockfile_path.display(),
            package_name
        );
    }
    if !integrity.contains('-') {
        anyhow::bail!(
            "Required lockfile '{}' entry '{}' has malformed integrity metadata '{}'.",
            lockfile_path.display(),
            package_name,
            crate::report::sanitize_for_terminal(integrity)
        );
    }

    Ok(())
}

fn yarn_registry_tarball_path(resolved: &str) -> Option<&str> {
    let resolved = resolved.trim();
    let resolved = resolved.strip_prefix("https://").unwrap_or(resolved);
    let resolved = resolved
        .strip_prefix("registry.yarnpkg.com/")
        .or_else(|| resolved.strip_prefix("registry.npmjs.org/"))?;
    Some(
        resolved
            .split_once('#')
            .map(|(path, _)| path)
            .unwrap_or(resolved),
    )
}

fn expected_yarn_registry_tarball_paths(package_name: &str, version: &str) -> Vec<String> {
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

fn selector_package_name_and_source(selector: &str) -> Option<(&str, &str)> {
    if let Some((manifest_name, rest)) = selector.rsplit_once("@npm:") {
        if let Some((actual_name, _)) = split_npm_package_and_spec(rest) {
            return Some((actual_name, "registry"));
        }
        return Some((manifest_name, "registry"));
    }
    if let Some((name, _rest)) = selector.rsplit_once("@workspace:") {
        return Some((name, "workspace"));
    }
    if let Some((name, _rest)) = selector.rsplit_once("@portal:") {
        return Some((name, "portal"));
    }
    if let Some((name, _rest)) = selector.rsplit_once("@patch:") {
        return Some((name, "patch"));
    }
    if let Some((name, _rest)) = selector.rsplit_once("@file:") {
        return Some((name, "file"));
    }
    if let Some((name, _rest)) = selector.rsplit_once("@link:") {
        return Some((name, "link"));
    }

    let split = if selector.starts_with('@') {
        let slash = selector.find('/')?;
        let after_scope = 1 + slash + 1;
        let version_at = selector[after_scope..].rfind('@')?;
        after_scope + version_at
    } else {
        selector.rfind('@')?
    };
    Some((&selector[..split], "registry"))
}

impl ParsedYarnLock {
    fn entry_for_dependency(&self, dep: &Dependency) -> Option<&YarnLockEntry> {
        self.entry_index_for_dependency(dep)
            .and_then(|index| self.entries.get(index))
    }

    fn entry_index_for_dependency(&self, dep: &Dependency) -> Option<usize> {
        for selector in dependency_selectors(dep) {
            if let Some(index) = self.by_selector.get(&selector) {
                return Some(*index);
            }
        }
        None
    }

    fn workspace_entry(
        &self,
        project_name: &str,
        package_entry_key: &str,
    ) -> Option<&YarnLockEntry> {
        let workspace_target = if package_entry_key.is_empty() {
            ".".to_string()
        } else {
            package_entry_key.to_string()
        };
        let selector = format!("{project_name}@workspace:{workspace_target}");
        self.by_selector
            .get(&selector)
            .and_then(|index| self.entries.get(*index))
    }
}

fn manifest_selectors(name: &str, requested: &str) -> Vec<String> {
    if requested.starts_with("npm:") {
        vec![format!("{name}@{requested}")]
    } else {
        vec![
            format!("{name}@{requested}"),
            format!("{name}@npm:{requested}"),
        ]
    }
}

fn dependency_selectors(dep: &Dependency) -> Vec<String> {
    let Some(requested) = dep.version.as_deref() else {
        return Vec::new();
    };
    let mut selectors = Vec::new();
    if let Some(actual_name) = dep.actual_name.as_deref() {
        selectors.push(format!("{}@npm:{}@{}", dep.name, actual_name, requested));
    }
    selectors.extend(manifest_selectors(&dep.name, requested));
    if dep.actual_name.is_none() && dep.package_name() != dep.name {
        selectors.extend(manifest_selectors(dep.package_name(), requested));
    }
    selectors
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_resolved_property_line_handles_colons_inside_urls() {
        let parsed = parse_property_line(
            r#"resolved "https://registry.yarnpkg.com/not-react/-/not-react-18.3.1.tgz#49ab892009c53933625bd16b2533fc754cab2891""#,
        )
        .expect("classic resolved line should parse");
        assert_eq!(parsed.0, "resolved");
        assert_eq!(
            parsed.1,
            r#""https://registry.yarnpkg.com/not-react/-/not-react-18.3.1.tgz#49ab892009c53933625bd16b2533fc754cab2891""#
        );
    }

    #[test]
    fn classic_provenance_rejects_wrong_tarball_identity() {
        let parsed = parse_lockfile(
            r#"# yarn lockfile v1

react@^18.0.0:
  version "18.3.1"
  resolved "https://registry.yarnpkg.com/not-react/-/not-react-18.3.1.tgz#49ab892009c53933625bd16b2533fc754cab2891"
  integrity sha512-react
"#,
            PathBuf::from("yarn.lock"),
            Path::new("."),
        )
        .expect("classic yarn lockfile should parse");

        assert!(validate_provenance(&parsed).is_err());
    }

    #[test]
    fn berry_provenance_accepts_exact_resolution_identity() {
        let parsed = parse_lockfile(
            r#"# This file is generated by running "yarn install" inside your project.

"react@npm:^18.0.0":
  version 18.3.1
  resolution: "react@npm:18.3.1"
  checksum: 10c0/react
  languageName: node
  linkType: hard
"#,
            PathBuf::from("yarn.lock"),
            Path::new("."),
        )
        .expect("Berry yarn lockfile should parse");

        validate_provenance(&parsed).expect("Berry provenance should remain accepted");
    }

    #[test]
    fn berry_provenance_rejects_missing_checksum() {
        let parsed = parse_lockfile(
            r#"# This file is generated by running "yarn install" inside your project.

"react@npm:^18.0.0":
  version 18.3.1
  resolution: "react@npm:18.3.1"
  languageName: node
  linkType: hard
"#,
            PathBuf::from("yarn.lock"),
            Path::new("."),
        )
        .expect("Berry yarn lockfile should parse");

        assert!(validate_provenance(&parsed).is_err());
    }

    #[test]
    fn berry_alias_entries_preserve_real_package_identity() {
        let parsed = parse_lockfile(
            r#"# This file is generated by running "yarn install" inside your project.

"alias-react@npm:react@^18.0.0":
  version 18.3.1
  resolution: "react@npm:18.3.1"
  checksum: 10c0/react
  languageName: node
  linkType: hard
"#,
            PathBuf::from("yarn.lock"),
            Path::new("."),
        )
        .expect("Berry alias lockfile should parse");

        validate_provenance(&parsed).expect("Berry alias provenance should remain accepted");

        let dep = crate::Dependency {
            name: "alias-react".to_string(),
            version: Some("^18.0.0".to_string()),
            ecosystem: crate::Ecosystem::Npm,
            actual_name: Some("react".to_string()),
        };
        assert!(
            parsed.entry_for_dependency(&dep).is_some(),
            "alias selectors should resolve for direct dependencies"
        );
    }
}
