use crate::Dependency;
use anyhow::Result;
use std::collections::{BTreeMap, HashMap};
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
            .find_map(|selector| selector_name_and_source(selector))
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
                .map(|(name, value)| (name, value.trim_start_matches("npm:").to_string()))
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
            let classic = format!("{}@{}", name, requested);
            let modern = format!("{}@npm:{}", name, requested);
            if !parsed.by_selector.contains_key(&classic)
                && !parsed.by_selector.contains_key(&modern)
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
            .find_map(|selector| selector_name_and_source(selector))
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
                if let Some(resolution) = &entry.resolution {
                    let expected = format!("{name}@npm:");
                    if !resolution.starts_with(&expected) {
                        anyhow::bail!(
                            "Required lockfile '{}' entry '{}' has untrusted resolution '{}'.",
                            parsed.path.display(),
                            entry.selectors.join(", "),
                            crate::report::sanitize_for_terminal(resolution)
                        );
                    }
                } else if let Some(resolved) = &entry.resolved {
                    let resolved = resolved.trim();
                    if !(resolved.starts_with("https://registry.yarnpkg.com/")
                        || resolved.starts_with("https://registry.npmjs.org/"))
                    {
                        anyhow::bail!(
                            "Required lockfile '{}' entry '{}' has untrusted resolved source '{}'.",
                            parsed.path.display(),
                            entry.selectors.join(", "),
                            crate::report::sanitize_for_terminal(resolved)
                        );
                    }
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
    if let Some((key, value)) = line.split_once(':') {
        return Some((key.trim().to_string(), value.trim().to_string()));
    }
    let split = line.find(char::is_whitespace)?;
    let (key, value) = line.split_at(split);
    Some((key.trim().to_string(), value.trim().to_string()))
}

fn normalize_yarn_value(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

fn selector_name_and_source(selector: &str) -> Option<(&str, &str)> {
    if let Some((name, _rest)) = selector.rsplit_once("@npm:") {
        return Some((name, "registry"));
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
        let requested = dep.version.as_deref()?;
        for selector in [
            format!("{}@{}", dep.package_name(), requested),
            format!("{}@npm:{}", dep.package_name(), requested),
        ] {
            if let Some(index) = self.by_selector.get(&selector) {
                return self.entries.get(*index);
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
