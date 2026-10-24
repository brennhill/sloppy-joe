mod validate;
use crate::Dependency;
use anyhow::Result;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
pub(crate) use validate::*;

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

fn is_blank_or_comment(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty() || trimmed.starts_with('#')
}

pub(crate) fn parse_lockfile(
    content: &str,
    path: PathBuf,
    _project_dir: &Path,
) -> Result<ParsedYarnLock> {
    // Yarn's lexer (and Berry's YAML) end a line at a lone `\r`; `lines()` does not.
    crate::fsutil::reject_unmodeled_line_breaks(content, &path)?;
    let mut entries = Vec::new();
    let mut by_selector = HashMap::new();
    let lines = crate::untrusted::rows(content).collect::<Vec<_>>();
    let mut index = 0usize;

    while index < lines.len() {
        if is_blank_or_comment(lines[index]) {
            index += 1;
            continue;
        }
        let selectors = parse_entry_header(lines[index], index, &path)?;
        index += 1;
        let entry = parse_entry_body(&lines, &mut index, selectors, &path)?;
        let entry_index = entries.len();
        for selector in &entry.selectors {
            // A repeated selector makes both the locked version and the
            // dependency graph ambiguous, and would hide the shadowed entry.
            if by_selector.insert(selector.clone(), entry_index).is_some() {
                anyhow::bail!(
                    "Broken lockfile '{}': selector '{}' appears in more than one entry.",
                    path.display(),
                    crate::report::sanitize_for_terminal(selector)
                );
            }
        }
        entries.push(entry);
    }

    Ok(ParsedYarnLock {
        path,
        entries,
        by_selector,
    })
}

fn parse_entry_header(line: &str, index: usize, path: &Path) -> Result<Vec<String>> {
    if line.starts_with(' ') {
        anyhow::bail!(
            "Broken lockfile '{}': unexpected indentation before entry header on line {}.",
            path.display(),
            index + 1
        );
    }
    let Some(header) = line.trim().strip_suffix(':') else {
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
    Ok(selectors)
}

fn parse_entry_body(
    lines: &[&str],
    index: &mut usize,
    selectors: Vec<String>,
    path: &Path,
) -> Result<YarnLockEntry> {
    let mut entry = YarnLockEntry {
        selectors,
        version: None,
        resolved: None,
        resolution: None,
        checksum: None,
        integrity: None,
        link_type: None,
        sections: HashMap::new(),
    };
    while *index < lines.len() {
        let line = lines[*index];
        if is_blank_or_comment(line) {
            *index += 1;
            continue;
        }
        if !line.starts_with("  ") {
            break;
        }
        let body = &line[2..];
        if let Some(section_name) = body.trim_end().strip_suffix(':') {
            *index += 1;
            let section = parse_nested_section(lines, index, path)?;
            entry
                .sections
                .insert(section_name.trim().to_string(), section);
            continue;
        }

        let (key, value) = parse_property_line(body).ok_or_else(|| {
            anyhow::anyhow!(
                "Broken lockfile '{}': invalid property on line {}.",
                path.display(),
                *index + 1
            )
        })?;
        entry.set_property(&key, normalize_yarn_value(&value));
        *index += 1;
    }
    Ok(entry)
}

fn parse_nested_section(
    lines: &[&str],
    index: &mut usize,
    path: &Path,
) -> Result<BTreeMap<String, String>> {
    let mut section = BTreeMap::new();
    while *index < lines.len() {
        let line = lines[*index];
        if is_blank_or_comment(line) {
            *index += 1;
            continue;
        }
        if !line.starts_with("    ") {
            break;
        }
        let (name, value) = parse_property_line(&line[4..]).ok_or_else(|| {
            anyhow::anyhow!(
                "Broken lockfile '{}': invalid nested property on line {}.",
                path.display(),
                *index + 1
            )
        })?;
        section.insert(name, normalize_yarn_value(&value));
        *index += 1;
    }
    Ok(section)
}

impl YarnLockEntry {
    fn set_property(&mut self, key: &str, value: String) {
        match key {
            "version" => self.version = Some(value),
            "resolved" => self.resolved = Some(value),
            "resolution" => self.resolution = Some(value),
            "checksum" => self.checksum = Some(value),
            "integrity" => self.integrity = Some(value),
            "linkType" => self.link_type = Some(value),
            _ => {}
        }
    }
}

pub(super) fn resolve_from_parsed(
    parsed: &ParsedYarnLock,
    deps: &[Dependency],
    mode: super::ResolutionMode,
) -> Result<ResolutionResult> {
    let mut result = ResolutionResult::default();

    for dep in deps {
        // Transitive deps come from the lockfile walk and carry the locked
        // version, not a manifest selector: match them by locked identity.
        let entry = match mode {
            super::ResolutionMode::Direct => parsed.entry_for_dependency(dep),
            super::ResolutionMode::Transitive => parsed.entry_for_locked_package(dep),
        };
        let Some(entry) = entry else {
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

/// Check name for lockfile entries no dependency reaches.
pub(crate) const LOCKFILE_ORPHAN_ENTRIES: &str = "lockfile/orphan-entries";

/// The registry package (name, version) an entry locks, if it is one. Blocks
/// on invalid package names instead of silently dropping the entry.
fn registry_package(entry: &YarnLockEntry, path: &Path) -> Result<Option<(String, String)>> {
    let Some(version) = &entry.version else {
        return Ok(None);
    };
    let Some((name, source)) = entry
        .selectors
        .iter()
        .find_map(|selector| selector_package_name_and_source(selector))
    else {
        return Ok(None);
    };
    if source != "registry" {
        return Ok(None);
    }
    if !crate::ecosystem::validate_package_name(name) {
        anyhow::bail!(
            "Broken lockfile '{}': entry '{}' has an invalid package name '{}'.",
            path.display(),
            crate::report::sanitize_for_terminal(&entry.selectors.join(", ")),
            crate::report::sanitize_for_terminal(name)
        );
    }
    Ok(Some((name.to_string(), version.clone())))
}

fn registry_dependency(name: String, version: String) -> Dependency {
    Dependency {
        name,
        version: Some(version),
        ecosystem: crate::Ecosystem::Npm,
        actual_name: None,
    }
}

/// One Yarn classic registry entry: what `lockfiles::integrity` compares.
pub(crate) struct YarnClassicRegistryEntry {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) location: String,
    pub(crate) integrity: Option<String>,
    pub(crate) resolved: Option<String>,
}

impl ParsedYarnLock {
    /// Registry entries of a Yarn classic lockfile. `None` for Yarn Berry,
    /// whose `checksum` hashes Yarn's own zip archive, not the tarball.
    pub(crate) fn classic_registry_entries(&self) -> Option<Vec<YarnClassicRegistryEntry>> {
        let berry = self
            .entries
            .iter()
            .any(|entry| entry.selectors.len() == 1 && entry.selectors[0] == "__metadata");
        if berry {
            return None;
        }
        Some(
            self.entries
                .iter()
                .filter_map(|entry| {
                    let (name, version) = registry_package(entry, &self.path).ok().flatten()?;
                    Some(YarnClassicRegistryEntry {
                        name,
                        version,
                        location: entry.selectors.join(", "),
                        integrity: entry.integrity.clone(),
                        resolved: entry.resolved.clone(),
                    })
                })
                .collect(),
        )
    }
}

pub(super) fn parse_all_from_parsed(parsed: &ParsedYarnLock) -> Result<Vec<Dependency>> {
    let mut deps = Vec::new();
    for entry in &parsed.entries {
        if let Some((name, version)) = registry_package(entry, &parsed.path)? {
            deps.push(registry_dependency(name, version));
        }
    }
    Ok(deps)
}

/// Entries reachable from a set of start entries, and whether any required
/// (non-peer) dependency edge pointed at a selector the lockfile lacks.
struct YarnWalk {
    reachable: HashSet<usize>,
    unresolved_edge: bool,
}

impl ParsedYarnLock {
    fn walk(&self, start: impl IntoIterator<Item = usize>) -> YarnWalk {
        let mut reachable = HashSet::new();
        let mut unresolved_edge = false;
        let mut queue = start.into_iter().collect::<VecDeque<_>>();
        while let Some(index) = queue.pop_front() {
            if !reachable.insert(index) {
                continue;
            }
            let Some(entry) = self.entries.get(index) else {
                continue;
            };
            for section in [
                "dependencies",
                "optionalDependencies",
                "peerDependencies",
                "devDependencies",
            ] {
                let Some(entries) = entry.sections.get(section) else {
                    continue;
                };
                for (dep_name, specifier) in entries {
                    match manifest_selectors(dep_name, specifier)
                        .iter()
                        .find_map(|selector| self.by_selector.get(selector))
                    {
                        Some(next) => queue.push_back(*next),
                        // Unprovided peers are legitimately absent; any other
                        // missing target makes the graph untrustworthy.
                        None if section == "peerDependencies" => {}
                        None => unresolved_edge = true,
                    }
                }
            }
        }
        YarnWalk {
            reachable,
            unresolved_edge,
        }
    }

    fn workspace_entry_indices(&self) -> Vec<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry.selectors.iter().any(|selector| {
                    selector_package_name_and_source(selector)
                        .is_some_and(|(_, source)| source == "workspace")
                })
            })
            .map(|(index, _)| index)
            .collect()
    }

    /// Whether this lockfile belongs to the project in `project_dir` (as
    /// opposed to a workspace member using its ancestor's lockfile).
    fn is_owned_by(&self, project_dir: &Path) -> bool {
        let Some(lock_dir) = self.path.parent() else {
            return false;
        };
        match (
            std::fs::canonicalize(lock_dir),
            std::fs::canonicalize(project_dir),
        ) {
            (Ok(lock_dir), Ok(project_dir)) => lock_dir == project_dir,
            _ => lock_dir == project_dir,
        }
    }
}

/// Whether the owning project's manifest is a workspace root. Unreadable
/// manifests count as workspace roots so orphans are scanned (fail closed).
fn declares_workspaces(project_dir: &Path) -> bool {
    crate::parsers::read_file_limited(
        &project_dir.join("package.json"),
        crate::parsers::MAX_MANIFEST_BYTES,
    )
    .ok()
    .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
    .is_none_or(|manifest| manifest.get("workspaces").is_some())
}

/// Dependencies to scan for `project_dir`, plus lockfile-level issues.
///
/// Workspace members scan only what their direct dependencies reach. The
/// project owning the lockfile also accounts for entries nothing reaches:
/// when reachability is certain they are stale and never installed, so they
/// are flagged (non-blocking) instead of scanned; when it is not certain they
/// are scanned, so a walker gap can never hide an installed package.
pub(super) fn parse_all_from_parsed_for_project(
    parsed: &ParsedYarnLock,
    direct_deps: &[Dependency],
    project_dir: &Path,
) -> Result<(Vec<Dependency>, Vec<crate::report::Issue>)> {
    let mut packages = Vec::with_capacity(parsed.entries.len());
    for entry in &parsed.entries {
        packages.push(registry_package(entry, &parsed.path)?);
    }

    let mut roots = Vec::new();
    let mut certain = true;
    for dep in direct_deps {
        match parsed.entry_index_for_dependency(dep) {
            Some(index) => roots.push(index),
            None => certain = false,
        }
    }
    if !parsed.is_owned_by(project_dir) {
        let walk = parsed.walk(roots);
        return Ok((dependencies_for(&packages, walk.reachable), Vec::new()));
    }

    let workspaces = parsed.workspace_entry_indices();
    let root_workspaces = workspaces
        .iter()
        .copied()
        .filter(|index| {
            parsed.entries[*index]
                .selectors
                .iter()
                .any(|selector| selector.ends_with("@workspace:."))
        })
        .collect::<Vec<_>>();
    // The owner scans what its own manifest (and its own workspace entry)
    // reaches; member workspaces scan their own graphs.
    let own = parsed.walk(roots.iter().copied().chain(root_workspaces.iter().copied()));
    let global = parsed.walk(roots.into_iter().chain(workspaces.iter().copied()));
    let mut scan = own.reachable;
    let mut issues = Vec::new();
    certain &= !own.unresolved_edge
        && !global.unresolved_edge
        && root_workspaces.len() == workspaces.len()
        && !declares_workspaces(project_dir);
    let workspaces = workspaces.into_iter().collect::<HashSet<_>>();

    let (orphans, unattributable) =
        unreferenced_entries(parsed, &packages, &global.reachable, &workspaces);
    certain &= !unattributable;

    if certain {
        if !orphans.is_empty() {
            issues.push(orphan_entries_issue(parsed, &packages, &orphans));
        }
    } else {
        // Fail closed: when the graph cannot be trusted, scan every entry
        // nothing provably reaches rather than calling it stale.
        scan.extend(orphans);
    }

    Ok((dependencies_for(&packages, scan), issues))
}

/// Entries nothing reaches. The flag is set when one of them is not a package sloppy-joe can
/// attribute, so reachability is unknown.
fn unreferenced_entries(
    parsed: &ParsedYarnLock,
    packages: &[Option<(String, String)>],
    reachable: &HashSet<usize>,
    workspaces: &HashSet<usize>,
) -> (Vec<usize>, bool) {
    let mut orphans = Vec::new();
    let mut unattributable = false;
    for (index, entry) in parsed.entries.iter().enumerate() {
        if reachable.contains(&index) || workspaces.contains(&index) {
            continue;
        }
        if packages[index].is_some() {
            orphans.push(index);
        } else if !(entry.selectors.len() == 1 && entry.selectors[0] == "__metadata") {
            unattributable = true;
        }
    }
    (orphans, unattributable)
}

fn dependencies_for(
    packages: &[Option<(String, String)>],
    entries: HashSet<usize>,
) -> Vec<Dependency> {
    let mut ordered = entries.into_iter().collect::<Vec<_>>();
    ordered.sort_unstable();
    let mut seen = HashSet::new();
    ordered
        .into_iter()
        .filter_map(|index| packages.get(index).cloned().flatten())
        .filter(|package| seen.insert(package.clone()))
        .map(|(name, version)| registry_dependency(name, version))
        .collect()
}

fn orphan_entries_issue(
    parsed: &ParsedYarnLock,
    packages: &[Option<(String, String)>],
    orphans: &[usize],
) -> crate::report::Issue {
    let names = orphans
        .iter()
        .filter_map(|index| packages[*index].as_ref())
        .map(|(name, version)| format!("{name}@{version}"))
        .collect::<Vec<_>>();
    super::stale_orphan_entries_issue(
        &parsed.path,
        names,
        "Yarn",
        "Run `yarn install` to prune the stale entries from yarn.lock, then commit the result.",
    )
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
        // `slash` indexes the full selector (leading '@' included), so the leaf
        // starts right after it. '/' is ASCII, so this is a char boundary.
        let slash = selector.find('/')?;
        let after_scope = slash + 1;
        let version_at = selector.get(after_scope..)?.rfind('@')?;
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

    fn entry_for_locked_package(&self, dep: &Dependency) -> Option<&YarnLockEntry> {
        let version = dep.version.as_deref()?;
        self.entries.iter().find(|entry| {
            entry.version.as_deref() == Some(version)
                && entry
                    .selectors
                    .iter()
                    .find_map(|selector| selector_package_name_and_source(selector))
                    .is_some_and(|(name, source)| {
                        source == "registry" && name == dep.package_name()
                    })
        })
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
mod tests;
