use crate::Dependency;
use crate::parsers::python_scope::PythonScopedDependency;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IncludeDirective<'a> {
    Requirement(&'a str),
    Constraint(&'a str),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RequirementsSourceProvenance {
    pub primary_index: Option<String>,
    pub extra_indexes: BTreeSet<String>,
    /// The requirements file that first declared each index, for error messages.
    pub origins: BTreeMap<String, PathBuf>,
}

enum SupportedSourceDirective {
    PrimaryIndex(String),
    ExtraIndex(String),
}

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    parse_file(&project_dir.join("requirements.txt"), project_dir)
}

pub(crate) fn is_hash_locked_requirements_file(path: &Path, scan_root: &Path) -> Result<bool> {
    let scan_root = std::fs::canonicalize(scan_root)
        .with_context(|| format!("Failed to inspect scan root {}", scan_root.display()))?;
    let mut visited = HashSet::new();
    let mut saw_installable = false;
    Ok(
        classify_trust_inner(path, &scan_root, &mut visited, &mut saw_installable)?
            && saw_installable,
    )
}

pub(crate) fn parse_file(path: &Path, scan_root: &Path) -> Result<Vec<Dependency>> {
    Ok(parse_scoped_file(path, scan_root)?
        .into_iter()
        .map(|dep| dep.dependency)
        .collect())
}

pub(crate) fn parse_scoped_file(
    path: &Path,
    scan_root: &Path,
) -> Result<Vec<PythonScopedDependency>> {
    let scan_root = std::fs::canonicalize(scan_root)
        .with_context(|| format!("Failed to inspect scan root {}", scan_root.display()))?;
    let mut visited = HashSet::new();
    parse_scoped_file_inner(path, &scan_root, &mut visited)
}

pub(crate) fn included_paths(path: &Path, scan_root: &Path) -> Result<Vec<PathBuf>> {
    let scan_root = std::fs::canonicalize(scan_root)
        .with_context(|| format!("Failed to inspect scan root {}", scan_root.display()))?;
    let mut visited = HashSet::new();
    let mut includes = HashSet::new();
    collect_included_paths(path, &scan_root, &mut visited, &mut includes)?;
    Ok(includes.into_iter().collect())
}

pub(crate) fn source_provenance(
    path: &Path,
    scan_root: &Path,
) -> Result<RequirementsSourceProvenance> {
    let scan_root = std::fs::canonicalize(scan_root)
        .with_context(|| format!("Failed to inspect scan root {}", scan_root.display()))?;
    let mut visited = HashSet::new();
    collect_source_provenance_inner(path, &scan_root, &mut visited)
}

/// Every `--index-url` / `-i` / `--extra-index-url` in the requirements graph (including `-r`
/// and `-c` includes) decides where pip downloads from. Each must be the default PyPI index or
/// exactly allowlisted in `trusted_indexes.pypi`; otherwise the scanner would vet the public
/// package while pip installs whatever the other index serves.
pub(crate) fn ensure_trusted_indexes(
    path: &Path,
    scan_root: &Path,
    config: &crate::config::SloppyJoeConfig,
) -> Result<RequirementsSourceProvenance> {
    let provenance = source_provenance(path, scan_root)?;
    for index in provenance.all_indexes() {
        if config.is_trusted_index("pypi", index) {
            continue;
        }
        let declared_in = provenance
            .origins
            .get(index)
            .map(|origin| origin.display().to_string())
            .unwrap_or_else(|| path.display().to_string());
        bail!(
            "Untrusted Python index ({}): requirements file '{}' declares untrusted Python index '{}': it is not the default PyPI index and is not allowlisted in trusted_indexes.pypi. pip would install from that index while sloppy-joe vetted the public PyPI package. Add the exact URL to trusted_indexes.pypi in the out-of-repo sloppy-joe config, or remove the index option.",
            crate::names::RESOLUTION_UNTRUSTED_REGISTRY_SOURCE,
            declared_in,
            crate::report::sanitize_for_terminal(index),
        );
    }
    Ok(provenance)
}

/// Maximum nesting of `-r` / `-c` includes. pip itself recurses without a limit, so a hostile
/// chain could otherwise exhaust the stack and abort the scan.
const MAX_INCLUDE_DEPTH: usize = 64;

/// Push `key` onto the active include stack, rejecting cycles and excessive nesting.
/// `visited` holds exactly the files on the current include path (callers remove on exit).
fn enter_include(visited: &mut HashSet<PathBuf>, key: &Path, path: &Path) -> Result<()> {
    if visited.len() >= MAX_INCLUDE_DEPTH {
        bail!(
            "requirements include depth exceeds {} at {}; refusing to scan an unbounded include chain",
            MAX_INCLUDE_DEPTH,
            path.display()
        );
    }
    if !visited.insert(key.to_path_buf()) {
        bail!("requirements include cycle detected at {}", path.display());
    }
    Ok(())
}

fn parse_scoped_file_inner(
    path: &Path,
    scan_root: &Path,
    visited: &mut HashSet<PathBuf>,
) -> Result<Vec<PythonScopedDependency>> {
    let normalized_path = normalize_path(path);
    let visited_key =
        std::fs::canonicalize(&normalized_path).unwrap_or_else(|_| normalized_path.clone());
    enter_include(visited, &visited_key, &normalized_path)?;

    let content = super::read_file_limited(&normalized_path, super::MAX_MANIFEST_BYTES)
        .with_context(|| format!("Failed to read {}", normalized_path.display()))?;
    let mut deps = Vec::new();

    for entry in logical_requirement_lines(&content)? {
        let line = strip_inline_comment(&entry).trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(include) = requirement_include_target(line) {
            let include_target = match include {
                IncludeDirective::Requirement(path) | IncludeDirective::Constraint(path) => path,
            };
            let include_path = resolve_include_path(&normalized_path, include_target, scan_root)?;
            if matches!(include, IncludeDirective::Requirement(_)) {
                deps.extend(parse_scoped_file_inner(&include_path, scan_root, visited)?);
            }
            continue;
        }

        if parse_supported_source_directive(line, &normalized_path)?.is_some() {
            continue;
        }

        if is_self_editable_install(line, &normalized_path) {
            continue;
        }

        if line.starts_with('-') {
            bail!(
                "Unsupported requirements directive '{}' in {}",
                crate::report::sanitize_for_terminal(line),
                normalized_path.display()
            );
        }

        if let Some(dep) = parse_scoped_requirement_spec(line, &normalized_path)? {
            deps.push(dep);
        }
    }

    visited.remove(&visited_key);
    Ok(deps)
}

fn classify_trust_inner(
    path: &Path,
    scan_root: &Path,
    visited: &mut HashSet<PathBuf>,
    saw_installable: &mut bool,
) -> Result<bool> {
    let normalized_path = normalize_path(path);
    let visited_key =
        std::fs::canonicalize(&normalized_path).unwrap_or_else(|_| normalized_path.clone());
    enter_include(visited, &visited_key, &normalized_path)?;

    let content = super::read_file_limited(&normalized_path, super::MAX_MANIFEST_BYTES)
        .with_context(|| format!("Failed to read {}", normalized_path.display()))?;
    let mut trusted = true;

    for entry in logical_requirement_lines(&content)? {
        let line = strip_inline_comment(&entry).trim();
        if line.is_empty() {
            continue;
        }

        if let Some(include) = requirement_include_target(line) {
            let include_target = match include {
                IncludeDirective::Requirement(path) | IncludeDirective::Constraint(path) => path,
            };
            let include_path = resolve_include_path(&normalized_path, include_target, scan_root)?;
            trusted &= classify_trust_inner(&include_path, scan_root, visited, saw_installable)?;
            continue;
        }

        if parse_supported_source_directive(line, &normalized_path)?.is_some() {
            continue;
        }

        if line.starts_with('-') {
            trusted = false;
            continue;
        }

        *saw_installable = true;
        let Some(dep) = (match parse_scoped_requirement_spec(line, &normalized_path) {
            Ok(dep) => dep,
            Err(_) => {
                trusted = false;
                continue;
            }
        }) else {
            continue;
        };
        if dep.dependency.exact_version().is_none() || !line.contains("--hash=") {
            trusted = false;
        }
    }

    visited.remove(&visited_key);
    Ok(trusted)
}

fn collect_source_provenance_inner(
    path: &Path,
    scan_root: &Path,
    visited: &mut HashSet<PathBuf>,
) -> Result<RequirementsSourceProvenance> {
    let normalized_path = normalize_path(path);
    let visited_key =
        std::fs::canonicalize(&normalized_path).unwrap_or_else(|_| normalized_path.clone());
    enter_include(visited, &visited_key, &normalized_path)?;

    let content = super::read_file_limited(&normalized_path, super::MAX_MANIFEST_BYTES)
        .with_context(|| format!("Failed to read {}", normalized_path.display()))?;
    let mut provenance = RequirementsSourceProvenance::default();

    for entry in logical_requirement_lines(&content)? {
        let line = strip_inline_comment(&entry).trim();
        if line.is_empty() {
            continue;
        }

        if let Some(include) = requirement_include_target(line) {
            let include_target = match include {
                IncludeDirective::Requirement(path) | IncludeDirective::Constraint(path) => path,
            };
            let include_path = resolve_include_path(&normalized_path, include_target, scan_root)?;
            provenance.merge(collect_source_provenance_inner(
                &include_path,
                scan_root,
                visited,
            )?)?;
            continue;
        }

        if let Some(directive) = parse_supported_source_directive(line, &normalized_path)? {
            provenance.observe(directive, &normalized_path)?;
        }
    }

    visited.remove(&visited_key);
    Ok(provenance)
}

fn collect_included_paths(
    path: &Path,
    scan_root: &Path,
    visited: &mut HashSet<PathBuf>,
    includes: &mut HashSet<PathBuf>,
) -> Result<()> {
    let normalized_path = normalize_path(path);
    let visited_key =
        std::fs::canonicalize(&normalized_path).unwrap_or_else(|_| normalized_path.clone());
    enter_include(visited, &visited_key, &normalized_path)?;

    let content = super::read_file_limited(&normalized_path, super::MAX_MANIFEST_BYTES)
        .with_context(|| format!("Failed to read {}", normalized_path.display()))?;

    for entry in logical_requirement_lines(&content)? {
        let line = strip_inline_comment(&entry).trim();
        if let Some(include) = requirement_include_target(line) {
            let include_target = match include {
                IncludeDirective::Requirement(path) | IncludeDirective::Constraint(path) => path,
            };
            let include_path = resolve_include_path(&normalized_path, include_target, scan_root)?;
            let include_key =
                std::fs::canonicalize(&include_path).unwrap_or_else(|_| include_path.clone());
            includes.insert(include_key);
            collect_included_paths(&include_path, scan_root, visited, includes)?;
        }
    }

    visited.remove(&visited_key);
    Ok(())
}

fn requirement_include_target(line: &str) -> Option<IncludeDirective<'_>> {
    let trimmed = line.trim();
    if let Some(rest) = trimmed.strip_prefix("-r") {
        let rest = rest.trim();
        if !rest.is_empty() {
            return Some(IncludeDirective::Requirement(rest));
        }
    }
    if let Some(rest) = trimmed.strip_prefix("--requirement=") {
        let rest = rest.trim();
        if !rest.is_empty() {
            return Some(IncludeDirective::Requirement(rest));
        }
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix("--requirement") {
        if !rest.chars().next().is_some_and(char::is_whitespace) {
            return None;
        }
        let rest = rest.trim();
        if !rest.is_empty() {
            return Some(IncludeDirective::Requirement(rest));
        }
    }
    if let Some(rest) = trimmed.strip_prefix("-c") {
        let rest = rest.trim();
        if !rest.is_empty() {
            return Some(IncludeDirective::Constraint(rest));
        }
    }
    if let Some(rest) = trimmed.strip_prefix("--constraint=") {
        let rest = rest.trim();
        if !rest.is_empty() {
            return Some(IncludeDirective::Constraint(rest));
        }
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix("--constraint") {
        if !rest.chars().next().is_some_and(char::is_whitespace) {
            return None;
        }
        let rest = rest.trim();
        if !rest.is_empty() {
            return Some(IncludeDirective::Constraint(rest));
        }
    }
    None
}

/// `-e .` / `--editable .[extras]`: install the project in this directory in
/// development mode. Its dependencies come from the project's own manifest,
/// which is scanned as a separate project, so the line adds nothing to verify.
/// Only accepted when that manifest sits next to the requirements file; any
/// other editable target (paths, URLs, VCS) cannot be verified.
fn is_self_editable_install(line: &str, requirements_path: &Path) -> bool {
    let line = line.trim();
    let target = line
        .strip_prefix("--editable")
        .or_else(|| line.strip_prefix("-e"))
        .map(|rest| rest.strip_prefix('=').unwrap_or(rest).trim());
    let Some(target) = target else {
        return false;
    };
    let extras_ok = match target.strip_prefix('.') {
        Some("") => true,
        Some(rest) => rest
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .is_some_and(|extras| {
                !extras.trim().is_empty()
                    && extras.chars().all(|ch| {
                        ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ',' | ' ')
                    })
            }),
        None => false,
    };
    if !extras_ok {
        return false;
    }
    requirements_path.parent().is_some_and(|dir| {
        ["pyproject.toml", "setup.py", "setup.cfg"]
            .iter()
            .any(|manifest| dir.join(manifest).is_file())
    })
}

fn parse_supported_source_directive(
    line: &str,
    source_path: &Path,
) -> Result<Option<SupportedSourceDirective>> {
    let line = strip_inline_comment(line).trim();
    let Some((kind, url)) = source_directive_parts(line) else {
        return Ok(None);
    };
    if url.trim().is_empty() {
        bail!(
            "Unsupported requirements directive '{}' in {}",
            crate::report::sanitize_for_terminal(line),
            source_path.display()
        );
    }
    if !crate::config::python_index_url_has_supported_scheme(url) {
        bail!(
            "Unsupported requirements directive '{}' in {}: only http:// and https:// package index URLs are supported",
            crate::report::sanitize_for_terminal(line),
            source_path.display()
        );
    }
    let normalized = crate::config::normalize_python_index_url(url);
    Ok(Some(match kind {
        "primary" => SupportedSourceDirective::PrimaryIndex(normalized),
        "extra" => SupportedSourceDirective::ExtraIndex(normalized),
        _ => unreachable!("source directive kind is validated by source_directive_parts"),
    }))
}

fn source_directive_parts(line: &str) -> Option<(&'static str, &str)> {
    if let Some(url) = line.strip_prefix("--index-url=") {
        return Some(("primary", url.trim()));
    }
    if let Some(rest) = line.strip_prefix("--index-url")
        && rest.chars().next().is_some_and(char::is_whitespace)
    {
        return Some(("primary", rest.trim()));
    }
    if let Some(rest) = line.strip_prefix("-i")
        && rest.chars().next().is_some_and(char::is_whitespace)
    {
        return Some(("primary", rest.trim()));
    }
    if let Some(url) = line.strip_prefix("--extra-index-url=") {
        return Some(("extra", url.trim()));
    }
    if let Some(rest) = line.strip_prefix("--extra-index-url")
        && rest.chars().next().is_some_and(char::is_whitespace)
    {
        return Some(("extra", rest.trim()));
    }
    None
}

fn resolve_include_path(
    current_file: &Path,
    include_target: &str,
    scan_root: &Path,
) -> Result<PathBuf> {
    let candidate = if Path::new(include_target).is_absolute() {
        PathBuf::from(include_target)
    } else {
        current_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(include_target)
    };
    let normalized = normalize_path(&candidate);

    if let Ok(canonical) = std::fs::canonicalize(&normalized) {
        if !canonical.starts_with(scan_root) {
            bail!(
                "requirements include '{}' resolves outside the scan root from {}",
                crate::report::sanitize_for_terminal(include_target),
                current_file.display()
            );
        }
        return Ok(normalized);
    }

    if !normalized.starts_with(scan_root) {
        bail!(
            "requirements include '{}' resolves outside the scan root from {}",
            crate::report::sanitize_for_terminal(include_target),
            current_file.display()
        );
    }

    Ok(normalized)
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::RootDir | Component::Prefix(_) => normalized.push(component.as_os_str()),
            Component::Normal(part) => normalized.push(part),
        }
    }

    normalized
}

/// Drop a leading UTF-8 byte-order mark, which Windows editors commonly write and which
/// pip and configparser ignore.
pub(crate) fn strip_utf8_bom(content: &str) -> &str {
    content.strip_prefix('\u{feff}').unwrap_or(content)
}

/// pip decodes a requirements file with the codec a `# -*- coding: X -*-` line in its first
/// two lines declares. Only codecs that read ASCII bytes as ASCII are modeled; anything else
/// (UTF-7 can hide a newline behind a comment) would make pip see different lines.
fn ensure_modeled_encoding(content: &str) -> Result<()> {
    for line in content.lines().take(2) {
        let line = line.trim_start_matches('\u{feff}');
        if !line.starts_with('#') {
            continue;
        }
        let Some(position) = line.find("coding") else {
            continue;
        };
        let rest = &line[position + "coding".len()..];
        let Some(rest) = rest.strip_prefix(':').or_else(|| rest.strip_prefix('=')) else {
            continue;
        };
        let name: String = rest
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            .collect();
        let normalized = name.to_ascii_lowercase().replace('_', "-");
        if !matches!(
            normalized.as_str(),
            "utf-8" | "utf8" | "ascii" | "us-ascii" | "latin-1" | "latin1" | "iso-8859-1"
        ) {
            bail!(
                "requirements file declares the unsupported encoding '{name}'; pip would decode it differently than sloppy-joe, so it cannot be scanned reliably. Fix: save the file as UTF-8 and remove the coding line."
            );
        }
    }
    Ok(())
}

fn logical_requirement_lines(content: &str) -> Result<Vec<String>> {
    ensure_modeled_encoding(content)?;
    let mut entries = Vec::new();
    let mut current = String::new();

    for raw_line in strip_utf8_bom(content).lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            // pip ends a backslash continuation at a blank or comment line.
            if !current.trim().is_empty() {
                entries.push(current.trim().to_string());
            }
            current.clear();
            continue;
        }

        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(trimmed);

        if current.ends_with('\\') {
            current.pop();
            current = current.trim_end().to_string();
            continue;
        }

        entries.push(current.trim().to_string());
        current.clear();
    }

    if !current.trim().is_empty() {
        entries.push(current.trim().to_string());
    }

    Ok(entries)
}

/// Whether a file is a pip requirements manifest by naming convention: any `*.txt` whose name
/// contains `requirements` (`requirements-dev.txt`, `dev-requirements.txt`, ...), or any `*.txt`
/// inside a `requirements/` directory (`requirements/base.txt`).
pub(crate) fn is_requirements_manifest_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let lowered = name.to_ascii_lowercase();
    let Some(stem) = lowered.strip_suffix(".txt") else {
        return false;
    };
    stem.contains("requirements") || is_in_requirements_directory(path)
}

/// Whether a file lives directly inside a directory named `requirements`.
pub(crate) fn is_in_requirements_directory(path: &Path) -> bool {
    path.parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("requirements"))
}

pub(crate) fn requirement_looks_like_local_path(line: &str) -> bool {
    let candidate = line.trim();
    if candidate == "." || candidate.starts_with("./") || candidate.starts_with("../") {
        return true;
    }
    if candidate.starts_with(".[") || candidate.starts_with("/.") || candidate.starts_with('/') {
        return true;
    }
    if candidate.contains('/') || candidate.contains('\\') {
        return true;
    }
    [".whl", ".zip", ".tar.gz", ".tar.bz2", ".tgz"]
        .iter()
        .any(|ext| candidate.ends_with(ext))
}

fn strip_inline_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut previous_was_whitespace = false;

    for (idx, ch) in line.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double && previous_was_whitespace => {
                return line[..idx].trim_end();
            }
            _ => {}
        }
        previous_was_whitespace = ch.is_whitespace();
    }

    line
}

fn strip_trailing_hashes(line: &str) -> &str {
    for (idx, ch) in line.char_indices() {
        if !ch.is_whitespace() {
            continue;
        }
        let remainder = line[idx..].trim_start();
        if remainder.starts_with("--hash=") {
            return line[..idx].trim_end();
        }
    }
    line
}

/// Find position of first `;` not inside quotes.
fn find_unquoted_semicolon(s: &str) -> Option<usize> {
    let mut in_single = false;
    let mut in_double = false;
    for (i, ch) in s.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            ';' if !in_single && !in_double => return Some(i),
            _ => {}
        }
    }
    None
}

/// Normalize per PEP 503: lowercase, replace runs of [-_.] with single `-`, strip extras.
pub(crate) fn normalize_distribution_name(raw: &str) -> String {
    let stripped = raw.trim().split('[').next().unwrap_or("").trim();
    normalize_distribution_atom(stripped)
}

pub(crate) fn parse_distribution_name_and_requested_extras(
    raw: &str,
) -> (String, std::collections::BTreeSet<String>) {
    let raw = raw.trim();
    let Some(open) = raw.find('[') else {
        return (
            normalize_distribution_name(raw),
            std::collections::BTreeSet::new(),
        );
    };
    let Some(close) = raw[open + 1..].find(']').map(|offset| open + 1 + offset) else {
        return (
            normalize_distribution_name(raw),
            std::collections::BTreeSet::new(),
        );
    };
    let name = normalize_distribution_name(&raw[..open]);
    let extras = raw[open + 1..close]
        .split(',')
        .map(normalize_distribution_atom)
        .filter(|extra| !extra.is_empty())
        .collect();
    (name, extras)
}

fn normalize_distribution_atom(raw: &str) -> String {
    let stripped = raw.trim();
    let lowered = stripped.to_lowercase();
    // Replace consecutive separator runs with a single dash
    let mut result = String::with_capacity(lowered.len());
    let mut prev_sep = false;
    for ch in lowered.chars() {
        if ch == '-' || ch == '_' || ch == '.' {
            if !prev_sep && !result.is_empty() {
                result.push('-');
            }
            prev_sep = true;
        } else {
            result.push(ch);
            prev_sep = false;
        }
    }
    // Trim trailing separator
    if result.ends_with('-') {
        result.pop();
    }
    result
}

impl RequirementsSourceProvenance {
    fn observe(&mut self, directive: SupportedSourceDirective, source_path: &Path) -> Result<()> {
        let url = match &directive {
            SupportedSourceDirective::PrimaryIndex(url)
            | SupportedSourceDirective::ExtraIndex(url) => url,
        };
        self.origins
            .entry(url.clone())
            .or_insert_with(|| source_path.to_path_buf());
        match directive {
            SupportedSourceDirective::PrimaryIndex(url) => {
                if let Some(existing) = &self.primary_index
                    && existing != &url
                {
                    bail!(
                        "Unsupported requirements directive in {}: conflicting --index-url values '{}' and '{}'",
                        source_path.display(),
                        existing,
                        url
                    );
                }
                self.primary_index = Some(url);
            }
            SupportedSourceDirective::ExtraIndex(url) => {
                self.extra_indexes.insert(url);
            }
        }
        Ok(())
    }

    fn merge(&mut self, other: RequirementsSourceProvenance) -> Result<()> {
        for (url, origin) in other.origins {
            self.origins.entry(url).or_insert(origin);
        }
        if let Some(url) = other.primary_index {
            self.observe(
                SupportedSourceDirective::PrimaryIndex(url),
                Path::new("requirements include"),
            )?;
        }
        self.extra_indexes.extend(other.extra_indexes);
        Ok(())
    }

    pub(crate) fn all_indexes(&self) -> impl Iterator<Item = &String> {
        self.primary_index.iter().chain(self.extra_indexes.iter())
    }
}

pub(crate) fn parse_requirement_spec(raw: &str, source_path: &Path) -> Result<Option<Dependency>> {
    Ok(parse_scoped_requirement_spec(raw, source_path)?.map(|dep| dep.dependency))
}

pub(crate) fn parse_scoped_requirement_spec(
    raw: &str,
    source_path: &Path,
) -> Result<Option<PythonScopedDependency>> {
    let raw = strip_inline_comment(raw);
    let (line, marker) = split_requirement_marker(raw);
    let line = strip_trailing_hashes(line);
    let marker = marker
        .map(strip_trailing_hashes)
        .map(str::trim)
        .filter(|marker| !marker.is_empty())
        .map(str::to_string);
    let line = line.trim_end_matches('\\').trim();
    if line.is_empty() {
        return Ok(None);
    }

    if line.contains("://") || line.contains(" @ ") || line.starts_with("git+") {
        bail!(
            "Unsupported direct requirement '{}' in {}",
            crate::report::sanitize_for_terminal(line),
            source_path.display()
        );
    }

    if requirement_looks_like_local_path(line) {
        bail!(
            "Unsupported local requirement '{}' in {}",
            crate::report::sanitize_for_terminal(line),
            source_path.display()
        );
    }

    let (name, requested_extras, version) = if let Some(pos) =
        line.find(['=', '>', '<', '~', '!', '^'])
    {
        // PEP 508 also allows the specifier in parentheses: `name (>=1.0,<2)`.
        let unbalanced = || {
            anyhow::anyhow!(
                "Unsupported requirement '{}' in {}: unbalanced parentheses in the version specifier",
                crate::report::sanitize_for_terminal(line),
                source_path.display()
            )
        };
        let name_part = line[..pos].trim_end();
        let version_part = line[pos..].trim();
        let (name_part, version_part) = match name_part.strip_suffix('(') {
            Some(stripped) => {
                let inner = version_part.strip_suffix(')').ok_or_else(unbalanced)?;
                (stripped.trim_end(), inner.trim())
            }
            None => (name_part, version_part),
        };
        if version_part.contains(['(', ')']) {
            return Err(unbalanced());
        }
        let (name, requested_extras) = parse_distribution_name_and_requested_extras(name_part);
        (name, requested_extras, Some(version_part.to_string()))
    } else {
        let (name, requested_extras) = parse_distribution_name_and_requested_extras(line);
        (name, requested_extras, None)
    };

    if name.is_empty() {
        bail!(
            "Unsupported requirement '{}' in {}: missing a package name",
            crate::report::sanitize_for_terminal(line),
            source_path.display()
        );
    }

    let dep = Dependency {
        name,
        version,
        ecosystem: crate::Ecosystem::PyPI,
        actual_name: None,
    };
    super::validate_dependency(&dep, source_path)?;
    let scoped = requested_extras.into_iter().fold(
        PythonScopedDependency::runtime(dep, marker),
        |dep, extra| dep.with_requested_extra(&extra),
    );
    Ok(Some(scoped))
}

fn split_requirement_marker(raw: &str) -> (&str, Option<&str>) {
    if let Some(semi_pos) = find_unquoted_semicolon(raw) {
        let line = raw[..semi_pos].trim();
        let marker = raw[semi_pos + 1..].trim();
        (line, Some(marker))
    } else {
        (raw, None)
    }
}

#[cfg(test)]
#[path = "requirements_coverage_tests.rs"]
mod coverage_tests;

#[cfg(test)]
mod tests;
