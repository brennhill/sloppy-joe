mod directives;
pub(crate) use directives::*;
mod spec;
use crate::Dependency;
use crate::parsers::python_scope::PythonScopedDependency;
use anyhow::{Context, Result, bail};
pub(crate) use spec::*;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RequirementsSourceProvenance {
    pub primary_index: Option<String>,
    pub extra_indexes: BTreeSet<String>,
    /// The requirements file that first declared each index, for error messages.
    pub origins: BTreeMap<String, PathBuf>,
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
    crate::fsutil::reject_unmodeled_line_breaks(content, Path::new("requirements file"))?;
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

#[cfg(test)]
#[path = "requirements_coverage_tests.rs"]
mod coverage_tests;

#[cfg(test)]
mod tests;
