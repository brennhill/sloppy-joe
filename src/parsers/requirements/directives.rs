use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IncludeDirective<'a> {
    Requirement(&'a str),
    Constraint(&'a str),
}

pub(crate) enum SupportedSourceDirective {
    PrimaryIndex(String),
    ExtraIndex(String),
}

/// Maximum nesting of `-r` / `-c` includes. pip itself recurses without a limit, so a hostile
/// chain could otherwise exhaust the stack and abort the scan.
pub(crate) const MAX_INCLUDE_DEPTH: usize = 64;

/// Push `key` onto the active include stack, rejecting cycles and excessive nesting.
/// `visited` holds exactly the files on the current include path (callers remove on exit).
pub(crate) fn enter_include(visited: &mut HashSet<PathBuf>, key: &Path, path: &Path) -> Result<()> {
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

pub(crate) fn collect_included_paths(
    path: &Path,
    scan_root: &Path,
    visited: &mut HashSet<PathBuf>,
    includes: &mut HashSet<PathBuf>,
) -> Result<()> {
    let normalized_path = normalize_path(path);
    let visited_key =
        std::fs::canonicalize(&normalized_path).unwrap_or_else(|_| normalized_path.clone());
    enter_include(visited, &visited_key, &normalized_path)?;

    let content =
        crate::parsers::read_file_limited(&normalized_path, crate::parsers::MAX_MANIFEST_BYTES)
            .with_context(|| format!("Failed to read {}", normalized_path.display()))?;

    for entry in logical_requirement_lines(&content)? {
        let line = strip_inline_comment(&entry).trim();
        if let Some(include) = requirement_include_target(line) {
            let (include_target, installs) = match include {
                IncludeDirective::Requirement(path) => (path, true),
                IncludeDirective::Constraint(path) => (path, false),
            };
            let include_path = resolve_include_path(&normalized_path, include_target, scan_root)?;
            let include_key =
                std::fs::canonicalize(&include_path).unwrap_or_else(|_| include_path.clone());
            // Only `-r` targets are covered by the including file's scan. A `-c` file installs
            // nothing by itself but its own entries must stay visible, so it is not pruned.
            if installs {
                includes.insert(include_key);
            }
            collect_included_paths(&include_path, scan_root, visited, includes)?;
        }
    }

    visited.remove(&visited_key);
    Ok(())
}

pub(crate) fn requirement_include_target(line: &str) -> Option<IncludeDirective<'_>> {
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
pub(crate) fn is_self_editable_install(line: &str, requirements_path: &Path) -> bool {
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

pub(crate) fn parse_supported_source_directive(
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

pub(crate) fn source_directive_parts(line: &str) -> Option<(&'static str, &str)> {
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

pub(crate) fn resolve_include_path(
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

pub(crate) fn normalize_path(path: &Path) -> PathBuf {
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
