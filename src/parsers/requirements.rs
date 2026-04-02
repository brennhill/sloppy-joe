use crate::Dependency;
use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    parse_file(&project_dir.join("requirements.txt"), project_dir)
}

pub(crate) fn parse_file(path: &Path, scan_root: &Path) -> Result<Vec<Dependency>> {
    let scan_root = std::fs::canonicalize(scan_root)
        .with_context(|| format!("Failed to inspect scan root {}", scan_root.display()))?;
    let mut visited = HashSet::new();
    parse_file_inner(path, &scan_root, &mut visited)
}

pub(crate) fn included_paths(path: &Path, scan_root: &Path) -> Result<Vec<PathBuf>> {
    let scan_root = std::fs::canonicalize(scan_root)
        .with_context(|| format!("Failed to inspect scan root {}", scan_root.display()))?;
    let mut visited = HashSet::new();
    let mut includes = HashSet::new();
    collect_included_paths(path, &scan_root, &mut visited, &mut includes)?;
    Ok(includes.into_iter().collect())
}

fn parse_file_inner(
    path: &Path,
    scan_root: &Path,
    visited: &mut HashSet<PathBuf>,
) -> Result<Vec<Dependency>> {
    let normalized_path = normalize_path(path);
    let visited_key =
        std::fs::canonicalize(&normalized_path).unwrap_or_else(|_| normalized_path.clone());
    if !visited.insert(visited_key.clone()) {
        bail!(
            "requirements include cycle detected at {}",
            normalized_path.display()
        );
    }

    let content = super::read_file_limited(&normalized_path, super::MAX_MANIFEST_BYTES)
        .with_context(|| format!("Failed to read {}", normalized_path.display()))?;
    let mut deps = Vec::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "\\" || line.starts_with("--hash=") {
            continue;
        }

        if let Some(include_target) = requirement_include_target(line) {
            let include_path = resolve_include_path(&normalized_path, include_target, scan_root)?;
            deps.extend(parse_file_inner(&include_path, scan_root, visited)?);
            continue;
        }

        if line.starts_with('-') {
            bail!(
                "Unsupported requirements directive '{}' in {}",
                crate::report::sanitize_for_terminal(line),
                normalized_path.display()
            );
        }

        if let Some(dep) = parse_requirement_spec(line, &normalized_path)? {
            deps.push(dep);
        }
    }

    visited.remove(&visited_key);
    Ok(deps)
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
    if !visited.insert(visited_key.clone()) {
        bail!(
            "requirements include cycle detected at {}",
            normalized_path.display()
        );
    }

    let content = super::read_file_limited(&normalized_path, super::MAX_MANIFEST_BYTES)
        .with_context(|| format!("Failed to read {}", normalized_path.display()))?;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if let Some(include_target) = requirement_include_target(line) {
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

fn requirement_include_target(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if let Some(rest) = trimmed.strip_prefix("-r") {
        let rest = rest.trim();
        if !rest.is_empty() {
            return Some(rest);
        }
    }
    if let Some(rest) = trimmed.strip_prefix("--requirement") {
        let rest = rest.trim();
        if !rest.is_empty() {
            return Some(rest);
        }
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

pub(crate) fn parse_requirement_spec(raw: &str, source_path: &Path) -> Result<Option<Dependency>> {
    let line = if let Some(semi_pos) = find_unquoted_semicolon(raw) {
        raw[..semi_pos].trim()
    } else {
        raw
    };
    let line = strip_inline_comment(line);
    let line = strip_trailing_hashes(line);
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

    let (name, version) = if let Some(pos) = line.find(['=', '>', '<', '~', '!']) {
        let name = normalize_distribution_name(&line[..pos]);
        let version_part = line[pos..].trim();
        (name, Some(version_part.to_string()))
    } else {
        (normalize_distribution_name(line), None)
    };

    if name.is_empty() {
        return Ok(None);
    }

    let dep = Dependency {
        name,
        version,
        ecosystem: crate::Ecosystem::PyPI,
        actual_name: None,
    };
    super::validate_dependency(&dep, source_path)?;
    Ok(Some(dep))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::test_utils::*;

    fn setup_dir(content: &str) -> std::path::PathBuf {
        setup_test_dir("req", "requirements.txt", content)
    }

    #[test]
    fn parse_simple_version() {
        let dir = setup_dir("requests==2.28.0\nflask==2.3.0");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version, Some("==2.28.0".to_string()));
        assert_eq!(deps[0].ecosystem, crate::Ecosystem::PyPI);
        cleanup(&dir);
    }

    #[test]
    fn parse_version_range() {
        let dir = setup_dir("requests>=1.0,<2.0");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version, Some(">=1.0,<2.0".to_string()));
        cleanup(&dir);
    }

    #[test]
    fn skip_comments_and_blank_lines() {
        let dir = setup_dir("# this is a comment\n\nrequests==1.0\n  \n# another comment");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "requests");
        cleanup(&dir);
    }

    #[test]
    fn parse_bare_package_name() {
        let dir = setup_dir("requests\nflask");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].version, None);
        assert_eq!(deps[1].version, None);
        cleanup(&dir);
    }

    #[test]
    fn parse_include_flag_with_following_dependency() {
        let dir = setup_dir("-r other.txt\nrequests==1.0");
        std::fs::write(dir.join("other.txt"), "flask==2.0\n").unwrap();
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|dep| dep.name == "requests"));
        assert!(deps.iter().any(|dep| dep.name == "flask"));
        cleanup(&dir);
    }

    #[test]
    fn reject_url_based_requirements() {
        let dir = setup_dir("git+https://github.com/user/repo.git#egg=pkg\nrequests==1.0");
        let err = parse(&dir).expect_err("unsupported direct references must block scanning");
        assert!(
            err.to_string()
                .contains("git+https://github.com/user/repo.git#egg=pkg")
        );
        cleanup(&dir);
    }

    #[test]
    fn reject_url_with_egg_fragment() {
        let dir = setup_dir("git+https://github.com/user/repo.git@v1.0#egg=mypkg\nflask==2.0");
        let err = parse(&dir).expect_err("egg-based direct references must block scanning");
        assert!(
            err.to_string()
                .contains("git+https://github.com/user/repo.git@v1.0#egg=mypkg")
        );
        cleanup(&dir);
    }

    #[test]
    fn strip_environment_markers() {
        let dir = setup_dir("pywin32>=300; sys_platform == \"win32\"");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "pywin32");
        assert_eq!(deps[0].version, Some(">=300".to_string()));
        cleanup(&dir);
    }

    #[test]
    fn environment_marker_bare_package() {
        let dir = setup_dir("pywin32; sys_platform == \"win32\"");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "pywin32");
        assert_eq!(deps[0].version, None);
        cleanup(&dir);
    }

    #[test]
    fn strip_extras_from_distribution_name() {
        let dir = setup_dir("requests[socks]==2.28.0");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version, Some("==2.28.0".to_string()));
        cleanup(&dir);
    }

    #[test]
    fn strip_inline_comments_after_exact_pin() {
        let dir = setup_dir("requests==2.31.0 # production pin\n");
        let deps = parse(&dir)
            .expect("inline comments after exact pins should not make the version unresolved");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version.as_deref(), Some("==2.31.0"));
        cleanup(&dir);
    }

    #[test]
    fn strip_inline_hash_options_after_exact_pin() {
        let dir = setup_dir("requests==2.31.0 --hash=sha256:deadbeef\n");
        let deps = parse(&dir).expect("hash options should not make exact pins unreadable");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version.as_deref(), Some("==2.31.0"));
        cleanup(&dir);
    }

    #[test]
    fn skip_hash_continuation_lines() {
        let dir = setup_dir("requests==2.31.0 \\\n    --hash=sha256:deadbeef\n");
        let deps = parse(&dir).expect("pip-compile hash continuation lines should not fail");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version.as_deref(), Some("==2.31.0"));
        cleanup(&dir);
    }

    // ── Environment marker edge cases ──

    #[test]
    fn environment_marker_with_single_quotes() {
        let dir = setup_dir("pywin32>=300; sys_platform == 'win32'");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "pywin32");
        assert_eq!(deps[0].version, Some(">=300".to_string()));
        cleanup(&dir);
    }

    #[test]
    fn environment_marker_semicolon_inside_quotes_not_stripped() {
        // A semicolon inside quotes should NOT be treated as a marker delimiter
        // "pkg>=1.0; extra == \"foo;bar\"" — the ; inside quotes should be ignored
        let dir = setup_dir("pkg>=1.0; extra == \"foo;bar\"");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "pkg");
        assert_eq!(deps[0].version, Some(">=1.0".to_string()));
        cleanup(&dir);
    }

    // ── -r / --requirement include lines ──

    #[test]
    fn skip_r_include_flag() {
        let dir = setup_dir("-r base.txt\nflask==2.0");
        std::fs::write(dir.join("base.txt"), "requests==2.31.0\n").unwrap();
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|dep| dep.name == "flask"));
        assert!(deps.iter().any(|dep| dep.name == "requests"));
        cleanup(&dir);
    }

    #[test]
    fn skip_requirement_long_flag() {
        let dir = setup_dir("--requirement base.txt\nflask==2.0");
        std::fs::write(dir.join("base.txt"), "requests==2.31.0\n").unwrap();
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|dep| dep.name == "flask"));
        assert!(deps.iter().any(|dep| dep.name == "requests"));
        cleanup(&dir);
    }

    #[test]
    fn reject_editable_requirements() {
        let dir = setup_dir("-e .\nflask==2.0");
        let err = parse(&dir).expect_err("editable requirements must block scanning");
        assert!(err.to_string().contains("-e ."));
        cleanup(&dir);
    }

    #[test]
    fn reject_other_unsupported_flags() {
        let dir = setup_dir("-i https://pypi.org/simple\nflask==2.0");
        let err = parse(&dir).expect_err("unsupported flags must block scanning");
        assert!(err.to_string().contains("-i https://pypi.org/simple"));
        cleanup(&dir);
    }

    #[test]
    fn reject_vcs_url_requirements() {
        let dir = setup_dir("git+https://github.com/user/repo.git#egg=mypkg\n");
        let err = parse(&dir).expect_err("unsupported direct references must block scanning");
        assert!(
            err.to_string()
                .contains("git+https://github.com/user/repo.git#egg=mypkg")
        );
        cleanup(&dir);
    }

    #[test]
    fn reject_pep508_direct_url_requirements() {
        let dir = setup_dir("mypkg @ https://example.com/mypkg-1.0.0.tar.gz\n");
        let err = parse(&dir).expect_err("direct URL requirements must block scanning");
        assert!(
            err.to_string()
                .contains("https://example.com/mypkg-1.0.0.tar.gz")
        );
        cleanup(&dir);
    }

    #[test]
    fn reject_local_project_requirements() {
        let dir = setup_dir(".[prod]\n");
        let err = parse(&dir).expect_err("local project requirements must block scanning");
        assert!(err.to_string().contains("Unsupported local requirement"));
        cleanup(&dir);
    }

    #[test]
    fn reject_relative_path_requirements() {
        let dir = setup_dir("./vendor/pkg.whl\n");
        let err = parse(&dir).expect_err("relative path requirements must block scanning");
        assert!(err.to_string().contains("Unsupported local requirement"));
        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn detect_include_cycles_across_symlink_aliases() {
        let dir = setup_test_dir("req-cycle", "requirements.txt", "-r a/base.txt\n");
        std::fs::create_dir_all(dir.join("real")).unwrap();
        std::fs::write(dir.join("real/base.txt"), "-r ../b/base.txt\n").unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("a")).unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("b")).unwrap();

        let err = parse(&dir).expect_err("include cycles through symlink aliases must be detected");
        assert!(err.to_string().contains("include cycle"));
        cleanup(&dir);
    }

    // ── PEP 503 normalization edge cases ──

    #[test]
    fn normalize_underscores_and_dots() {
        let dir = setup_dir("My_Package.Name==1.0");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps[0].name, "my-package-name");
        cleanup(&dir);
    }

    #[test]
    fn normalize_consecutive_separators() {
        let dir = setup_dir("my__package..name==1.0");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps[0].name, "my-package-name");
        cleanup(&dir);
    }

    // ── Tilde-equals version specifier ──

    #[test]
    fn parse_tilde_equals_version() {
        let dir = setup_dir("Django~=4.2");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps[0].name, "django");
        assert_eq!(deps[0].version, Some("~=4.2".to_string()));
        cleanup(&dir);
    }

    // ── Not-equals version specifier ──

    #[test]
    fn parse_not_equals_version() {
        let dir = setup_dir("requests!=2.28.0");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version, Some("!=2.28.0".to_string()));
        cleanup(&dir);
    }

    // ── find_unquoted_semicolon unit tests ──

    #[test]
    fn find_unquoted_semicolon_basic() {
        assert_eq!(find_unquoted_semicolon("foo; bar"), Some(3));
    }

    #[test]
    fn find_unquoted_semicolon_none() {
        assert_eq!(find_unquoted_semicolon("foo bar"), None);
    }

    #[test]
    fn find_unquoted_semicolon_in_double_quotes() {
        assert_eq!(find_unquoted_semicolon(r#"foo "a;b" ; bar"#), Some(10));
    }

    #[test]
    fn find_unquoted_semicolon_in_single_quotes() {
        assert_eq!(find_unquoted_semicolon("foo 'a;b' ; bar"), Some(10));
    }

    // ── normalize_distribution_name unit tests ──

    #[test]
    fn normalize_distribution_name_strips_extras() {
        assert_eq!(normalize_distribution_name("requests[socks]"), "requests");
    }

    #[test]
    fn normalize_distribution_name_lowercases() {
        assert_eq!(normalize_distribution_name("Flask"), "flask");
    }

    #[test]
    fn normalize_distribution_name_empty_input() {
        assert_eq!(normalize_distribution_name(""), "");
    }
}
