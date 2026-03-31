use crate::Dependency;
use anyhow::{Context, Result};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let path = project_dir.join("requirements.txt");
    let content = super::read_file_limited(&path, super::MAX_MANIFEST_BYTES)
        .context("Failed to read requirements.txt")?;

    let mut deps = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Warn about -r/--requirement includes (deps in referenced files are not scanned)
        if line.starts_with('-') {
            if line.starts_with("-r ") || line.starts_with("--requirement") {
                eprintln!(
                    "Warning: requirements.txt includes '{}' — referenced file's dependencies are not scanned.",
                    crate::report::sanitize_for_terminal(line)
                );
            }
            continue;
        }

        // Skip URL-based requirements (e.g., git+https://github.com/...)
        if line.contains("://") {
            continue;
        }

        // Strip environment markers: split on unquoted `;` before version parsing
        let line = if let Some(semi_pos) = find_unquoted_semicolon(line) {
            line[..semi_pos].trim()
        } else {
            line
        };

        // Parse "package==version", "package>=version", "package~=version", or just "package"
        let (name, version) = if let Some(pos) = line.find(['=', '>', '<', '~', '!']) {
            let name = normalize_distribution_name(&line[..pos]);
            let version_part = line[pos..].trim();
            (name, Some(version_part.to_string()))
        } else {
            (normalize_distribution_name(line), None)
        };

        if !name.is_empty() {
            let dep = Dependency {
                name,
                version,
                ecosystem: crate::Ecosystem::PyPI,
            };
            super::validate_dependency(&dep, &path)?;
            deps.push(dep);
        }
    }

    Ok(deps)
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
fn normalize_distribution_name(raw: &str) -> String {
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
    fn skip_flags() {
        let dir = setup_dir("-r other.txt\nrequests==1.0");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "requests");
        cleanup(&dir);
    }

    #[test]
    fn skip_url_based_requirements() {
        let dir = setup_dir("git+https://github.com/user/repo.git#egg=pkg\nrequests==1.0");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "requests");
        cleanup(&dir);
    }

    #[test]
    fn skip_url_with_egg_fragment() {
        let dir = setup_dir("git+https://github.com/user/repo.git@v1.0#egg=mypkg\nflask==2.0");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "flask");
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
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "flask");
        cleanup(&dir);
    }

    #[test]
    fn skip_requirement_long_flag() {
        let dir = setup_dir("--requirement base.txt\nflask==2.0");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "flask");
        cleanup(&dir);
    }

    #[test]
    fn skip_other_flags() {
        // Other flags like -i, -e, --index-url should also be skipped (they start with -)
        let dir = setup_dir("-i https://pypi.org/simple\n-e .\nflask==2.0");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "flask");
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
