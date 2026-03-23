use crate::Dependency;
use anyhow::{Context, Result};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let path = project_dir.join("requirements.txt");
    let content = std::fs::read_to_string(&path).context("Failed to read requirements.txt")?;

    let mut deps = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
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
            deps.push(Dependency {
                name,
                version,
                ecosystem: "pypi".to_string(),
            });
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

fn normalize_distribution_name(raw: &str) -> String {
    raw.trim()
        .split('[')
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn setup_dir(content: &str) -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sj-req-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("requirements.txt"), content).unwrap();
        dir
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_simple_version() {
        let dir = setup_dir("requests==2.28.0\nflask==2.3.0");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version, Some("==2.28.0".to_string()));
        assert_eq!(deps[0].ecosystem, "pypi");
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
}
