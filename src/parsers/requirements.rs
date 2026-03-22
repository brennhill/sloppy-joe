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
    fn strip_extras_from_distribution_name() {
        let dir = setup_dir("requests[socks]==2.28.0");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version, Some("==2.28.0".to_string()));
        cleanup(&dir);
    }
}
