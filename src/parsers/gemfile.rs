use crate::Dependency;
use anyhow::{Context, Result};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let path = project_dir.join("Gemfile");
    let content = std::fs::read_to_string(&path).context("Failed to read Gemfile")?;

    let mut deps = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if (line.starts_with("gem ") || line.starts_with("gem\t"))
            && let Some(name) = extract_gem_name(line)
        {
            deps.push(Dependency {
                name,
                version: None,
                ecosystem: "ruby".to_string(),
            });
        }
    }

    Ok(deps)
}

fn extract_gem_name(line: &str) -> Option<String> {
    // Match gem 'name' or gem "name"
    let after_gem = line.strip_prefix("gem")?.trim_start();
    let quote = after_gem.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let rest = &after_gem[1..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn setup_dir(content: &str) -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sj-gemfile-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Gemfile"), content).unwrap();
        dir
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_single_quotes() {
        let dir = setup_dir("gem 'rails'");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "rails");
        assert_eq!(deps[0].ecosystem, "ruby");
        cleanup(&dir);
    }

    #[test]
    fn parse_double_quotes() {
        let dir = setup_dir("gem \"rails\"");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "rails");
        cleanup(&dir);
    }

    #[test]
    fn parse_with_version() {
        let dir = setup_dir("gem 'rails', '~> 7.0'");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "rails");
        cleanup(&dir);
    }

    #[test]
    fn skip_comments_and_blank_lines() {
        let dir = setup_dir("# comment\n\ngem 'rails'\n  \n# another");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        cleanup(&dir);
    }

    #[test]
    fn multiple_gems() {
        let dir = setup_dir("gem 'rails'\ngem \"puma\"\ngem 'sidekiq', '~> 6.0'");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 3);
        cleanup(&dir);
    }

    #[test]
    fn extract_gem_name_single_quotes() {
        assert_eq!(extract_gem_name("gem 'rails'"), Some("rails".to_string()));
    }

    #[test]
    fn extract_gem_name_double_quotes() {
        assert_eq!(extract_gem_name("gem \"puma\""), Some("puma".to_string()));
    }

    #[test]
    fn extract_gem_name_no_quotes() {
        assert_eq!(extract_gem_name("gem rails"), None);
    }
}
