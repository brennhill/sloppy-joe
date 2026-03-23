use crate::Dependency;
use anyhow::{Context, Result};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let path = project_dir.join("Gemfile");
    let content = super::read_file_limited(&path, super::MAX_MANIFEST_BYTES)
        .context("Failed to read Gemfile")?;

    let mut deps = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if (line.starts_with("gem ") || line.starts_with("gem\t"))
            && let Some((name, version)) = extract_gem_spec(line)
        {
            deps.push(Dependency {
                name,
                version,
                ecosystem: crate::Ecosystem::Ruby,
            });
        }
    }

    Ok(deps)
}

fn extract_gem_spec(line: &str) -> Option<(String, Option<String>)> {
    // Match gem 'name' or gem "name"
    let after_gem = line.strip_prefix("gem")?.trim_start();
    let quote = after_gem.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let rest = &after_gem[1..];
    let end = rest.find(quote)?;
    let name = rest[..end].to_string();
    let version = after_gem[end + 2..]
        .split(',')
        .map(str::trim)
        .find_map(|part| {
            let part = part.trim_start_matches(',').trim();
            if part.starts_with('\'') || part.starts_with('"') {
                let q = part.chars().next()?;
                let remainder = &part[1..];
                let end = remainder.find(q)?;
                Some(remainder[..end].to_string())
            } else {
                None
            }
        });
    Some((name, version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::test_utils::*;

    fn setup_dir(content: &str) -> std::path::PathBuf {
        setup_test_dir("gemfile", "Gemfile", content)
    }

    #[test]
    fn parse_single_quotes() {
        let dir = setup_dir("gem 'rails'");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "rails");
        assert_eq!(deps[0].ecosystem, crate::Ecosystem::Ruby);
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
        assert_eq!(deps[0].version, Some("~> 7.0".to_string()));
        cleanup(&dir);
    }

    #[test]
    fn parse_exact_version() {
        let dir = setup_dir("gem 'rails', '7.0.4'");
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].version, Some("7.0.4".to_string()));
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
        assert_eq!(
            extract_gem_spec("gem 'rails'"),
            Some(("rails".to_string(), None))
        );
    }

    #[test]
    fn extract_gem_name_double_quotes() {
        assert_eq!(
            extract_gem_spec("gem \"puma\""),
            Some(("puma".to_string(), None))
        );
    }

    #[test]
    fn extract_gem_name_no_quotes() {
        assert_eq!(extract_gem_spec("gem rails"), None);
    }

    #[test]
    fn extract_gem_name_and_version() {
        assert_eq!(
            extract_gem_spec("gem 'rails', '7.0.4'"),
            Some(("rails".to_string(), Some("7.0.4".to_string())))
        );
    }
}
