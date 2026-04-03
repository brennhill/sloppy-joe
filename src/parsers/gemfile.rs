use crate::Dependency;
use anyhow::{Context, Result};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let path = project_dir.join("Gemfile");
    let content = super::read_file_limited(&path, super::MAX_MANIFEST_BYTES)
        .context("Failed to read Gemfile")?;

    let mut deps = Vec::new();

    for entry in collect_gem_entries(&content)? {
        if has_unsupported_gem_source(&entry) {
            anyhow::bail!(
                "Unsupported non-registry Gemfile dependency source in {}",
                path.display()
            );
        }

        if let Some((name, version)) = extract_gem_spec(&entry) {
            let dep = Dependency {
                name,
                version,
                ecosystem: crate::Ecosystem::Ruby,
                actual_name: None,
            };
            super::validate_dependency(&dep, &path)?;
            deps.push(dep);
        }
    }

    Ok(deps)
}

fn collect_gem_entries(content: &str) -> Result<Vec<String>> {
    let mut entries = Vec::new();
    let mut current = String::new();
    let mut in_entry = false;
    let mut state = RubyExpressionState::default();

    for raw_line in content.lines() {
        let trimmed = raw_line.trim();
        if !in_entry {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if trimmed.starts_with("gem ") || trimmed.starts_with("gem\t") {
                in_entry = true;
                current.clear();
            } else {
                continue;
            }
        }

        if !current.is_empty() {
            current.push('\n');
        }
        current.push_str(raw_line);
        state.ingest(raw_line);

        if state.is_complete(raw_line) {
            entries.push(current.clone());
            current.clear();
            in_entry = false;
            state = RubyExpressionState::default();
        }
    }

    if in_entry {
        anyhow::bail!("Unterminated Gemfile dependency declaration");
    }

    Ok(entries)
}

fn has_unsupported_gem_source(line: &str) -> bool {
    let normalized = strip_ruby_comments(line);
    [
        "git:",
        "github:",
        "gist:",
        "bitbucket:",
        "path:",
        "source:",
        "gitlab:",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn extract_gem_spec(line: &str) -> Option<(String, Option<String>)> {
    // Match gem 'name' or gem "name"
    let after_gem = line.strip_prefix("gem")?.trim_start();
    let after_gem = after_gem.trim_start_matches('(').trim_start();
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

fn strip_ruby_comments(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;

    for ch in line.chars() {
        if escape {
            out.push(ch);
            escape = false;
            continue;
        }
        match ch {
            '\\' if in_single || in_double => {
                out.push(ch);
                escape = true;
            }
            '\'' if !in_double => {
                in_single = !in_single;
                out.push(ch);
            }
            '"' if !in_single => {
                in_double = !in_double;
                out.push(ch);
            }
            '#' if !in_single && !in_double => break,
            _ => out.push(ch),
        }
    }

    out
}

#[derive(Default)]
struct RubyExpressionState {
    parens: usize,
    brackets: usize,
    braces: usize,
    in_single: bool,
    in_double: bool,
    escape: bool,
}

impl RubyExpressionState {
    fn ingest(&mut self, line: &str) {
        for ch in line.chars() {
            if self.escape {
                self.escape = false;
                continue;
            }
            match ch {
                '\\' if self.in_single || self.in_double => self.escape = true,
                '\'' if !self.in_double => self.in_single = !self.in_single,
                '"' if !self.in_single => self.in_double = !self.in_double,
                _ if self.in_single || self.in_double => {}
                '(' => self.parens += 1,
                ')' => self.parens = self.parens.saturating_sub(1),
                '[' => self.brackets += 1,
                ']' => self.brackets = self.brackets.saturating_sub(1),
                '{' => self.braces += 1,
                '}' => self.braces = self.braces.saturating_sub(1),
                _ => {}
            }
        }
    }

    fn is_complete(&self, line: &str) -> bool {
        self.parens == 0
            && self.brackets == 0
            && self.braces == 0
            && !self.in_single
            && !self.in_double
            && !line.trim_end().ends_with(',')
    }
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

    #[test]
    fn reject_git_sourced_gems() {
        let dir = setup_dir("gem 'rails', git: 'https://github.com/rails/rails'");
        let err = parse(&dir).expect_err("Gemfile git sources must fail closed");
        assert!(
            err.to_string()
                .contains("non-registry Gemfile dependency source")
        );
        cleanup(&dir);
    }

    #[test]
    fn reject_multiline_git_sourced_gems() {
        let dir = setup_dir(
            r#"
gem "rails",
  git: "https://github.com/rails/rails",
  branch: "main"
"#,
        );
        let err = parse(&dir).expect_err("multiline Gemfile sources must fail closed");
        assert!(
            err.to_string()
                .contains("non-registry Gemfile dependency source")
        );
        cleanup(&dir);
    }
}
