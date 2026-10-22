use crate::Dependency;
use anyhow::{Context, Result};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let path = project_dir.join("Gemfile");
    let content = super::read_file_limited(&path, super::MAX_MANIFEST_BYTES)
        .context("Failed to read Gemfile")?;

    for line in content.lines() {
        let line = strip_ruby_comments(line);
        let line = line.trim();
        let method = line
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .next();
        let trusted_source = line
            .strip_prefix("source")
            .and_then(|argument| {
                literal_arguments(
                    argument
                        .trim()
                        .strip_suffix("do")
                        .unwrap_or(argument)
                        .trim(),
                )
            })
            .is_some_and(|arguments| {
                arguments.len() == 1 && arguments[0].trim_end_matches('/') == "https://rubygems.org"
            });

        if matches!(method, Some("git" | "path" | "github" | "git_source"))
            || (method == Some("source") && !trusted_source)
        {
            anyhow::bail!(
                "Unsupported non-registry Gemfile dependency source in {}",
                path.display()
            );
        }
    }

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
        } else {
            anyhow::bail!(
                "Unsupported dynamic Gemfile dependency declaration in {}",
                path.display()
            );
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
        let uncommented = strip_ruby_comments(raw_line);
        let trimmed = uncommented.trim();
        if !in_entry {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if trimmed.starts_with("gem ")
                || trimmed.starts_with("gem\t")
                || trimmed.starts_with("gem(")
            {
                in_entry = true;
                current.clear();
            } else {
                let method = trimmed.split_whitespace().next().unwrap_or_default();
                let literal_runtime = method == "ruby"
                    && literal_arguments(trimmed[4..].trim())
                        .is_some_and(|arguments| arguments.len() == 1);
                let literal_group = matches!(method, "group" | "platform" | "platforms")
                    && trimmed.strip_suffix("do").is_some_and(|prefix| {
                        prefix[method.len()..].split(',').all(|symbol| {
                            symbol.trim().strip_prefix(':').is_some_and(|name| {
                                !name.is_empty()
                                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                            })
                        })
                    });
                if (method == "source" || trimmed == "end" || literal_runtime || literal_group)
                    && !trimmed.contains(';')
                {
                    continue;
                }
                anyhow::bail!(
                    "Unsupported Gemfile statement: dependency declarations cannot be verified"
                );
            }
        }

        if uncommented.contains(';') {
            anyhow::bail!(
                "Unsupported inline Gemfile statements: dependency declarations cannot be verified"
            );
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
    let args = line.trim_start().strip_prefix("gem")?;
    let mut arguments = literal_arguments(args)?.into_iter();
    let name = arguments.next()?;
    let version = arguments.next();
    if arguments.next().is_some() {
        return None;
    }
    Some((name, version))
}

fn literal_arguments(expression: &str) -> Option<Vec<String>> {
    let mut remaining = expression.trim();
    if let Some(body) = remaining.strip_prefix('(') {
        remaining = body.strip_suffix(')')?.trim();
    }
    let mut arguments = Vec::new();
    loop {
        let quote = remaining.chars().next()?;
        if !matches!(quote, '\'' | '"') {
            return None;
        }
        let body = &remaining[1..];
        let end = body.find(quote)?;
        let literal = &body[..end];
        if literal.contains('\\') || literal.contains("#{") {
            return None;
        }
        arguments.push(literal.to_string());
        remaining = body[end + 1..].trim();
        if remaining.is_empty() {
            return Some(arguments);
        }
        remaining = remaining.strip_prefix(',')?.trim();
    }
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
    fn parse_parenthesized_and_indented_gems() {
        for declaration in ["gem('rake', '13.0.6')", "  gem 'rake', '13.0.6'"] {
            let dir = setup_dir(declaration);
            let deps = parse(&dir).unwrap();
            assert_eq!(deps.len(), 1);
            assert_eq!(deps[0].name, "rake");
            assert_eq!(deps[0].version.as_deref(), Some("13.0.6"));
            cleanup(&dir);
        }
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
    fn reject_side_effects_in_otherwise_literal_gemfile_statements() {
        for body in [
            "gem 'rake', '13.0.6' and gem 'payload', '1.0.0'",
            "gem 'rake', '13.0.6', require: gem('payload', '1.0.0')",
            "group gem('payload', '1.0.0') do\nend",
            "ruby '3.2' if gem('payload', '1.0.0')",
        ] {
            let dir = setup_dir(body);
            assert!(
                parse(&dir).is_err(),
                "unmodeled expressions must fail closed: {body}"
            );
            cleanup(&dir);
        }
    }

    #[test]
    fn reject_dynamic_or_hidden_gem_declarations() {
        for body in [
            "gem package_name",
            "eval_gemfile 'other.Gemfile'",
            "gemspec",
            "source 'https://rubygems.org'; gem('payload', '1.0.0')",
            "source 'https://rubygems.org' + '.attacker.example'",
            "group :test do gem 'payload', '1.0.0' end",
        ] {
            let dir = setup_dir(body);
            assert!(
                parse(&dir).is_err(),
                "unmodeled Gemfile code must fail closed: {body}"
            );
            cleanup(&dir);
        }
    }

    #[test]
    fn reject_block_level_dependency_sources() {
        for source in [
            "git 'https://example.com/payload.git'",
            "path '../payload'",
            "source 'https://example.com/gems'",
        ] {
            let dir = setup_dir(&format!("{source} do\n gem 'rake', '13.0.6'\nend\n"));
            let err =
                parse(&dir).expect_err("block sources must not inherit public registry trust");
            assert!(err.to_string().contains("Gemfile dependency source"));
            cleanup(&dir);
        }
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
