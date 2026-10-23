use crate::Dependency;
use anyhow::{Context, Result};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let project_dir = std::fs::canonicalize(project_dir)?;
    let boundary = crate::config::registry::find_git_root(&project_dir)
        .map_err(anyhow::Error::msg)?
        .unwrap_or_else(|| project_dir.clone());
    for ancestor in project_dir
        .ancestors()
        .take_while(|path| path.starts_with(&boundary))
    {
        let config = ancestor.join(".bundle/config");
        if super::path_detected(&config)? {
            anyhow::bail!(
                "Unsupported Bundler configuration '{}': registry mirrors and local overrides cannot be verified",
                config.display()
            );
        }
    }
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
    let mut gemspecs = Vec::new();
    for line in content.lines() {
        let line = strip_ruby_comments(line);
        if let Some(statement) = gemspec_statement(line.trim()) {
            gemspecs.push(statement?);
        }
    }

    for entry in collect_gem_entries(&content)? {
        let entry = strip_condition_modifier(&entry);
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

    for name in gemspecs {
        deps.extend(parse_gemspec(&project_dir, name.as_deref())?);
    }

    Ok(deps)
}

/// `gemspec`, `gemspec name: 'x'` or `gemspec :name => 'x'`. `Some(Err)`: a
/// `gemspec` call with options that could point somewhere else.
fn gemspec_statement(trimmed: &str) -> Option<Result<Option<String>>> {
    let rest = trimmed.strip_prefix("gemspec")?;
    if rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let unsupported = || {
        Some(Err(anyhow::anyhow!(
            "Unsupported gemspec options '{}': only a plain `gemspec` or `gemspec name: \"x\"` can be verified",
            crate::report::sanitize_for_terminal(trimmed)
        )))
    };
    let mut rest = rest.trim();
    if let Some(inner) = rest.strip_prefix('(') {
        let Some(inner) = inner.strip_suffix(')') else {
            return unsupported();
        };
        rest = inner.trim();
    }
    if rest.is_empty() {
        return Some(Ok(None));
    }
    let value = rest
        .strip_prefix("name:")
        .or_else(|| {
            rest.strip_prefix(":name")
                .and_then(|r| r.trim_start().strip_prefix("=>"))
        })
        .map(str::trim);
    let Some((name, tail)) = value.and_then(take_string_literal) else {
        return unsupported();
    };
    let plain = !name.is_empty()
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !tail.trim().is_empty() || !plain {
        return unsupported();
    }
    Some(Ok(Some(name)))
}

/// Dependencies a project's own `.gemspec` adds to the bundle. Only literal
/// `add_dependency "name", "requirement"...` calls are understood.
fn parse_gemspec(project_dir: &Path, name: Option<&str>) -> Result<Vec<Dependency>> {
    let path = match name {
        Some(name) => project_dir.join(format!("{name}.gemspec")),
        None => {
            let mut found = Vec::new();
            for entry in std::fs::read_dir(project_dir)? {
                let entry = entry?;
                if entry.file_name().to_string_lossy().ends_with(".gemspec") {
                    found.push(entry.path());
                }
            }
            match found.as_slice() {
                [only] => only.clone(),
                _ => anyhow::bail!(
                    "Unsupported `gemspec` in {}: expected exactly one .gemspec file, found {}",
                    project_dir.display(),
                    found.len()
                ),
            }
        }
    };
    if !super::path_detected(&path)? {
        anyhow::bail!(
            "`gemspec` in the Gemfile names missing file {}",
            path.display()
        );
    }
    let content = super::read_file_limited(&path, super::MAX_MANIFEST_BYTES)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let text: String = content
        .lines()
        .map(strip_ruby_comments)
        .collect::<Vec<_>>()
        .join("\n");
    let unsupported = |why: &str| {
        anyhow::anyhow!(
            "Unsupported gemspec {}: {why}; dependency declarations cannot be verified",
            path.display()
        )
    };
    if text.contains(".dependencies")
        || text
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|w| w.contains("eval"))
    {
        return Err(unsupported("it modifies dependencies dynamically"));
    }
    let mut deps = Vec::new();
    let mut offset = 0usize;
    while let Some(found) = text[offset..].find("add_") {
        let start = offset + found;
        offset = start + 4;
        let after_add = &text[start + 4..];
        let method_tail = ["runtime_dependency", "development_dependency", "dependency"]
            .iter()
            .find_map(|m| after_add.strip_prefix(m));
        let Some(mut rest) = method_tail else {
            continue;
        };
        if rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        rest = rest.trim_start_matches([' ', '\t']);
        let parenthesized = rest.starts_with('(');
        if parenthesized {
            rest = &rest[1..];
        }
        let mut literals = Vec::new();
        let mut after_last = rest;
        loop {
            rest = rest.trim_start();
            let Some((literal, tail)) = take_string_literal(rest) else {
                return Err(unsupported("a dependency argument is not a plain string"));
            };
            if literal.contains('"') {
                return Err(unsupported("a dependency argument contains a quote"));
            }
            literals.push(literal);
            after_last = tail;
            rest = tail.trim_start();
            match rest.strip_prefix(',') {
                Some(next) => rest = next,
                None => break,
            }
        }
        rest = after_last;
        if parenthesized {
            let Some(next) = rest.trim_start().strip_prefix(')') else {
                return Err(unsupported("a dependency call is not closed"));
            };
            rest = next;
        }
        let line_tail = rest.split('\n').next().unwrap_or_default().trim();
        if !(line_tail.is_empty()
            || line_tail.starts_with('}')
            || line_tail.starts_with(';')
            || line_tail == "end")
        {
            return Err(unsupported("a dependency call has trailing expressions"));
        }
        let quoted: Vec<String> = literals.iter().map(|l| format!("\"{l}\"")).collect();
        let Some((name, version)) = extract_gem_spec(&format!("gem {}", quoted.join(", "))) else {
            return Err(unsupported("a dependency has an unrecognized requirement"));
        };
        let dep = Dependency {
            name,
            version,
            ecosystem: crate::Ecosystem::Ruby,
            actual_name: None,
        };
        super::validate_dependency(&dep, &path)?;
        deps.push(dep);
    }
    Ok(deps)
}

/// A condition guarding gems (`RUBY_VERSION >= "3.4"`, `ENV["CI"]`). Both
/// branches are scanned, so the condition's value never changes what is
/// verified; it only has to be unable to declare gems or run commands itself.
fn simple_condition(condition: &str) -> bool {
    let condition = condition.trim();
    if condition.is_empty() || condition.ends_with(['\\', ',']) {
        return false;
    }
    let allowed = |c: char| {
        c.is_ascii_alphanumeric()
            || c.is_whitespace()
            || matches!(
                c,
                '_' | '.'
                    | '\''
                    | '"'
                    | '['
                    | ']'
                    | '('
                    | ')'
                    | '='
                    | '!'
                    | '<'
                    | '>'
                    | '&'
                    | '|'
                    | '~'
                    | ':'
                    | '-'
            )
    };
    if !condition.chars().all(allowed) {
        return false;
    }
    const FORBIDDEN: &[&str] = &[
        "gem",
        "gemspec",
        "source",
        "git",
        "github",
        "path",
        "group",
        "platforms",
        "eval",
        "instance_eval",
        "system",
        "exec",
        "require",
        "load",
        "send",
        "File",
        "IO",
        "Kernel",
        "Dir",
        "Open3",
        "Process",
        "do",
    ];
    !condition
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|word| FORBIDDEN.contains(&word))
}

/// Removes a trailing `if <cond>` / `unless <cond>` modifier from a gem
/// declaration when the condition is simple (see [`simple_condition`]).
fn strip_condition_modifier(entry: &str) -> String {
    let mut quote: Option<char> = None;
    let bytes: Vec<char> = entry.chars().collect();
    for (idx, ch) in bytes.iter().enumerate() {
        match quote {
            Some(open) if *ch == open => quote = None,
            Some(_) => {}
            None if matches!(ch, '\'' | '"') => quote = Some(*ch),
            None if ch.is_whitespace() => {
                let rest: String = bytes[idx + 1..].iter().collect();
                for keyword in ["if ", "unless "] {
                    if let Some(condition) = rest.strip_prefix(keyword)
                        && simple_condition(condition)
                    {
                        return bytes[..idx].iter().collect();
                    }
                }
            }
            None => {}
        }
    }
    entry.to_string()
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
            if let Some(statement) = gemspec_statement(trimmed) {
                statement?;
                continue;
            }
            if trimmed.starts_with("gem ")
                || trimmed.starts_with("gem\t")
                || trimmed.starts_with("gem(")
            {
                in_entry = true;
                current.clear();
            } else {
                let method = trimmed
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .next()
                    .unwrap_or_default();
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
                let literal_conditional = match method {
                    "else" => trimmed == "else",
                    "if" | "unless" | "elsif" => simple_condition(&trimmed[method.len()..]),
                    _ => false,
                };
                if (method == "source"
                    || trimmed == "end"
                    || literal_runtime
                    || literal_group
                    || literal_conditional)
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
        current.push_str(&uncommented);
        state.ingest(&uncommented);

        if state.is_complete(&uncommented) {
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
    let mut remaining = args.trim();
    if let Some(body) = remaining.strip_prefix('(') {
        remaining = body.strip_suffix(')')?.trim();
    }
    let mut positional = Vec::new();
    while remaining.starts_with(['\'', '"']) {
        let (literal, rest) = take_string_literal(remaining)?;
        positional.push(literal);
        remaining = rest.trim();
        if remaining.is_empty() {
            break;
        }
        remaining = remaining.strip_prefix(',')?.trim();
        if remaining.is_empty() {
            return None;
        }
    }
    if !remaining.is_empty() && !static_gem_options(remaining) {
        return None;
    }
    let mut arguments = positional.into_iter();
    let name = arguments.next()?;
    let constraints: Vec<String> = arguments.collect();
    let version = match constraints.as_slice() {
        [] => None,
        [single] => Some(single.clone()),
        // Bundler accepts any number of requirement strings and ANDs them.
        // Keep all of them, in Gemfile.lock's `a, b` notation; a comma-joined
        // requirement is never treated as an exact pin.
        many => {
            if !many.iter().all(|c| is_gem_requirement(c)) {
                return None;
            }
            Some(many.iter().map(|c| c.trim()).collect::<Vec<_>>().join(", "))
        }
    };
    Some((name, version))
}

/// One `Gem::Requirement` clause: an optional operator followed by a
/// `Gem::Version`. Anything else would be rejected by Bundler, so it fails
/// closed here instead of being guessed at.
fn is_gem_requirement(constraint: &str) -> bool {
    let constraint = constraint.trim();
    let version = ["~>", ">=", "<=", "!=", "=", ">", "<"]
        .iter()
        .find_map(|op| constraint.strip_prefix(op))
        .unwrap_or(constraint)
        .trim();
    let mut chars = version.chars();
    chars.next().is_some_and(|c| c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
}

/// Read one quoted literal without escapes or interpolation.
fn take_string_literal(expression: &str) -> Option<(String, &str)> {
    let quote = expression.chars().next()?;
    if !matches!(quote, '\'' | '"') {
        return None;
    }
    let body = &expression[1..];
    let end = body.find(quote)?;
    let literal = &body[..end];
    if literal.contains('\\') || literal.contains("#{") {
        return None;
    }
    Some((literal.to_string(), &body[end + 1..]))
}

/// Gem options that only affect Bundler's require/group/platform behavior and
/// carry static literal values. Anything else (sources, lambdas, method
/// calls, unknown keys) is treated as dynamic and fails closed upstream.
const STATIC_GEM_OPTION_KEYS: &[&str] = &["require", "group", "groups", "platform", "platforms"];

fn static_gem_options(expression: &str) -> bool {
    let mut remaining = expression.trim();
    loop {
        let key_end = remaining
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
            .unwrap_or(remaining.len());
        let (key, rest) = if let Some(symbol) = remaining.strip_prefix(':') {
            // `:key => value`
            let end = symbol
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(symbol.len());
            let Some(rest) = symbol[end..].trim_start().strip_prefix("=>") else {
                return false;
            };
            (&symbol[..end], rest)
        } else if let Some(key) = remaining[..key_end].strip_suffix(':') {
            // `key: value`
            (key, &remaining[key_end..])
        } else {
            return false;
        };
        if !STATIC_GEM_OPTION_KEYS.contains(&key) {
            return false;
        }
        let Some(rest) = take_static_option_value(rest.trim_start()) else {
            return false;
        };
        let rest = rest.trim();
        if rest.is_empty() {
            return true;
        }
        let Some(rest) = rest.strip_prefix(',') else {
            return false;
        };
        remaining = rest.trim();
    }
}

fn is_ruby_word(word: &str) -> bool {
    !word.is_empty() && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `true`, `false`, `nil`, `:symbol`, a plain string, `[...]` of symbols or
/// strings, or `%i[...]` / `%w[...]` word lists.
fn take_static_option_value(expression: &str) -> Option<&str> {
    for keyword in ["true", "false", "nil"] {
        if let Some(rest) = expression.strip_prefix(keyword)
            && !rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        {
            return Some(rest);
        }
    }
    if let Some(symbol) = expression.strip_prefix(':') {
        let end = symbol
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(symbol.len());
        return is_ruby_word(&symbol[..end]).then(|| &symbol[end..]);
    }
    if expression.starts_with(['\'', '"']) {
        return take_string_literal(expression).map(|(_, rest)| rest);
    }
    if let Some(list) = expression
        .strip_prefix("%i[")
        .or_else(|| expression.strip_prefix("%w["))
    {
        let end = list.find(']')?;
        return list[..end]
            .split_whitespace()
            .all(is_ruby_word)
            .then(|| &list[end + 1..]);
    }
    if let Some(list) = expression.strip_prefix('[') {
        let end = list.find(']')?;
        let all_static = list[..end].split(',').all(|item| {
            let item = item.trim();
            take_static_option_value(item).is_some_and(|rest| rest.trim().is_empty())
                && !item.starts_with('[')
        });
        return all_static.then(|| &list[end + 1..]);
    }
    None
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
#[path = "gemfile_gemspec_tests.rs"]
mod gemspec_tests;

#[cfg(test)]
#[path = "gemfile_constraint_tests.rs"]
mod constraint_tests;

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
    fn parse_literal_groups_and_multiline_gems_with_comments() {
        let dir = setup_dir(
            r#"
source("https://rubygems.org") # registry
ruby "3.2" # runtime
group :development, :test do
  gem(
    "rake", # package name
    "13.0.6" # pinned version
  )
end
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "rake");
        assert_eq!(deps[0].version.as_deref(), Some("13.0.6"));
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
    fn reject_repository_bundler_mirror_configuration() {
        let dir = setup_dir("source 'https://rubygems.org'\ngem 'rake', '13.0.6'\n");
        std::fs::create_dir(dir.join(".bundle")).unwrap();
        std::fs::write(
            dir.join(".bundle/config"),
            "---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: https://attacker.example\n",
        )
        .unwrap();
        let err = parse(&dir).expect_err("Bundler mirrors can redirect otherwise trusted gems");
        assert!(err.to_string().contains(".bundle/config"));
        cleanup(&dir);
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

#[cfg(test)]
mod gem_option_tests {
    use super::*;
    use crate::parsers::test_utils::*;

    #[test]
    fn accept_static_gem_options() {
        for body in [
            "gem 'bootsnap', require: false",
            "gem \"bootsnap\", \"1.18.4\", require: false",
            "gem 'bootsnap', '1.18.4', require: 'bootsnap/setup'",
            "gem 'bootsnap', group: :development",
            "gem 'bootsnap', '1.18.4', groups: [:development, :test], platforms: %i[mri windows]",
            "gem 'bootsnap', platforms: [:mri, :mingw], require: nil",
            "gem 'bootsnap', :require => false, :group => :test",
            "gem('bootsnap', '1.18.4', require: false)",
            "gem 'bootsnap', '1.18.4',\n  require: false,\n  platform: :ruby",
        ] {
            let dir = setup_test_dir("gemfile", "Gemfile", body);
            let deps = parse(&dir).unwrap_or_else(|err| panic!("{body}: {err}"));
            assert_eq!(deps.len(), 1, "{body}");
            assert_eq!(deps[0].name, "bootsnap");
            cleanup(&dir);
        }
    }

    #[test]
    fn reject_dynamic_gem_options() {
        for body in [
            "gem 'bootsnap', require: ENV['X']",
            "gem 'bootsnap', install_if: -> { true }",
            "gem 'bootsnap', require: \"#{name}\"",
            "gem 'bootsnap', group: some_group",
            "gem 'bootsnap', require: false, 'extra'",
            "gem 'bootsnap', unknown_option: true",
        ] {
            let dir = setup_test_dir("gemfile", "Gemfile", body);
            assert!(parse(&dir).is_err(), "must fail closed: {body}");
            cleanup(&dir);
        }
    }
}
