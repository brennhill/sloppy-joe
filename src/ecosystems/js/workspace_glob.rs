//! Workspace member patterns as npm, pnpm, Yarn and Bun expand them: `*`, `?`, `**`, character
//! classes (`[a-c]`, `[!b]`), brace alternatives and ranges (`{a,b}`, `{1..3}`) and leading-`!`
//! negation. Syntax that is not modeled, or that the managers read differently (extglobs and
//! regex groups, backslash escapes, POSIX classes, patterns that leave the workspace root), is
//! rejected: a pattern that silently matched nothing would let a member's own lockfile stand in
//! for the workspace lockfile the package manager actually installs from.
//!
//! Where the managers differ, the reading that makes more directories members wins: positive
//! patterns match without regard to case (npm's glob does so on macOS and Windows), negated ones
//! only exactly.

use anyhow::Result;
use std::path::Path;

/// How a leading-`!` pattern combines with the others.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Negation {
    /// npm, Yarn and Bun: the last pattern that matches a directory decides, so a later positive
    /// pattern adds a member back. It is the wider of the two readings.
    Ordered,
    /// pnpm (fast-glob): a negated pattern excludes its matches whatever the order.
    Global,
}

#[derive(Clone, Debug)]
pub(crate) struct WorkspaceGlobs {
    rules: Vec<Rule>,
    negation: Negation,
}

#[derive(Clone, Debug)]
struct Rule {
    negated: bool,
    /// One segment list per brace expansion.
    alternatives: Vec<Vec<Segment>>,
}

#[derive(Clone, Debug)]
enum Segment {
    Globstar,
    Name(Vec<Token>),
}

#[derive(Clone, Debug)]
enum Token {
    Char(char),
    AnyChar,
    AnyRun,
    Class {
        negated: bool,
        ranges: Vec<(char, char)>,
    },
}

/// Brace expansion beyond this many patterns blocks instead of growing without bound.
const MAX_EXPANSIONS: usize = 1024;

impl WorkspaceGlobs {
    /// Compile every pattern; any pattern that cannot be evaluated exactly is an error naming it.
    pub(crate) fn compile(patterns: &[String], negation: Negation) -> Result<Self> {
        let rules = patterns
            .iter()
            .map(|pattern| {
                compile_rule(pattern).map_err(|reason| {
                    anyhow::anyhow!(
                        "Unsupported workspace pattern '{}': {}. The package manager may install members sloppy-joe cannot identify. Fix: rewrite it with *, **, ?, [...], {{a,b}} or a leading !.",
                        crate::report::sanitize_for_terminal(pattern),
                        reason
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { rules, negation })
    }

    /// Whether `candidate_dir` (below `root_dir`) is a workspace member. The root itself is not.
    pub(crate) fn matches(&self, root_dir: &Path, candidate_dir: &Path) -> bool {
        let Ok(relative) = candidate_dir.strip_prefix(root_dir) else {
            return false;
        };
        let parts = relative
            .components()
            .filter_map(|component| match component {
                std::path::Component::Normal(part) => Some(part.to_string_lossy().to_string()),
                _ => None,
            })
            .collect::<Vec<_>>();
        !parts.is_empty() && self.matches_parts(&parts)
    }

    fn matches_parts(&self, parts: &[String]) -> bool {
        match self.negation {
            Negation::Ordered => self
                .rules
                .iter()
                .rev()
                .find(|rule| rule.matches(parts))
                .is_some_and(|rule| !rule.negated),
            Negation::Global => {
                self.rules
                    .iter()
                    .any(|rule| !rule.negated && rule.matches(parts))
                    && !self
                        .rules
                        .iter()
                        .any(|rule| rule.negated && rule.matches(parts))
            }
        }
    }
}

impl Rule {
    fn matches(&self, parts: &[String]) -> bool {
        let fold_case = !self.negated;
        self.alternatives
            .iter()
            .any(|segments| path_matches(segments, parts, fold_case))
    }
}

fn compile_rule(pattern: &str) -> std::result::Result<Rule, String> {
    let trimmed = pattern.trim();
    let (negated, body) = match trimmed.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, trimmed),
    };
    reject_unmodeled(body)?;
    let mut expanded = Vec::new();
    expand_braces(body, &mut expanded)?;
    let alternatives = expanded
        .iter()
        .map(|path| compile_path(path))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(Rule {
        negated,
        alternatives,
    })
}

fn reject_unmodeled(body: &str) -> std::result::Result<(), String> {
    if body.is_empty() {
        return Err("the pattern is empty".into());
    }
    if body.starts_with('!') {
        return Err("repeated '!' negation is not modeled".into());
    }
    if body.contains('\\') {
        return Err(
            "backslash escapes are read differently by npm and by pnpm, Yarn and Bun".into(),
        );
    }
    if body.contains(['(', ')', '|']) {
        return Err("extglobs and '(a|b)' groups are not modeled".into());
    }
    if body.contains("[:") {
        return Err("POSIX character classes are not modeled".into());
    }
    Ok(())
}

/// Expand `{a,b}` alternatives and `{1..3}` / `{a..c}` ranges, nested braces included.
fn expand_braces(pattern: &str, out: &mut Vec<String>) -> std::result::Result<(), String> {
    let Some((open, close)) = first_brace_pair(pattern)? else {
        if out.len() >= MAX_EXPANSIONS {
            return Err(format!("brace expansion exceeds {MAX_EXPANSIONS} patterns"));
        }
        out.push(pattern.to_string());
        return Ok(());
    };
    let (prefix, body, suffix) = (
        &pattern[..open],
        &pattern[open + 1..close],
        &pattern[close + 1..],
    );
    let alternatives = match split_top_level_commas(body) {
        parts if parts.len() > 1 => parts,
        _ => brace_range(body)?,
    };
    for alternative in alternatives {
        expand_braces(&format!("{prefix}{alternative}{suffix}"), out)?;
    }
    Ok(())
}

/// Byte offsets of the first `{` and its matching `}`. Unbalanced braces are an error.
fn first_brace_pair(pattern: &str) -> std::result::Result<Option<(usize, usize)>, String> {
    let mut open = None;
    let mut depth = 0usize;
    for (at, ch) in pattern.char_indices() {
        match ch {
            '{' => {
                open.get_or_insert(at);
                depth += 1;
            }
            '}' if depth == 0 => return Err("unbalanced '}'".into()),
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(open.map(|open| (open, at)));
                }
            }
            _ => {}
        }
    }
    match open {
        Some(_) => Err("unbalanced '{'".into()),
        None => Ok(None),
    }
}

fn split_top_level_commas(body: &str) -> Vec<String> {
    let mut parts = vec![String::new()];
    let mut depth = 0usize;
    for ch in body.chars() {
        match ch {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(String::new());
                continue;
            }
            _ => {}
        }
        parts.last_mut().expect("parts is never empty").push(ch);
    }
    parts
}

/// `{x..y}` or `{x..y..step}` over integers or single letters.
fn brace_range(body: &str) -> std::result::Result<Vec<String>, String> {
    let fields = body.split("..").collect::<Vec<_>>();
    let step = match fields.as_slice() {
        [_, _] => 1,
        [_, _, step] => step
            .parse::<i64>()
            .map_err(|_| format!("brace range step '{step}' is not an integer"))?
            .unsigned_abs()
            .max(1),
        _ => {
            return Err(format!(
                "'{{{body}}}' is neither a list of alternatives nor a range"
            ));
        }
    };
    let (start, end) = (fields[0], fields[1]);
    if let (Ok(from), Ok(to)) = (start.parse::<i64>(), end.parse::<i64>()) {
        return numeric_range(start, end, from, to, step);
    }
    match (single_char(start), single_char(end)) {
        (Some(from), Some(to)) if from.is_ascii_alphabetic() && to.is_ascii_alphabetic() => {
            let values = stepped(from as i64, to as i64, step)?;
            Ok(values
                .into_iter()
                .filter_map(|value| char::from_u32(value as u32).map(String::from))
                .collect())
        }
        _ => Err(format!(
            "'{{{body}}}' is neither a list of alternatives nor a range"
        )),
    }
}

fn numeric_range(
    start: &str,
    end: &str,
    from: i64,
    to: i64,
    step: u64,
) -> std::result::Result<Vec<String>, String> {
    let padded = |text: &str| {
        let digits = text.trim_start_matches('-');
        digits.len() > 1 && digits.starts_with('0')
    };
    let width = if padded(start) || padded(end) {
        start.len().max(end.len())
    } else {
        0
    };
    Ok(stepped(from, to, step)?
        .into_iter()
        .map(|value| match value < 0 {
            true => format!(
                "-{:0>width$}",
                value.unsigned_abs(),
                width = width.saturating_sub(1)
            ),
            false => format!("{value:0>width$}"),
        })
        .collect())
}

fn stepped(from: i64, to: i64, step: u64) -> std::result::Result<Vec<i64>, String> {
    let span = from.abs_diff(to) / step;
    if span >= MAX_EXPANSIONS as u64 {
        return Err(format!("brace range exceeds {MAX_EXPANSIONS} patterns"));
    }
    let step = step as i64;
    Ok((0..=span as i64)
        .map(|index| match from <= to {
            true => from + index * step,
            false => from - index * step,
        })
        .collect())
}

fn single_char(text: &str) -> Option<char> {
    let mut chars = text.chars();
    let first = chars.next()?;
    chars.next().is_none().then_some(first)
}

fn compile_path(path: &str) -> std::result::Result<Vec<Segment>, String> {
    if path.starts_with('/') {
        return Err("absolute paths are outside the workspace root".into());
    }
    let mut segments = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => return Err("'..' leaves the workspace root".into()),
            "**" => {
                if !matches!(segments.last(), Some(Segment::Globstar)) {
                    segments.push(Segment::Globstar);
                }
            }
            name => segments.push(Segment::Name(compile_name(name)?)),
        }
    }
    Ok(segments)
}

fn compile_name(name: &str) -> std::result::Result<Vec<Token>, String> {
    let chars = name.chars().collect::<Vec<_>>();
    let mut tokens = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        match chars[at] {
            '*' => {
                if !matches!(tokens.last(), Some(Token::AnyRun)) {
                    tokens.push(Token::AnyRun);
                }
                at += 1;
            }
            '?' => {
                tokens.push(Token::AnyChar);
                at += 1;
            }
            '[' => {
                let (class, next) = compile_class(&chars, at + 1)?;
                tokens.push(class);
                at = next;
            }
            ch => {
                tokens.push(Token::Char(ch));
                at += 1;
            }
        }
    }
    Ok(tokens)
}

/// A `[...]` class whose body starts at `start`; a `]` first in the body is a literal.
fn compile_class(chars: &[char], start: usize) -> std::result::Result<(Token, usize), String> {
    let negated = matches!(chars.get(start), Some('!' | '^'));
    let first = start + usize::from(negated);
    let mut at = first;
    let mut ranges = Vec::new();
    loop {
        let Some(&low) = chars.get(at) else {
            return Err("unclosed '['".into());
        };
        if low == ']' && at > first {
            return Ok((Token::Class { negated, ranges }, at + 1));
        }
        match (chars.get(at + 1), chars.get(at + 2)) {
            (Some('-'), Some(&high)) if high != ']' => {
                if high < low {
                    return Err(format!("reversed character range '{low}-{high}'"));
                }
                ranges.push((low, high));
                at += 3;
            }
            _ => {
                ranges.push((low, low));
                at += 1;
            }
        }
    }
}

/// Whether `segments` consume exactly `parts`; `**` spans zero or more directories.
fn path_matches(segments: &[Segment], parts: &[String], fold_case: bool) -> bool {
    let mut reach = vec![false; parts.len() + 1];
    reach[0] = true;
    for segment in segments {
        let mut next = vec![false; parts.len() + 1];
        match segment {
            Segment::Globstar => {
                let mut seen = false;
                for (at, reached) in reach.iter().enumerate() {
                    seen |= *reached;
                    next[at] = seen;
                }
            }
            Segment::Name(tokens) => {
                for (at, part) in parts.iter().enumerate() {
                    next[at + 1] = reach[at] && name_matches(tokens, part, fold_case);
                }
            }
        }
        reach = next;
    }
    reach[parts.len()]
}

fn name_matches(tokens: &[Token], name: &str, fold_case: bool) -> bool {
    let chars = name.chars().collect::<Vec<_>>();
    let mut reach = vec![false; chars.len() + 1];
    reach[0] = true;
    for token in tokens {
        let mut next = vec![false; chars.len() + 1];
        if let Token::AnyRun = token {
            let mut seen = false;
            for (at, reached) in reach.iter().enumerate() {
                seen |= *reached;
                next[at] = seen;
            }
        } else {
            for (at, ch) in chars.iter().enumerate() {
                next[at + 1] = reach[at] && token.accepts(*ch, fold_case);
            }
        }
        reach = next;
    }
    reach[chars.len()]
}

impl Token {
    fn accepts(&self, ch: char, fold_case: bool) -> bool {
        let variants = if fold_case {
            [ch, ch.to_ascii_lowercase(), ch.to_ascii_uppercase()]
        } else {
            [ch; 3]
        };
        match self {
            Token::Char(expected) => variants.contains(expected),
            Token::AnyChar | Token::AnyRun => true,
            // A class accepts any case variant it lists; a negated class excludes only the exact
            // character (on a case-sensitive system `[!b]` still matches `B`).
            Token::Class { negated, ranges } => {
                let listed =
                    |ch: &char| ranges.iter().any(|(low, high)| (low..=high).contains(&ch));
                match negated {
                    true => !listed(&ch),
                    false => variants.iter().any(listed),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
