//! YAML a `yarn.lock` value can carry beyond the plain and quoted scalars the line parser reads.
//! Yarn Berry loads its lockfile with js-yaml, so `dependencies: { a: "npm:1.0.0" }` is the same
//! section as the block form, and anchors, aliases, tags, block scalars and comments all change
//! what an entry says. Neither Yarn writes any of them (Berry quotes every value that starts with
//! a YAML indicator, classic every value that does not start with a letter), so an inline map on
//! one line is read as the section it is and everything else blocks.

use std::collections::BTreeMap;

/// A property value: a scalar, or an inline `{ ... }` map that stands for a section.
pub(super) enum InlineValue {
    Scalar,
    Map(BTreeMap<String, String>),
}

/// Classify an entry property's raw value.
pub(super) fn property_value(raw: &str) -> Result<InlineValue, String> {
    let raw = raw.trim();
    if raw.starts_with('{') {
        return parse_flow_map(raw).map(InlineValue::Map);
    }
    reject_unmodeled(raw)?;
    Ok(InlineValue::Scalar)
}

/// A value inside a section (a dependency range, a `bin` path) must be a scalar.
pub(super) fn section_value(raw: &str) -> Result<(), String> {
    reject_unmodeled(raw.trim())
}

/// Plain values that start with a YAML indicator are not scalars to js-yaml.
fn reject_unmodeled(value: &str) -> Result<(), String> {
    let Some(first) = value.chars().next() else {
        return Ok(());
    };
    let structural = matches!(value, "-" | "?" | ":")
        || ["- ", "? ", ": "]
            .iter()
            .any(|lead| value.starts_with(lead));
    if structural || "[]{}&*!|>%@`#,".contains(first) {
        return Err(format!(
            "value '{}' uses YAML syntax (a collection, anchor, alias, tag, block scalar or comment) that Yarn never writes and sloppy-joe does not model",
            crate::report::sanitize_for_terminal(value)
        ));
    }
    Ok(())
}

fn parse_flow_map(raw: &str) -> Result<BTreeMap<String, String>, String> {
    let inner = raw
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
        .ok_or_else(|| "an inline map must open and close on one line".to_string())?;
    let mut items = split_flow_items(inner)?;
    if items.last().is_some_and(|item| item.trim().is_empty()) {
        items.pop();
    }
    let mut map = BTreeMap::new();
    for item in items {
        let (key, value) = flow_entry(item.trim())?;
        map.insert(key, value);
    }
    Ok(map)
}

/// Split on commas outside quotes. Nested collections, comments and escapes block.
fn split_flow_items(inner: &str) -> Result<Vec<&str>, String> {
    let mut items = Vec::new();
    let mut quote = None;
    let mut start = 0;
    for (at, ch) in inner.char_indices() {
        match (quote, ch) {
            (Some(_), '\\') => return Err("escapes in inline map strings are not modeled".into()),
            (Some(open), ch) if ch == open => quote = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => quote = Some(ch),
            (None, ',') => {
                items.push(&inner[start..at]);
                start = at + 1;
            }
            (None, '{' | '}' | '[' | ']' | '#') => {
                return Err(format!(
                    "'{ch}' inside an inline map (a nested collection or a comment) is not modeled"
                ));
            }
            (None, _) => {}
        }
    }
    if quote.is_some() {
        return Err("unterminated string in an inline map".into());
    }
    items.push(&inner[start..]);
    Ok(items)
}

/// `key: value`, either side plain or quoted. A plain key ends at the first `: `.
fn flow_entry(item: &str) -> Result<(String, String), String> {
    let (key, rest) = match quoted(item)? {
        Some((key, rest)) => (key, rest.trim_start().strip_prefix(':')),
        None => match item.split_once(": ") {
            Some((key, rest)) => {
                reject_unmodeled(key.trim())?;
                (key.trim().to_string(), Some(rest))
            }
            None => (String::new(), None),
        },
    };
    let Some(rest) = rest.map(str::trim) else {
        return Err(format!(
            "inline map item '{}' is not 'key: value'",
            crate::report::sanitize_for_terminal(item)
        ));
    };
    let value = match quoted(rest)? {
        Some((value, tail)) if tail.trim().is_empty() => value,
        Some(_) => return Err("text after a quoted inline map value".into()),
        None => {
            reject_unmodeled(rest)?;
            rest.to_string()
        }
    };
    if key.is_empty() || value.is_empty() {
        return Err(format!(
            "inline map item '{}' has an empty key or value",
            crate::report::sanitize_for_terminal(item)
        ));
    }
    Ok((key, value))
}

/// A leading quoted string and the text after it, or `None` when `text` is not quoted.
fn quoted(text: &str) -> Result<Option<(String, &str)>, String> {
    let Some(open) = text.chars().next().filter(|ch| matches!(ch, '"' | '\'')) else {
        return Ok(None);
    };
    let body = &text[1..];
    let close = body
        .find(open)
        .ok_or_else(|| "unterminated string in an inline map".to_string())?;
    Ok(Some((body[..close].to_string(), &body[close + 1..])))
}
