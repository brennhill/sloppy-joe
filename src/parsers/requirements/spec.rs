use super::*;

/// Python's `str.isspace()`, which `\s` in pip's patterns and configparser's indentation use:
/// Unicode whitespace plus the separators U+001C..U+001F that Rust does not count.
pub(crate) fn is_python_whitespace(ch: char) -> bool {
    ch.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&ch)
}

/// `text` without leading and trailing Python whitespace.
pub(crate) fn trim_python_whitespace(text: &str) -> &str {
    text.trim_matches(is_python_whitespace)
}

/// pip removes `(^|\s+)#.*$`: a `#` at the start or after Python whitespace begins a comment,
/// whatever quotes surround it.
pub(crate) fn strip_inline_comment(line: &str) -> &str {
    let mut previous_was_whitespace = true;
    for (idx, ch) in line.char_indices() {
        if ch == '#' && previous_was_whitespace {
            return line[..idx].trim_end_matches(is_python_whitespace);
        }
        previous_was_whitespace = is_python_whitespace(ch);
    }
    line
}

fn split_trailing_hashes(line: &str) -> (&str, &str) {
    let mut quote = None;
    for (idx, ch) in line.char_indices() {
        match quote {
            Some(active) if ch == active => quote = None,
            None if matches!(ch, '\'' | '"') => quote = Some(ch),
            None if is_python_whitespace(ch) => {
                let remainder = line[idx..].trim_start_matches(is_python_whitespace);
                if remainder.starts_with("--hash=")
                    || remainder
                        .strip_prefix("--hash")
                        .is_some_and(|value| value.starts_with(is_python_whitespace))
                {
                    return (
                        line[..idx].trim_end_matches(is_python_whitespace),
                        remainder,
                    );
                }
            }
            _ => {}
        }
    }
    (line, "")
}

pub(crate) fn has_supported_requirement_hashes(line: &str) -> bool {
    let (_, options) = split_trailing_hashes(line);
    let mut tokens = options
        .split(is_python_whitespace)
        .filter(|token| !token.is_empty());
    let mut saw_hash = false;
    while let Some(option) = tokens.next() {
        let hash = if option == "--hash" {
            tokens.next()
        } else {
            option.strip_prefix("--hash=")
        };
        if !hash.is_some_and(is_supported_python_hash) {
            return false;
        }
        saw_hash = true;
    }
    saw_hash
}

pub(crate) fn is_supported_python_hash(hash: &str) -> bool {
    let Some((algorithm, digest)) = hash.split_once(':') else {
        return false;
    };
    let expected_len = match algorithm {
        "sha256" => 64,
        "sha384" => 96,
        "sha512" => 128,
        _ => return false,
    };
    digest.len() == expected_len && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Find position of first `;` not inside quotes.
pub(crate) fn find_unquoted_semicolon(s: &str) -> Option<usize> {
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
pub(crate) fn normalize_distribution_name(raw: &str) -> String {
    let stripped = raw.trim().split('[').next().unwrap_or("").trim();
    normalize_distribution_atom(stripped)
}

pub(crate) fn parse_distribution_name_and_requested_extras(
    raw: &str,
) -> (String, std::collections::BTreeSet<String>) {
    let raw = raw.trim();
    let Some(open) = raw.find('[') else {
        return (
            normalize_distribution_name(raw),
            std::collections::BTreeSet::new(),
        );
    };
    let Some(close) = raw[open + 1..].find(']').map(|offset| open + 1 + offset) else {
        return (
            normalize_distribution_name(raw),
            std::collections::BTreeSet::new(),
        );
    };
    let name = normalize_distribution_name(&raw[..open]);
    let extras = raw[open + 1..close]
        .split(',')
        .map(normalize_distribution_atom)
        .filter(|extra| !extra.is_empty())
        .collect();
    (name, extras)
}

pub(crate) fn normalize_distribution_atom(raw: &str) -> String {
    let stripped = raw.trim();
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

pub(crate) fn parse_requirement_spec(raw: &str, source_path: &Path) -> Result<Option<Dependency>> {
    Ok(parse_scoped_requirement_spec(raw, source_path)?.map(|dep| dep.dependency))
}

pub(crate) fn parse_scoped_requirement_spec(
    raw: &str,
    source_path: &Path,
) -> Result<Option<PythonScopedDependency>> {
    let raw = strip_inline_comment(raw);
    let (line, marker) = split_requirement_marker(raw);
    let (line, _) = split_trailing_hashes(line);
    let marker = marker
        .map(|marker| split_trailing_hashes(marker).0)
        .map(str::trim)
        .filter(|marker| !marker.is_empty())
        .map(str::to_string);
    let line = line.trim_end_matches('\\').trim();
    if line.is_empty() {
        return Ok(None);
    }

    if line.contains("://") || line.contains(" @ ") || line.starts_with("git+") {
        bail!(
            "Unsupported direct requirement '{}' in {}",
            crate::report::sanitize_for_terminal(line),
            source_path.display()
        );
    }

    if requirement_looks_like_local_path(line) {
        bail!(
            "Unsupported local requirement '{}' in {}",
            crate::report::sanitize_for_terminal(line),
            source_path.display()
        );
    }

    let (name, requested_extras, version) = if let Some(pos) =
        line.find(['=', '>', '<', '~', '!', '^'])
    {
        // PEP 508 also allows the specifier in parentheses: `name (>=1.0,<2)`.
        let unbalanced = || {
            anyhow::anyhow!(
                "Unsupported requirement '{}' in {}: unbalanced parentheses in the version specifier",
                crate::report::sanitize_for_terminal(line),
                source_path.display()
            )
        };
        let name_part = line[..pos].trim_end();
        let version_part = line[pos..].trim();
        let (name_part, version_part) = match name_part.strip_suffix('(') {
            Some(stripped) => {
                let inner = version_part.strip_suffix(')').ok_or_else(unbalanced)?;
                (stripped.trim_end(), inner.trim())
            }
            None => (name_part, version_part),
        };
        if version_part.contains(['(', ')']) {
            return Err(unbalanced());
        }
        let (name, requested_extras) = parse_distribution_name_and_requested_extras(name_part);
        (name, requested_extras, Some(version_part.to_string()))
    } else {
        let (name, requested_extras) = parse_distribution_name_and_requested_extras(line);
        (name, requested_extras, None)
    };

    if name.is_empty() {
        bail!(
            "Unsupported requirement '{}' in {}: missing a package name",
            crate::report::sanitize_for_terminal(line),
            source_path.display()
        );
    }

    let dep = Dependency {
        name,
        version,
        ecosystem: crate::Ecosystem::PyPI,
        actual_name: None,
    };
    crate::parsers::validate_dependency(&dep, source_path)?;
    let scoped = requested_extras.into_iter().fold(
        PythonScopedDependency::runtime(dep, marker),
        |dep, extra| dep.with_requested_extra(&extra),
    );
    Ok(Some(scoped))
}

pub(crate) fn split_requirement_marker(raw: &str) -> (&str, Option<&str>) {
    if let Some(semi_pos) = find_unquoted_semicolon(raw) {
        let line = raw[..semi_pos].trim();
        let marker = raw[semi_pos + 1..].trim();
        (line, Some(marker))
    } else {
        (raw, None)
    }
}
