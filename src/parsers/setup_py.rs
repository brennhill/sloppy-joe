use crate::Dependency;
use anyhow::{Result, bail};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    parse_file(&project_dir.join("setup.py"))
}

pub(crate) fn parse_file(path: &Path) -> Result<Vec<Dependency>> {
    let content = super::read_file_limited(path, super::MAX_MANIFEST_BYTES)?;
    // shortcut: the literal scanner cannot model triple-quoted strings; reject until tokenized properly.
    if content.contains("\"\"\"") || content.contains("'''") {
        bail!(
            "Scan not supported: triple-quoted setup.py strings in {}",
            path.display()
        );
    }
    for line in content
        .lines()
        .take(2)
        .filter(|line| line.trim_start().starts_with('#'))
    {
        if let Some(start) = ["coding:", "coding="]
            .iter()
            .filter_map(|marker| line.find(marker))
            .min()
        {
            let encoding = line[start + 7..]
                .trim_start()
                .split(|ch: char| !ch.is_ascii_alphanumeric() && !matches!(ch, '-' | '_' | '.'))
                .next()
                .unwrap_or_default();
            let encoding = encoding.to_ascii_lowercase().replace('_', "-");
            if !matches!(encoding.as_str(), "utf-8" | "utf8" | "ascii") {
                bail!("Scan not supported: setup.py source encoding");
            }
        }
    }
    let setup_call = extract_setup_call(&content)?;
    if setup_call.is_none() {
        bail!(
            "Scan not supported: no static setup() call in {}",
            path.display()
        );
    }
    validate_setup_keywords(setup_call.as_deref().unwrap_or_default(), path)?;
    let mut deps = Vec::new();

    for key in ["install_requires", "setup_requires", "tests_require"] {
        if let Some(value) = extract_argument_literal(setup_call.as_deref(), key, path)? {
            let (entries, _) = parse_python_string_list(&value, 0)?;
            collect_dependency_lines(&entries, path, &mut deps)?;
        }
    }
    if let Some(value) = extract_argument_literal(setup_call.as_deref(), "extras_require", path)? {
        let (entries, _) = parse_python_string_dict_values(&value, 0)?;
        collect_dependency_lines(&entries, path, &mut deps)?;
    }

    Ok(deps)
}

/// setup() keywords whose values are parsed as dependency lists.
const DEPENDENCY_KEYWORDS: &[&str] = &[
    "install_requires",
    "setup_requires",
    "tests_require",
    "extras_require",
];

/// Standard setuptools/distutils keywords that cannot add or redirect installed dependencies.
/// `requires`/`provides`/`obsoletes` are PEP 314 metadata that installers ignore, and
/// `python_requires` constrains the interpreter, not packages. `options` is checked
/// separately for `easy_install` source overrides.
const NON_DEPENDENCY_KEYWORDS: &[&str] = &[
    "name",
    "version",
    "description",
    "long_description",
    "long_description_content_type",
    "author",
    "author_email",
    "maintainer",
    "maintainer_email",
    "url",
    "download_url",
    "project_urls",
    "license",
    "license_file",
    "license_files",
    "classifiers",
    "keywords",
    "platforms",
    "packages",
    "package_dir",
    "package_data",
    "exclude_package_data",
    "include_package_data",
    "py_modules",
    "scripts",
    "entry_points",
    "zip_safe",
    "python_requires",
    "namespace_packages",
    "test_suite",
    "eager_resources",
    "requires",
    "provides",
    "obsoletes",
];

/// Every keyword in the literal setup() call must be one the scanner models. Keywords that
/// point installers at other sources (`dependency_links`, `options={'easy_install': ...}`),
/// plugin keywords that load dependencies from elsewhere (`pbr=True`), unknown keywords, and
/// repeated keywords block instead of being skipped.
fn validate_setup_keywords(setup_call: &str, source_path: &Path) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for keyword in setup_keywords(setup_call)? {
        if !seen.insert(keyword.clone()) {
            bail!(
                "Scan not supported: setup.py keyword '{}' is repeated in {}",
                keyword,
                source_path.display()
            );
        }
        match keyword.as_str() {
            "dependency_links" => {
                let value = extract_argument_literal(Some(setup_call), &keyword, source_path)?
                    .unwrap_or_default();
                let (links, _) = parse_python_string_list(&value, 0)?;
                if !links.is_empty() {
                    bail!(
                        "Scan not supported: setup.py dependency_links in {} can redirect where dependencies are downloaded from",
                        source_path.display()
                    );
                }
            }
            "options" => {
                let value = extract_argument_literal(Some(setup_call), &keyword, source_path)?
                    .unwrap_or_default();
                if value.contains("easy_install") || value.contains("easy-install") {
                    bail!(
                        "Scan not supported: setup.py easy_install options in {} can redirect where build dependencies are downloaded from",
                        source_path.display()
                    );
                }
            }
            known
                if DEPENDENCY_KEYWORDS.contains(&known)
                    || NON_DEPENDENCY_KEYWORDS.contains(&known) => {}
            unknown => bail!(
                "Scan not supported: unrecognized setup.py keyword '{}' in {} may carry dependencies",
                crate::report::sanitize_for_terminal(unknown),
                source_path.display()
            ),
        }
    }
    Ok(())
}

/// Top-level keyword names of a setup() call that `validate_literal_setup_arguments`
/// already accepted.
fn setup_keywords(content: &str) -> Result<Vec<String>> {
    let bytes = content.as_bytes();
    let mut keywords = Vec::new();
    let mut index = 0;
    let mut depth = 0usize;
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'\'' | b'"' => index = parse_python_string(content, index)?.1,
            b'#' => {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'[' | b'{' | b'(' => {
                depth += 1;
                index += 1;
            }
            b']' | b'}' | b')' => {
                depth = depth.saturating_sub(1);
                index += 1;
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                let start = index;
                while bytes
                    .get(index)
                    .is_some_and(|ch| ch.is_ascii_alphanumeric() || *ch == b'_')
                {
                    index += 1;
                }
                let mut next = index;
                skip_ws(bytes, &mut next);
                if depth == 0
                    && bytes.get(next) == Some(&b'=')
                    && bytes.get(next + 1) != Some(&b'=')
                {
                    keywords.push(content[start..index].to_string());
                }
            }
            _ => index += 1,
        }
    }
    Ok(keywords)
}

fn extract_argument_literal(
    setup_call: Option<&str>,
    key: &str,
    source_path: &Path,
) -> Result<Option<String>> {
    let Some(content) = setup_call else {
        return Ok(None);
    };
    let Some(start) = find_keyword_assignment(content, key)? else {
        return Ok(None);
    };
    let value = content[start..].trim_start();
    let opener = value.chars().next().ok_or_else(|| {
        anyhow::anyhow!(
            "Unsupported setup.py dependency declaration for '{}' in {}",
            key,
            source_path.display()
        )
    })?;

    if opener != '[' && opener != '{' {
        bail!(
            "Scan not supported: Unsupported dynamic setup.py dependency declaration for '{}' in {}",
            key,
            source_path.display()
        );
    }

    let end = matching_delimiter(value, 0, opener, if opener == '[' { ']' } else { '}' })?;
    let tail = value[end + 1..].trim_start();
    if !tail.is_empty() && !tail.starts_with(',') {
        bail!(
            "Scan not supported: setup.py dependency expressions in {}",
            source_path.display()
        );
    }
    Ok(Some(value[..=end].to_string()))
}

fn extract_setup_call(content: &str) -> Result<Option<String>> {
    let mut setup_call = None;
    let bytes = content.as_bytes();
    let mut index = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;

    while index < bytes.len() {
        let byte = bytes[index];
        if escape {
            escape = false;
            index += 1;
            continue;
        }

        match byte {
            b'\\' if in_single || in_double => {
                escape = true;
                index += 1;
            }
            b'\'' if !in_double => {
                in_single = !in_single;
                index += 1;
            }
            b'"' if !in_single => {
                in_double = !in_double;
                index += 1;
            }
            b'#' if !in_single && !in_double => {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            _ if in_single || in_double => {
                index += 1;
            }
            b's' if bytes[index..].starts_with(b"setup(")
                && is_identifier_boundary_at(bytes, index.checked_sub(1))
                && is_identifier_boundary_at(bytes, Some(index + "setup".len())) =>
            {
                let start = index + "setup(".len();
                let end = matching_parenthesis(content, start - 1)?;
                if setup_call.is_some() {
                    bail!("Scan not supported: multiple setup.py setup() calls");
                }
                let prefix = content[..index]
                    .strip_suffix("setuptools.")
                    .unwrap_or(&content[..index]);
                for line in prefix.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    if matches!(
                        line.split('#').next().unwrap().trim(),
                        "from setuptools import setup"
                            | "import setuptools"
                            | "from distutils.core import setup"
                    ) {
                        continue;
                    }
                    if let Some((name, value)) = line.split_once('=') {
                        let name = name.trim();
                        let value = value.trim();
                        if !name.is_empty()
                            && name
                                .bytes()
                                .all(|ch| ch.is_ascii_alphanumeric() || ch == b'_')
                            && matches!(value.as_bytes().first(), Some(b'\'' | b'"'))
                        {
                            let (_, consumed) = parse_python_string(value, 0)?;
                            let tail = value[consumed..].trim();
                            if tail.is_empty() || tail.starts_with('#') {
                                continue;
                            }
                        }
                    }
                    bail!("Scan not supported: executable setup.py preamble");
                }
                if content[end + 1..].lines().any(|line| {
                    let line = line.trim();
                    !line.is_empty() && !line.starts_with('#')
                }) {
                    bail!("Scan not supported: executable statements after setup()");
                }
                validate_literal_setup_arguments(&content[start..end])?;
                setup_call = Some(content[start..end].to_string());
                index = end + 1;
            }
            _ => index += 1,
        }
    }

    Ok(setup_call)
}

fn validate_literal_setup_arguments(content: &str) -> Result<()> {
    let bytes = content.as_bytes();
    let mut index = 0;
    let mut depth = 0usize;
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'\'' | b'"' => {
                index = parse_python_string(content, index)?.1;
            }
            b'#' => {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'[' | b'{' => {
                depth += 1;
                index += 1;
            }
            b']' | b'}' => {
                depth = depth.saturating_sub(1);
                index += 1;
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                let start = index;
                while bytes
                    .get(index)
                    .is_some_and(|ch| ch.is_ascii_alphanumeric() || *ch == b'_')
                {
                    index += 1;
                }
                let token = &content[start..index];
                let mut next = index;
                skip_ws(bytes, &mut next);
                if !(matches!(token, "True" | "False" | "None")
                    || depth == 0 && bytes.get(next) == Some(&b'='))
                {
                    bail!("Scan not supported: nonliteral setup.py argument");
                }
            }
            b'0'..=b'9' | b',' | b':' | b'=' | b'.' | b'+' | b'-' => {
                index += 1;
            }
            byte if byte.is_ascii_whitespace() => {
                index += 1;
            }
            _ => bail!("Scan not supported: nonliteral setup.py argument"),
        }
    }
    Ok(())
}

fn find_keyword_assignment(content: &str, key: &str) -> Result<Option<usize>> {
    let mut assignment_start = None;
    let mut depth = 0usize;
    let bytes = content.as_bytes();
    let mut index = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;

    while index < bytes.len() {
        let byte = bytes[index];
        if escape {
            escape = false;
            index += 1;
            continue;
        }

        match byte {
            b'\\' if in_single || in_double => {
                escape = true;
                index += 1;
            }
            b'\'' if !in_double => {
                in_single = !in_single;
                index += 1;
            }
            b'"' if !in_single => {
                in_double = !in_double;
                index += 1;
            }
            b'#' if !in_single && !in_double => {
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            _ if in_single || in_double => {
                index += 1;
            }
            b'*' if bytes.get(index + 1) == Some(&b'*') => {
                // Expanded keyword arguments may supply or override dependency declarations.
                bail!("Scan not supported: expanded setup.py keyword arguments");
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                index += 1;
            }
            b')' | b']' | b'}' => {
                depth = depth.saturating_sub(1);
                index += 1;
            }
            _ if depth == 0
                && bytes[index..].starts_with(key.as_bytes())
                && is_identifier_boundary_at(bytes, index.checked_sub(1))
                && is_identifier_boundary_at(bytes, Some(index + key.len())) =>
            {
                let mut assignment = index + key.len();
                while let Some(next) = bytes.get(assignment) {
                    if !next.is_ascii_whitespace() {
                        break;
                    }
                    assignment += 1;
                }
                if bytes.get(assignment) == Some(&b'=') {
                    assignment_start = Some(assignment + 1);
                }
                index += key.len();
            }
            _ => index += 1,
        }
    }

    Ok(assignment_start)
}

fn is_identifier_boundary_at(bytes: &[u8], index: Option<usize>) -> bool {
    index
        .and_then(|idx| bytes.get(idx))
        .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
}

fn matching_parenthesis(input: &str, open_index: usize) -> Result<usize> {
    matching_delimiter(input, open_index, '(', ')')
}

fn matching_delimiter(input: &str, start: usize, open: char, close: char) -> Result<usize> {
    let mut in_comment = false;
    let mut depth = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;

    for (idx, ch) in input.char_indices().skip_while(|(idx, _)| *idx < start) {
        if in_comment {
            in_comment = ch != '\n';
            continue;
        }
        if escape {
            escape = false;
            continue;
        }
        match ch {
            '\\' if in_single || in_double => {
                escape = true;
            }
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => in_comment = true,
            _ if in_single || in_double => {}
            _ if ch == open => depth += 1,
            _ if ch == close => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Ok(idx);
                }
            }
            _ => {}
        }
    }

    bail!("Unterminated Python literal")
}

fn parse_python_string_list(input: &str, start: usize) -> Result<(Vec<String>, usize)> {
    let bytes = input.as_bytes();
    let mut index = start;
    skip_ws_and_commas(bytes, &mut index);
    if bytes.get(index).copied() != Some(b'[') {
        bail!("Scan not supported: expected a Python list literal of strings");
    }
    index += 1;

    let mut values = Vec::new();
    loop {
        skip_ws_and_commas(bytes, &mut index);
        match bytes.get(index).copied() {
            Some(b']') => return Ok((values, index + 1)),
            Some(b'\'') | Some(b'"') => {
                let (value, next_index) = parse_python_string(input, index)?;
                values.push(value);
                index = next_index;
                skip_ws(bytes, &mut index);
                if !matches!(bytes.get(index), Some(b',' | b']')) {
                    bail!("Scan not supported: nonliteral Python list expression");
                }
            }
            Some(_) => bail!("Scan not supported: unsupported Python list literal entry"),
            None => bail!("Unterminated Python list literal"),
        }
    }
}

fn parse_python_string_dict_values(input: &str, start: usize) -> Result<(Vec<String>, usize)> {
    let bytes = input.as_bytes();
    let mut index = start;
    skip_ws_and_commas(bytes, &mut index);
    if bytes.get(index).copied() != Some(b'{') {
        bail!("Scan not supported: expected a Python dict literal");
    }
    index += 1;

    let mut values = Vec::new();
    loop {
        skip_ws_and_commas(bytes, &mut index);
        match bytes.get(index).copied() {
            Some(b'}') => return Ok((values, index + 1)),
            Some(b'\'') | Some(b'"') => {
                let (_, next_index) = parse_python_string(input, index)?;
                index = next_index;
                skip_ws(bytes, &mut index);
                if bytes.get(index).copied() != Some(b':') {
                    bail!("Scan not supported: unsupported Python dict literal");
                }
                index += 1;
                let (group_values, next_index) = parse_python_string_list(input, index)?;
                values.extend(group_values);
                index = next_index;
                skip_ws(bytes, &mut index);
                if !matches!(bytes.get(index), Some(b',' | b'}')) {
                    bail!("Scan not supported: nonliteral Python dict expression");
                }
            }
            Some(_) => bail!("Scan not supported: unsupported Python dict literal entry"),
            None => bail!("Unterminated Python dict literal"),
        }
    }
}

fn parse_python_string(input: &str, start: usize) -> Result<(String, usize)> {
    let bytes = input.as_bytes();
    let quote = bytes
        .get(start)
        .copied()
        .ok_or_else(|| anyhow::anyhow!("Missing Python string quote"))?;
    let mut index = start + 1;
    let mut value = String::new();

    while let Some(&byte) = bytes.get(index) {
        if byte == b'\\' {
            let escaped = *bytes
                .get(index + 1)
                .ok_or_else(|| anyhow::anyhow!("Unterminated Python string literal"))?;
            if escaped != quote && escaped != b'\\' {
                bail!("Scan not supported: escaped Python dependency strings");
            }
            value.push(escaped as char);
            index += 2;
            continue;
        }
        if byte == quote {
            return Ok((value, index + 1));
        }
        value.push(byte as char);
        index += 1;
    }

    bail!("Unterminated Python string literal")
}

fn skip_ws(bytes: &[u8], index: &mut usize) {
    while let Some(byte) = bytes.get(*index) {
        if !byte.is_ascii_whitespace() {
            break;
        }
        *index += 1;
    }
}

fn skip_ws_and_commas(bytes: &[u8], index: &mut usize) {
    while let Some(byte) = bytes.get(*index) {
        if !byte.is_ascii_whitespace() && *byte != b',' {
            break;
        }
        *index += 1;
    }
}

fn collect_dependency_lines(
    entries: &[String],
    source_path: &Path,
    deps: &mut Vec<Dependency>,
) -> Result<()> {
    for entry in entries {
        if let Some(dep) = super::requirements::parse_requirement_spec(entry, source_path)? {
            deps.push(dep);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "setup_py_redteam_tests.rs"]
mod redteam_tests;

#[cfg(test)]
mod tests;
