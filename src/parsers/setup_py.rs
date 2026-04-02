use crate::Dependency;
use anyhow::{Result, bail};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    parse_file(&project_dir.join("setup.py"))
}

pub(crate) fn parse_file(path: &Path) -> Result<Vec<Dependency>> {
    let content = super::read_file_limited(path, super::MAX_MANIFEST_BYTES)?;
    let mut deps = Vec::new();

    if let Some(value) = extract_argument_literal(&content, "install_requires", path)? {
        let (entries, _) = parse_python_string_list(&value, 0)?;
        collect_dependency_lines(&entries, path, &mut deps)?;
    }
    if let Some(value) = extract_argument_literal(&content, "extras_require", path)? {
        let (entries, _) = parse_python_string_dict_values(&value, 0)?;
        collect_dependency_lines(&entries, path, &mut deps)?;
    }

    Ok(deps)
}

fn extract_argument_literal(
    content: &str,
    key: &str,
    source_path: &Path,
) -> Result<Option<String>> {
    let Some(start) = content.find(key) else {
        return Ok(None);
    };
    let after_key = &content[start + key.len()..];
    let Some(eq_index) = after_key.find('=') else {
        bail!(
            "Unsupported setup.py dependency declaration for '{}' in {}",
            key,
            source_path.display()
        );
    };
    let value = after_key[eq_index + 1..].trim_start();
    let opener = value.chars().next().ok_or_else(|| {
        anyhow::anyhow!(
            "Unsupported setup.py dependency declaration for '{}' in {}",
            key,
            source_path.display()
        )
    })?;

    if opener != '[' && opener != '{' {
        bail!(
            "Unsupported dynamic setup.py dependency declaration for '{}' in {}",
            key,
            source_path.display()
        );
    }

    let end = matching_delimiter(value, 0, opener, if opener == '[' { ']' } else { '}' })?;
    Ok(Some(value[..=end].to_string()))
}

fn matching_delimiter(input: &str, start: usize, open: char, close: char) -> Result<usize> {
    let mut depth = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;

    for (idx, ch) in input.char_indices().skip(start) {
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
        bail!("Expected Python list literal");
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
            }
            Some(_) => bail!("Unsupported Python list literal entry"),
            None => bail!("Unterminated Python list literal"),
        }
    }
}

fn parse_python_string_dict_values(input: &str, start: usize) -> Result<(Vec<String>, usize)> {
    let bytes = input.as_bytes();
    let mut index = start;
    skip_ws_and_commas(bytes, &mut index);
    if bytes.get(index).copied() != Some(b'{') {
        bail!("Expected Python dict literal");
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
                    bail!("Unsupported Python dict literal");
                }
                index += 1;
                let (group_values, next_index) = parse_python_string_list(input, index)?;
                values.extend(group_values);
                index = next_index;
            }
            Some(_) => bail!("Unsupported Python dict literal entry"),
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
mod tests {
    use super::*;
    use crate::parsers::test_utils::*;

    #[test]
    fn parse_static_install_requires_and_extras() {
        let dir = setup_test_dir(
            "setup-py",
            "setup.py",
            "from setuptools import setup\nsetup(name='demo', version='0.1.0', install_requires=['requests==2.31.0'], extras_require={'dev': ['pytest==8.1.1']})\n",
        );

        let deps = parse(&dir).unwrap();
        let names: Vec<&str> = deps.iter().map(|dep| dep.name.as_str()).collect();
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"pytest"));

        cleanup(&dir);
    }

    #[test]
    fn reject_dynamic_install_requires() {
        let dir = setup_test_dir(
            "setup-py-dynamic",
            "setup.py",
            "deps = ['requests==2.31.0']\nfrom setuptools import setup\nsetup(install_requires=deps)\n",
        );

        let err = parse(&dir).unwrap_err();
        assert!(err.to_string().contains("Unsupported dynamic setup.py"));

        cleanup(&dir);
    }
}
