use crate::Dependency;
use anyhow::Result;
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    parse_file(&project_dir.join("setup.cfg"))
}

pub(crate) fn parse_file(path: &Path) -> Result<Vec<Dependency>> {
    let content = super::read_file_limited(path, super::MAX_MANIFEST_BYTES)?;
    let lines: Vec<&str> = content.lines().collect();
    let mut deps = Vec::new();
    let mut section = String::new();
    let mut index = 0usize;

    while index < lines.len() {
        let raw = lines[index];
        let trimmed = raw.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            index += 1;
            continue;
        }

        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed[1..trimmed.len() - 1].trim().to_string();
            index += 1;
            continue;
        }

        match section.as_str() {
            "options" if key_name(trimmed) == Some("install_requires") => {
                let (entries, next_index) = read_cfg_value_block(&lines, index);
                collect_dependency_lines(&entries, path, &mut deps)?;
                index = next_index;
            }
            "options.extras_require" => {
                let (entries, next_index) = read_cfg_value_block(&lines, index);
                collect_dependency_lines(&entries, path, &mut deps)?;
                index = next_index;
            }
            _ => {
                index += 1;
            }
        }
    }

    Ok(deps)
}

fn key_name(line: &str) -> Option<&str> {
    line.split_once('=').map(|(key, _)| key.trim())
}

fn read_cfg_value_block(lines: &[&str], start: usize) -> (Vec<String>, usize) {
    let mut entries = Vec::new();
    let Some((_, first_value)) = lines[start].split_once('=') else {
        return (entries, start + 1);
    };
    let first_value = first_value.trim();
    if !first_value.is_empty() {
        entries.push(first_value.to_string());
    }

    let mut index = start + 1;
    while index < lines.len() {
        let raw = lines[index];
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            index += 1;
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            break;
        }
        let is_continuation = raw.starts_with(' ') || raw.starts_with('\t');
        if !is_continuation {
            break;
        }
        entries.push(trimmed.to_string());
        index += 1;
    }

    (entries, index)
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
    fn parse_install_requires_and_extras() {
        let dir = setup_test_dir(
            "setup-cfg",
            "setup.cfg",
            "[metadata]\nname = demo\nversion = 0.1.0\n[options]\ninstall_requires =\n    requests==2.31.0\n[options.extras_require]\ndev =\n    pytest==8.1.1\n",
        );

        let deps = parse(&dir).unwrap();
        let names: Vec<&str> = deps.iter().map(|dep| dep.name.as_str()).collect();
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"pytest"));

        cleanup(&dir);
    }
}
