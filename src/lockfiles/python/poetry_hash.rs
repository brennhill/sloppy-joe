use super::*;

pub(crate) fn poetry_lock_version_supported(lock_version: &str) -> bool {
    let Ok((major, _minor)) = parse_simple_version(lock_version) else {
        return false;
    };
    (1..3).contains(&major)
}

pub(crate) fn generated_poetry_version(lockfile_content: &str) -> Option<(u64, u64, u64)> {
    let first_line = lockfile_content.lines().next()?;
    let (_, version) = first_line.split_once("Poetry ")?;
    let token = version.split_whitespace().next()?;
    parse_semver_like(token).ok()
}

pub(crate) fn parse_simple_version(value: &str) -> Result<(u64, u64)> {
    let mut parts = value.trim().split('.');
    let major = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing major version"))?
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid major version"))?;
    let minor = parts
        .next()
        .unwrap_or("0")
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid minor version"))?;
    Ok((major, minor))
}

pub(crate) fn parse_semver_like(value: &str) -> Result<(u64, u64, u64)> {
    let token = value
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == '.')
        .collect::<String>();
    let mut parts = token.split('.');
    let major = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing major version"))?
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid major version"))?;
    let minor = parts
        .next()
        .unwrap_or("0")
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid minor version"))?;
    let patch = parts
        .next()
        .unwrap_or("0")
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("invalid patch version"))?;
    Ok((major, minor, patch))
}

pub(crate) fn poetry_content_hash(
    pyproject: &toml::Value,
    with_dependency_groups: bool,
) -> Result<String> {
    let project = pyproject.get("project").and_then(|value| value.as_table());
    let dependency_groups = with_dependency_groups
        .then(|| {
            pyproject
                .get("dependency-groups")
                .and_then(|value| value.as_table())
                .filter(|groups| !groups.is_empty())
        })
        .flatten();
    let tool_poetry = pyproject
        .get("tool")
        .and_then(|tool| tool.get("poetry"))
        .and_then(|value| value.as_table());

    let mut relevant_project = toml::value::Table::new();
    for key in ["requires-python", "dependencies", "optional-dependencies"] {
        if let Some(value) = project.and_then(|table| table.get(key)).cloned() {
            relevant_project.insert(key.to_string(), value);
        }
    }

    // Poetry hashes a missing legacy key as JSON `null` unless [project] or
    // [dependency-groups] carry the dependencies; a missing `group` is left out.
    let project_content = !relevant_project.is_empty() || dependency_groups.is_some();
    let mut poetry_entries = Vec::new();
    for key in [
        "dependencies",
        "source",
        "extras",
        "dev-dependencies",
        "group",
    ] {
        let is_legacy = key != "group";
        match tool_poetry.and_then(|table| table.get(key)) {
            Some(value) => poetry_entries.push((key, canonical_json_from_toml(value)?)),
            None if is_legacy && !project_content => poetry_entries.push((key, "null".to_string())),
            None => {}
        }
    }
    let poetry_json = json_object(poetry_entries);

    let relevant_json = if project_content {
        let mut top = Vec::new();
        if !relevant_project.is_empty() {
            top.push((
                "project",
                canonical_json_from_toml(&toml::Value::Table(relevant_project))?,
            ));
        }
        if let Some(groups) = dependency_groups {
            top.push((
                "dependency-groups",
                canonical_json_from_toml(&toml::Value::Table(groups.clone()))?,
            ));
        }
        top.push(("tool", json_object(vec![("poetry", poetry_json)])));
        json_object(top)
    } else {
        poetry_json
    };

    let mut hasher = Sha256::new();
    hasher.update(relevant_json.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

/// A JSON object with sorted keys, formatted like Python's `json.dumps(sort_keys=True)`.
fn json_object(mut entries: Vec<(&str, String)>) -> String {
    entries.sort_by(|left, right| left.0.cmp(right.0));
    let parts: Vec<String> = entries
        .iter()
        .map(|(key, value)| format!("{}: {value}", python_json_string(key)))
        .collect();
    format!("{{{}}}", parts.join(", "))
}

/// A JSON string as Python's `json.dumps` writes it (`ensure_ascii`): non-ASCII characters become
/// `\uXXXX` escapes, as UTF-16 surrogate pairs above the BMP.
fn python_json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (' '..='~').contains(&c) => out.push(c),
            c => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
pub(crate) fn poetry_content_hash_for_test(pyproject: &str) -> Result<String> {
    let parsed = toml::from_str::<toml::Value>(pyproject)?;
    poetry_content_hash(&parsed, true)
}

pub(crate) fn canonical_json_from_toml(value: &toml::Value) -> Result<String> {
    match value {
        toml::Value::String(text) => Ok(python_json_string(text)),
        toml::Value::Integer(value) => Ok(value.to_string()),
        toml::Value::Float(value) => serde_json::to_string(value).map_err(Into::into),
        toml::Value::Boolean(value) => Ok(value.to_string()),
        toml::Value::Datetime(value) => Ok(python_json_string(&value.to_string())),
        toml::Value::Array(values) => {
            let parts = values
                .iter()
                .map(canonical_json_from_toml)
                .collect::<Result<Vec<_>>>()?;
            Ok(format!("[{}]", parts.join(", ")))
        }
        toml::Value::Table(table) => {
            let mut keys = table.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let mut parts = Vec::with_capacity(keys.len());
            for key in keys {
                let key_json = python_json_string(&key);
                let value_json = canonical_json_from_toml(
                    table
                        .get(&key)
                        .expect("sorted key list must resolve back into table"),
                )?;
                parts.push(format!("{key_json}: {value_json}"));
            }
            Ok(format!("{{{}}}", parts.join(", ")))
        }
    }
}

#[cfg(test)]
mod hash_tests {
    use super::*;

    /// Hashes taken from `poetry lock` (Poetry 2.4.1) on the same pyproject.toml text.
    #[test]
    fn legacy_pyproject_matches_poetry_2_4_1() {
        let pyproject = "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\ndescription = \"\"\nauthors = [\"a <a@b.c>\"]\n\n[tool.poetry.dependencies]\npython = \"^3.9\"\nsix = \"1.16.0\"\n\n[build-system]\nrequires = [\"poetry-core\"]\nbuild-backend = \"poetry.core.masonry.api\"\n";
        assert_eq!(
            poetry_content_hash_for_test(pyproject).unwrap(),
            "57165a07a06690e5c3f617e000388c8ca18ea3c10401178325696cf7073768e8"
        );
    }

    #[test]
    fn non_ascii_text_is_escaped_like_python() {
        assert_eq!(python_json_string("é😀\n"), "\"\\u00e9\\ud83d\\ude00\\n\"");
    }
}
