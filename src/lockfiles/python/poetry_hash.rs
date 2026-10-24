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

    let mut relevant_poetry = toml::value::Table::new();
    for key in [
        "dependencies",
        "source",
        "extras",
        "dev-dependencies",
        "group",
    ] {
        let value = tool_poetry.and_then(|table| table.get(key)).cloned();
        let is_legacy = matches!(
            key,
            "dependencies" | "source" | "extras" | "dev-dependencies"
        );
        if value.is_none()
            && (!is_legacy || !relevant_project.is_empty() || dependency_groups.is_some())
        {
            continue;
        }
        if let Some(value) = value {
            relevant_poetry.insert(key.to_string(), value);
        }
    }

    let relevant = if !relevant_project.is_empty() || dependency_groups.is_some() {
        let mut top = toml::value::Table::new();
        if !relevant_project.is_empty() {
            top.insert("project".to_string(), toml::Value::Table(relevant_project));
        }
        if let Some(groups) = dependency_groups
            && !groups.is_empty()
        {
            top.insert(
                "dependency-groups".to_string(),
                toml::Value::Table(groups.clone()),
            );
        }
        let mut tool = toml::value::Table::new();
        tool.insert("poetry".to_string(), toml::Value::Table(relevant_poetry));
        top.insert("tool".to_string(), toml::Value::Table(tool));
        toml::Value::Table(top)
    } else {
        toml::Value::Table(relevant_poetry)
    };

    let mut hasher = Sha256::new();
    hasher.update(canonical_json_from_toml(&relevant)?.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
pub(crate) fn poetry_content_hash_for_test(pyproject: &str) -> Result<String> {
    let parsed = toml::from_str::<toml::Value>(pyproject)?;
    poetry_content_hash(&parsed, true)
}

pub(crate) fn canonical_json_from_toml(value: &toml::Value) -> Result<String> {
    match value {
        toml::Value::String(text) => serde_json::to_string(text).map_err(Into::into),
        toml::Value::Integer(value) => Ok(value.to_string()),
        toml::Value::Float(value) => serde_json::to_string(value).map_err(Into::into),
        toml::Value::Boolean(value) => Ok(value.to_string()),
        toml::Value::Datetime(value) => {
            serde_json::to_string(&value.to_string()).map_err(Into::into)
        }
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
                let key_json = serde_json::to_string(&key)?;
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
