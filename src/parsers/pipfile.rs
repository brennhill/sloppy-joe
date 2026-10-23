use crate::Dependency;
use anyhow::{Result, bail};
use std::collections::HashMap;
use std::path::Path;

/// Top-level Pipfile tables that hold settings rather than packages.
const PIPFILE_RESERVED_TABLES: &[&str] = &["source", "requires", "pipenv", "scripts"];

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    parse_file(&project_dir.join("Pipfile"))
}

pub(crate) fn parse_file(path: &Path) -> Result<Vec<Dependency>> {
    Ok(parse_file_categories(path)?
        .categories
        .into_iter()
        .flat_map(|category| category.deps)
        .collect())
}

/// One Pipfile package category and the Pipfile.lock section that locks it.
pub(crate) struct PipfileCategory {
    pub(crate) lock_section: String,
    pub(crate) deps: Vec<Dependency>,
}

/// Pipenv's `Pipfile.get_hash()`: sha256 of the compact, key-sorted,
/// ASCII-escaped JSON of the raw Pipfile data laid out as
/// `{"_meta": {"sources", "requires"}, "default", "develop", <custom categories>}`.
/// Returns `None` when the Pipfile has no `[[source]]` or holds a value pipenv's
/// serializer would not render the way this one does (floats, datetimes), so the
/// caller can fall back to the two-way package reconciliation instead of
/// guessing.
pub(crate) fn pipfile_hash(pipfile: &toml::Value) -> Option<String> {
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    let table = pipfile.as_table()?;
    let empty = toml::Value::Table(toml::Table::new());
    let mut meta = BTreeMap::new();
    meta.insert("sources", table.get("source")?);
    meta.insert("requires", table.get("requires").unwrap_or(&empty));
    let mut top: BTreeMap<&str, JsonNode> = BTreeMap::new();
    top.insert("_meta", JsonNode::Map(meta));
    top.insert(
        "default",
        JsonNode::Toml(table.get("packages").unwrap_or(&empty)),
    );
    top.insert(
        "develop",
        JsonNode::Toml(table.get("dev-packages").unwrap_or(&empty)),
    );
    for (key, value) in table {
        if PIPFILE_RESERVED_TABLES.contains(&key.as_str())
            || ["packages", "dev-packages", "default", "develop", "pipfile"].contains(&key.as_str())
        {
            continue;
        }
        top.insert(key.as_str(), JsonNode::Toml(value));
    }

    let mut out = String::new();
    write_json_node(&JsonNode::Top(top), &mut out)?;
    Some(format!("{:x}", Sha256::digest(out.as_bytes())))
}

enum JsonNode<'a> {
    Top(std::collections::BTreeMap<&'a str, JsonNode<'a>>),
    Map(std::collections::BTreeMap<&'a str, &'a toml::Value>),
    Toml(&'a toml::Value),
}

fn write_json_node(node: &JsonNode<'_>, out: &mut String) -> Option<()> {
    match node {
        JsonNode::Top(map) => {
            out.push('{');
            for (index, (key, value)) in map.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_json_string(key, out);
                out.push(':');
                write_json_node(value, out)?;
            }
            out.push('}');
        }
        JsonNode::Map(map) => {
            out.push('{');
            for (index, (key, value)) in map.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_json_string(key, out);
                out.push(':');
                write_json_value(value, out)?;
            }
            out.push('}');
        }
        JsonNode::Toml(value) => write_json_value(value, out)?,
    }
    Some(())
}

fn write_json_value(value: &toml::Value, out: &mut String) -> Option<()> {
    match value {
        toml::Value::String(text) => write_json_string(text, out),
        toml::Value::Integer(number) => out.push_str(&number.to_string()),
        toml::Value::Boolean(flag) => out.push_str(if *flag { "true" } else { "false" }),
        toml::Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_json_value(item, out)?;
            }
            out.push(']');
        }
        toml::Value::Table(table) => {
            let mut keys: Vec<&String> = table.keys().collect();
            keys.sort();
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_json_string(key, out);
                out.push(':');
                write_json_value(&table[key], out)?;
            }
            out.push('}');
        }
        toml::Value::Float(_) | toml::Value::Datetime(_) => return None,
    }
    Some(())
}

/// Python `json.dumps` with `ensure_ascii=True`: everything outside
/// space..`~` is escaped, characters above the BMP as surrogate pairs.
fn write_json_string(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(ch),
            _ => {
                let mut units = [0u16; 2];
                for unit in ch.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
}

pub(crate) struct ParsedPipfile {
    pub(crate) categories: Vec<PipfileCategory>,
    /// Normalized URLs of the declared `[[source]]` indexes.
    pub(crate) source_urls: Vec<String>,
    /// Pipenv's `Pipfile.get_hash()`, or `None` when it cannot be reproduced
    /// exactly (no `[[source]]`, float/datetime values).
    pub(crate) hash: Option<String>,
}

/// Pipenv locks `[packages]` under `default`, `[dev-packages]` under
/// `develop`, and every custom category under its own name.
fn lock_section_for_category(category: &str) -> &str {
    match category {
        "packages" => "default",
        "dev-packages" => "develop",
        other => other,
    }
}

pub(crate) fn parse_file_categories(path: &Path) -> Result<ParsedPipfile> {
    let content = super::read_file_limited(path, super::MAX_MANIFEST_BYTES)?;
    let parsed = toml::from_str::<toml::Value>(&content)
        .map_err(|err| anyhow::anyhow!("Failed to parse {}: {}", path.display(), err))?;
    let sources = parse_sources(&parsed, path)?;
    let default_index = sources.first().map(|(name, _)| name.as_str());
    let source_urls: HashMap<&str, &str> = sources
        .iter()
        .map(|(name, url)| (name.as_str(), url.as_str()))
        .collect();

    let top_level = parsed
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Failed to parse {}: expected a table", path.display()))?;
    // Pipenv treats every top-level table other than its reserved settings tables as a
    // package category (`pipenv install --categories docs`), so scan them all.
    let mut sections: Vec<&str> = vec!["packages", "dev-packages"];
    for key in top_level.keys() {
        if !PIPFILE_RESERVED_TABLES.contains(&key.as_str())
            && key != "packages"
            && key != "dev-packages"
        {
            sections.push(key.as_str());
        }
    }

    let mut categories = Vec::new();
    for section in sections {
        let Some(value) = top_level.get(section) else {
            continue;
        };
        let Some(table) = value.as_table() else {
            bail!(
                "Unsupported Pipfile entry '{}' in {}: expected a package category table",
                crate::report::sanitize_for_terminal(section),
                path.display()
            );
        };
        let mut deps = Vec::new();
        for (name, value) in table {
            if let Some(dep) =
                parse_pipfile_dependency(name, value, default_index, &source_urls, path)?
            {
                deps.push(dep);
            }
        }
        categories.push(PipfileCategory {
            lock_section: lock_section_for_category(section).to_string(),
            deps,
        });
    }

    Ok(ParsedPipfile {
        categories,
        source_urls: sources.into_iter().map(|(_, url)| url).collect(),
        hash: pipfile_hash(&parsed),
    })
}

fn parse_sources(parsed: &toml::Value, source_path: &Path) -> Result<Vec<(String, String)>> {
    let mut sources = Vec::new();

    let Some(entries) = parsed.get("source").and_then(|value| value.as_array()) else {
        return Ok(sources);
    };

    for entry in entries {
        let table = entry.as_table().ok_or_else(|| {
            anyhow::anyhow!(
                "Unsupported Pipfile source declaration in {}: expected a table",
                source_path.display()
            )
        })?;
        let name = table
            .get("name")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Unsupported Pipfile source declaration in {}: missing source name",
                    source_path.display()
                )
            })?;
        let url = table
            .get("url")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Unsupported Pipfile source declaration '{}' in {}: missing source URL",
                    crate::report::sanitize_for_terminal(name),
                    source_path.display()
                )
            })?;
        let normalized = crate::config::normalize_python_index_url(url);
        if normalized != crate::config::normalized_default_pypi_index() {
            bail!(
                "Unsupported Pipfile source declaration '{}' in {}: alternate package indexes are not supported",
                crate::report::sanitize_for_terminal(name),
                source_path.display()
            );
        }
        sources.push((name.to_string(), normalized));
    }

    Ok(sources)
}

fn parse_pipfile_dependency(
    name: &str,
    value: &toml::Value,
    _default_index: Option<&str>,
    source_urls: &HashMap<&str, &str>,
    source_path: &Path,
) -> Result<Option<Dependency>> {
    let requirement = match value {
        toml::Value::String(spec) => compose_requirement(name, Some(spec.as_str())),
        toml::Value::Table(table) => {
            for forbidden in [
                "git",
                "path",
                "file",
                "url",
                "editable",
                "ref",
                "subdirectory",
            ] {
                if table.contains_key(forbidden) {
                    bail!(
                        "Unsupported Pipfile dependency '{}' in {}: {} sources are not supported",
                        crate::report::sanitize_for_terminal(name),
                        source_path.display(),
                        forbidden
                    );
                }
            }
            if let Some(index) = table.get("index").and_then(|value| value.as_str()) {
                let Some(source_url) = source_urls.get(index).copied() else {
                    bail!(
                        "Unsupported Pipfile dependency '{}' in {}: referenced package index '{}' is not declared",
                        crate::report::sanitize_for_terminal(name),
                        source_path.display(),
                        crate::report::sanitize_for_terminal(index)
                    );
                };
                if source_url != crate::config::normalized_default_pypi_index() {
                    bail!(
                        "Unsupported Pipfile dependency '{}' in {}: alternate package indexes are not supported",
                        crate::report::sanitize_for_terminal(name),
                        source_path.display()
                    );
                }
            }
            let version = table.get("version").and_then(|value| value.as_str());
            compose_requirement(name, version)
        }
        _ => bail!(
            "Unsupported Pipfile dependency '{}' in {}",
            crate::report::sanitize_for_terminal(name),
            source_path.display()
        ),
    };

    super::requirements::parse_requirement_spec(&requirement, source_path)
}

fn compose_requirement(name: &str, spec: Option<&str>) -> String {
    match spec {
        Some("*") | None => name.to_string(),
        // Pipenv reads a version with no comparison operator as `==<version>`.
        Some(version) if !version.trim_start().starts_with(['<', '>', '=', '~', '!']) => {
            format!("{name}=={}", version.trim())
        }
        Some(version) => format!("{name}{version}"),
    }
}

#[cfg(test)]
#[path = "pipfile_coverage_tests.rs"]
mod coverage_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::test_utils::*;

    #[test]
    fn parse_packages_and_dev_packages() {
        let dir = setup_test_dir(
            "pipfile",
            "Pipfile",
            "[[source]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\n[packages]\nrequests = \"==2.31.0\"\n[dev-packages]\npytest = \"==8.1.1\"\n",
        );

        let deps = parse(&dir).unwrap();
        let names: Vec<&str> = deps.iter().map(|dep| dep.name.as_str()).collect();
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"pytest"));

        cleanup(&dir);
    }

    #[test]
    fn reject_path_dependencies() {
        let dir = setup_test_dir(
            "pipfile-path",
            "Pipfile",
            "[packages]\nlocal = { path = \"../local\" }\n",
        );

        let err = parse(&dir).unwrap_err();
        assert!(err.to_string().contains("Unsupported Pipfile dependency"));

        cleanup(&dir);
    }

    #[test]
    fn reject_non_default_package_indexes() {
        let dir = setup_test_dir(
            "pipfile-index",
            "Pipfile",
            r#"[[source]]
name = "pypi"
url = "https://pypi.org/simple"
verify_ssl = true

[[source]]
name = "internal"
url = "https://packages.example.com/simple"
verify_ssl = true

[packages]
private = { version = "==1.0.0", index = "internal" }
"#,
        );

        let err = parse(&dir).unwrap_err();
        assert!(err.to_string().contains("alternate package indexes"));
        cleanup(&dir);
    }

    #[test]
    fn reject_default_source_mirror_named_pypi() {
        let dir = setup_test_dir(
            "pipfile-default-mirror",
            "Pipfile",
            r#"[[source]]
name = "pypi"
url = "https://mirror.example.com/simple"
verify_ssl = true

[packages]
requests = "==2.31.0"
"#,
        );

        let err = parse(&dir).unwrap_err();
        assert!(err.to_string().contains("alternate package indexes"));
        cleanup(&dir);
    }

    #[test]
    fn allow_same_pypi_url_via_non_default_alias() {
        let dir = setup_test_dir(
            "pipfile-same-pypi-alias",
            "Pipfile",
            r#"[[source]]
name = "mirror-a"
url = "https://pypi.org/simple/"
verify_ssl = true

[[source]]
name = "mirror-b"
url = "https://pypi.org/simple"
verify_ssl = true

[packages]
requests = { version = "==2.31.0", index = "mirror-b" }
"#,
        );

        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "requests");
        cleanup(&dir);
    }
}

#[cfg(test)]
#[path = "pipfile_hash_tests.rs"]
mod pipfile_hash_tests;
