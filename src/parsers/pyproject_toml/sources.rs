use super::*;

pub(crate) fn parse_poetry_sources(path: &Path) -> Result<Vec<PythonSourceDecl>> {
    let parsed = parse_toml(path)?;
    let poetry = parsed
        .get("tool")
        .and_then(|tool| tool.get("poetry"))
        .and_then(|value| value.as_table())
        .ok_or_else(|| anyhow::anyhow!("Poetry metadata missing from {}", path.display()))?;

    let mut sources = Vec::new();
    let mut seen_names = std::collections::HashSet::new();
    if let Some(entries) = poetry.get("source").and_then(|value| value.as_array()) {
        for entry in entries {
            let table = entry.as_table().ok_or_else(|| {
                anyhow::anyhow!(
                    "Unsupported Poetry source declaration in {}: expected a table",
                    path.display()
                )
            })?;
            let name = table
                .get("name")
                .and_then(|value| value.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Unsupported Poetry source declaration in {}: missing source name",
                        path.display()
                    )
                })?;
            let normalized_url = if name.eq_ignore_ascii_case("pypi") {
                if let Some(url) = table.get("url").and_then(|value| value.as_str()) {
                    let normalized = crate::config::normalize_python_index_url(url);
                    if normalized != crate::config::normalized_default_pypi_index() {
                        bail!(
                            "Unsupported Poetry source declaration '{}' in {}: the reserved source name 'pypi' must point to {}",
                            name,
                            path.display(),
                            crate::config::normalized_default_pypi_index()
                        );
                    }
                }
                crate::config::normalized_default_pypi_index().to_string()
            } else {
                let normalized = crate::config::normalize_python_index_url(
                    table.get("url").and_then(|value| value.as_str()).ok_or_else(|| {
                        anyhow::anyhow!(
                            "Unsupported Poetry source declaration '{}' in {}: missing source URL",
                            name,
                            path.display()
                        )
                    })?,
                );
                if !crate::config::python_index_url_has_supported_scheme(&normalized) {
                    bail!(
                        "Unsupported Poetry source declaration '{}' in {}: only http:// and https:// package index URLs are supported",
                        name,
                        path.display()
                    );
                }
                if normalized == crate::config::normalized_default_pypi_index() {
                    bail!(
                        "Unsupported Poetry source declaration '{}' in {}: do not rename PyPI. Use the reserved source name 'pypi' or omit the declaration entirely",
                        name,
                        path.display()
                    );
                }
                normalized
            };
            if !seen_names.insert(name.to_lowercase()) {
                bail!(
                    "Unsupported Poetry source declaration '{}' in {}: duplicate source names are not supported",
                    name,
                    path.display()
                );
            }
            sources.push(PythonSourceDecl {
                name: name.to_string(),
                normalized_url,
            });
        }
    }
    Ok(sources)
}

#[cfg(test)]
pub(crate) fn parse_poetry_source_intents(
    path: &Path,
) -> Result<Vec<PythonDependencySourceIntent>> {
    Ok(parse_poetry_source_intents_scoped(path)?
        .into_iter()
        .map(|intent| intent.intent)
        .collect())
}

pub(crate) fn parse_poetry_source_intents_scoped(
    path: &Path,
) -> Result<Vec<PythonScopedDependencySourceIntent>> {
    let parsed = parse_toml(path)?;
    let poetry = parsed
        .get("tool")
        .and_then(|tool| tool.get("poetry"))
        .and_then(|value| value.as_table())
        .ok_or_else(|| anyhow::anyhow!("Poetry metadata missing from {}", path.display()))?;

    let sources = declared_source_map(&parse_poetry_sources(path)?);
    let legacy_extras = legacy_poetry_extras(poetry);
    let mut intents = Vec::new();
    collect_poetry_source_intents_scoped(
        poetry
            .get("dependencies")
            .and_then(|value| value.as_table()),
        path,
        &sources,
        &mut intents,
        None,
        &legacy_extras,
    )?;
    collect_poetry_source_intents_scoped(
        poetry
            .get("dev-dependencies")
            .and_then(|value| value.as_table()),
        path,
        &sources,
        &mut intents,
        Some("dev"),
        &legacy_extras,
    )?;
    if let Some(groups) = poetry.get("group").and_then(|value| value.as_table()) {
        for (group_name, group) in groups {
            collect_poetry_source_intents_scoped(
                group.get("dependencies").and_then(|value| value.as_table()),
                path,
                &sources,
                &mut intents,
                Some(group_name.as_str()),
                &legacy_extras,
            )?;
        }
    }
    Ok(intents)
}

/// uv settings that redirect resolution to indexes or directories outside the declared
/// `[[tool.uv.index]]` entries.
const UV_UNVERIFIABLE_KEYS: &[&str] = &[
    "index-url",
    "extra-index-url",
    "find-links",
    "no-index",
    "index",
    "index-strategy",
    "default-index",
];

fn reject_uv_redirects(table: &toml::map::Map<String, toml::Value>, source: &Path) -> Result<()> {
    let pip = table.get("pip").and_then(|value| value.as_table());
    for key in UV_UNVERIFIABLE_KEYS {
        if table.contains_key(*key) || pip.is_some_and(|pip| pip.contains_key(*key)) {
            bail!(
                "Unsupported uv setting '{key}' in {}: it redirects package resolution to an index or directory that cannot be verified",
                source.display()
            );
        }
    }
    Ok(())
}

/// `uv.toml` in the project directory or any parent configures uv for the project (and, when
/// present, replaces `[tool.uv]`), so its index settings count the same as pyproject's.
fn reject_uv_toml_redirects(pyproject: &Path) -> Result<()> {
    let dir = std::fs::canonicalize(pyproject.parent().unwrap_or(Path::new(".")))?;
    let boundary = crate::cache::find_git_root(&dir).map_err(anyhow::Error::msg)?;
    for ancestor in dir.ancestors() {
        let file = ancestor.join("uv.toml");
        if super::super::path_detected(&file)? {
            let parsed = parse_toml(&file)?;
            if let Some(table) = parsed.as_table() {
                reject_uv_redirects(table, &file)?;
            }
        }
        if boundary.as_deref() == Some(ancestor) {
            break;
        }
    }
    Ok(())
}

pub(crate) fn parse_uv_sources(path: &Path) -> Result<Vec<PythonSourceDecl>> {
    let parsed = parse_toml(path)?;
    reject_uv_toml_redirects(path)?;
    let Some(uv) = parsed.get("tool").and_then(|tool| tool.get("uv")) else {
        return Ok(Vec::new());
    };
    let uv = uv
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Invalid uv metadata in {}", path.display()))?;
    // `index` here is the supported `[[tool.uv.index]]` array; the legacy keys are not.
    let mut legacy = uv.clone();
    legacy.remove("index");
    reject_uv_redirects(&legacy, path)?;

    let mut sources = Vec::new();
    let mut seen_names = std::collections::HashSet::new();
    if let Some(entries) = uv.get("index").and_then(|value| value.as_array()) {
        for entry in entries {
            let table = entry.as_table().ok_or_else(|| {
                anyhow::anyhow!(
                    "Unsupported uv index declaration in {}: expected a table",
                    path.display()
                )
            })?;
            let name = table
                .get("name")
                .and_then(|value| value.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Unsupported uv index declaration in {}: missing index name",
                        path.display()
                    )
                })?;
            let url = table
                .get("url")
                .and_then(|value| value.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Unsupported uv index declaration '{}' in {}: missing index URL",
                        name,
                        path.display()
                    )
                })?;
            let normalized_url = crate::config::normalize_python_index_url(url);
            let normalized_url = if name.eq_ignore_ascii_case("pypi") {
                if normalized_url != crate::config::normalized_default_pypi_index() {
                    bail!(
                        "Unsupported uv index declaration '{}' in {}: the reserved index name 'pypi' must point to {}",
                        name,
                        path.display(),
                        crate::config::normalized_default_pypi_index()
                    );
                }
                crate::config::normalized_default_pypi_index().to_string()
            } else {
                if !crate::config::python_index_url_has_supported_scheme(&normalized_url) {
                    bail!(
                        "Unsupported uv index declaration '{}' in {}: only http:// and https:// package index URLs are supported",
                        name,
                        path.display()
                    );
                }
                if normalized_url == crate::config::normalized_default_pypi_index() {
                    bail!(
                        "Unsupported uv index declaration '{}' in {}: do not rename PyPI. Use the reserved index name 'pypi' or omit the declaration entirely",
                        name,
                        path.display()
                    );
                }
                normalized_url
            };
            if !seen_names.insert(name.to_lowercase()) {
                bail!(
                    "Unsupported uv index declaration '{}' in {}: duplicate index names are not supported",
                    name,
                    path.display()
                );
            }
            sources.push(PythonSourceDecl {
                name: name.to_string(),
                normalized_url,
            });
        }
    }
    Ok(sources)
}

#[cfg(test)]
pub(crate) fn parse_uv_source_intents(path: &Path) -> Result<Vec<PythonDependencySourceIntent>> {
    Ok(parse_uv_source_intents_scoped(path)?
        .into_iter()
        .map(|intent| intent.intent)
        .collect())
}

pub(crate) fn parse_uv_source_intents_scoped(
    path: &Path,
) -> Result<Vec<PythonScopedDependencySourceIntent>> {
    let parsed = parse_toml(path)?;
    let Some(uv) = parsed.get("tool").and_then(|tool| tool.get("uv")) else {
        return Ok(Vec::new());
    };
    let uv = uv
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Invalid uv metadata in {}", path.display()))?;
    let source_map = declared_source_map(&parse_uv_sources(path)?);
    let mut intents = Vec::new();

    let Some(sources) = uv.get("sources").and_then(|value| value.as_table()) else {
        return Ok(intents);
    };

    for (package, value) in sources {
        intents.extend(parse_uv_source_entry_scoped(
            package,
            value,
            path,
            &source_map,
        )?);
    }

    Ok(intents)
}

pub(crate) fn collect_poetry_source_intents_scoped(
    section: Option<&toml::map::Map<String, toml::Value>>,
    source_path: &Path,
    sources: &std::collections::HashMap<String, String>,
    intents: &mut Vec<PythonScopedDependencySourceIntent>,
    group: Option<&str>,
    legacy_extras: &HashMap<String, BTreeSet<String>>,
) -> Result<()> {
    let Some(section) = section else {
        return Ok(());
    };
    for (name, value) in section {
        if name == "python" {
            continue;
        }
        let Some(table) = value.as_table() else {
            continue;
        };
        let Some(source_name) = table.get("source").and_then(|value| value.as_str()) else {
            continue;
        };
        let Some(mut scope) = parse_poetry_dependency_scoped(name, value, source_path)? else {
            continue;
        };
        if let Some(group) = group {
            scope = scope.with_group(group);
        }
        if let Some(extras) = legacy_extras.get(&scope.dependency.name) {
            scope.extras.extend(extras.iter().cloned());
            scope.runtime_default = false;
        }
        let normalized_name = crate::parsers::requirements::normalize_distribution_name(name);
        let normalized_url = sources
            .get(&source_name.to_lowercase())
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Poetry dependency '{}' in {} references unknown source '{}'",
                    crate::report::sanitize_for_terminal(name),
                    source_path.display(),
                    crate::report::sanitize_for_terminal(source_name)
                )
            })?;
        intents.push(PythonScopedDependencySourceIntent {
            intent: PythonDependencySourceIntent {
                package: normalized_name,
                source_name: source_name.to_string(),
                normalized_url,
            },
            scope,
        });
    }
    Ok(())
}

pub(crate) fn declared_source_map(
    sources: &[PythonSourceDecl],
) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    map.insert(
        "pypi".to_string(),
        crate::config::normalized_default_pypi_index().to_string(),
    );
    for source in sources {
        map.insert(source.name.to_lowercase(), source.normalized_url.clone());
    }
    map
}

pub(crate) fn parse_uv_source_entry_scoped(
    package: &str,
    value: &toml::Value,
    source_path: &Path,
    sources: &std::collections::HashMap<String, String>,
) -> Result<Vec<PythonScopedDependencySourceIntent>> {
    match value {
        toml::Value::Table(table) => Ok(vec![parse_uv_index_source_table_scoped(
            package,
            table,
            source_path,
            sources,
        )?]),
        toml::Value::Array(entries) => entries
            .iter()
            .map(|entry| {
                let table = entry.as_table().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Unsupported uv source declaration in {}: expected a table",
                        source_path.display()
                    )
                })?;
                parse_uv_index_source_table_scoped(package, table, source_path, sources)
            })
            .collect(),
        _ => bail!(
            "Unsupported uv source declaration in {}",
            source_path.display()
        ),
    }
}

pub(crate) fn parse_uv_index_source_table_scoped(
    package: &str,
    table: &toml::map::Map<String, toml::Value>,
    source_path: &Path,
    sources: &std::collections::HashMap<String, String>,
) -> Result<PythonScopedDependencySourceIntent> {
    let marker = table
        .get("marker")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let Some(index_name) = table.get("index").and_then(|value| value.as_str()) else {
        bail!(
            "Unsupported uv source declaration in {}: only index-based uv sources are supported",
            source_path.display()
        );
    };
    let normalized_url = sources
        .get(&index_name.to_lowercase())
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "uv dependency source in {} references unknown index '{}'",
                source_path.display(),
                crate::report::sanitize_for_terminal(index_name)
            )
        })?;
    Ok(PythonScopedDependencySourceIntent {
        intent: PythonDependencySourceIntent {
            package: crate::parsers::requirements::normalize_distribution_name(package),
            source_name: index_name.to_string(),
            normalized_url,
        },
        scope: PythonScopedDependency::runtime(
            Dependency {
                name: crate::parsers::requirements::normalize_distribution_name(package),
                version: None,
                ecosystem: crate::Ecosystem::PyPI,
                actual_name: None,
            },
            marker,
        ),
    })
}
