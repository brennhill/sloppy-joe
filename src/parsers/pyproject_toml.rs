use crate::Dependency;
use crate::parsers::python_scope::{PythonProfile, PythonScopedDependency};
use anyhow::{Result, bail};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PythonSourceDecl {
    pub name: String,
    pub normalized_url: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PythonDependencySourceIntent {
    pub package: String,
    pub source_name: String,
    pub normalized_url: String,
}

#[derive(Clone, Debug)]
pub(crate) struct PythonScopedDependencySourceIntent {
    pub intent: PythonDependencySourceIntent,
    pub scope: PythonScopedDependency,
}

impl PythonScopedDependencySourceIntent {
    pub(crate) fn is_in_scope(&self, profile: &PythonProfile) -> Result<bool> {
        self.scope.is_in_scope(profile)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PyprojectKind {
    Poetry,
    Uv,
    Legacy,
}

pub fn parse_poetry(project_dir: &Path) -> Result<Vec<Dependency>> {
    parse_poetry_file(&project_dir.join("pyproject.toml"))
}

pub fn parse_legacy(project_dir: &Path) -> Result<Vec<Dependency>> {
    parse_legacy_file(&project_dir.join("pyproject.toml"))
}

pub(crate) fn classify_manifest(path: &Path) -> Result<PyprojectKind> {
    let parsed = parse_toml(path)?;
    let has_poetry = parsed
        .get("tool")
        .and_then(|tool| tool.get("poetry"))
        .is_some();
    let has_uv = parsed.get("tool").and_then(|tool| tool.get("uv")).is_some();
    if has_poetry && has_uv {
        bail!(
            "Ambiguous Python project metadata in {}: both [tool.poetry] and [tool.uv] are present",
            path.display()
        );
    }
    if has_poetry {
        Ok(PyprojectKind::Poetry)
    } else if has_uv {
        Ok(PyprojectKind::Uv)
    } else {
        Ok(PyprojectKind::Legacy)
    }
}

pub(crate) fn parse_poetry_file(path: &Path) -> Result<Vec<Dependency>> {
    Ok(parse_poetry_scoped_file(path)?
        .into_iter()
        .map(|dep| dep.dependency)
        .collect())
}

pub(crate) fn parse_poetry_scoped_file(path: &Path) -> Result<Vec<PythonScopedDependency>> {
    let parsed = parse_toml(path)?;
    let poetry = parsed
        .get("tool")
        .and_then(|tool| tool.get("poetry"))
        .and_then(|value| value.as_table())
        .ok_or_else(|| anyhow::anyhow!("Poetry metadata missing from {}", path.display()))?;

    let mut deps = Vec::new();
    let legacy_extras = legacy_poetry_extras(poetry);
    collect_poetry_section_scoped(
        poetry
            .get("dependencies")
            .and_then(|value| value.as_table()),
        path,
        &mut deps,
        None,
        &legacy_extras,
    )?;
    collect_poetry_section_scoped(
        poetry
            .get("dev-dependencies")
            .and_then(|value| value.as_table()),
        path,
        &mut deps,
        Some("dev"),
        &legacy_extras,
    )?;
    if let Some(groups) = poetry.get("group").and_then(|value| value.as_table()) {
        for (group_name, group) in groups {
            collect_poetry_section_scoped(
                group.get("dependencies").and_then(|value| value.as_table()),
                path,
                &mut deps,
                Some(group_name.as_str()),
                &legacy_extras,
            )?;
        }
    }

    Ok(deps)
}

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

pub(crate) fn parse_uv_sources(path: &Path) -> Result<Vec<PythonSourceDecl>> {
    let parsed = parse_toml(path)?;
    let tool = parsed
        .get("tool")
        .and_then(|tool| tool.as_table())
        .ok_or_else(|| anyhow::anyhow!("Missing [tool] table in {}", path.display()))?;
    let uv = tool
        .get("uv")
        .and_then(|value| value.as_table())
        .ok_or_else(|| anyhow::anyhow!("uv metadata missing from {}", path.display()))?;

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
    let tool = parsed
        .get("tool")
        .and_then(|value| value.as_table())
        .ok_or_else(|| anyhow::anyhow!("Missing [tool] table in {}", path.display()))?;
    let uv = tool
        .get("uv")
        .and_then(|value| value.as_table())
        .ok_or_else(|| anyhow::anyhow!("uv metadata missing from {}", path.display()))?;
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

pub(crate) fn parse_legacy_file(path: &Path) -> Result<Vec<Dependency>> {
    Ok(parse_legacy_scoped_file(path)?
        .into_iter()
        .map(|dep| dep.dependency)
        .collect())
}

pub(crate) fn parse_legacy_scoped_file(path: &Path) -> Result<Vec<PythonScopedDependency>> {
    let parsed = parse_toml(path)?;
    if parsed
        .get("tool")
        .and_then(|tool| tool.get("poetry"))
        .is_some()
    {
        bail!(
            "Poetry projects must be parsed through the trusted Poetry path in {}",
            path.display()
        );
    }

    let mut deps = Vec::new();

    if let Some(project) = parsed.get("project").and_then(|value| value.as_table()) {
        if project
            .get("dynamic")
            .and_then(|value| value.as_array())
            .into_iter()
            .flatten()
            .filter_map(|value| value.as_str())
            .any(|value| value == "dependencies" || value == "optional-dependencies")
        {
            bail!(
                "Unsupported dynamic dependency declaration in {}",
                path.display()
            );
        }

        collect_requirement_array_scoped(project.get("dependencies"), path, &mut deps, None, None)?;
        if let Some(optional) = project
            .get("optional-dependencies")
            .and_then(|value| value.as_table())
        {
            for (extra, group) in optional {
                collect_requirement_array_scoped(
                    Some(group),
                    path,
                    &mut deps,
                    None,
                    Some(extra.as_str()),
                )?;
            }
        }
    }

    if parsed
        .get("tool")
        .and_then(|tool| tool.get("setuptools"))
        .and_then(|setuptools| setuptools.get("dynamic"))
        .and_then(|value| value.as_table())
        .is_some_and(|dynamic| {
            dynamic.contains_key("dependencies") || dynamic.contains_key("optional-dependencies")
        })
    {
        bail!(
            "Unsupported dynamic dependency declaration in {}",
            path.display()
        );
    }

    if let Some(groups) = parsed
        .get("dependency-groups")
        .and_then(|value| value.as_table())
    {
        for (group_name, group) in groups {
            collect_requirement_array_scoped(
                Some(group),
                path,
                &mut deps,
                Some(group_name.as_str()),
                None,
            )?;
        }
    }

    Ok(deps)
}

fn parse_toml(path: &Path) -> Result<toml::Value> {
    let content = super::read_file_limited(path, super::MAX_MANIFEST_BYTES)?;
    toml::from_str(&content)
        .map_err(|err| anyhow::anyhow!("Failed to parse {}: {}", path.display(), err))
}

fn collect_poetry_section_scoped(
    section: Option<&toml::map::Map<String, toml::Value>>,
    source_path: &Path,
    deps: &mut Vec<PythonScopedDependency>,
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
        if let Some(dep) = parse_poetry_dependency_scoped(name, value, source_path)? {
            let mut dep = if let Some(group) = group {
                dep.with_group(group)
            } else {
                dep
            };
            if let Some(extras) = legacy_extras.get(&dep.dependency.name) {
                dep.extras.extend(extras.iter().cloned());
                dep.runtime_default = false;
            }
            deps.push(dep);
        }
    }

    Ok(())
}

fn parse_poetry_dependency_scoped(
    name: &str,
    value: &toml::Value,
    source_path: &Path,
) -> Result<Option<PythonScopedDependency>> {
    let requirement = match value {
        toml::Value::String(spec) => compose_poetry_requirement(name, Some(spec.as_str())),
        toml::Value::Table(table) => {
            for forbidden in ["git", "path", "url", "file", "develop", "directory"] {
                if table.contains_key(forbidden) {
                    let source_kind = if forbidden == "source" {
                        "alternate package indexes"
                    } else {
                        forbidden
                    };
                    bail!(
                        "Unsupported Poetry dependency '{}' in {}: {} sources are not supported",
                        crate::report::sanitize_for_terminal(name),
                        source_path.display(),
                        source_kind
                    );
                }
            }
            let requirement = compose_poetry_requirement(
                name,
                table.get("version").and_then(|value| value.as_str()),
            );
            let mut dep =
                super::requirements::parse_scoped_requirement_spec(&requirement, source_path)?;
            if let Some(dep) = &mut dep {
                for extra in poetry_dependency_requested_extras(table) {
                    dep.requested_extras.insert(extra);
                }
                if let Some(constraint) = table.get("python").and_then(|value| value.as_str()) {
                    dep.python_constraint = Some(constraint.trim().to_string());
                }
                if let Some(constraint) = table.get("platform").and_then(|value| value.as_str()) {
                    dep.platform_constraint = Some(constraint.trim().to_string());
                }
                if let Some(marker) = table.get("markers").and_then(|value| value.as_str()) {
                    dep.marker = Some(marker.to_string());
                }
                if table.get("optional").and_then(|value| value.as_bool()) == Some(true) {
                    dep.runtime_default = false;
                }
            }
            return Ok(dep);
        }
        _ => bail!(
            "Unsupported Poetry dependency '{}' in {}",
            crate::report::sanitize_for_terminal(name),
            source_path.display()
        ),
    };

    super::requirements::parse_scoped_requirement_spec(&requirement, source_path)
}

fn legacy_poetry_extras(poetry: &toml::value::Table) -> HashMap<String, BTreeSet<String>> {
    let mut by_package: HashMap<String, BTreeSet<String>> = HashMap::new();
    let Some(extras) = poetry.get("extras").and_then(|value| value.as_table()) else {
        return by_package;
    };
    for (extra, packages) in extras {
        let Some(packages) = packages.as_array() else {
            continue;
        };
        let extra = super::requirements::normalize_distribution_name(extra);
        for package in packages.iter().filter_map(|value| value.as_str()) {
            let package = super::requirements::normalize_distribution_name(package);
            if !package.is_empty() && !extra.is_empty() {
                by_package.entry(package).or_default().insert(extra.clone());
            }
        }
    }
    by_package
}

fn poetry_dependency_requested_extras(table: &toml::value::Table) -> Vec<String> {
    table
        .get("extras")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str())
        .map(super::requirements::normalize_distribution_name)
        .filter(|extra| !extra.is_empty())
        .collect()
}

fn collect_poetry_source_intents_scoped(
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

fn declared_source_map(sources: &[PythonSourceDecl]) -> std::collections::HashMap<String, String> {
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

fn parse_uv_source_entry_scoped(
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

fn parse_uv_index_source_table_scoped(
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

fn collect_requirement_array_scoped(
    value: Option<&toml::Value>,
    source_path: &Path,
    deps: &mut Vec<PythonScopedDependency>,
    group: Option<&str>,
    extra: Option<&str>,
) -> Result<()> {
    let Some(entries) = value.and_then(|value| value.as_array()) else {
        return Ok(());
    };

    for entry in entries {
        let spec = entry.as_str().ok_or_else(|| {
            anyhow::anyhow!(
                "Unsupported dependency entry in {}: expected a string requirement",
                source_path.display()
            )
        })?;
        if let Some(dep) = super::requirements::parse_scoped_requirement_spec(spec, source_path)? {
            let dep = if let Some(group) = group {
                dep.with_group(group)
            } else {
                dep
            };
            let dep = if let Some(extra) = extra {
                dep.with_extra(extra)
            } else {
                dep
            };
            deps.push(dep);
        }
    }

    Ok(())
}

fn compose_poetry_requirement(name: &str, spec: Option<&str>) -> String {
    match spec.map(str::trim) {
        Some("*") | None => name.to_string(),
        Some(version)
            if version.starts_with(['^', '~', '>', '<', '=', '!']) || version.contains(',') =>
        {
            format!("{name}{version}")
        }
        Some(version) => format!("{name}=={version}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::test_utils::*;

    #[test]
    fn classify_poetry_manifest() {
        let dir = setup_test_dir(
            "pyproject-poetry",
            "pyproject.toml",
            "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        );

        assert_eq!(
            classify_manifest(&dir.join("pyproject.toml")).unwrap(),
            PyprojectKind::Poetry
        );

        cleanup(&dir);
    }

    #[test]
    fn parse_legacy_pep621_dependencies() {
        let dir = setup_test_dir(
            "pyproject-legacy",
            "pyproject.toml",
            "[project]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\"requests==2.31.0\"]\n[project.optional-dependencies]\ndev = [\"pytest==8.1.1\"]\n",
        );

        let deps = parse_legacy(&dir).unwrap();
        let names: Vec<&str> = deps.iter().map(|dep| dep.name.as_str()).collect();
        assert!(names.contains(&"requests"));
        assert!(names.contains(&"pytest"));

        cleanup(&dir);
    }

    #[test]
    fn poetry_dev_dependencies_are_group_scoped() {
        let dir = setup_test_dir(
            "pyproject-poetry-dev-scope",
            "pyproject.toml",
            r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
fastapi = "^0.116"

[tool.poetry.dev-dependencies]
pytest = "^8"
"#,
        );

        let deps = parse_poetry_scoped_file(&dir.join("pyproject.toml")).unwrap();
        let pytest = deps
            .iter()
            .find(|dep| dep.dependency.name == "pytest")
            .unwrap();
        assert!(pytest.groups.contains("dev"));
        assert!(!pytest.runtime_default);
        cleanup(&dir);
    }

    #[test]
    fn poetry_table_dependency_preserves_requested_extras() {
        let dir = setup_test_dir(
            "pyproject-poetry-requested-extras",
            "pyproject.toml",
            r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
fastapi = { version = "0.116.0", extras = ["standard"] }
"#,
        );

        let deps = parse_poetry_scoped_file(&dir.join("pyproject.toml")).unwrap();
        let fastapi = deps
            .iter()
            .find(|dep| dep.dependency.name == "fastapi")
            .unwrap();
        assert!(fastapi.requested_extras.contains("standard"));
        cleanup(&dir);
    }

    #[test]
    fn poetry_table_dependency_preserves_markers() {
        let dir = setup_test_dir(
            "pyproject-poetry-table-markers",
            "pyproject.toml",
            r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
pywin32 = { version = "306", markers = "sys_platform == 'win32'" }
"#,
        );

        let deps = parse_poetry_scoped_file(&dir.join("pyproject.toml")).unwrap();
        let pywin32 = deps
            .iter()
            .find(|dep| dep.dependency.name == "pywin32")
            .unwrap();
        assert_eq!(pywin32.marker.as_deref(), Some("sys_platform == 'win32'"));
        let linux = crate::parsers::python_scope::PythonProfile::for_target("linux", "3.12");
        assert!(!pywin32.is_in_scope(&linux).unwrap());
        cleanup(&dir);
    }

    #[test]
    fn poetry_table_dependency_scopes_python_shorthand() {
        let dir = setup_test_dir(
            "pyproject-poetry-table-python-shorthand",
            "pyproject.toml",
            r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
pywin32 = { version = "306", python = "<3.13" }
"#,
        );

        let deps = parse_poetry_scoped_file(&dir.join("pyproject.toml")).unwrap();
        let pywin32 = deps
            .iter()
            .find(|dep| dep.dependency.name == "pywin32")
            .unwrap();
        let py312 = crate::parsers::python_scope::PythonProfile::for_target("linux", "3.12");
        let py313 = crate::parsers::python_scope::PythonProfile::for_target("linux", "3.13");
        assert!(pywin32.is_in_scope(&py312).unwrap());
        assert!(!pywin32.is_in_scope(&py313).unwrap());
        cleanup(&dir);
    }

    #[test]
    fn poetry_table_dependency_scopes_platform_shorthand() {
        let dir = setup_test_dir(
            "pyproject-poetry-table-platform-shorthand",
            "pyproject.toml",
            r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
pyobjc = { version = "10.0", platform = "darwin" }
"#,
        );

        let deps = parse_poetry_scoped_file(&dir.join("pyproject.toml")).unwrap();
        let pyobjc = deps
            .iter()
            .find(|dep| dep.dependency.name == "pyobjc")
            .unwrap();
        let macos = crate::parsers::python_scope::PythonProfile::for_target("darwin", "3.12");
        let linux = crate::parsers::python_scope::PythonProfile::for_target("linux", "3.12");
        assert!(pyobjc.is_in_scope(&macos).unwrap());
        assert!(!pyobjc.is_in_scope(&linux).unwrap());
        cleanup(&dir);
    }

    #[test]
    fn legacy_poetry_extras_select_optional_dependencies() {
        let dir = setup_test_dir(
            "pyproject-poetry-legacy-extras",
            "pyproject.toml",
            r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
requests = "2.31.0"
uvicorn = { version = "0.30.0", optional = true }

[tool.poetry.extras]
standard = ["uvicorn"]
"#,
        );

        let deps = parse_poetry_scoped_file(&dir.join("pyproject.toml")).unwrap();
        let requests = deps
            .iter()
            .find(|dep| dep.dependency.name == "requests")
            .unwrap();
        let uvicorn = deps
            .iter()
            .find(|dep| dep.dependency.name == "uvicorn")
            .unwrap();
        assert!(requests.runtime_default);
        assert!(!uvicorn.runtime_default);
        assert!(uvicorn.extras.contains("standard"));
        cleanup(&dir);
    }

    #[test]
    fn pep621_optional_dependencies_are_extra_scoped() {
        let dir = setup_test_dir(
            "pyproject-pep621-extra-scope",
            "pyproject.toml",
            r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["requests==2.31.0"]

[project.optional-dependencies]
docs = ["mkdocs==1.6.0"]
"#,
        );

        let deps = parse_legacy_scoped_file(&dir.join("pyproject.toml")).unwrap();
        let mkdocs = deps
            .iter()
            .find(|dep| dep.dependency.name == "mkdocs")
            .unwrap();
        assert!(mkdocs.extras.contains("docs"));
        assert!(!mkdocs.runtime_default);
        cleanup(&dir);
    }

    #[test]
    fn poetry_extracts_declared_sources() {
        let dir = setup_test_dir(
            "pyproject-poetry-source",
            "pyproject.toml",
            r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
private-lib = { version = "^1.0.0", source = "internal" }

[[tool.poetry.source]]
name = "internal"
url = "https://packages.example.com/simple"
priority = "explicit"
"#,
        );

        let sources = parse_poetry_sources(&dir.join("pyproject.toml")).unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].name, "internal");
        assert_eq!(
            sources[0].normalized_url,
            "https://packages.example.com/simple/"
        );
        cleanup(&dir);
    }

    #[test]
    fn poetry_extracts_dependency_source_intent() {
        let dir = setup_test_dir(
            "pyproject-poetry-source-intent",
            "pyproject.toml",
            r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
private-lib = { version = "^1.0.0", source = "internal" }

[[tool.poetry.source]]
name = "internal"
url = "https://packages.example.com/simple"
"#,
        );

        let intents = parse_poetry_source_intents(&dir.join("pyproject.toml")).unwrap();
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].package, "private-lib");
        assert_eq!(intents[0].source_name, "internal");
        assert_eq!(
            intents[0].normalized_url,
            "https://packages.example.com/simple/"
        );
        cleanup(&dir);
    }

    #[test]
    fn poetry_rejects_source_binding_to_unknown_source_name() {
        let dir = setup_test_dir(
            "pyproject-poetry-source-unknown",
            "pyproject.toml",
            r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
private-lib = { version = "^1.0.0", source = "internal" }
"#,
        );

        let err = parse_poetry_source_intents(&dir.join("pyproject.toml")).unwrap_err();
        assert!(err.to_string().contains("unknown source"));
        cleanup(&dir);
    }

    #[test]
    fn poetry_rejects_reserved_pypi_source_name_with_custom_url() {
        let dir = setup_test_dir(
            "pyproject-poetry-source-pypi-custom-url",
            "pyproject.toml",
            r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[[tool.poetry.source]]
name = "pypi"
url = "https://packages.example.com/simple"
"#,
        );

        let err = parse_poetry_sources(&dir.join("pyproject.toml")).unwrap_err();
        assert!(err.to_string().contains("reserved source name 'pypi'"));
        cleanup(&dir);
    }

    #[test]
    fn poetry_rejects_default_pypi_url_under_non_pypi_alias() {
        let dir = setup_test_dir(
            "pyproject-poetry-source-pypi-alias",
            "pyproject.toml",
            r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[[tool.poetry.source]]
name = "public"
url = "https://pypi.org/simple"
"#,
        );

        let err = parse_poetry_sources(&dir.join("pyproject.toml")).unwrap_err();
        assert!(err.to_string().contains("rename PyPI"));
        cleanup(&dir);
    }

    #[test]
    fn poetry_rejects_non_http_source_urls() {
        let dir = setup_test_dir(
            "pyproject-poetry-source-file-url",
            "pyproject.toml",
            r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[[tool.poetry.source]]
name = "internal"
url = "file:///tmp/internal"
"#,
        );

        let err = parse_poetry_sources(&dir.join("pyproject.toml")).unwrap_err();
        assert!(err.to_string().contains("http:// and https://"));
        cleanup(&dir);
    }

    #[test]
    fn poetry_rejects_duplicate_source_names() {
        let dir = setup_test_dir(
            "pyproject-poetry-source-duplicate",
            "pyproject.toml",
            r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[[tool.poetry.source]]
name = "internal"
url = "https://packages.example.com/simple"

[[tool.poetry.source]]
name = "internal"
url = "https://mirror.example.com/simple"
"#,
        );

        let err = parse_poetry_sources(&dir.join("pyproject.toml")).unwrap_err();
        assert!(err.to_string().contains("duplicate source names"));
        cleanup(&dir);
    }

    #[test]
    fn parse_poetry_exact_versions_as_exact_pins() {
        let dir = setup_test_dir(
            "pyproject-poetry-versions",
            "pyproject.toml",
            "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"2.31.0\"\n",
        );

        let deps = parse_poetry(&dir).unwrap();
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version.as_deref(), Some("==2.31.0"));

        cleanup(&dir);
    }

    #[test]
    fn reject_setuptools_dynamic_dependencies() {
        let dir = setup_test_dir(
            "pyproject-setuptools-dynamic",
            "pyproject.toml",
            "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.setuptools.dynamic]\ndependencies = { file = [\"requirements.txt\"] }\n",
        );

        let err = parse_legacy(&dir).unwrap_err();
        assert!(err.to_string().contains("dynamic"));

        cleanup(&dir);
    }

    #[test]
    fn classify_uv_manifest() {
        let dir = setup_test_dir(
            "pyproject-uv",
            "pyproject.toml",
            "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.uv]\n",
        );

        assert_eq!(
            classify_manifest(&dir.join("pyproject.toml")).unwrap(),
            PyprojectKind::Uv
        );

        cleanup(&dir);
    }

    #[test]
    fn classify_mixed_poetry_and_uv_manifest_fails() {
        let dir = setup_test_dir(
            "pyproject-mixed",
            "pyproject.toml",
            "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n[tool.uv]\n",
        );

        let err = classify_manifest(&dir.join("pyproject.toml"))
            .expect_err("mixed Poetry and uv metadata must fail closed");
        assert!(
            err.to_string()
                .contains("Ambiguous Python project metadata")
        );

        cleanup(&dir);
    }

    #[test]
    fn uv_extracts_declared_sources() {
        let dir = setup_test_dir(
            "pyproject-uv-sources",
            "pyproject.toml",
            r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["torch"]

[tool.uv.sources]
torch = { index = "pytorch" }

[[tool.uv.index]]
name = "pytorch"
url = "https://download.pytorch.org/whl/cu124"
"#,
        );

        let sources = parse_uv_sources(&dir.join("pyproject.toml")).unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].name, "pytorch");
        assert_eq!(
            sources[0].normalized_url,
            "https://download.pytorch.org/whl/cu124/"
        );
        cleanup(&dir);
    }

    #[test]
    fn uv_extracts_dependency_source_intent() {
        let dir = setup_test_dir(
            "pyproject-uv-source-intent",
            "pyproject.toml",
            r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["torch"]

[tool.uv.sources]
torch = { index = "pytorch" }

[[tool.uv.index]]
name = "pytorch"
url = "https://download.pytorch.org/whl/cu124"
"#,
        );

        let intents = parse_uv_source_intents(&dir.join("pyproject.toml")).unwrap();
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].package, "torch");
        assert_eq!(intents[0].source_name, "pytorch");
        assert_eq!(
            intents[0].normalized_url,
            "https://download.pytorch.org/whl/cu124/"
        );
        cleanup(&dir);
    }

    #[test]
    fn uv_extracts_marker_scoped_source_intents_from_arrays() {
        let dir = setup_test_dir(
            "pyproject-uv-source-marker",
            "pyproject.toml",
            r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["torch"]

[tool.uv.sources]
torch = [{ index = "pytorch", marker = "sys_platform == 'darwin'" }]

[[tool.uv.index]]
name = "pytorch"
url = "https://download.pytorch.org/whl/cu124"

[[tool.uv.index]]
name = "cpu"
url = "https://download.pytorch.org/whl/cpu"
"#,
        );

        let intents = parse_uv_source_intents_scoped(&dir.join("pyproject.toml")).unwrap();
        assert_eq!(intents.len(), 1);
        let darwin = crate::parsers::python_scope::PythonProfile::for_target("darwin", "3.12");
        assert!(intents[0].is_in_scope(&darwin).unwrap());
        assert_eq!(intents[0].intent.source_name, "pytorch");
        cleanup(&dir);
    }

    #[test]
    fn uv_extracts_multiple_marker_scoped_source_intents_from_arrays() {
        let dir = setup_test_dir(
            "pyproject-uv-source-marker-multi",
            "pyproject.toml",
            r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["torch"]

[tool.uv.sources]
torch = [
  { index = "pytorch", marker = "sys_platform == 'darwin'" },
  { index = "cpu", marker = "sys_platform == 'linux'" },
]

[[tool.uv.index]]
name = "pytorch"
url = "https://download.pytorch.org/whl/cu124"

[[tool.uv.index]]
name = "cpu"
url = "https://download.pytorch.org/whl/cpu"
"#,
        );

        let intents = parse_uv_source_intents_scoped(&dir.join("pyproject.toml")).unwrap();
        assert_eq!(intents.len(), 2);
        let linux = crate::parsers::python_scope::PythonProfile::for_target("linux", "3.12");
        let linux_intents: Vec<_> = intents
            .iter()
            .filter_map(|intent| {
                intent
                    .is_in_scope(&linux)
                    .unwrap()
                    .then_some(&intent.intent)
            })
            .collect();
        assert_eq!(linux_intents.len(), 1);
        assert_eq!(linux_intents[0].source_name, "cpu");
        cleanup(&dir);
    }

    #[test]
    fn uv_rejects_non_http_index_urls() {
        let dir = setup_test_dir(
            "pyproject-uv-source-file-url",
            "pyproject.toml",
            r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["torch"]

[[tool.uv.index]]
name = "internal"
url = "file:///tmp/internal"
"#,
        );

        let err = parse_uv_sources(&dir.join("pyproject.toml")).unwrap_err();
        assert!(err.to_string().contains("http:// and https://"));
        cleanup(&dir);
    }

    #[test]
    fn uv_rejects_reserved_pypi_index_name_with_custom_url() {
        let dir = setup_test_dir(
            "pyproject-uv-source-pypi-custom-url",
            "pyproject.toml",
            r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["torch"]

[[tool.uv.index]]
name = "pypi"
url = "https://packages.example.com/simple"
"#,
        );

        let err = parse_uv_sources(&dir.join("pyproject.toml")).unwrap_err();
        assert!(err.to_string().contains("reserved index name 'pypi'"));
        cleanup(&dir);
    }

    #[test]
    fn uv_rejects_default_pypi_url_under_non_pypi_alias() {
        let dir = setup_test_dir(
            "pyproject-uv-source-pypi-alias",
            "pyproject.toml",
            r#"[project]
name = "demo"
version = "0.1.0"
dependencies = ["torch"]

[[tool.uv.index]]
name = "public"
url = "https://pypi.org/simple"
"#,
        );

        let err = parse_uv_sources(&dir.join("pyproject.toml")).unwrap_err();
        assert!(err.to_string().contains("rename PyPI"));
        cleanup(&dir);
    }

    #[test]
    fn uv_rejects_duplicate_index_names() {
        let dir = setup_test_dir(
            "pyproject-uv-source-duplicate",
            "pyproject.toml",
            r#"[project]
name = "demo"
version = "0.1.0"

[[tool.uv.index]]
name = "internal"
url = "https://packages.example.com/simple"

[[tool.uv.index]]
name = "internal"
url = "https://mirror.example.com/simple"
"#,
        );

        let err = parse_uv_sources(&dir.join("pyproject.toml")).unwrap_err();
        assert!(err.to_string().contains("duplicate index names"));
        cleanup(&dir);
    }
}
