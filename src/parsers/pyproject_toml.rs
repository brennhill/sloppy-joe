mod sources;
mod uv_surface;
pub(crate) use sources::*;
mod groups;
pub(crate) use groups::*;
mod tooling;
use crate::Dependency;
use crate::parsers::python_scope::{PythonProfile, PythonScopedDependency};
use anyhow::{Result, bail};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;
pub(crate) use tooling::*;

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
    let has_uv = parsed.get("tool").and_then(|tool| tool.get("uv")).is_some()
        || (!has_poetry && super::path_detected(&path.with_file_name("uv.lock"))?);
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
    let mut deps: Vec<Dependency> = parse_poetry_scoped_file(path)?
        .into_iter()
        .map(|dep| dep.dependency)
        .collect();
    deps.extend(parse_unlocked_tooling_file(path)?);
    Ok(deps)
}

pub(crate) fn parse_poetry_scoped_file(path: &Path) -> Result<Vec<PythonScopedDependency>> {
    let parsed = parse_toml(path)?;
    let poetry = parsed
        .get("tool")
        .and_then(|tool| tool.get("poetry"))
        .and_then(|value| value.as_table())
        .ok_or_else(|| anyhow::anyhow!("Poetry metadata missing from {}", path.display()))?;

    let mut deps = Vec::new();
    // Poetry 2 reads PEP 621 `[project]` metadata and PEP 735 groups in addition to
    // `[tool.poetry.*]`; scan the union so neither declaration style can hide packages.
    collect_pep621_project_scoped(&parsed, path, &mut deps, Pep621Dynamic::ProvidedByPoetry)?;
    collect_dependency_groups_scoped(&parsed, path, &mut deps)?;
    collect_tool_dev_dependencies_scoped(&parsed, path, &mut deps)?;
    let legacy_extras = legacy_poetry_extras(poetry);
    collect_poetry_section_scoped(
        optional_table(
            poetry.get("dependencies"),
            "[tool.poetry.dependencies]",
            path,
        )?,
        path,
        &mut deps,
        None,
        &legacy_extras,
    )?;
    collect_poetry_section_scoped(
        optional_table(
            poetry.get("dev-dependencies"),
            "[tool.poetry.dev-dependencies]",
            path,
        )?,
        path,
        &mut deps,
        Some("dev"),
        &legacy_extras,
    )?;
    if let Some(groups) = optional_table(poetry.get("group"), "[tool.poetry.group]", path)? {
        for (group_name, group) in groups {
            let group = optional_table(Some(group), "[tool.poetry.group.*]", path)?
                .expect("value is present");
            collect_poetry_section_scoped(
                optional_table(
                    group.get("dependencies"),
                    "[tool.poetry.group.*.dependencies]",
                    path,
                )?,
                path,
                &mut deps,
                Some(group_name.as_str()),
                &legacy_extras,
            )?;
        }
    }

    Ok(deps)
}

/// A table-valued manifest field that may be absent. Present-but-wrong-type values are
/// rejected instead of being treated as "no dependencies".
fn optional_table<'a>(
    value: Option<&'a toml::Value>,
    label: &str,
    path: &Path,
) -> Result<Option<&'a toml::value::Table>> {
    match value {
        None => Ok(None),
        Some(toml::Value::Table(table)) => Ok(Some(table)),
        Some(_) => bail!(
            "Unsupported {} in {}: expected a table",
            label,
            path.display()
        ),
    }
}

pub(crate) fn parse_legacy_file(path: &Path) -> Result<Vec<Dependency>> {
    let mut deps: Vec<Dependency> = parse_legacy_scoped_file(path)?
        .into_iter()
        .map(|dep| dep.dependency)
        .collect();
    deps.extend(parse_unlocked_tooling_file(path)?);
    Ok(deps)
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

    collect_pep621_project_scoped(&parsed, path, &mut deps, Pep621Dynamic::Reject)?;

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

    collect_dependency_groups_scoped(&parsed, path, &mut deps)?;
    collect_tool_dev_dependencies_scoped(&parsed, path, &mut deps)?;

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

fn collect_requirement_array_scoped(
    value: Option<&toml::Value>,
    source_path: &Path,
    deps: &mut Vec<PythonScopedDependency>,
    group: Option<&str>,
    extra: Option<&str>,
) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let entries = value.as_array().ok_or_else(|| {
        anyhow::anyhow!(
            "Unsupported dependency declaration in {}: expected an array of requirement strings",
            source_path.display()
        )
    })?;

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
#[path = "pyproject_toml_coverage_tests.rs"]
mod coverage_tests;

#[cfg(test)]
mod tests;
