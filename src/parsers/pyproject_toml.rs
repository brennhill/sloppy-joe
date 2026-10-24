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

/// Packages that build frontends or package managers install for this project even though
/// the project lockfile does not record them: PEP 518 `[build-system] requires`.
///
/// These are kept separate from the scoped project dependencies because lockfile
/// reconciliation would (correctly) report them as missing from poetry.lock / uv.lock.
pub(crate) fn parse_unlocked_tooling_file(path: &Path) -> Result<Vec<Dependency>> {
    let parsed = parse_toml(path)?;
    let mut deps = Vec::new();

    if let Some(build_system) = parsed.get("build-system") {
        let build_system = build_system.as_table().ok_or_else(|| {
            anyhow::anyhow!(
                "Unsupported [build-system] declaration in {}: expected a table",
                path.display()
            )
        })?;
        collect_tooling_requirement_array(
            build_system.get("requires"),
            "[build-system] requires",
            path,
            &mut deps,
        )?;
    }

    let tool = parsed.get("tool");
    if let Some(plugins) = tool
        .and_then(|tool| tool.get("poetry"))
        .and_then(|poetry| poetry.get("requires-plugins"))
    {
        // Poetry 2 installs these into Poetry's own environment before running any command.
        let plugins = plugins.as_table().ok_or_else(|| {
            anyhow::anyhow!(
                "Unsupported [tool.poetry.requires-plugins] in {}: expected a table",
                path.display()
            )
        })?;
        for (name, value) in plugins {
            if let Some(dep) = parse_poetry_dependency_scoped(name, value, path)? {
                deps.push(dep.dependency);
            }
        }
    }
    if let Some(uv) = tool.and_then(|tool| tool.get("uv")) {
        // Constraints/overrides steer resolution of packages that uv.lock records under
        // [manifest], not as project roots. Validate them and scan the named packages.
        for key in ["constraint-dependencies", "override-dependencies"] {
            collect_tooling_requirement_array(
                uv.get(key),
                &format!("[tool.uv] {key}"),
                path,
                &mut deps,
            )?;
        }
    }
    if let Some(overrides) = tool
        .and_then(|tool| tool.get("pdm"))
        .and_then(|pdm| pdm.get("resolution"))
        .and_then(|resolution| resolution.get("overrides"))
    {
        let overrides = overrides.as_table().ok_or_else(|| {
            anyhow::anyhow!(
                "Unsupported [tool.pdm.resolution.overrides] in {}: expected a table",
                path.display()
            )
        })?;
        for (name, spec) in overrides {
            let spec = spec.as_str().ok_or_else(|| {
                anyhow::anyhow!(
                    "Unsupported [tool.pdm.resolution.overrides] entry '{}' in {}: expected a string",
                    crate::report::sanitize_for_terminal(name),
                    path.display()
                )
            })?;
            let requirement = compose_pdm_override_requirement(name, spec);
            if let Some(dep) = super::requirements::parse_requirement_spec(&requirement, path)? {
                deps.push(dep);
            }
        }
    }
    if let Some(hatch) = tool.and_then(|tool| tool.get("hatch")) {
        if let Some(env) = hatch.get("env") {
            collect_tooling_requirement_array(
                env.get("requires"),
                "[tool.hatch.env] requires",
                path,
                &mut deps,
            )?;
        }
        if let Some(build) = hatch.get("build") {
            collect_hatch_build_dependencies(build, "tool.hatch.build", path, &mut deps)?;
        }
    }

    Ok(deps)
}

fn compose_pdm_override_requirement(name: &str, spec: &str) -> String {
    let spec = spec.trim();
    if spec.is_empty() || spec == "*" {
        name.to_string()
    } else if spec.starts_with(['=', '>', '<', '~', '!']) {
        format!("{name}{spec}")
    } else {
        // Anything else (URLs, paths) is handed to the requirement parser as a direct
        // reference so unsupported sources fail closed.
        format!("{name} @ {spec}")
    }
}

/// Hatch build targets and build hooks each accept a `dependencies` array of packages that are
/// installed into the build environment.
fn collect_hatch_build_dependencies(
    value: &toml::Value,
    label: &str,
    path: &Path,
    deps: &mut Vec<Dependency>,
) -> Result<()> {
    let Some(table) = value.as_table() else {
        return Ok(());
    };
    for (key, child) in table {
        let child_label = format!("{label}.{key}");
        if key == "dependencies" {
            collect_tooling_requirement_array(
                Some(child),
                &format!("[{child_label}]"),
                path,
                deps,
            )?;
        } else if child.is_table() {
            collect_hatch_build_dependencies(child, &child_label, path, deps)?;
        }
    }
    Ok(())
}

/// Development dependency declarations from tool-specific tables. They are group scoped, like
/// PEP 735 groups. PDM and Hatch environments are additionally marked as unlocked tool
/// environments: uv.lock and poetry.lock never record them, so they are scanned without
/// lockfile reconciliation.
fn collect_tool_dev_dependencies_scoped(
    parsed: &toml::Value,
    path: &Path,
    deps: &mut Vec<PythonScopedDependency>,
) -> Result<()> {
    let Some(tool) = parsed.get("tool") else {
        return Ok(());
    };
    if let Some(uv) = tool.get("uv")
        && let Some(dev) = uv.get("dev-dependencies")
    {
        require_requirement_array(dev, "[tool.uv] dev-dependencies", path)?;
        collect_requirement_array_scoped(Some(dev), path, deps, Some("dev"), None)?;
    }
    let tool_env_start = deps.len();
    collect_tool_env_dependencies_scoped(tool, path, deps)?;
    for dep in &mut deps[tool_env_start..] {
        dep.unlocked_tool_env = true;
    }
    Ok(())
}

fn collect_tool_env_dependencies_scoped(
    tool: &toml::Value,
    path: &Path,
    deps: &mut Vec<PythonScopedDependency>,
) -> Result<()> {
    if let Some(pdm_dev) = tool.get("pdm").and_then(|pdm| pdm.get("dev-dependencies")) {
        let groups = pdm_dev.as_table().ok_or_else(|| {
            anyhow::anyhow!(
                "Unsupported [tool.pdm.dev-dependencies] in {}: expected a table of groups",
                path.display()
            )
        })?;
        for (group, entries) in groups {
            require_requirement_array(entries, "[tool.pdm.dev-dependencies] group", path)?;
            collect_requirement_array_scoped(Some(entries), path, deps, Some(group), None)?;
        }
    }

    if let Some(envs) = tool.get("hatch").and_then(|hatch| hatch.get("envs")) {
        let envs = envs.as_table().ok_or_else(|| {
            anyhow::anyhow!(
                "Unsupported [tool.hatch.envs] in {}: expected a table of environments",
                path.display()
            )
        })?;
        for (env_name, env) in envs {
            let Some(env) = env.as_table() else {
                bail!(
                    "Unsupported [tool.hatch.envs.{}] in {}: expected a table",
                    crate::report::sanitize_for_terminal(env_name),
                    path.display()
                );
            };
            for key in ["dependencies", "extra-dependencies"] {
                if let Some(entries) = env.get(key) {
                    require_requirement_array(entries, "Hatch environment dependencies", path)?;
                    collect_requirement_array_scoped(
                        Some(entries),
                        path,
                        deps,
                        Some(env_name),
                        None,
                    )?;
                }
            }
            if let Some(overrides) = env.get("overrides")
                && toml_value_declares_dependencies(overrides)
            {
                bail!(
                    "Unsupported [tool.hatch.envs.{}.overrides] in {}: conditional dependency overrides cannot be evaluated safely",
                    crate::report::sanitize_for_terminal(env_name),
                    path.display()
                );
            }
        }
    }

    Ok(())
}

fn toml_value_declares_dependencies(value: &toml::Value) -> bool {
    match value {
        toml::Value::Table(table) => table.iter().any(|(key, child)| {
            key == "dependencies"
                || key == "extra-dependencies"
                || toml_value_declares_dependencies(child)
        }),
        toml::Value::Array(entries) => entries.iter().any(toml_value_declares_dependencies),
        _ => false,
    }
}

fn require_requirement_array(value: &toml::Value, label: &str, path: &Path) -> Result<()> {
    if value.is_array() {
        Ok(())
    } else {
        bail!(
            "Unsupported {} in {}: expected an array of requirement strings",
            label,
            path.display()
        )
    }
}

fn collect_tooling_requirement_array(
    value: Option<&toml::Value>,
    label: &str,
    path: &Path,
    deps: &mut Vec<Dependency>,
) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let entries = value.as_array().ok_or_else(|| {
        anyhow::anyhow!(
            "Unsupported {} in {}: expected an array of requirement strings",
            label,
            path.display()
        )
    })?;
    for entry in entries {
        let spec = entry.as_str().ok_or_else(|| {
            anyhow::anyhow!(
                "Unsupported {} entry in {}: expected a string requirement",
                label,
                path.display()
            )
        })?;
        if let Some(dep) = super::requirements::parse_requirement_spec(spec, path)? {
            deps.push(dep);
        }
    }
    Ok(())
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
    let Some(uv) = parsed.get("tool").and_then(|tool| tool.get("uv")) else {
        return Ok(Vec::new());
    };
    let uv = uv
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("Invalid uv metadata in {}", path.display()))?;

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

/// How `[project] dynamic` dependency declarations are treated.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pep621Dynamic {
    /// The build backend computes dependencies from data sloppy-joe cannot see.
    Reject,
    /// Poetry fills dynamic dependencies from `[tool.poetry.dependencies]`, which is parsed
    /// separately. Declaring the same field both dynamically and statically is still rejected.
    ProvidedByPoetry,
}

fn collect_pep621_project_scoped(
    parsed: &toml::Value,
    path: &Path,
    deps: &mut Vec<PythonScopedDependency>,
    dynamic_mode: Pep621Dynamic,
) -> Result<()> {
    let Some(project) = parsed.get("project").and_then(|value| value.as_table()) else {
        return Ok(());
    };
    let dynamic_fields: Vec<&str> = project
        .get("dynamic")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str())
        .filter(|value| *value == "dependencies" || *value == "optional-dependencies")
        .collect();
    for field in &dynamic_fields {
        if dynamic_mode == Pep621Dynamic::Reject || project.contains_key(*field) {
            bail!(
                "Unsupported dynamic dependency declaration in {}",
                path.display()
            );
        }
    }

    collect_requirement_array_scoped(project.get("dependencies"), path, deps, None, None)?;
    if let Some(optional) = optional_table(
        project.get("optional-dependencies"),
        "[project.optional-dependencies]",
        path,
    )? {
        for (extra, group) in optional {
            collect_requirement_array_scoped(Some(group), path, deps, None, Some(extra.as_str()))?;
        }
    }
    Ok(())
}

fn collect_dependency_groups_scoped(
    parsed: &toml::Value,
    path: &Path,
    deps: &mut Vec<PythonScopedDependency>,
) -> Result<()> {
    let Some(groups) =
        optional_table(parsed.get("dependency-groups"), "[dependency-groups]", path)?
    else {
        return Ok(());
    };
    for (group_name, requirements) in resolve_dependency_groups(groups, path)? {
        for spec in requirements {
            if let Some(dep) = super::requirements::parse_scoped_requirement_spec(spec, path)? {
                deps.push(dep.with_group(&group_name));
            }
        }
    }
    Ok(())
}

/// Maximum `include-group` nesting depth. Real projects nest a handful of levels; anything
/// deeper is rejected instead of risking unbounded recursion.
const MAX_INCLUDE_GROUP_DEPTH: usize = 64;

type DependencyGroupIndex<'a> = HashMap<String, (&'a String, &'a toml::Value)>;

/// Expand PEP 735 `{include-group = "..."}` entries. Each group maps to its own requirement
/// strings plus those of every group it includes (transitively). Group names are matched after
/// normalization; duplicate normalized names, unknown includes, cycles and malformed entries
/// fail closed.
fn resolve_dependency_groups<'a>(
    groups: &'a toml::value::Table,
    path: &Path,
) -> Result<Vec<(String, Vec<&'a str>)>> {
    let mut index: DependencyGroupIndex<'a> = HashMap::new();
    for (name, value) in groups {
        let normalized = crate::parsers::python_scope::normalize_scope_name(name);
        if let Some((previous, _)) = index.insert(normalized, (name, value)) {
            bail!(
                "Unsupported [dependency-groups] in {}: duplicate group names '{}' and '{}' normalize to the same group",
                path.display(),
                crate::report::sanitize_for_terminal(previous),
                crate::report::sanitize_for_terminal(name)
            );
        }
    }
    let mut memo: HashMap<String, Vec<&'a str>> = HashMap::new();
    let mut resolved = Vec::new();
    for name in groups.keys() {
        let normalized = crate::parsers::python_scope::normalize_scope_name(name);
        let requirements =
            flatten_dependency_group(&normalized, &index, &mut memo, &mut Vec::new(), path)?;
        resolved.push((name.clone(), requirements));
    }
    Ok(resolved)
}

fn flatten_dependency_group<'a>(
    normalized: &str,
    index: &DependencyGroupIndex<'a>,
    memo: &mut HashMap<String, Vec<&'a str>>,
    stack: &mut Vec<String>,
    path: &Path,
) -> Result<Vec<&'a str>> {
    if let Some(done) = memo.get(normalized) {
        return Ok(done.clone());
    }
    if stack.iter().any(|entry| entry == normalized) {
        let mut chain = stack.clone();
        chain.push(normalized.to_string());
        bail!(
            "Unsupported [dependency-groups] in {}: include-group cycle {}",
            path.display(),
            crate::report::sanitize_for_terminal(&chain.join(" -> "))
        );
    }
    if stack.len() >= MAX_INCLUDE_GROUP_DEPTH {
        bail!(
            "Unsupported [dependency-groups] in {}: include-group nesting deeper than {} levels",
            path.display(),
            MAX_INCLUDE_GROUP_DEPTH
        );
    }
    let (declared, value) = index.get(normalized).copied().ok_or_else(|| {
        anyhow::anyhow!(
            "Unsupported [dependency-groups] in {}: unknown dependency group '{}'",
            path.display(),
            crate::report::sanitize_for_terminal(normalized)
        )
    })?;
    let entries = value.as_array().ok_or_else(|| {
        anyhow::anyhow!(
            "Unsupported [dependency-groups] group '{}' in {}: expected an array of requirement strings",
            crate::report::sanitize_for_terminal(declared),
            path.display()
        )
    })?;

    stack.push(normalized.to_string());
    let mut requirements: Vec<&'a str> = Vec::new();
    for entry in entries {
        match entry {
            toml::Value::String(spec) => {
                if !requirements.contains(&spec.as_str()) {
                    requirements.push(spec.as_str());
                }
            }
            toml::Value::Table(table) => {
                let target = match (table.len(), table.get("include-group")) {
                    (1, Some(toml::Value::String(target))) => target,
                    _ => bail!(
                        "Unsupported entry in [dependency-groups] group '{}' in {}: tables must contain exactly one string 'include-group' key",
                        crate::report::sanitize_for_terminal(declared),
                        path.display()
                    ),
                };
                let target_normalized = crate::parsers::python_scope::normalize_scope_name(target);
                if !index.contains_key(&target_normalized) {
                    bail!(
                        "Unsupported [dependency-groups] group '{}' in {}: include-group references unknown dependency group '{}'",
                        crate::report::sanitize_for_terminal(declared),
                        path.display(),
                        crate::report::sanitize_for_terminal(target)
                    );
                }
                for spec in flatten_dependency_group(&target_normalized, index, memo, stack, path)?
                {
                    if !requirements.contains(&spec) {
                        requirements.push(spec);
                    }
                }
            }
            _ => bail!(
                "Unsupported entry in [dependency-groups] group '{}' in {}: expected a requirement string or an include-group table",
                crate::report::sanitize_for_terminal(declared),
                path.display()
            ),
        }
    }
    stack.pop();
    memo.insert(normalized.to_string(), requirements.clone());
    Ok(requirements)
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
