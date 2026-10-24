use super::*;

/// How `[project] dynamic` dependency declarations are treated.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pep621Dynamic {
    /// The build backend computes dependencies from data sloppy-joe cannot see.
    Reject,
    /// Poetry fills dynamic dependencies from `[tool.poetry.dependencies]`, which is parsed
    /// separately. Declaring the same field both dynamically and statically is still rejected.
    ProvidedByPoetry,
}

pub(crate) fn collect_pep621_project_scoped(
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

pub(crate) fn collect_dependency_groups_scoped(
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
            if let Some(dep) =
                crate::parsers::requirements::parse_scoped_requirement_spec(spec, path)?
            {
                deps.push(dep.with_group(&group_name));
            }
        }
    }
    Ok(())
}

/// Maximum `include-group` nesting depth. Real projects nest a handful of levels; anything
/// deeper is rejected instead of risking unbounded recursion.
pub(crate) const MAX_INCLUDE_GROUP_DEPTH: usize = 64;

pub(crate) type DependencyGroupIndex<'a> = HashMap<String, (&'a String, &'a toml::Value)>;

/// Expand PEP 735 `{include-group = "..."}` entries. Each group maps to its own requirement
/// strings plus those of every group it includes (transitively). Group names are matched after
/// normalization; duplicate normalized names, unknown includes, cycles and malformed entries
/// fail closed.
pub(crate) fn resolve_dependency_groups<'a>(
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

pub(crate) fn flatten_dependency_group<'a>(
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
