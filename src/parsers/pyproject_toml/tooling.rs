use super::*;

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
            if let Some(dep) =
                crate::parsers::requirements::parse_requirement_spec(&requirement, path)?
            {
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

pub(crate) fn compose_pdm_override_requirement(name: &str, spec: &str) -> String {
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
pub(crate) fn collect_hatch_build_dependencies(
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
pub(crate) fn collect_tool_dev_dependencies_scoped(
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

pub(crate) fn collect_tool_env_dependencies_scoped(
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

pub(crate) fn toml_value_declares_dependencies(value: &toml::Value) -> bool {
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

pub(crate) fn require_requirement_array(
    value: &toml::Value,
    label: &str,
    path: &Path,
) -> Result<()> {
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

pub(crate) fn collect_tooling_requirement_array(
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
        if let Some(dep) = crate::parsers::requirements::parse_requirement_spec(spec, path)? {
            deps.push(dep);
        }
    }
    Ok(())
}
