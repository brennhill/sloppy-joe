use crate::Dependency;
use anyhow::{Result, bail};
use std::path::Path;

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
    let parsed = parse_toml(path)?;
    let poetry = parsed
        .get("tool")
        .and_then(|tool| tool.get("poetry"))
        .and_then(|value| value.as_table())
        .ok_or_else(|| anyhow::anyhow!("Poetry metadata missing from {}", path.display()))?;

    let mut deps = Vec::new();
    collect_poetry_section(
        poetry
            .get("dependencies")
            .and_then(|value| value.as_table()),
        path,
        &mut deps,
    )?;
    collect_poetry_section(
        poetry
            .get("dev-dependencies")
            .and_then(|value| value.as_table()),
        path,
        &mut deps,
    )?;
    if let Some(groups) = poetry.get("group").and_then(|value| value.as_table()) {
        for group in groups.values() {
            collect_poetry_section(
                group.get("dependencies").and_then(|value| value.as_table()),
                path,
                &mut deps,
            )?;
        }
    }

    Ok(deps)
}

pub(crate) fn parse_legacy_file(path: &Path) -> Result<Vec<Dependency>> {
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

        collect_requirement_array(project.get("dependencies"), path, &mut deps)?;
        if let Some(optional) = project
            .get("optional-dependencies")
            .and_then(|value| value.as_table())
        {
            for group in optional.values() {
                collect_requirement_array(Some(group), path, &mut deps)?;
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
        for group in groups.values() {
            collect_requirement_array(Some(group), path, &mut deps)?;
        }
    }

    Ok(deps)
}

fn parse_toml(path: &Path) -> Result<toml::Value> {
    let content = super::read_file_limited(path, super::MAX_MANIFEST_BYTES)?;
    toml::from_str(&content)
        .map_err(|err| anyhow::anyhow!("Failed to parse {}: {}", path.display(), err))
}

fn collect_poetry_section(
    section: Option<&toml::map::Map<String, toml::Value>>,
    source_path: &Path,
    deps: &mut Vec<Dependency>,
) -> Result<()> {
    let Some(section) = section else {
        return Ok(());
    };

    for (name, value) in section {
        if name == "python" {
            continue;
        }
        if let Some(dep) = parse_poetry_dependency(name, value, source_path)? {
            deps.push(dep);
        }
    }

    Ok(())
}

fn parse_poetry_dependency(
    name: &str,
    value: &toml::Value,
    source_path: &Path,
) -> Result<Option<Dependency>> {
    let requirement = match value {
        toml::Value::String(spec) => compose_poetry_requirement(name, Some(spec.as_str())),
        toml::Value::Table(table) => {
            for forbidden in [
                "git",
                "path",
                "url",
                "file",
                "develop",
                "directory",
                "source",
            ] {
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
            compose_poetry_requirement(name, table.get("version").and_then(|value| value.as_str()))
        }
        _ => bail!(
            "Unsupported Poetry dependency '{}' in {}",
            crate::report::sanitize_for_terminal(name),
            source_path.display()
        ),
    };

    super::requirements::parse_requirement_spec(&requirement, source_path)
}

fn collect_requirement_array(
    value: Option<&toml::Value>,
    source_path: &Path,
    deps: &mut Vec<Dependency>,
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
        if let Some(dep) = super::requirements::parse_requirement_spec(spec, source_path)? {
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
    fn reject_poetry_source_overrides() {
        let dir = setup_test_dir(
            "pyproject-poetry-source",
            "pyproject.toml",
            r#"[tool.poetry]
name = "demo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.12"
private-lib = { version = "^1.0.0", source = "internal" }
"#,
        );

        let err = parse_poetry(&dir).unwrap_err();
        assert!(err.to_string().contains("alternate package indexes"));
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
}
