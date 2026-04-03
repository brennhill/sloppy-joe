use crate::Dependency;
use anyhow::{Result, bail};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    parse_file(&project_dir.join("Pipfile"))
}

pub(crate) fn parse_file(path: &Path) -> Result<Vec<Dependency>> {
    let content = super::read_file_limited(path, super::MAX_MANIFEST_BYTES)?;
    let parsed = toml::from_str::<toml::Value>(&content)
        .map_err(|err| anyhow::anyhow!("Failed to parse {}: {}", path.display(), err))?;
    let default_index = parsed
        .get("source")
        .and_then(|value| value.as_array())
        .and_then(|sources| sources.first())
        .and_then(|source| source.get("name"))
        .and_then(|value| value.as_str());

    let mut deps = Vec::new();
    for section in ["packages", "dev-packages"] {
        let Some(table) = parsed.get(section).and_then(|value| value.as_table()) else {
            continue;
        };
        for (name, value) in table {
            if let Some(dep) = parse_pipfile_dependency(name, value, default_index, path)? {
                deps.push(dep);
            }
        }
    }

    Ok(deps)
}

fn parse_pipfile_dependency(
    name: &str,
    value: &toml::Value,
    default_index: Option<&str>,
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
            if let Some(index) = table.get("index").and_then(|value| value.as_str())
                && Some(index) != default_index
            {
                bail!(
                    "Unsupported Pipfile dependency '{}' in {}: alternate package indexes are not supported",
                    crate::report::sanitize_for_terminal(name),
                    source_path.display()
                );
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
        Some(version) => format!("{name}{version}"),
    }
}

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
}
