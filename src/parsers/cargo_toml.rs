use crate::Dependency;
use anyhow::{Context, Result};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let path = project_dir.join("Cargo.toml");
    let content = super::read_file_limited(&path, super::MAX_MANIFEST_BYTES)
        .context("Failed to read Cargo.toml")?;
    let parsed: toml::Value = toml::from_str(&content).context("Failed to parse Cargo.toml")?;

    let mut deps = Vec::new();

    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(table) = parsed.get(section).and_then(|v| v.as_table()) {
            for (name, value) in table {
                let (package_name, version) = match value {
                    toml::Value::String(v) => (name.clone(), Some(v.clone())),
                    toml::Value::Table(t) => (
                        t.get("package")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                            .unwrap_or_else(|| name.clone()),
                        t.get("version").and_then(|v| v.as_str()).map(String::from),
                    ),
                    _ => (name.clone(), None),
                };
                let dep = Dependency {
                    name: package_name,
                    version,
                    ecosystem: crate::Ecosystem::Cargo,
                    actual_name: None,
                };
                super::validate_dependency(&dep, &path)?;
                deps.push(dep);
            }
        }
    }

    Ok(deps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::test_utils::*;

    fn setup_dir(content: &str) -> std::path::PathBuf {
        setup_test_dir("cargo", "Cargo.toml", content)
    }

    #[test]
    fn parse_string_style_deps() {
        let dir = setup_dir(
            r#"
[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
anyhow = "1"
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 2);
        let names: Vec<_> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"serde"));
        assert!(names.contains(&"anyhow"));
        assert_eq!(deps[0].ecosystem, crate::Ecosystem::Cargo);
        cleanup(&dir);
    }

    #[test]
    fn parse_table_style_deps() {
        let dir = setup_dir(
            r#"
[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].version, Some("1.0".to_string()));
        cleanup(&dir);
    }

    #[test]
    fn handle_missing_dependencies_section() {
        let dir = setup_dir(
            r#"
[package]
name = "test"
version = "0.1.0"
"#,
        );
        let deps = parse(&dir).unwrap();
        assert!(deps.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn parse_dev_dependencies() {
        let dir = setup_dir(
            r#"
[package]
name = "test"
version = "0.1.0"

[dev-dependencies]
tokio-test = "0.4"
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "tokio-test");
        cleanup(&dir);
    }

    #[test]
    fn parse_renamed_dependency_uses_package_name() {
        let dir = setup_dir(
            r#"
[package]
name = "test"
version = "0.1.0"

[dependencies]
serde1 = { package = "serde", version = "1.0" }
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "serde");
        assert_eq!(deps[0].version, Some("1.0".to_string()));
        cleanup(&dir);
    }
}
