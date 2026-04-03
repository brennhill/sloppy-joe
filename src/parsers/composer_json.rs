use crate::Dependency;
use anyhow::{Context, Result};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let path = project_dir.join("composer.json");
    let content = super::read_file_limited(&path, super::MAX_MANIFEST_BYTES)
        .context("Failed to read composer.json")?;
    let parsed: serde_json::Value =
        serde_json::from_str(&content).context("Failed to parse composer.json")?;
    validate_supported_sources(&parsed, &path)?;

    let mut deps = Vec::new();

    for section in ["require", "require-dev"] {
        if let Some(obj) = parsed.get(section).and_then(|v| v.as_object()) {
            for (name, version) in obj {
                // Skip platform requirements
                if name == "php" || name.starts_with("ext-") {
                    continue;
                }
                let version = version.as_str().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Unsupported Composer dependency '{}' in {}: only string version constraints are supported",
                        crate::report::sanitize_for_terminal(name),
                        path.display()
                    )
                })?;
                let dep = Dependency {
                    name: name.clone(),
                    version: Some(version.to_string()),
                    ecosystem: crate::Ecosystem::Php,
                    actual_name: None,
                };
                super::validate_dependency(&dep, &path)?;
                deps.push(dep);
            }
        }
    }

    Ok(deps)
}

fn validate_supported_sources(parsed: &serde_json::Value, path: &Path) -> Result<()> {
    let has_custom_repositories = parsed.get("repositories").is_some_and(|value| match value {
        serde_json::Value::Array(entries) => !entries.is_empty(),
        serde_json::Value::Object(entries) => !entries.is_empty(),
        _ => true,
    });

    if has_custom_repositories {
        anyhow::bail!(
            "Unsupported Composer repositories in {}: custom package sources are not supported",
            path.display()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::test_utils::*;

    fn setup_dir(content: &str) -> std::path::PathBuf {
        setup_test_dir("composer", "composer.json", content)
    }

    #[test]
    fn parse_require_and_require_dev() {
        let dir = setup_dir(
            r#"{
            "require": {"laravel/framework": "^10.0", "guzzlehttp/guzzle": "^7.0"},
            "require-dev": {"phpunit/phpunit": "^10.0"}
        }"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 3);
        let names: Vec<_> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"laravel/framework"));
        assert!(names.contains(&"phpunit/phpunit"));
        assert_eq!(deps[0].ecosystem, crate::Ecosystem::Php);
        cleanup(&dir);
    }

    #[test]
    fn skip_php_and_ext_entries() {
        let dir = setup_dir(
            r#"{
            "require": {"php": "^8.1", "ext-json": "*", "laravel/framework": "^10.0"}
        }"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "laravel/framework");
        cleanup(&dir);
    }

    #[test]
    fn handle_missing_sections() {
        let dir = setup_dir(r#"{"name": "test/pkg", "description": "test"}"#);
        let deps = parse(&dir).unwrap();
        assert!(deps.is_empty());
        cleanup(&dir);
    }
}
