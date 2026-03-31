use crate::Dependency;
use anyhow::{Context, Result};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let path = project_dir.join("package.json");
    let content = super::read_file_limited(&path, super::MAX_MANIFEST_BYTES)
        .context("Failed to read package.json")?;
    let parsed: serde_json::Value =
        serde_json::from_str(&content).context("Failed to parse package.json")?;

    let mut deps = Vec::new();

    for section in ["dependencies", "devDependencies"] {
        if let Some(obj) = parsed.get(section).and_then(|v| v.as_object()) {
            for (name, version) in obj {
                let dep = Dependency {
                    name: name.clone(),
                    version: version.as_str().map(String::from),
                    ecosystem: crate::Ecosystem::Npm,
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
        setup_test_dir("pkgjson", "package.json", content)
    }

    #[test]
    fn parse_dependencies_and_dev_dependencies() {
        let dir = setup_dir(
            r#"{
            "dependencies": {"react": "^18.0", "express": "^4.0"},
            "devDependencies": {"jest": "^29.0"}
        }"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 3);
        let names: Vec<_> = deps.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"react"));
        assert!(names.contains(&"express"));
        assert!(names.contains(&"jest"));
        assert_eq!(deps[0].ecosystem, crate::Ecosystem::Npm);
        cleanup(&dir);
    }

    #[test]
    fn skip_empty_sections() {
        let dir = setup_dir(
            r#"{
            "dependencies": {},
            "devDependencies": {}
        }"#,
        );
        let deps = parse(&dir).unwrap();
        assert!(deps.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn handle_no_dependencies_key() {
        let dir = setup_dir(r#"{"name": "test", "version": "1.0.0"}"#);
        let deps = parse(&dir).unwrap();
        assert!(deps.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn version_extracted_correctly() {
        let dir = setup_dir(r#"{"dependencies": {"react": "^18.2.0"}}"#);
        let deps = parse(&dir).unwrap();
        assert_eq!(deps[0].version, Some("^18.2.0".to_string()));
        cleanup(&dir);
    }

    #[test]
    fn reject_invalid_dependency_name_with_control_character() {
        let dir = setup_dir("{\"dependencies\": {\"bad\\u001bname\": \"1.0.0\"}}");
        let err = parse(&dir).expect_err("invalid dependency names should fail parsing");
        let msg = err.to_string();
        assert!(msg.contains("package.json"));
        assert!(msg.contains("invalid package name"));
        cleanup(&dir);
    }
}
