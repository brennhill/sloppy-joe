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
                deps.push(Dependency {
                    name: name.clone(),
                    version: version.as_str().map(String::from),
                    ecosystem: "npm".to_string(),
                });
            }
        }
    }

    Ok(deps)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn setup_dir(content: &str) -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sj-pkgjson-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("package.json"), content).unwrap();
        dir
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
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
        assert_eq!(deps[0].ecosystem, "npm");
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
}
