use crate::Dependency;
use anyhow::{Context, Result};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let path = project_dir.join("composer.json");
    let content = std::fs::read_to_string(&path).context("Failed to read composer.json")?;
    let parsed: serde_json::Value =
        serde_json::from_str(&content).context("Failed to parse composer.json")?;

    let mut deps = Vec::new();

    for section in ["require", "require-dev"] {
        if let Some(obj) = parsed.get(section).and_then(|v| v.as_object()) {
            for (name, version) in obj {
                // Skip platform requirements
                if name == "php" || name.starts_with("ext-") {
                    continue;
                }
                deps.push(Dependency {
                    name: name.clone(),
                    version: version.as_str().map(String::from),
                    ecosystem: "php".to_string(),
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
        let dir = std::env::temp_dir().join(format!("sj-composer-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("composer.json"), content).unwrap();
        dir
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
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
        assert_eq!(deps[0].ecosystem, "php");
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
