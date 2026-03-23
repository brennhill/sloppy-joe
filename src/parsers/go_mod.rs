use crate::Dependency;
use anyhow::{Context, Result};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let path = project_dir.join("go.mod");
    let content = super::read_file_limited(&path, super::MAX_MANIFEST_BYTES)
        .context("Failed to read go.mod")?;

    let mut deps = Vec::new();
    let mut in_require = false;

    for line in content.lines() {
        let line = line.trim();

        if line == "require (" {
            in_require = true;
            continue;
        }
        if line == ")" {
            in_require = false;
            continue;
        }

        if let Some(rest) = line.strip_prefix("require ") {
            if let Some(name) = rest.split_whitespace().next() {
                let version = rest.split_whitespace().nth(1).map(String::from);
                deps.push(Dependency {
                    name: name.to_string(),
                    version,
                    ecosystem: crate::Ecosystem::Go,
                });
            }
            continue;
        }

        if in_require
            && !line.is_empty()
            && !line.starts_with("//")
            && line.split("//").nth(1).is_none_or(|comment| comment.trim() != "indirect")
            && let Some(name) = line.split_whitespace().next()
        {
            let version = line.split_whitespace().nth(1).map(String::from);
            deps.push(Dependency {
                name: name.to_string(),
                version,
                ecosystem: crate::Ecosystem::Go,
            });
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
        let dir = std::env::temp_dir().join(format!("sj-gomod-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("go.mod"), content).unwrap();
        dir
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_require_block() {
        let dir = setup_dir(
            r#"
module example.com/myapp

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/spf13/cobra v1.7.0
)
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "github.com/gin-gonic/gin");
        assert_eq!(deps[0].version, Some("v1.9.1".to_string()));
        assert_eq!(deps[0].ecosystem, crate::Ecosystem::Go);
        assert_eq!(deps[1].name, "github.com/spf13/cobra");
        cleanup(&dir);
    }

    #[test]
    fn skip_module_and_go_version() {
        let dir = setup_dir(
            r#"
module example.com/myapp

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
)
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        // module and go lines should not appear as deps
        assert_eq!(deps[0].name, "github.com/gin-gonic/gin");
        cleanup(&dir);
    }

    #[test]
    fn handle_empty_require_block() {
        let dir = setup_dir(
            r#"
module example.com/myapp

go 1.21

require (
)
"#,
        );
        let deps = parse(&dir).unwrap();
        assert!(deps.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn skip_comments_in_require_block() {
        let dir = setup_dir(
            r#"
module example.com/myapp

go 1.21

require (
	// indirect dependency
	github.com/gin-gonic/gin v1.9.1
)
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        cleanup(&dir);
    }

    #[test]
    fn indirect_deps_excluded() {
        let dir = setup_dir(
            r#"
module example.com/myapp

go 1.21

require (
	github.com/gin-gonic/gin v1.9.1
	github.com/spf13/cobra v1.7.0 // indirect
)
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "github.com/gin-gonic/gin");
        cleanup(&dir);
    }

    #[test]
    fn parse_single_line_require() {
        let dir = setup_dir(
            r#"
module example.com/myapp

go 1.21

require github.com/gin-gonic/gin v1.9.1
"#,
        );
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "github.com/gin-gonic/gin");
        assert_eq!(deps[0].version, Some("v1.9.1".to_string()));
        cleanup(&dir);
    }
}
