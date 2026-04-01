use crate::Dependency;
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let path = project_dir.join("go.mod");
    let content = super::read_file_limited(&path, super::MAX_MANIFEST_BYTES)
        .context("Failed to read go.mod")?;

    let requirements = parse_requirements(&content, false);
    let mut deps = Vec::new();
    for (name, version) in requirements {
        let dep = Dependency {
            name,
            version,
            ecosystem: crate::Ecosystem::Go,
            actual_name: None,
        };
        super::validate_dependency(&dep, &path)?;
        deps.push(dep);
    }

    Ok(deps)
}

fn parse_requirements(content: &str, include_indirect: bool) -> Vec<(String, Option<String>)> {
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
            let comment = rest
                .split_once("//")
                .map(|(_, comment)| comment.trim())
                .unwrap_or("");
            if !include_indirect && comment == "indirect" {
                continue;
            }
            if let Some(name) = rest.split_whitespace().next() {
                let version = rest.split_whitespace().nth(1).map(String::from);
                deps.push((name.to_string(), version));
            }
            continue;
        }

        if in_require
            && !line.is_empty()
            && !line.starts_with("//")
            && let Some(name) = line.split_whitespace().next()
        {
            let comment = line
                .split_once("//")
                .map(|(_, comment)| comment.trim())
                .unwrap_or("");
            if !include_indirect && comment == "indirect" {
                continue;
            }
            let version = line.split_whitespace().nth(1).map(String::from);
            deps.push((name.to_string(), version));
        }
    }

    deps
}

pub(crate) fn requires_go_sum(content: &str) -> bool {
    let required: HashSet<String> = parse_requirements(content, true)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    if required.is_empty() {
        return false;
    }

    let local_replacements = parse_local_replace_targets(content);
    required
        .iter()
        .any(|dep| !local_replacements.contains(dep.as_str()))
}

fn parse_local_replace_targets(content: &str) -> HashSet<String> {
    let mut replacements = HashSet::new();
    let mut in_replace = false;

    for line in content.lines() {
        let line = line.trim();
        if line == "replace (" {
            in_replace = true;
            continue;
        }
        if line == ")" {
            in_replace = false;
            continue;
        }

        if let Some(rest) = line.strip_prefix("replace ") {
            if let Some(module) = parse_local_replace_entry(rest) {
                replacements.insert(module);
            }
            continue;
        }

        if in_replace
            && !line.is_empty()
            && !line.starts_with("//")
            && let Some(module) = parse_local_replace_entry(line)
        {
            replacements.insert(module);
        }
    }

    replacements
}

fn parse_local_replace_entry(entry: &str) -> Option<String> {
    let (left, right) = entry.split_once("=>")?;
    let old_module = left.split_whitespace().next()?.to_string();
    let right_tokens: Vec<&str> = right.split_whitespace().collect();
    if right_tokens.len() == 1 {
        return Some(old_module);
    }
    if let Some(path) = right_tokens.first()
        && (path.starts_with("./") || path.starts_with("../") || path.starts_with('/'))
    {
        return Some(old_module);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::test_utils::*;

    fn setup_dir(content: &str) -> std::path::PathBuf {
        setup_test_dir("gomod", "go.mod", content)
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

    #[test]
    fn go_sum_required_for_indirect_external_dependencies() {
        let content = r#"
module example.com/myapp

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1 // indirect
)
"#;
        assert!(requires_go_sum(content));
    }

    #[test]
    fn go_sum_required_for_external_dependencies() {
        let content = r#"
module example.com/myapp

go 1.21

require github.com/gin-gonic/gin v1.9.1
"#;
        assert!(requires_go_sum(content));
    }

    #[test]
    fn go_sum_not_required_for_stdlib_only_modules() {
        let content = "module example.com/myapp\n\ngo 1.21\n";
        assert!(!requires_go_sum(content));
    }

    #[test]
    fn go_sum_not_required_when_all_dependencies_are_local_replaces() {
        let content = r#"
module example.com/myapp

go 1.21

require (
    example.com/localdep v0.0.0
)

replace example.com/localdep => ../localdep
"#;
        assert!(!requires_go_sum(content));
    }
}
