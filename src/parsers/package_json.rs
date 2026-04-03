use crate::Dependency;
use anyhow::{Context, Result};
use std::path::Path;

pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    let path = project_dir.join("package.json");
    let content = super::read_file_limited(&path, super::MAX_MANIFEST_BYTES)
        .context("Failed to read package.json")?;
    let parsed: serde_json::Value =
        serde_json::from_str(&content).context("Failed to parse package.json")?;

    parse_manifest_value(&path, &parsed)
}

pub(crate) fn parse_manifest_value(
    path: &Path,
    parsed: &serde_json::Value,
) -> Result<Vec<Dependency>> {
    let mut deps = Vec::new();

    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(obj) = parsed.get(section).and_then(|v| v.as_object()) {
            for (name, version) in obj {
                if let Some(dep) = parse_dependency(name, version, path)? {
                    super::validate_dependency(&dep, path)?;
                    deps.push(dep);
                }
            }
        }
    }

    Ok(deps)
}

fn parse_dependency(
    manifest_name: &str,
    version: &serde_json::Value,
    source_path: &Path,
) -> Result<Option<Dependency>> {
    let version = version.as_str().ok_or_else(|| {
        anyhow::anyhow!(
            "Unsupported npm dependency declaration for '{}' in {}: expected a string version spec",
            crate::report::sanitize_for_terminal(manifest_name),
            source_path.display()
        )
    })?;
    let version = version.trim();
    if version.is_empty() {
        anyhow::bail!(
            "Unsupported npm dependency declaration for '{}' in {}: empty version specs are not allowed",
            crate::report::sanitize_for_terminal(manifest_name),
            source_path.display()
        );
    }

    if let Some(alias_spec) = version.strip_prefix("npm:") {
        let (target_name, target_version) = alias_spec.rsplit_once('@').ok_or_else(|| {
            anyhow::anyhow!(
                "Unsupported npm alias '{}' in {}: expected npm:<package>@<version>",
                crate::report::sanitize_for_terminal(version),
                source_path.display()
            )
        })?;
        let actual = Dependency {
            name: target_name.to_string(),
            version: Some(target_version.to_string()),
            ecosystem: crate::Ecosystem::Npm,
            actual_name: None,
        };
        super::validate_dependency(&actual, source_path)?;
        return Ok(Some(Dependency {
            name: manifest_name.to_string(),
            version: Some(target_version.to_string()),
            ecosystem: crate::Ecosystem::Npm,
            actual_name: Some(target_name.to_string()),
        }));
    }

    if is_unsupported_remote_spec(version) {
        anyhow::bail!(
            "Unsupported non-registry npm dependency '{}' in {}",
            crate::report::sanitize_for_terminal(version),
            source_path.display()
        );
    }

    if version.starts_with("workspace:")
        || version.starts_with("file:")
        || version.starts_with("link:")
    {
        return Ok(None);
    }

    Ok(Some(Dependency {
        name: manifest_name.to_string(),
        version: Some(version.to_string()),
        ecosystem: crate::Ecosystem::Npm,
        actual_name: None,
    }))
}

fn is_unsupported_remote_spec(version: &str) -> bool {
    let version = version.trim();
    version.starts_with("git+")
        || version.starts_with("git://")
        || version.starts_with("github:")
        || version.starts_with("gitlab:")
        || version.starts_with("bitbucket:")
        || version.starts_with("gist:")
        || version.contains("://")
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
    fn parse_optional_dependencies() {
        let dir = setup_dir(r#"{"optionalDependencies": {"fsevents": "^2.3.0"}}"#);
        let deps = parse(&dir).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "fsevents");
        assert_eq!(deps[0].version, Some("^2.3.0".to_string()));
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

    #[test]
    fn parse_peer_dependencies_as_direct_inputs() {
        let dir = setup_dir(r#"{"peerDependencies": {"react": "^18.0.0"}}"#);
        let deps = parse(&dir).expect("peer dependencies should be treated as direct inputs");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "react");
        cleanup(&dir);
    }

    #[test]
    fn skip_workspace_and_file_dependencies() {
        let dir = setup_dir(
            r#"{"dependencies": {"workspace-lib": "workspace:*", "local-lib": "file:../local-lib", "react": "18.3.1"}}"#,
        );
        let deps =
            parse(&dir).expect("local dependency protocols should not be treated as registry deps");
        let names: Vec<_> = deps.iter().map(|dep| dep.name.as_str()).collect();
        assert_eq!(names, vec!["react"]);
        cleanup(&dir);
    }

    #[test]
    fn reject_git_and_remote_dependency_sources() {
        for spec in [
            "github:owner/repo",
            "git+https://github.com/owner/repo.git",
            "https://registry.npmjs.org/react/-/react-18.3.1.tgz",
        ] {
            let dir = setup_dir(&format!(r#"{{"dependencies": {{"react": "{spec}"}}}}"#));
            let err = parse(&dir).expect_err("unsupported npm dependency sources must fail closed");
            assert!(err.to_string().contains(spec));
            cleanup(&dir);
        }
    }

    #[test]
    fn parse_npm_alias_dependency_into_target_spec() {
        let dir = setup_dir(r#"{"dependencies": {"lodash": "npm:evil-pkg@1.2.3"}}"#);
        let deps = parse(&dir).expect("npm aliases should parse into a dependency identity");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "lodash");
        assert_eq!(deps[0].version, Some("1.2.3".to_string()));
        assert_eq!(deps[0].actual_name.as_deref(), Some("evil-pkg"));
        cleanup(&dir);
    }

    #[test]
    fn reject_non_string_dependency_specs() {
        let dir = setup_dir(r#"{"dependencies": {"react": null}}"#);
        let err = parse(&dir).expect_err("non-string npm dependency specs must fail closed");
        assert!(err.to_string().contains("expected a string version spec"));
        cleanup(&dir);
    }

    #[test]
    fn reject_empty_dependency_specs() {
        let dir = setup_dir(r#"{"dependencies": {"react": "   "}}"#);
        let err = parse(&dir).expect_err("empty npm dependency specs must fail closed");
        assert!(err.to_string().contains("empty version specs"));
        cleanup(&dir);
    }
}
