use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Config format:
/// ```json
/// {
///   "canonical": {
///     "npm": {
///       "lodash": ["underscore", "ramda", "lazy.js"],
///       "dayjs": ["moment", "luxon"]
///     }
///   },
///   "internal": {
///     "go": ["github.com/yourorg/*"],
///     "npm": ["@yourorg/*"]
///   },
///   "allowed": {
///     "npm": ["some-vetted-pkg"]
///   },
///   "min_version_age_hours": 72,
///   "allow_unresolved_versions": false
/// }
/// ```
///
/// - `canonical`: keys are approved packages, values are rejected alternatives.
/// - `internal`: your org's packages. Skip ALL checks. These change constantly.
/// - `allowed`: vetted external packages. Skip existence + similarity, but
///   still subject to version age gating.
/// - `min_version_age_hours`: block any dependency whose latest version was
///   published less than this many hours ago. Default: 72 (3 days).
///   Internal packages are exempt. Allowed packages are NOT exempt.
/// - `allow_unresolved_versions`: downgrade unresolved-version policy failures
///   to warnings, but still emit them. Default: false.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloppyJoeConfig {
    #[serde(default)]
    pub canonical: HashMap<String, HashMap<String, Vec<String>>>,
    #[serde(default)]
    pub internal: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub allowed: HashMap<String, Vec<String>>,
    #[serde(default = "default_min_version_age_hours")]
    pub min_version_age_hours: u64,
    #[serde(default)]
    pub allow_unresolved_versions: bool,
}

fn default_min_version_age_hours() -> u64 {
    72
}

impl Default for SloppyJoeConfig {
    fn default() -> Self {
        Self {
            canonical: HashMap::new(),
            internal: HashMap::new(),
            allowed: HashMap::new(),
            min_version_age_hours: default_min_version_age_hours(),
            allow_unresolved_versions: false,
        }
    }
}

impl SloppyJoeConfig {
    /// Build a reverse lookup: alternative_name → canonical_name
    pub fn alternatives_map(&self, ecosystem: &str) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Some(ecosystem_map) = self.canonical.get(ecosystem) {
            for (canonical, alternatives) in ecosystem_map {
                for alt in alternatives {
                    map.insert(alt.clone(), canonical.clone());
                }
            }
        }
        map
    }

    /// Check if a package is internal (skip ALL checks).
    pub fn is_internal(&self, ecosystem: &str, package: &str) -> bool {
        Self::matches_patterns(&self.internal, ecosystem, package)
    }

    /// Check if a package is in the allowed list (skip existence + similarity,
    /// but still subject to age gating).
    pub fn is_allowed(&self, ecosystem: &str, package: &str) -> bool {
        Self::matches_patterns(&self.allowed, ecosystem, package)
    }

    /// Validate config at load time. Returns a list of errors.
    pub fn validate(&self) -> Vec<String> {
        let valid_ecosystems = ["npm", "pypi", "cargo", "go", "ruby", "php", "jvm", "dotnet"];
        let mut errors = Vec::new();

        // Check ecosystem names in all sections
        for (section, keys) in [
            ("canonical", self.canonical.keys().collect::<Vec<_>>()),
            ("internal", self.internal.keys().collect::<Vec<_>>()),
            ("allowed", self.allowed.keys().collect::<Vec<_>>()),
        ] {
            for key in keys {
                if !valid_ecosystems.contains(&key.as_str()) {
                    errors.push(format!(
                        "Unknown ecosystem '{}' in {} section. Valid: {}",
                        key,
                        section,
                        valid_ecosystems.join(", ")
                    ));
                }
            }
        }

        // Check glob patterns: * only at end
        for (section_name, section) in [("internal", &self.internal), ("allowed", &self.allowed)] {
            for (eco, patterns) in section {
                for pattern in patterns {
                    if let Some(pos) = pattern.find('*')
                        && pos != pattern.len() - 1
                    {
                        errors.push(format!(
                            "Invalid glob pattern '{}' in {}.{}: wildcard (*) must be at the end",
                            pattern, section_name, eco
                        ));
                    }
                }
            }
        }

        // Check canonical conflicts: a package that's both canonical and an alternative
        for eco_map in self.canonical.values() {
            let canonical_names: std::collections::HashSet<&String> = eco_map.keys().collect();
            for (canonical, alternatives) in eco_map {
                for alt in alternatives {
                    if canonical_names.contains(alt) {
                        errors.push(format!(
                            "'{}' is listed as both a canonical package and an alternative to '{}'. This is contradictory.",
                            alt, canonical
                        ));
                    }
                }
            }
        }

        errors
    }

    fn matches_patterns(
        map: &HashMap<String, Vec<String>>,
        ecosystem: &str,
        package: &str,
    ) -> bool {
        let Some(patterns) = map.get(ecosystem) else {
            return false;
        };
        for pattern in patterns {
            if pattern.ends_with('*') {
                let prefix = &pattern[..pattern.len() - 1];
                if package.starts_with(prefix) {
                    return true;
                }
            } else if pattern == package {
                return true;
            }
        }
        false
    }
}

/// Resolve config source: --config flag overrides SLOPPY_JOE_CONFIG env var.
/// Never reads from the project directory.
/// Accepts a file path or a URL (http:// or https://).
pub fn resolve_config_source(cli_config: Option<&str>) -> Option<String> {
    if let Some(source) = cli_config {
        return Some(source.to_string());
    }
    std::env::var("SLOPPY_JOE_CONFIG").ok()
}

/// Load config from a resolved path. Fails hard on malformed config —
/// a broken config should never silently fall back to no protection.
pub fn load_config(config_path: Option<&Path>) -> Result<SloppyJoeConfig, String> {
    load_config_with_project(config_path, None)
}

pub fn load_config_with_project(
    config_path: Option<&Path>,
    project_dir: Option<&Path>,
) -> Result<SloppyJoeConfig, String> {
    let Some(path) = config_path else {
        return Ok(SloppyJoeConfig::default());
    };

    ensure_config_outside_project(path, project_dir)?;

    let content = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "Could not read config file: {}\n  Path: {}\n  Fix: Check that the file exists and is readable.\n       Use 'sloppy-joe init > config.json' to generate a template.",
            e, path.display()
        )
    })?;

    parse_config_content(&content, &path.display().to_string())
}

/// Load config from a string source — either a file path or a URL.
/// Fails hard on errors — a misconfigured CI pipeline should not
/// silently run without protection.
pub async fn load_config_from_source(
    source: Option<&str>,
    project_dir: Option<&Path>,
) -> Result<SloppyJoeConfig, String> {
    let Some(source) = source else {
        return Ok(SloppyJoeConfig::default());
    };

    if source.starts_with("http://") {
        Err(format!(
            "Config URL must use HTTPS.\n  URL: {}\n  Fix: Use an https:// URL or a local path outside the project directory.",
            source
        ))
    } else if source.starts_with("https://") {
        fetch_config_from_url(source).await
    } else {
        load_config_with_project(Some(Path::new(source)), project_dir)
    }
}

/// Fetch config JSON from a URL.
async fn fetch_config_from_url(url: &str) -> Result<SloppyJoeConfig, String> {
    // Use a dedicated client with no redirects to prevent SSRF via redirect chains
    let client = reqwest::Client::builder()
        .user_agent("sloppy-joe")
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("failed to build config HTTP client");
    let response = client.get(url).send().await.map_err(|e| {
        format!(
            "Could not fetch config from URL: {}\n  URL: {}\n  Fix: Check that the URL is reachable and returns valid JSON.\n       For private repos, ensure your CI token has read access.",
            e, url
        )
    })?;

    if !response.status().is_success() {
        return Err(format!(
            "Config URL returned HTTP {}\n  URL: {}\n  Fix: Check that the URL points to a valid JSON file.\n       For GitHub raw URLs, use: https://raw.githubusercontent.com/org/repo/main/sloppy-joe.json",
            response.status(),
            url
        ));
    }

    // Reject oversized responses BEFORE reading the body into memory.
    // Check Content-Length header first (fast path), then cap the read.
    const MAX_CONFIG_BYTES: u64 = 1_024 * 1_024;
    if let Some(len) = response.content_length()
        && len > MAX_CONFIG_BYTES
    {
        return Err(format!(
            "Config response too large ({} bytes, max {} bytes)\n  URL: {}",
            len, MAX_CONFIG_BYTES, url
        ));
    }
    // Read body in chunks with a hard size cap to prevent OOM from chunked responses
    // that bypass Content-Length (the header check above only works when the server sends it).
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    use futures::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| format!("Could not read response body from {}: {}", url, e))?;
        body.extend_from_slice(&chunk);
        if body.len() as u64 > MAX_CONFIG_BYTES {
            return Err(format!(
                "Config response too large (>{} bytes)\n  URL: {}",
                MAX_CONFIG_BYTES, url
            ));
        }
    }
    let bytes = body;
    let content = String::from_utf8(bytes)
        .map_err(|e| format!("Config response is not valid UTF-8: {}", e))?;

    parse_config_content(&content, url)
}

/// Parse config JSON content with actionable error messages.
fn parse_config_content(content: &str, source: &str) -> Result<SloppyJoeConfig, String> {
    if content.trim().is_empty() {
        return Err(format!(
            "Config is empty.\n  Source: {}\n  Fix: Use 'sloppy-joe init > config.json' to generate a template.",
            source
        ));
    }

    let config: SloppyJoeConfig = serde_json::from_str(content).map_err(|e| {
        let mut msg = format!(
            "Config is not valid JSON.\n  Source: {}\n  Error: {}",
            source, e
        );

        // Add specific hints for common mistakes
        if content.contains("//") {
            msg.push_str("\n  Hint: JSON does not support comments. Remove lines starting with //.");
        }
        if content.contains(",\n}") || content.contains(",\n]") || content.contains(", }") || content.contains(", ]") {
            msg.push_str("\n  Hint: Trailing commas are not allowed in JSON. Remove the comma before } or ].");
        }
        if !content.starts_with('{') {
            msg.push_str("\n  Hint: Config must be a JSON object starting with {.");
        }

        msg.push_str("\n  Fix: Validate your JSON at https://jsonlint.com or use 'sloppy-joe init' for a template.");
        msg
    })?;

    let validation_errors = config.validate();
    if !validation_errors.is_empty() {
        return Err(format!(
            "Config validation failed:\n  {}",
            validation_errors.join("\n  ")
        ));
    }

    Ok(config)
}

fn ensure_config_outside_project(path: &Path, project_dir: Option<&Path>) -> Result<(), String> {
    let Some(project_dir) = project_dir else {
        return Ok(());
    };

    let project_dir =
        std::fs::canonicalize(project_dir).unwrap_or_else(|_| project_dir.to_path_buf());
    let path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

    if path.starts_with(&project_dir) {
        return Err(format!(
            "Config file must live outside the project directory.\n  Config: {}\n  Project: {}\n  Fix: Move the config file outside the repo or use an https:// URL.",
            path.display(),
            project_dir.display()
        ));
    }

    Ok(())
}

/// Print a template config to stdout.
pub fn print_template() {
    let config = SloppyJoeConfig {
        canonical: {
            let mut m = HashMap::new();
            m.insert(
                "npm".to_string(),
                HashMap::from([
                    (
                        "lodash".to_string(),
                        vec!["underscore".to_string(), "ramda".to_string()],
                    ),
                    (
                        "dayjs".to_string(),
                        vec!["moment".to_string(), "luxon".to_string()],
                    ),
                    (
                        "axios".to_string(),
                        vec![
                            "request".to_string(),
                            "got".to_string(),
                            "node-fetch".to_string(),
                            "superagent".to_string(),
                        ],
                    ),
                ]),
            );
            m.insert(
                "pypi".to_string(),
                HashMap::from([
                    (
                        "httpx".to_string(),
                        vec!["urllib3".to_string(), "requests".to_string()],
                    ),
                    (
                        "ruff".to_string(),
                        vec!["flake8".to_string(), "pylint".to_string()],
                    ),
                ]),
            );
            m.insert("cargo".to_string(), HashMap::new());
            m.insert("go".to_string(), HashMap::new());
            m.insert("ruby".to_string(), HashMap::new());
            m.insert("php".to_string(), HashMap::new());
            m.insert("jvm".to_string(), HashMap::new());
            m.insert("dotnet".to_string(), HashMap::new());
            m
        },
        internal: HashMap::from([
            ("go".to_string(), vec!["github.com/yourorg/*".to_string()]),
            ("npm".to_string(), vec!["@yourorg/*".to_string()]),
        ]),
        allowed: HashMap::from([(
            "npm".to_string(),
            vec!["some-vetted-external-pkg".to_string()],
        )]),
        min_version_age_hours: 72,
        allow_unresolved_versions: false,
    };
    let json = serde_json::to_string_pretty(&config).unwrap();
    println!("{json}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_internal_exact_match() {
        let config = SloppyJoeConfig {
            internal: HashMap::from([("npm".to_string(), vec!["my-pkg".to_string()])]),
            ..Default::default()
        };
        assert!(config.is_internal("npm", "my-pkg"));
    }

    #[test]
    fn is_internal_glob_pattern() {
        let config = SloppyJoeConfig {
            internal: HashMap::from([("npm".to_string(), vec!["@myorg/*".to_string()])]),
            ..Default::default()
        };
        assert!(config.is_internal("npm", "@myorg/utils"));
        assert!(config.is_internal("npm", "@myorg/core"));
        assert!(!config.is_internal("npm", "@other/utils"));
    }

    #[test]
    fn is_internal_missing_ecosystem() {
        let config = SloppyJoeConfig {
            internal: HashMap::from([("npm".to_string(), vec!["my-pkg".to_string()])]),
            ..Default::default()
        };
        assert!(!config.is_internal("pypi", "my-pkg"));
    }

    #[test]
    fn is_allowed_exact_match() {
        let config = SloppyJoeConfig {
            allowed: HashMap::from([("npm".to_string(), vec!["vetted-pkg".to_string()])]),
            ..Default::default()
        };
        assert!(config.is_allowed("npm", "vetted-pkg"));
    }

    #[test]
    fn is_allowed_glob_pattern() {
        let config = SloppyJoeConfig {
            allowed: HashMap::from([("go".to_string(), vec!["github.com/trusted/*".to_string()])]),
            ..Default::default()
        };
        assert!(config.is_allowed("go", "github.com/trusted/lib"));
    }

    #[test]
    fn is_allowed_non_matching() {
        let config = SloppyJoeConfig {
            allowed: HashMap::from([("npm".to_string(), vec!["my-pkg".to_string()])]),
            ..Default::default()
        };
        assert!(!config.is_allowed("npm", "other-pkg"));
    }

    #[test]
    fn internal_is_not_allowed() {
        let config = SloppyJoeConfig {
            internal: HashMap::from([("npm".to_string(), vec!["@myorg/*".to_string()])]),
            ..Default::default()
        };
        // Internal packages are NOT in the allowed list
        assert!(!config.is_allowed("npm", "@myorg/utils"));
        assert!(config.is_internal("npm", "@myorg/utils"));
    }

    #[test]
    fn alternatives_map_builds_reverse_lookup() {
        let config = SloppyJoeConfig {
            canonical: HashMap::from([(
                "npm".to_string(),
                HashMap::from([
                    (
                        "lodash".to_string(),
                        vec!["underscore".to_string(), "ramda".to_string()],
                    ),
                    ("dayjs".to_string(), vec!["moment".to_string()]),
                ]),
            )]),
            ..Default::default()
        };
        let map = config.alternatives_map("npm");
        assert_eq!(map.get("underscore"), Some(&"lodash".to_string()));
        assert_eq!(map.get("ramda"), Some(&"lodash".to_string()));
        assert_eq!(map.get("moment"), Some(&"dayjs".to_string()));
        assert_eq!(map.get("lodash"), None);
    }

    #[test]
    fn alternatives_map_empty_config() {
        let config = SloppyJoeConfig::default();
        let map = config.alternatives_map("npm");
        assert!(map.is_empty());
    }

    #[test]
    fn load_config_none_returns_default() {
        let config = load_config(None).unwrap();
        assert!(config.canonical.is_empty());
        assert!(config.internal.is_empty());
        assert!(config.allowed.is_empty());
        assert_eq!(config.min_version_age_hours, 72);
        assert!(!config.allow_unresolved_versions);
    }

    #[test]
    fn load_config_nonexistent_path_returns_error() {
        let result = load_config(Some(Path::new("/tmp/nonexistent-sloppy-joe-config.json")));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Could not read config file"));
        assert!(err.contains("Fix:"));
    }

    #[test]
    fn load_config_valid_file() {
        let dir = std::env::temp_dir().join("sloppy-joe-test-config-v2");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(
            &path,
            r#"{"canonical":{"npm":{"lodash":["underscore"]}},"internal":{"npm":["@myorg/*"]},"allowed":{"npm":["vetted"]},"min_version_age_hours":48,"allow_unresolved_versions":true}"#,
        ).unwrap();
        let config = load_config(Some(&path)).unwrap();
        assert!(config.canonical.contains_key("npm"));
        assert!(config.internal.contains_key("npm"));
        assert!(config.allowed.contains_key("npm"));
        assert_eq!(config.min_version_age_hours, 48);
        assert!(config.allow_unresolved_versions);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_config_rejects_project_local_path() {
        let dir = std::env::temp_dir().join("sloppy-joe-test-project-boundary");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, r#"{"canonical":{},"internal":{},"allowed":{}}"#).unwrap();
        let err = load_config_with_project(Some(&path), Some(&dir)).unwrap_err();
        assert!(err.contains("outside the project directory"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_config_empty_file_returns_error() {
        let dir = std::env::temp_dir().join("sloppy-joe-test-empty");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, "").unwrap();
        let result = load_config(Some(&path));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Config is empty"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_config_invalid_json_returns_error_with_hints() {
        let dir = std::env::temp_dir().join("sloppy-joe-test-invalid");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, r#"{ "canonical": {}, // this is a comment }"#).unwrap();
        let result = load_config(Some(&path));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Config is not valid JSON"));
        assert!(err.contains("comments"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn default_min_version_age_is_72() {
        let config = SloppyJoeConfig::default();
        assert_eq!(config.min_version_age_hours, 72);
    }

    #[test]
    fn resolve_config_source_with_cli_flag() {
        let source = resolve_config_source(Some("/some/path.json"));
        assert_eq!(source, Some("/some/path.json".to_string()));
    }

    #[test]
    fn resolve_config_source_with_url() {
        let source = resolve_config_source(Some("https://example.com/config.json"));
        assert_eq!(source, Some("https://example.com/config.json".to_string()));
    }

    #[test]
    fn resolve_config_source_none() {
        // When no env var is set and no CLI flag, returns None
        // (can't reliably test env var in parallel tests)
        let source = resolve_config_source(None);
        // May or may not be None depending on env, just verify it doesn't panic
        let _ = source;
    }

    #[test]
    fn print_template_does_not_panic() {
        print_template();
    }

    #[test]
    fn validate_rejects_unknown_ecosystem() {
        let config = SloppyJoeConfig {
            internal: HashMap::from([("nodejs".to_string(), vec!["pkg".to_string()])]),
            ..Default::default()
        };
        let errors = config.validate();
        assert!(!errors.is_empty());
        assert!(errors[0].contains("nodejs"));
    }

    #[test]
    fn validate_rejects_bad_glob_pattern() {
        let config = SloppyJoeConfig {
            internal: HashMap::from([("npm".to_string(), vec!["@org/*/sub".to_string()])]),
            ..Default::default()
        };
        let errors = config.validate();
        assert!(!errors.is_empty());
        assert!(errors[0].contains("*"));
    }

    #[test]
    fn validate_accepts_valid_config() {
        let config = SloppyJoeConfig {
            canonical: HashMap::from([(
                "npm".to_string(),
                HashMap::from([("lodash".to_string(), vec!["underscore".to_string()])]),
            )]),
            internal: HashMap::from([("npm".to_string(), vec!["@myorg/*".to_string()])]),
            allowed: HashMap::from([("npm".to_string(), vec!["vetted-pkg".to_string()])]),
            ..Default::default()
        };
        let errors = config.validate();
        assert!(errors.is_empty(), "Expected no errors, got: {:?}", errors);
    }

    #[test]
    fn validate_rejects_canonical_listed_as_alternative() {
        let config = SloppyJoeConfig {
            canonical: HashMap::from([(
                "npm".to_string(),
                HashMap::from([
                    ("lodash".to_string(), vec!["underscore".to_string()]),
                    ("underscore".to_string(), vec!["ramda".to_string()]),
                ]),
            )]),
            ..Default::default()
        };
        let errors = config.validate();
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains("underscore")));
    }

    #[test]
    fn load_config_valid_file_runs_validation() {
        let dir = std::env::temp_dir().join("sloppy-joe-test-validate");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, r#"{"internal":{"nodejs":["pkg"]}}"#).unwrap();
        let result = load_config(Some(&path));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("nodejs"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn load_config_from_source_rejects_http_url() {
        let err = load_config_from_source(Some("http://example.invalid/sloppy-joe.json"), None)
            .await
            .unwrap_err();
        assert!(err.contains("must use HTTPS"));
    }

    // ── parse_config_content edge cases ──

    #[test]
    fn parse_config_content_trailing_comma_hint() {
        let content = r#"{
  "canonical": {},
  "internal": {},
}"#;
        let err = parse_config_content(content, "test.json").unwrap_err();
        assert!(err.contains("Trailing commas"));
    }

    #[test]
    fn parse_config_content_not_object_hint() {
        let content = r#"["not", "an", "object"]"#;
        let err = parse_config_content(content, "test.json").unwrap_err();
        assert!(err.contains("must be a JSON object"));
    }

    #[test]
    fn parse_config_content_empty_string() {
        let err = parse_config_content("", "test.json").unwrap_err();
        assert!(err.contains("Config is empty"));
    }

    #[test]
    fn parse_config_content_whitespace_only() {
        let err = parse_config_content("   \n  ", "test.json").unwrap_err();
        assert!(err.contains("Config is empty"));
    }

    #[test]
    fn parse_config_content_comment_hint() {
        let content = r#"{ // comment
  "canonical": {}
}"#;
        let err = parse_config_content(content, "test.json").unwrap_err();
        assert!(err.contains("comments"));
    }

    #[test]
    fn parse_config_content_valid_minimal() {
        let content = r#"{}"#;
        let config = parse_config_content(content, "test.json").unwrap();
        assert!(config.canonical.is_empty());
        assert_eq!(config.min_version_age_hours, 72);
    }

    #[test]
    fn parse_config_content_validation_fails() {
        let content = r#"{"internal":{"nodejs":["pkg"]}}"#;
        let err = parse_config_content(content, "test.json").unwrap_err();
        assert!(err.contains("nodejs"));
        assert!(err.contains("validation failed"));
    }

    #[test]
    fn parse_config_content_valid_full() {
        let content = r#"{"canonical":{"npm":{"lodash":["underscore"]}},"internal":{"npm":["@myorg/*"]},"allowed":{"npm":["vetted"]},"min_version_age_hours":48}"#;
        let config = parse_config_content(content, "test.json").unwrap();
        assert!(config.canonical.contains_key("npm"));
        assert_eq!(config.min_version_age_hours, 48);
    }

    #[tokio::test]
    async fn load_config_from_source_none_returns_default() {
        let config = load_config_from_source(None, None).await.unwrap();
        assert!(config.canonical.is_empty());
        assert_eq!(config.min_version_age_hours, 72);
    }

    #[tokio::test]
    async fn load_config_from_source_file_path() {
        let dir = std::env::temp_dir().join("sloppy-joe-test-source-file");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, r#"{"canonical":{}}"#).unwrap();
        let config = load_config_from_source(Some(path.to_str().unwrap()), None)
            .await
            .unwrap();
        assert!(config.canonical.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
