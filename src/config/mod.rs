pub mod registry;

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
///   "similarity_exceptions": {
///     "cargo": [
///       {
///         "package": "serde_json",
///         "candidate": "serde",
///         "generator": "segment-overlap"
///       }
///     ]
///   },
///   "metadata_exceptions": {
///     "cargo": [
///       {
///         "package": "colored",
///         "check": "metadata/maintainer-change",
///         "version": "2.2.0",
///         "previous_publisher": "kurtlawrence",
///         "current_publisher": "hwittenborn"
///       }
///     ]
///   },
///   "min_version_age_hours": 72,
///   "allow_unresolved_versions": false,
///   "allow_legacy_npm_v1_lockfile": false,
///   "python_enforcement": "prefer_poetry"
/// }
/// ```
///
/// - `canonical`: keys are approved packages, values are rejected alternatives.
/// - `internal`: your org's packages. Skip ALL checks. These change constantly.
/// - `allowed`: vetted external packages. Skip existence + similarity, but
///   still subject to version age gating.
/// - `similarity_exceptions`: exact package/candidate/generator suppressions
///   for known-good similarity false positives.
/// - `metadata_exceptions`: exact suppressions for reviewed metadata findings.
///   Currently only `metadata/maintainer-change` is supported, and it requires
///   exact package/version/previous_publisher/current_publisher matching.
/// - `min_version_age_hours`: block any dependency whose latest version was
///   published less than this many hours ago. Default: 72 (3 days).
///   Internal packages are exempt. Allowed packages are NOT exempt.
/// - `allow_unresolved_versions`: downgrade unresolved-version policy failures
///   to warnings, but still emit them. Default: false.
/// - `allow_legacy_npm_v1_lockfile`: allow legacy npm v5/v6
///   `lockfileVersion: 1` lockfiles in reduced-confidence mode. Default: false.
/// - `python_enforcement`: controls how strictly sloppy-joe enforces trusted
///   Python manifest workflows. `prefer_poetry` (default) trusts Poetry when
///   present and warns on legacy manifests. `poetry_only` blocks non-Poetry
///   Python manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PythonEnforcement {
    PreferPoetry,
    PoetryOnly,
}

fn default_python_enforcement() -> PythonEnforcement {
    PythonEnforcement::PreferPoetry
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimilarityException {
    pub package: String,
    pub candidate: String,
    pub generator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl SimilarityException {
    fn matches(&self, package: &str, candidate: &str, generator: &str) -> bool {
        self.package.eq_ignore_ascii_case(package)
            && self.candidate.eq_ignore_ascii_case(candidate)
            && self.generator == generator
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetadataException {
    pub package: String,
    pub check: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_publisher: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_publisher: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl MetadataException {
    fn matches(
        &self,
        package: &str,
        check: &str,
        version: &str,
        previous_publisher: Option<&str>,
        current_publisher: Option<&str>,
    ) -> bool {
        self.package.eq_ignore_ascii_case(package)
            && self.check == check
            && self.version == version
            && self.previous_publisher.as_deref() == previous_publisher
            && self.current_publisher.as_deref() == current_publisher
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloppyJoeConfig {
    #[serde(default)]
    pub canonical: HashMap<String, HashMap<String, Vec<String>>>,
    #[serde(default)]
    pub internal: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub allowed: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub similarity_exceptions: HashMap<String, Vec<SimilarityException>>,
    #[serde(default)]
    pub metadata_exceptions: HashMap<String, Vec<MetadataException>>,
    #[serde(default = "default_min_version_age_hours")]
    pub min_version_age_hours: u64,
    #[serde(default)]
    pub allow_unresolved_versions: bool,
    #[serde(default)]
    pub allow_legacy_npm_v1_lockfile: bool,
    #[serde(default = "default_python_enforcement")]
    pub python_enforcement: PythonEnforcement,
}

fn default_min_version_age_hours() -> u64 {
    72
}

fn extract_npm_scope(package_or_pattern: &str) -> Option<&str> {
    let value = package_or_pattern
        .strip_suffix("/*")
        .unwrap_or(package_or_pattern);
    if !value.starts_with('@') {
        return None;
    }
    value
        .split_once('/')
        .map(|(scope, _)| scope)
        .or(Some(value))
}

impl Default for SloppyJoeConfig {
    fn default() -> Self {
        Self {
            canonical: HashMap::new(),
            internal: HashMap::new(),
            allowed: HashMap::new(),
            similarity_exceptions: HashMap::new(),
            metadata_exceptions: HashMap::new(),
            min_version_age_hours: default_min_version_age_hours(),
            allow_unresolved_versions: false,
            allow_legacy_npm_v1_lockfile: false,
            python_enforcement: default_python_enforcement(),
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

    /// Additional trusted scopes derived from repo config.
    pub fn trusted_scopes(&self, ecosystem: &str) -> Vec<String> {
        let mut scopes = std::collections::BTreeSet::new();

        for pattern in self
            .internal
            .get(ecosystem)
            .into_iter()
            .flat_map(|rules| rules.iter())
            .chain(
                self.allowed
                    .get(ecosystem)
                    .into_iter()
                    .flat_map(|rules| rules.iter()),
            )
        {
            if let Some(scope) = extract_npm_scope(pattern) {
                scopes.insert(scope.to_string());
            }
        }

        for package in self
            .canonical
            .get(ecosystem)
            .into_iter()
            .flat_map(|rules| rules.keys())
        {
            if let Some(scope) = extract_npm_scope(package) {
                scopes.insert(scope.to_string());
            }
        }

        scopes.into_iter().collect()
    }

    /// Exact package roots that should participate in similarity checks even
    /// when they are not part of the built-in popular-package corpus.
    pub fn similarity_roots(&self, ecosystem: &str) -> Vec<String> {
        let mut roots = std::collections::BTreeSet::new();

        for package in self
            .allowed
            .get(ecosystem)
            .into_iter()
            .flat_map(|rules| rules.iter())
            .chain(
                self.internal
                    .get(ecosystem)
                    .into_iter()
                    .flat_map(|rules| rules.iter()),
            )
        {
            if !package.contains('*') {
                roots.insert(package.to_string());
            }
        }

        for package in self
            .canonical
            .get(ecosystem)
            .into_iter()
            .flat_map(|rules| rules.keys())
        {
            roots.insert(package.to_string());
        }

        roots.into_iter().collect()
    }

    /// Check whether a specific similarity match is explicitly suppressed.
    pub fn is_similarity_exception(
        &self,
        ecosystem: &str,
        package: &str,
        candidate: &str,
        generator: &str,
    ) -> bool {
        self.similarity_exceptions
            .get(ecosystem)
            .into_iter()
            .flat_map(|rules| rules.iter())
            .any(|rule| rule.matches(package, candidate, generator))
    }

    /// Check whether a specific metadata finding is explicitly suppressed.
    pub fn is_metadata_exception(
        &self,
        ecosystem: &str,
        package: &str,
        check: &str,
        version: &str,
        previous_publisher: Option<&str>,
        current_publisher: Option<&str>,
    ) -> bool {
        self.metadata_exceptions
            .get(ecosystem)
            .into_iter()
            .flat_map(|rules| rules.iter())
            .any(|rule| {
                rule.matches(
                    package,
                    check,
                    version,
                    previous_publisher,
                    current_publisher,
                )
            })
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
            (
                "similarity_exceptions",
                self.similarity_exceptions.keys().collect::<Vec<_>>(),
            ),
            (
                "metadata_exceptions",
                self.metadata_exceptions.keys().collect::<Vec<_>>(),
            ),
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

        for (eco, rules) in &self.similarity_exceptions {
            for rule in rules {
                if rule.package.trim().is_empty() || rule.candidate.trim().is_empty() {
                    errors.push(format!(
                        "Invalid similarity exception in {}: package and candidate must be non-empty",
                        eco
                    ));
                }
                if rule.package.contains('*') || rule.candidate.contains('*') {
                    errors.push(format!(
                        "Invalid similarity exception in {}: package and candidate must be exact names, not globs",
                        eco
                    ));
                }
                if !valid_similarity_generator(&rule.generator) {
                    errors.push(format!(
                        "Invalid similarity exception generator '{}' in {}. Valid: {}",
                        rule.generator,
                        eco,
                        valid_similarity_generators().join(", ")
                    ));
                }
            }
        }

        for (eco, rules) in &self.metadata_exceptions {
            for rule in rules {
                if rule.package.trim().is_empty() || rule.version.trim().is_empty() {
                    errors.push(format!(
                        "Invalid metadata exception in {}: package and version must be non-empty",
                        eco
                    ));
                }
                if rule.package.contains('*') {
                    errors.push(format!(
                        "Invalid metadata exception in {}: package must be an exact name, not a glob",
                        eco
                    ));
                }
                if rule.check != crate::checks::names::METADATA_MAINTAINER_CHANGE {
                    errors.push(format!(
                        "Invalid metadata exception check '{}' in {}. Only '{}' is currently supported.",
                        rule.check,
                        eco,
                        crate::checks::names::METADATA_MAINTAINER_CHANGE
                    ));
                }
                if rule
                    .previous_publisher
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
                    || rule
                        .current_publisher
                        .as_deref()
                        .unwrap_or("")
                        .trim()
                        .is_empty()
                {
                    errors.push(format!(
                        "Invalid metadata exception in {}: maintainer-change exceptions require exact previous_publisher and current_publisher values",
                        eco
                    ));
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

fn valid_similarity_generators() -> [&'static str; 13] {
    [
        "separator-swap",
        "collapse-repeated",
        "version-suffix",
        "word-reorder",
        "char-swap",
        "extra-char",
        "homoglyph",
        "confused-forms",
        "bitflip",
        "keyboard-proximity",
        "segment-overlap",
        "scope-squatting",
        "case-variant",
    ]
}

fn valid_similarity_generator(generator: &str) -> bool {
    valid_similarity_generators().contains(&generator)
}

/// Resolve config source with full resolution cascade:
/// 1. `--config` CLI flag (highest priority)
/// 2. `SLOPPY_JOE_CONFIG` env var
/// 3. Registry lookup (if project_dir is Some)
/// 4. None (caller must handle — usually a blocking error)
///
/// Never reads from the project directory.
/// Accepts a file path or a URL (http:// or https://).
pub fn resolve_config_source(
    cli_config: Option<&str>,
    project_dir: Option<&Path>,
) -> Result<Option<String>, String> {
    // Step 1: --config flag
    if let Some(source) = cli_config {
        return Ok(Some(source.to_string()));
    }

    // Step 2: SLOPPY_JOE_CONFIG env var (skip if empty)
    if let Ok(source) = std::env::var("SLOPPY_JOE_CONFIG")
        && !source.is_empty()
    {
        return Ok(Some(source));
    }

    // Step 3: Registry lookup (only if project_dir is Some)
    if let Some(dir) = project_dir {
        return registry::lookup(dir);
    }

    // Step 4: No config found
    Ok(None)
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
    let path = std::fs::canonicalize(path).map_err(|e| {
        format!(
            "Could not resolve config path for security validation.\n  Path: {}\n  Error: {}\n  Fix: Check that the config file exists and is accessible.",
            path.display(),
            e
        )
    })?;

    if path.starts_with(&project_dir) {
        return Err(format!(
            "Config file must live outside the project directory.\n  Config: {}\n  Project: {}\n  Fix: Move the config file outside the repo or use an https:// URL.",
            path.display(),
            project_dir.display()
        ));
    }

    Ok(())
}

/// Build the template config used by init.
fn template_config() -> SloppyJoeConfig {
    SloppyJoeConfig {
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
        similarity_exceptions: HashMap::new(),
        metadata_exceptions: HashMap::new(),
        min_version_age_hours: 72,
        allow_unresolved_versions: false,
        allow_legacy_npm_v1_lockfile: false,
        python_enforcement: default_python_enforcement(),
    }
}

/// Return a template config as a pretty-printed JSON string.
pub fn template_json() -> String {
    serde_json::to_string_pretty(&template_config()).unwrap()
}

/// Print a template config to stdout.
pub fn print_template() {
    println!("{}", template_json());
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
    fn trusted_scopes_include_configured_npm_patterns_and_names() {
        let config = SloppyJoeConfig {
            internal: HashMap::from([("npm".to_string(), vec!["@acme/*".to_string()])]),
            allowed: HashMap::from([("npm".to_string(), vec!["@partner/widget".to_string()])]),
            canonical: HashMap::from([(
                "npm".to_string(),
                HashMap::from([("@types/node".to_string(), vec![])]),
            )]),
            ..Default::default()
        };

        let scopes = config.trusted_scopes("npm");
        assert!(scopes.contains(&"@acme".to_string()));
        assert!(scopes.contains(&"@partner".to_string()));
        assert!(scopes.contains(&"@types".to_string()));
    }

    #[test]
    fn similarity_roots_include_exact_configured_package_names_only() {
        let config = SloppyJoeConfig {
            allowed: HashMap::from([(
                "npm".to_string(),
                vec!["acme-widget".to_string(), "@acme/*".to_string()],
            )]),
            canonical: HashMap::from([(
                "npm".to_string(),
                HashMap::from([("long-tail-lib".to_string(), vec!["other".to_string()])]),
            )]),
            ..Default::default()
        };

        let roots = config.similarity_roots("npm");
        assert!(roots.contains(&"acme-widget".to_string()));
        assert!(roots.contains(&"long-tail-lib".to_string()));
        assert!(!roots.contains(&"@acme/*".to_string()));
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
        assert!(config.similarity_exceptions.is_empty());
        assert!(config.metadata_exceptions.is_empty());
        assert_eq!(config.min_version_age_hours, 72);
        assert!(!config.allow_unresolved_versions);
        assert!(!config.allow_legacy_npm_v1_lockfile);
        assert_eq!(config.python_enforcement, PythonEnforcement::PreferPoetry);
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
    fn template_config_keeps_similarity_exceptions_empty() {
        let config = template_config();
        assert!(
            config.similarity_exceptions.is_empty(),
            "public init template must not embed repo-specific similarity suppressions"
        );
    }

    #[test]
    fn load_config_valid_file() {
        let dir = std::env::temp_dir().join("sloppy-joe-test-config-v2");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(
            &path,
            r#"{"canonical":{"npm":{"lodash":["underscore"]}},"internal":{"npm":["@myorg/*"]},"allowed":{"npm":["vetted"]},"similarity_exceptions":{"cargo":[{"package":"serde_json","candidate":"serde","generator":"segment-overlap","reason":"legitimate companion crate"}]},"metadata_exceptions":{"cargo":[{"package":"colored","check":"metadata/maintainer-change","version":"2.2.0","previous_publisher":"kurtlawrence","current_publisher":"hwittenborn","reason":"reviewed transfer"}]},"min_version_age_hours":48,"allow_unresolved_versions":true,"allow_legacy_npm_v1_lockfile":true,"python_enforcement":"poetry_only"}"#,
        ).unwrap();
        let config = load_config(Some(&path)).unwrap();
        assert!(config.canonical.contains_key("npm"));
        assert!(config.internal.contains_key("npm"));
        assert!(config.allowed.contains_key("npm"));
        assert!(config.similarity_exceptions.contains_key("cargo"));
        assert!(config.metadata_exceptions.contains_key("cargo"));
        assert_eq!(config.min_version_age_hours, 48);
        assert!(config.allow_unresolved_versions);
        assert!(config.allow_legacy_npm_v1_lockfile);
        assert_eq!(config.python_enforcement, PythonEnforcement::PoetryOnly);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_config_rejects_unknown_python_enforcement() {
        let dir = std::env::temp_dir().join("sloppy-joe-test-config-python-mode");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, r#"{"python_enforcement":"requirements_only"}"#).unwrap();

        let err = load_config(Some(&path)).expect_err("unknown Python enforcement modes must fail");
        assert!(err.contains("prefer_poetry"));
        assert!(err.contains("poetry_only"));

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
    fn resolve_config_source_cli_flag_returns_it_directly() {
        let source = resolve_config_source(Some("/some/path.json"), None).unwrap();
        assert_eq!(source, Some("/some/path.json".to_string()));
    }

    #[test]
    fn resolve_config_source_cli_flag_with_url() {
        let source = resolve_config_source(Some("https://example.com/config.json"), None).unwrap();
        assert_eq!(source, Some("https://example.com/config.json".to_string()));
    }

    #[test]
    fn resolve_config_source_none_and_none_returns_none() {
        // When no CLI flag and no project_dir, returns None
        // (if SLOPPY_JOE_CONFIG env var happens to be set, it would return that,
        // but we can't safely clear env vars in parallel tests — this test
        // verifies the function doesn't panic and returns Ok)
        let source = resolve_config_source(None, None);
        assert!(source.is_ok());
    }

    #[test]
    fn resolve_config_source_with_project_dir_triggers_registry_lookup() {
        // Use a temp dir that's not in a git repo — registry lookup should
        // find no git root and no default config, returning None
        let dir = std::env::temp_dir().join("sj-resolve-test");
        std::fs::create_dir_all(&dir).unwrap();
        let source = resolve_config_source(None, Some(&dir));
        // Should not error — exercising the registry::lookup code path
        assert!(source.is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_config_source_cli_flag_takes_priority_over_project_dir() {
        let source = resolve_config_source(
            Some("/explicit/config.json"),
            Some(Path::new("/some/project")),
        )
        .unwrap();
        assert_eq!(source, Some("/explicit/config.json".to_string()));
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
            similarity_exceptions: HashMap::from([(
                "cargo".to_string(),
                vec![SimilarityException {
                    package: "serde_json".to_string(),
                    candidate: "serde".to_string(),
                    generator: "segment-overlap".to_string(),
                    reason: Some("legitimate companion crate".to_string()),
                }],
            )]),
            metadata_exceptions: HashMap::from([(
                "cargo".to_string(),
                vec![MetadataException {
                    package: "colored".to_string(),
                    check: crate::checks::names::METADATA_MAINTAINER_CHANGE.to_string(),
                    version: "2.2.0".to_string(),
                    previous_publisher: Some("kurtlawrence".to_string()),
                    current_publisher: Some("hwittenborn".to_string()),
                    reason: Some("reviewed transfer".to_string()),
                }],
            )]),
            ..Default::default()
        };
        let errors = config.validate();
        assert!(errors.is_empty(), "Expected no errors, got: {:?}", errors);
    }

    #[test]
    fn similarity_exception_matches_exact_pair_and_generator_only() {
        let config = SloppyJoeConfig {
            similarity_exceptions: HashMap::from([(
                "cargo".to_string(),
                vec![SimilarityException {
                    package: "serde_json".to_string(),
                    candidate: "serde".to_string(),
                    generator: "segment-overlap".to_string(),
                    reason: Some("legitimate companion crate".to_string()),
                }],
            )]),
            ..Default::default()
        };

        assert!(config.is_similarity_exception("cargo", "serde_json", "serde", "segment-overlap"));
        assert!(!config.is_similarity_exception("cargo", "serde_json", "serde", "word-reorder"));
        assert!(!config.is_similarity_exception("cargo", "serde", "serde_json", "segment-overlap"));
        assert!(!config.is_similarity_exception(
            "cargo",
            "serde_json",
            "serde_yaml",
            "segment-overlap"
        ));
    }

    #[test]
    fn metadata_exception_matches_exact_package_version_and_publishers_only() {
        let config = SloppyJoeConfig {
            metadata_exceptions: HashMap::from([(
                "cargo".to_string(),
                vec![MetadataException {
                    package: "colored".to_string(),
                    check: crate::checks::names::METADATA_MAINTAINER_CHANGE.to_string(),
                    version: "2.2.0".to_string(),
                    previous_publisher: Some("kurtlawrence".to_string()),
                    current_publisher: Some("hwittenborn".to_string()),
                    reason: Some("reviewed transfer".to_string()),
                }],
            )]),
            ..Default::default()
        };

        assert!(config.is_metadata_exception(
            "cargo",
            "colored",
            crate::checks::names::METADATA_MAINTAINER_CHANGE,
            "2.2.0",
            Some("kurtlawrence"),
            Some("hwittenborn"),
        ));
        assert!(!config.is_metadata_exception(
            "cargo",
            "colored",
            crate::checks::names::METADATA_MAINTAINER_CHANGE,
            "2.2.1",
            Some("kurtlawrence"),
            Some("hwittenborn"),
        ));
        assert!(!config.is_metadata_exception(
            "cargo",
            "colored",
            crate::checks::names::METADATA_MAINTAINER_CHANGE,
            "2.2.0",
            Some("someone-else"),
            Some("hwittenborn"),
        ));
    }

    #[test]
    fn validate_rejects_incomplete_metadata_exception() {
        let config = SloppyJoeConfig {
            metadata_exceptions: HashMap::from([(
                "cargo".to_string(),
                vec![MetadataException {
                    package: "colored".to_string(),
                    check: crate::checks::names::METADATA_MAINTAINER_CHANGE.to_string(),
                    version: "2.2.0".to_string(),
                    previous_publisher: None,
                    current_publisher: Some("hwittenborn".to_string()),
                    reason: None,
                }],
            )]),
            ..Default::default()
        };

        let errors = config.validate();
        assert!(
            errors.iter().any(|err| err.contains("previous_publisher")),
            "expected validation error for incomplete metadata exception, got: {errors:?}"
        );
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

    // ── resolve_config_source end-to-end tests ──

    #[test]
    fn resolve_cli_flag_overrides_everything() {
        // CLI flag should take priority even when project_dir is provided
        let dir = std::env::temp_dir().join("sj-e2e-cli-override");
        std::fs::create_dir_all(&dir).unwrap();
        let result = resolve_config_source(Some("/explicit/config.json"), Some(&dir)).unwrap();
        assert_eq!(result, Some("/explicit/config.json".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_none_cli_none_project_returns_none() {
        // No CLI flag, no project dir, and assuming SLOPPY_JOE_CONFIG is not set
        // in the test environment — should return Ok(None) or Ok(Some(env_val))
        let result = resolve_config_source(None, None);
        assert!(result.is_ok(), "Should not error: {:?}", result);
        // We can't assert None because SLOPPY_JOE_CONFIG might be set.
        // The key assertion is no error.
    }

    #[test]
    fn resolve_non_git_dir_returns_none_via_registry() {
        // A temp dir that's not a git repo — registry lookup finds no git root,
        // no default config → returns None
        let dir = std::env::temp_dir().join(format!("sj-e2e-no-git-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let result = resolve_config_source(None, Some(&dir));
        // Should succeed — lookup finds no git root, checks global default
        assert!(result.is_ok(), "Should not error: {:?}", result);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_git_repo_with_no_registry_entry_uses_lookup() {
        // Run from current repo — lookup should find git root, check registry,
        // potentially find global default or return None. Key: no error.
        let cwd = std::env::current_dir().unwrap();
        let result = resolve_config_source(None, Some(&cwd));
        assert!(
            result.is_ok(),
            "Lookup in git repo should not error: {:?}",
            result
        );
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
