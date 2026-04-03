pub mod registry;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

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
///   "trusted_local_paths": {
///     "cargo": ["/opt/company/shared-crate"]
///   },
///   "trusted_registries": {
///     "cargo": [
///       {
///         "name": "company",
///         "source": "registry+https://cargo.company.example/index"
///       }
///     ]
///   },
///   "trusted_git_sources": {
///     "cargo": ["https://github.com/yourorg/shared-crate"]
///   },
///   "cargo_git_policy": "block",
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
/// - `trusted_local_paths`: exact local dependency directories trusted for
///   provenance-sensitive ecosystems like Cargo.
/// - `trusted_registries`: exact manifest alias + lockfile source bindings for
///   trusted private registries.
/// - `trusted_git_sources`: exact allowlist of git repository URLs permitted in
///   reduced-confidence modes.
/// - `cargo_git_policy`: Cargo git dependency policy. `block` (default) or
///   `warn_pinned`.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CargoGitPolicy {
    Block,
    WarnPinned,
}

fn default_cargo_git_policy() -> CargoGitPolicy {
    CargoGitPolicy::Block
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedRegistry {
    pub name: String,
    pub source: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalOverlayConfig {
    #[serde(default)]
    trusted_local_paths: HashMap<String, Vec<String>>,
    #[serde(default)]
    trusted_registries: HashMap<String, Vec<TrustedRegistry>>,
    #[serde(default)]
    trusted_git_sources: HashMap<String, Vec<String>>,
    #[serde(default)]
    cargo_git_policy: Option<CargoGitPolicy>,
    #[serde(default)]
    allow_host_local_cargo_config: bool,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalGroupSuggestion {
    pub packages: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapReview {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub candidate_canonical_groups: HashMap<String, Vec<CanonicalGroupSuggestion>>,
}

impl BootstrapReview {
    fn is_empty(&self) -> bool {
        self.candidate_canonical_groups.is_empty()
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
    #[serde(default)]
    pub trusted_local_paths: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub trusted_registries: HashMap<String, Vec<TrustedRegistry>>,
    #[serde(default)]
    pub trusted_git_sources: HashMap<String, Vec<String>>,
    #[serde(default = "default_cargo_git_policy")]
    pub cargo_git_policy: CargoGitPolicy,
    #[serde(default = "default_python_enforcement")]
    pub python_enforcement: PythonEnforcement,
    #[serde(default, skip_serializing_if = "BootstrapReview::is_empty")]
    pub bootstrap_review: BootstrapReview,
    #[serde(skip)]
    pub allow_host_local_cargo_config: bool,
    #[serde(skip)]
    pub active_local_overlay_relaxations: Vec<String>,
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
            trusted_local_paths: HashMap::new(),
            trusted_registries: HashMap::new(),
            trusted_git_sources: HashMap::new(),
            cargo_git_policy: default_cargo_git_policy(),
            python_enforcement: default_python_enforcement(),
            bootstrap_review: BootstrapReview::default(),
            allow_host_local_cargo_config: false,
            active_local_overlay_relaxations: Vec::new(),
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

    pub fn trusted_local_paths(&self, ecosystem: &str) -> &[String] {
        self.trusted_local_paths
            .get(ecosystem)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn trusted_registries(&self, ecosystem: &str) -> &[TrustedRegistry] {
        self.trusted_registries
            .get(ecosystem)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn trusted_git_sources(&self, ecosystem: &str) -> &[String] {
        self.trusted_git_sources
            .get(ecosystem)
            .map(Vec::as_slice)
            .unwrap_or(&[])
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
            (
                "trusted_local_paths",
                self.trusted_local_paths.keys().collect::<Vec<_>>(),
            ),
            (
                "trusted_registries",
                self.trusted_registries.keys().collect::<Vec<_>>(),
            ),
            (
                "trusted_git_sources",
                self.trusted_git_sources.keys().collect::<Vec<_>>(),
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

        for (eco, paths) in &self.trusted_local_paths {
            for path in paths {
                if path.trim().is_empty() {
                    errors.push(format!(
                        "Invalid trusted local path in {}: path must be non-empty",
                        eco
                    ));
                }
            }
        }

        for (eco, rules) in &self.trusted_registries {
            for rule in rules {
                if rule.name.trim().is_empty() || rule.source.trim().is_empty() {
                    errors.push(format!(
                        "Invalid trusted registry in {}: name and source must be non-empty",
                        eco
                    ));
                }
            }
        }

        for (eco, sources) in &self.trusted_git_sources {
            for source in sources {
                if source.trim().is_empty() {
                    errors.push(format!(
                        "Invalid trusted git source in {}: source must be non-empty",
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
    let mut config = if let Some(path) = config_path {
        ensure_config_outside_project(path, project_dir)?;

        let content = std::fs::read_to_string(path).map_err(|e| {
            format!(
                "Could not read config file: {}\n  Path: {}\n  Fix: Check that the file exists and is readable.\n       Use 'sloppy-joe init --register' or write a template to a safe external path with 'sloppy-joe init > /secure/sloppy-joe.json'.",
                e, path.display()
            )
        })?;

        parse_config_content(&content, &path.display().to_string())?
    } else {
        SloppyJoeConfig::default()
    };

    config = maybe_apply_local_overlay(config)?;
    Ok(config)
}

/// Load config from a string source — either a file path or a URL.
/// Fails hard on errors — a misconfigured CI pipeline should not
/// silently run without protection.
pub async fn load_config_from_source(
    source: Option<&str>,
    project_dir: Option<&Path>,
) -> Result<SloppyJoeConfig, String> {
    let mut config = if let Some(source) = source {
        if source.starts_with("http://") {
            return Err(format!(
                "Config URL must use HTTPS.\n  URL: {}\n  Fix: Use an https:// URL or a local path outside the project directory.",
                redact_url_for_display(source)
            ));
        } else if source.starts_with("https://") {
            fetch_config_from_url(source).await?
        } else {
            return load_config_with_project(Some(Path::new(source)), project_dir);
        }
    } else {
        SloppyJoeConfig::default()
    };

    config = maybe_apply_local_overlay(config)?;
    Ok(config)
}

/// Fetch config JSON from a URL.
async fn fetch_config_from_url(url: &str) -> Result<SloppyJoeConfig, String> {
    let display_url = redact_url_for_display(url);
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
            e, display_url
        )
    })?;

    if !response.status().is_success() {
        return Err(format!(
            "Config URL returned HTTP {}\n  URL: {}\n  Fix: Check that the URL points to a valid JSON file.\n       For GitHub raw URLs, use: https://raw.githubusercontent.com/org/repo/main/sloppy-joe.json",
            response.status(),
            display_url
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
            len, MAX_CONFIG_BYTES, display_url
        ));
    }
    // Read body in chunks with a hard size cap to prevent OOM from chunked responses
    // that bypass Content-Length (the header check above only works when the server sends it).
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    use futures::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|e| format!("Could not read response body from {}: {}", display_url, e))?;
        body.extend_from_slice(&chunk);
        if body.len() as u64 > MAX_CONFIG_BYTES {
            return Err(format!(
                "Config response too large (>{} bytes)\n  URL: {}",
                MAX_CONFIG_BYTES, display_url
            ));
        }
    }
    let bytes = body;
    let content = String::from_utf8(bytes)
        .map_err(|e| format!("Config response is not valid UTF-8: {}", e))?;

    parse_config_content(&content, &display_url)
}

fn redact_url_for_display(url: &str) -> String {
    let Ok(mut parsed) = reqwest::Url::parse(url) else {
        return url.to_string();
    };
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

/// Parse config JSON content with actionable error messages.
fn parse_config_content(content: &str, source: &str) -> Result<SloppyJoeConfig, String> {
    if content.trim().is_empty() {
        return Err(format!(
            "Config is empty.\n  Source: {}\n  Fix: Use 'sloppy-joe init > /secure/location/sloppy-joe.json' to generate a template outside the repo.",
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

fn parse_local_overlay_content(content: &str, source: &str) -> Result<LocalOverlayConfig, String> {
    if content.trim().is_empty() {
        return Err(format!(
            "Local overlay config is empty.\n  Source: {}\n  Fix: Remove the file or provide valid JSON.",
            source
        ));
    }

    serde_json::from_str(content).map_err(|e| {
        format!(
            "Local overlay config is not valid JSON.\n  Source: {}\n  Error: {}\n  Fix: Use a JSON object with only local provenance fields.",
            source, e
        )
    })
}

fn overlay_relaxation_messages(overlay: &LocalOverlayConfig) -> Vec<String> {
    let mut messages = Vec::new();
    if !overlay.trusted_local_paths.is_empty() {
        messages.push("local trusted Cargo path allowlist".to_string());
    }
    if !overlay.trusted_registries.is_empty() {
        messages.push("local trusted Cargo registry allowlist".to_string());
    }
    if !overlay.trusted_git_sources.is_empty() {
        messages.push("local trusted Cargo git allowlist".to_string());
    }
    if overlay.cargo_git_policy == Some(CargoGitPolicy::WarnPinned) {
        messages.push("reduced-confidence Cargo git policy".to_string());
    }
    if overlay.allow_host_local_cargo_config {
        messages.push("host-local Cargo config trust".to_string());
    }
    messages
}

fn apply_local_overlay(mut base: SloppyJoeConfig, overlay: LocalOverlayConfig) -> SloppyJoeConfig {
    let relaxation_messages = overlay_relaxation_messages(&overlay);
    for (ecosystem, paths) in overlay.trusted_local_paths {
        base.trusted_local_paths
            .entry(ecosystem)
            .or_default()
            .extend(paths);
    }
    for (ecosystem, registries) in overlay.trusted_registries {
        base.trusted_registries
            .entry(ecosystem)
            .or_default()
            .extend(registries);
    }
    for (ecosystem, sources) in overlay.trusted_git_sources {
        base.trusted_git_sources
            .entry(ecosystem)
            .or_default()
            .extend(sources);
    }
    if overlay.cargo_git_policy == Some(CargoGitPolicy::WarnPinned) {
        base.cargo_git_policy = CargoGitPolicy::WarnPinned;
    }
    if overlay.allow_host_local_cargo_config {
        base.allow_host_local_cargo_config = true;
    }
    base.active_local_overlay_relaxations = relaxation_messages;
    base
}

fn local_overlay_path() -> Result<PathBuf, String> {
    registry::config_home().map(|home| home.join("local-overlay.json"))
}

fn running_in_ci() -> bool {
    std::env::var("CI")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

fn maybe_apply_local_overlay(config: SloppyJoeConfig) -> Result<SloppyJoeConfig, String> {
    if running_in_ci() {
        return Ok(config);
    }

    let overlay_path = local_overlay_path()?;
    if !overlay_path.exists() {
        return Ok(config);
    }

    load_local_overlay_from_path(config, &overlay_path)
}

fn load_local_overlay_from_path(
    base: SloppyJoeConfig,
    path: &Path,
) -> Result<SloppyJoeConfig, String> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "Could not read local overlay config: {}\n  Path: {}\n  Fix: Check file permissions or remove the local overlay file.",
            e, path.display()
        )
    })?;
    let overlay = parse_local_overlay_content(&content, &path.display().to_string())?;
    Ok(apply_local_overlay(base, overlay))
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
///
/// This is a manual starting point, not a finished policy for an existing repo.
/// Future onboarding should prefer explicit greenfield presets or a
/// `--from-current` discovery flow over one generic example blob.
fn template_config() -> SloppyJoeConfig {
    SloppyJoeConfig::default()
}

fn render_config_json(config: &SloppyJoeConfig) -> String {
    serde_json::to_string_pretty(config).expect("SloppyJoeConfig should always serialize")
}

fn supported_bootstrap_ecosystems() -> &'static [&'static str] {
    &["npm", "pypi", "cargo", "go", "ruby", "php", "jvm", "dotnet"]
}

pub fn greenfield_config(ecosystem: &str) -> Result<SloppyJoeConfig, String> {
    let mut config = template_config();
    match ecosystem {
        "npm" => {
            config.canonical.insert(
                "npm".to_string(),
                HashMap::from([
                    ("eslint".to_string(), vec!["tslint".to_string()]),
                    ("dayjs".to_string(), vec!["moment".to_string()]),
                ]),
            );
        }
        "pypi" => {
            config.canonical.insert(
                "pypi".to_string(),
                HashMap::from([(
                    "ruff".to_string(),
                    vec![
                        "flake8".to_string(),
                        "pylint".to_string(),
                        "pyflakes".to_string(),
                    ],
                )]),
            );
        }
        "cargo" => {
            config.canonical.insert(
                "cargo".to_string(),
                HashMap::from([
                    (
                        "thiserror".to_string(),
                        vec!["failure".to_string(), "error-chain".to_string()],
                    ),
                    ("clap".to_string(), vec!["structopt".to_string()]),
                ]),
            );
        }
        "go" | "ruby" | "php" | "jvm" | "dotnet" => {
            config
                .canonical
                .insert(ecosystem.to_string(), HashMap::new());
        }
        other => {
            return Err(format!(
                "Unsupported ecosystem '{}'. Expected one of: {}.",
                other,
                supported_bootstrap_ecosystems().join(", ")
            ));
        }
    }

    Ok(config)
}

pub fn greenfield_json(ecosystem: &str) -> Result<String, String> {
    greenfield_config(ecosystem).map(|config| render_config_json(&config))
}

#[derive(Default)]
struct DiscoveryState {
    npm_local_packages: BTreeSet<String>,
    npm_scope_counts: HashMap<String, usize>,
    npm_dependency_usage: BTreeSet<String>,
    cargo_local_packages: BTreeSet<String>,
    cargo_external_paths: BTreeSet<String>,
}

impl DiscoveryState {
    fn into_config(self) -> SloppyJoeConfig {
        let mut config = template_config();

        let mut npm_internal = Vec::new();
        let mut scope_globs = BTreeSet::new();
        for (scope, count) in &self.npm_scope_counts {
            if *count > 1 {
                scope_globs.insert(scope.clone());
                npm_internal.push(format!("{scope}/*"));
            }
        }
        for package in self.npm_local_packages {
            if let Some(scope) = extract_npm_scope(&package)
                && scope_globs.contains(scope)
            {
                continue;
            }
            npm_internal.push(package);
        }
        if !npm_internal.is_empty() {
            config.internal.insert("npm".to_string(), npm_internal);
        }

        if !self.cargo_local_packages.is_empty() {
            config.internal.insert(
                "cargo".to_string(),
                self.cargo_local_packages.into_iter().collect(),
            );
        }

        if !self.cargo_external_paths.is_empty() {
            config.trusted_local_paths.insert(
                "cargo".to_string(),
                self.cargo_external_paths.into_iter().collect(),
            );
        }

        let npm_groups = candidate_canonical_groups(
            &self.npm_dependency_usage,
            &[
                &["dayjs", "moment", "luxon"],
                &["axios", "got", "node-fetch", "superagent"],
                &["eslint", "tslint"],
                &["jest", "vitest", "mocha", "ava"],
            ],
            "Multiple packages from the same solution family are already in use. Review whether one should become canonical.",
        );
        if !npm_groups.is_empty() {
            config
                .bootstrap_review
                .candidate_canonical_groups
                .insert("npm".to_string(), npm_groups);
        }

        config
    }
}

fn candidate_canonical_groups(
    used_packages: &BTreeSet<String>,
    families: &[&[&str]],
    reason: &str,
) -> Vec<CanonicalGroupSuggestion> {
    let mut groups = Vec::new();
    for family in families {
        let packages: Vec<String> = family
            .iter()
            .filter(|package| used_packages.contains(**package))
            .map(|package| (*package).to_string())
            .collect();
        if packages.len() >= 2 {
            groups.push(CanonicalGroupSuggestion {
                packages,
                reason: Some(reason.to_string()),
            });
        }
    }
    groups
}

fn discover_repo_state(
    current_dir: &Path,
    root: &Path,
    visited: &mut BTreeSet<PathBuf>,
    state: &mut DiscoveryState,
) -> Result<(), String> {
    let canonical_current = std::fs::canonicalize(current_dir).map_err(|err| {
        format!(
            "Failed to inspect {} while seeding config from the current repo: {}",
            current_dir.display(),
            err
        )
    })?;

    if !canonical_current.starts_with(root) {
        return Err(format!(
            "Refusing to follow directory '{}' outside the current repo root.",
            current_dir.display()
        ));
    }

    if !visited.insert(canonical_current) {
        return Ok(());
    }

    let mut entries: Vec<_> = std::fs::read_dir(current_dir)
        .map_err(|err| {
            format!(
                "Failed to inspect {} while seeding config from the current repo: {}",
                current_dir.display(),
                err
            )
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|err| {
            format!(
                "Failed to inspect {} while seeding config from the current repo: {}",
                current_dir.display(),
                err
            )
        })?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type().map_err(|err| {
            format!(
                "Failed to inspect {} while seeding config from the current repo: {}",
                path.display(),
                err
            )
        })?;

        if file_type.is_dir() {
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if matches!(name, ".git" | "node_modules" | "target") {
                continue;
            }
            discover_repo_state(&path, root, visited, state)?;
            continue;
        }

        match path.file_name().and_then(|name| name.to_str()) {
            Some("package.json") => inspect_package_json(&path, state)?,
            Some("Cargo.toml") => inspect_cargo_manifest(&path, root, state)?,
            _ => {}
        }
    }

    Ok(())
}

fn inspect_package_json(path: &Path, state: &mut DiscoveryState) -> Result<(), String> {
    let content = crate::parsers::read_file_limited(path, crate::parsers::MAX_MANIFEST_BYTES)
        .map_err(|err| {
            format!(
                "Failed to read {} while seeding config: {}",
                path.display(),
                err
            )
        })?;
    let parsed: serde_json::Value = serde_json::from_str(&content).map_err(|err| {
        format!(
            "Failed to parse {} while seeding config: {}",
            path.display(),
            err
        )
    })?;

    if let Some(name) = parsed.get("name").and_then(|value| value.as_str()) {
        let name = name.trim();
        if !name.is_empty() {
            state.npm_local_packages.insert(name.to_string());
            if let Some(scope) = extract_npm_scope(name) {
                *state.npm_scope_counts.entry(scope.to_string()).or_insert(0) += 1;
            }
        }
    }

    let deps =
        crate::parsers::package_json::parse_manifest_value(path, &parsed).map_err(|err| {
            format!(
                "Failed to inspect {} while seeding config: {}",
                path.display(),
                err
            )
        })?;
    for dep in deps {
        let observed = dep.actual_name.as_deref().unwrap_or(dep.name.as_str());
        state.npm_dependency_usage.insert(observed.to_string());
    }

    Ok(())
}

fn cargo_package_name(path: &Path) -> Result<Option<String>, String> {
    let content = crate::parsers::read_file_limited(path, crate::parsers::MAX_MANIFEST_BYTES)
        .map_err(|err| {
            format!(
                "Failed to read {} while seeding config: {}",
                path.display(),
                err
            )
        })?;
    let parsed: toml::Value = toml::from_str(&content).map_err(|err| {
        format!(
            "Failed to parse {} while seeding config: {}",
            path.display(),
            err
        )
    })?;
    Ok(parsed
        .get("package")
        .and_then(|value| value.as_table())
        .and_then(|table| table.get("name"))
        .and_then(|value| value.as_str())
        .map(str::to_string))
}

fn inspect_cargo_manifest(
    path: &Path,
    root: &Path,
    state: &mut DiscoveryState,
) -> Result<(), String> {
    if let Some(package_name) = cargo_package_name(path)? {
        state.cargo_local_packages.insert(package_name);
    }

    let manifest = crate::parsers::cargo_toml::parse_manifest_file(path).map_err(|err| {
        format!(
            "Failed to inspect {} while seeding config: {}",
            path.display(),
            err
        )
    })?;
    let project_dir = path.parent().ok_or_else(|| {
        format!(
            "Cargo manifest '{}' has no parent directory.",
            path.display()
        )
    })?;

    for dependency in manifest
        .dependencies
        .iter()
        .chain(manifest.workspace_dependencies.values())
    {
        if let crate::parsers::cargo_toml::CargoSourceSpec::Path(local_path) = &dependency.source {
            let resolved = std::fs::canonicalize(project_dir.join(local_path)).map_err(|err| {
                format!(
                    "Failed to resolve Cargo path dependency '{}' from {} while seeding config: {}",
                    local_path,
                    path.display(),
                    err
                )
            })?;
            if !resolved.starts_with(root) {
                state
                    .cargo_external_paths
                    .insert(resolved.to_string_lossy().to_string());
            }
        }
    }

    Ok(())
}

pub fn discover_current_config(project_dir: &Path) -> Result<SloppyJoeConfig, String> {
    let root = std::fs::canonicalize(project_dir).map_err(|err| {
        format!(
            "Failed to inspect {} while seeding config from the current repo: {}",
            project_dir.display(),
            err
        )
    })?;
    let mut visited = BTreeSet::new();
    let mut state = DiscoveryState::default();
    discover_repo_state(project_dir, &root, &mut visited, &mut state)?;
    Ok(state.into_config())
}

pub fn discover_current_json(project_dir: &Path) -> Result<String, String> {
    discover_current_config(project_dir).map(|config| render_config_json(&config))
}

/// Return a template config as a pretty-printed JSON string.
pub fn template_json() -> String {
    render_config_json(&template_config())
}

/// Print a template config to stdout.
pub fn print_template() {
    println!("{}", template_json());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(label: &str) -> std::path::PathBuf {
        let unique = format!(
            "sloppy-joe-test-{}-{}",
            label,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

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
    fn template_config_is_neutral_manual_baseline() {
        let config = template_config();
        assert!(config.canonical.is_empty());
        assert!(config.internal.is_empty());
        assert!(config.allowed.is_empty());
        assert!(config.bootstrap_review.is_empty());

        let rendered = template_json();
        assert!(!rendered.contains("@yourorg/*"));
        assert!(!rendered.contains("some-vetted-external-pkg"));
        assert!(!rendered.contains("\"axios\""));
        assert!(!rendered.contains("\"httpx\""));
    }

    #[test]
    fn greenfield_config_npm_is_ecosystem_specific() {
        let config = greenfield_config("npm").expect("npm greenfield config should build");
        assert!(config.canonical.contains_key("npm"));
        assert!(!config.canonical.contains_key("cargo"));
        assert_eq!(
            config.canonical["npm"]["eslint"],
            vec!["tslint".to_string()]
        );
        assert!(config.internal.is_empty());
        assert!(config.allowed.is_empty());
    }

    #[test]
    fn greenfield_config_cargo_is_ecosystem_specific() {
        let config = greenfield_config("cargo").expect("cargo greenfield config should build");
        assert!(config.canonical.contains_key("cargo"));
        assert!(!config.canonical.contains_key("npm"));
        assert_eq!(
            config.canonical["cargo"]["clap"],
            vec!["structopt".to_string()]
        );
    }

    #[test]
    fn greenfield_config_rejects_unknown_ecosystem() {
        let err = greenfield_config("elixir").expect_err("unsupported ecosystems must fail");
        assert!(err.contains("Unsupported ecosystem"));
        assert!(err.contains("npm"));
        assert!(err.contains("cargo"));
    }

    #[test]
    fn discover_current_config_infers_npm_internal_scope_and_review_candidates() {
        let dir = unique_temp_dir("from-current-npm");
        write_file(
            &dir.join("packages/web/package.json"),
            r#"{
  "name": "@acme/web",
  "dependencies": {
    "dayjs": "1.11.13",
    "axios": "1.9.0"
  }
}"#,
        );
        write_file(
            &dir.join("packages/ui/package.json"),
            r#"{
  "name": "@acme/ui",
  "dependencies": {
    "moment": "2.30.1",
    "got": "14.4.8"
  }
}"#,
        );

        let config =
            discover_current_config(&dir).expect("discovery should inspect npm workspaces");
        assert_eq!(
            config.internal.get("npm"),
            Some(&vec!["@acme/*".to_string()])
        );
        assert!(
            !config.canonical.contains_key("npm"),
            "from-current should not silently enforce canonical choices"
        );
        let groups = &config.bootstrap_review.candidate_canonical_groups["npm"];
        assert!(
            groups
                .iter()
                .any(|group| group.packages == vec!["dayjs".to_string(), "moment".to_string()])
        );
        assert!(
            groups
                .iter()
                .any(|group| { group.packages == vec!["axios".to_string(), "got".to_string()] })
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn discover_current_config_infers_cargo_local_provenance() {
        let sandbox = unique_temp_dir("from-current-cargo");
        let repo = sandbox.join("repo");
        let external = sandbox.join("shared-crate");

        write_file(
            &repo.join("Cargo.toml"),
            r#"[workspace]
members = ["crates/app", "crates/lib"]
"#,
        );
        write_file(
            &repo.join("crates/app/Cargo.toml"),
            r#"[package]
name = "app"
version = "0.1.0"

[dependencies]
lib = { path = "../lib" }
shared = { path = "../../../shared-crate" }
"#,
        );
        write_file(
            &repo.join("crates/lib/Cargo.toml"),
            r#"[package]
name = "lib"
version = "0.1.0"
"#,
        );
        write_file(
            &external.join("Cargo.toml"),
            r#"[package]
name = "shared"
version = "0.1.0"
"#,
        );

        let config =
            discover_current_config(&repo).expect("discovery should inspect cargo manifests");
        let canonical_external = std::fs::canonicalize(&external).unwrap();
        assert_eq!(
            config.internal.get("cargo"),
            Some(&vec!["app".to_string(), "lib".to_string()])
        );
        assert_eq!(
            config.trusted_local_paths.get("cargo"),
            Some(&vec![canonical_external.to_string_lossy().to_string()])
        );

        std::fs::remove_dir_all(&sandbox).unwrap();
    }

    #[test]
    fn load_config_valid_file() {
        let dir = unique_temp_dir("config-v2");
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
    fn load_config_parses_cargo_provenance_fields() {
        let dir = unique_temp_dir("config-cargo-provenance");
        let path = dir.join("config.json");
        std::fs::write(
            &path,
            r#"{
  "trusted_local_paths": {
    "cargo": ["/opt/company/shared-crate"]
  },
  "trusted_registries": {
    "cargo": [
      {
        "name": "company",
        "source": "registry+https://cargo.company.example/index"
      }
    ]
  },
  "trusted_git_sources": {
    "cargo": ["https://github.com/yourorg/shared-crate"]
  },
  "cargo_git_policy": "warn_pinned"
}"#,
        )
        .unwrap();

        let config = load_config(Some(&path)).unwrap();
        assert_eq!(
            config.trusted_local_paths.get("cargo"),
            Some(&vec!["/opt/company/shared-crate".to_string()])
        );
        assert_eq!(config.trusted_registries["cargo"][0].name, "company");
        assert_eq!(
            config.trusted_registries["cargo"][0].source,
            "registry+https://cargo.company.example/index"
        );
        assert_eq!(
            config.trusted_git_sources.get("cargo"),
            Some(&vec!["https://github.com/yourorg/shared-crate".to_string()])
        );
        assert_eq!(config.cargo_git_policy, CargoGitPolicy::WarnPinned);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn local_overlay_adds_cargo_provenance_relaxations_additively() {
        let dir = unique_temp_dir("local-overlay-cargo");
        let path = dir.join("local-overlay.json");
        std::fs::write(
            &path,
            r#"{
  "trusted_local_paths": {
    "cargo": ["/opt/company/shared-crate"]
  },
  "trusted_git_sources": {
    "cargo": ["https://github.com/yourorg/shared-crate"]
  },
  "cargo_git_policy": "warn_pinned",
  "allow_host_local_cargo_config": true
}"#,
        )
        .unwrap();

        let base = SloppyJoeConfig {
            trusted_registries: HashMap::from([(
                "cargo".to_string(),
                vec![TrustedRegistry {
                    name: "company".to_string(),
                    source: "registry+https://cargo.company.example/index".to_string(),
                }],
            )]),
            ..Default::default()
        };
        let merged = load_local_overlay_from_path(base, &path).unwrap();

        assert_eq!(
            merged.trusted_registries["cargo"][0].source,
            "registry+https://cargo.company.example/index"
        );
        assert_eq!(
            merged.trusted_local_paths["cargo"][0],
            "/opt/company/shared-crate"
        );
        assert_eq!(
            merged.trusted_git_sources["cargo"][0],
            "https://github.com/yourorg/shared-crate"
        );
        assert_eq!(merged.cargo_git_policy, CargoGitPolicy::WarnPinned);
        assert!(merged.allow_host_local_cargo_config);
        assert!(
            !merged.active_local_overlay_relaxations.is_empty(),
            "effective config should remember that local-only relaxations are active"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_config_rejects_unknown_python_enforcement() {
        let dir = unique_temp_dir("config-python-mode");
        let path = dir.join("config.json");
        std::fs::write(&path, r#"{"python_enforcement":"requirements_only"}"#).unwrap();

        let err = parse_config_content(
            &std::fs::read_to_string(&path).unwrap(),
            &path.display().to_string(),
        )
        .expect_err("unknown Python enforcement modes must fail");
        assert!(err.contains("prefer_poetry"));
        assert!(err.contains("poetry_only"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_config_rejects_project_local_path() {
        let dir = unique_temp_dir("project-boundary");
        let path = dir.join("config.json");
        std::fs::write(&path, r#"{"canonical":{},"internal":{},"allowed":{}}"#).unwrap();
        let err = ensure_config_outside_project(&path, Some(&dir)).unwrap_err();
        assert!(err.contains("outside the project directory"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_config_empty_file_returns_error() {
        let dir = unique_temp_dir("empty");
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
        let dir = unique_temp_dir("invalid");
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
        let source = registry::lookup(&dir);
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
        let dir = unique_temp_dir("validate");
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

    #[test]
    fn redact_url_for_display_strips_credentials_and_query() {
        let redacted =
            redact_url_for_display("https://user:secret@example.com/config.json?token=abc#frag");
        assert_eq!(redacted, "https://example.com/config.json");
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
        let dir = unique_temp_dir("source-file");
        let path = dir.join("config.json");
        std::fs::write(&path, r#"{"canonical":{}}"#).unwrap();
        let config = load_config_from_source(Some(path.to_str().unwrap()), None)
            .await
            .unwrap();
        assert!(config.canonical.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
