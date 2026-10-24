pub mod registry;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
///   "max_npm_tarball_verifications": 100,
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
///   "trusted_indexes": {
///     "pypi": ["https://download.pytorch.org/whl/cu124"]
///   },
///   "cargo_git_policy": "block",
///   "python_enforcement": "prefer_poetry"
/// }
/// ```
///
/// - `canonical`: keys are approved packages, values are rejected alternatives.
/// - `internal`: your org's packages. Keep OSV vulnerability checks; skip other package checks.
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
/// - `max_npm_tarball_verifications`: per-scan cap on npm tarball downloads
///   for verification (1..=1000, default 100). Selected versions past the cap
///   block with `metadata/tarball-unverified`.
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
/// - `trusted_indexes`: exact allowlist of alternate Python package index URLs.
/// - `cargo_git_policy`: Cargo git dependency policy. `block` (default) or
///   `warn_pinned`.
/// - `python_enforcement`: controls how strictly sloppy-joe enforces trusted
///   Python manifest workflows. `prefer_poetry` (default) trusts Poetry when
///   present and warns on legacy manifests. `poetry_only` blocks non-Poetry
///   Python manifests.
/// - `poetry_lock_policy`: controls how missing Poetry trust proof is handled.
///   `warn_missing_proofs` (default) downgrades incomplete lock trust proofs to
///   warnings. `strict` fails closed when poetry.lock cannot prove freshness or
///   artifact identity strongly enough.
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
pub enum PoetryLockPolicy {
    WarnMissingProofs,
    Strict,
}

fn default_poetry_lock_policy() -> PoetryLockPolicy {
    PoetryLockPolicy::WarnMissingProofs
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
#[serde(deny_unknown_fields)]
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

pub(crate) fn normalized_default_pypi_index() -> &'static str {
    "https://pypi.org/simple/"
}

pub(crate) fn normalize_python_index_url(url: &str) -> String {
    let trimmed = url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    if let Some((scheme, rest)) = trimmed.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        let (authority, suffix) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, ""),
        };
        return format!("{scheme}://{}{}/", authority.to_ascii_lowercase(), suffix);
    }
    format!("{trimmed}/")
}

pub(crate) fn python_index_url_has_supported_scheme(url: &str) -> bool {
    let trimmed = url.trim();
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("https://") || lower.starts_with("http://")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

pub use crate::report::MetadataException;

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
#[serde(deny_unknown_fields)]
pub struct CanonicalGroupSuggestion {
    pub packages: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapReview {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub suggested_internal: HashMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub suggested_trusted_local_paths: HashMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub candidate_canonical_groups: HashMap<String, Vec<CanonicalGroupSuggestion>>,
}

impl BootstrapReview {
    pub(crate) fn is_empty(&self) -> bool {
        self.suggested_internal.is_empty()
            && self.suggested_trusted_local_paths.is_empty()
            && self.candidate_canonical_groups.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SloppyJoeConfig {
    /// Directory names excluded from recursive project discovery.
    #[serde(default = "default_ignore_dirs")]
    pub ignore_dirs: Vec<String>,
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
    /// Per-scan cap on npm tarball downloads for verification (cache hits do
    /// not count). Selected versions past the cap block.
    #[serde(default = "default_max_npm_tarball_verifications")]
    pub max_npm_tarball_verifications: usize,
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
    #[serde(default)]
    pub trusted_indexes: HashMap<String, Vec<String>>,
    #[serde(default = "default_cargo_git_policy")]
    pub cargo_git_policy: CargoGitPolicy,
    #[serde(default = "default_python_enforcement")]
    pub python_enforcement: PythonEnforcement,
    #[serde(default = "default_poetry_lock_policy")]
    pub poetry_lock_policy: PoetryLockPolicy,
    #[serde(default, skip_serializing_if = "BootstrapReview::is_empty")]
    pub bootstrap_review: BootstrapReview,
    #[serde(skip)]
    pub allow_host_local_cargo_config: bool,
    #[serde(skip)]
    pub active_local_overlay_relaxations: Vec<String>,
}

fn default_ignore_dirs() -> Vec<String> {
    vec![".planning".to_string()]
}

fn default_min_version_age_hours() -> u64 {
    72
}

/// Bounds for `max_npm_tarball_verifications`.
pub const MAX_NPM_TARBALL_VERIFICATIONS_RANGE: std::ops::RangeInclusive<usize> = 1..=1000;

/// Default cap on npm tarballs downloaded for verification in one scan.
pub(crate) const DEFAULT_MAX_TARBALL_FETCHES: usize = 100;

/// Name of the trusted-registry rule that lists approved Gradle plugin repositories.
pub(crate) const TRUSTED_PLUGIN_REPOSITORY_NAME: &str = "gradle-plugins";

/// Base URL of the Gradle Plugin Portal's Maven repository.
pub(crate) const GRADLE_PLUGIN_PORTAL_URL: &str = "https://plugins.gradle.org/m2/";
/// Base URL of Maven Central's Maven repository.
pub(crate) const MAVEN_CENTRAL_URL: &str = "https://repo1.maven.org/maven2/";

/// A repository Gradle consults for plugin marker artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginRepository {
    GradlePluginPortal,
    MavenCentral,
    /// A repository-controlled URL (`maven { url ... }`).
    Custom(String),
}

fn default_max_npm_tarball_verifications() -> usize {
    DEFAULT_MAX_TARBALL_FETCHES
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
            ignore_dirs: default_ignore_dirs(),
            canonical: HashMap::new(),
            internal: HashMap::new(),
            allowed: HashMap::new(),
            similarity_exceptions: HashMap::new(),
            metadata_exceptions: HashMap::new(),
            min_version_age_hours: default_min_version_age_hours(),
            max_npm_tarball_verifications: default_max_npm_tarball_verifications(),
            allow_unresolved_versions: false,
            allow_legacy_npm_v1_lockfile: false,
            trusted_local_paths: HashMap::new(),
            trusted_registries: HashMap::new(),
            trusted_git_sources: HashMap::new(),
            trusted_indexes: HashMap::new(),
            cargo_git_policy: default_cargo_git_policy(),
            python_enforcement: default_python_enforcement(),
            poetry_lock_policy: default_poetry_lock_policy(),
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

    /// Check if a package is internal (OSV-only package checks).
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

    /// Whether out-of-repo config allowlists this exact npm `.npmrc` route
    /// (`default` or `@scope`) to point at `registry` (a normalized URL).
    pub(crate) fn is_trusted_npm_registry(&self, route: &str, registry: &str) -> bool {
        self.trusted_registries("npm").iter().any(|rule| {
            rule.name == route
                && crate::npm_config::normalize_registry_url(rule.source.trim()).as_deref()
                    == Some(registry)
        })
    }

    pub fn trusted_git_sources(&self, ecosystem: &str) -> &[String] {
        self.trusted_git_sources
            .get(ecosystem)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn trusted_indexes(&self, ecosystem: &str) -> &[String] {
        self.trusted_indexes
            .get(ecosystem)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn is_trusted_index(&self, ecosystem: &str, url: &str) -> bool {
        if ecosystem == "pypi" && normalize_python_index_url(url) == normalized_default_pypi_index()
        {
            return true;
        }
        let normalized = normalize_python_index_url(url);
        self.trusted_indexes(ecosystem)
            .iter()
            .any(|candidate| candidate == &normalized)
    }

    /// Validate config at load time. Returns a list of errors.
    pub fn validate(&self) -> Vec<String> {
        let valid_ecosystems = ["npm", "pypi", "cargo", "go", "ruby", "php", "jvm", "dotnet"];
        let mut errors = Vec::new();
        for name in &self.ignore_dirs {
            if name.trim().is_empty()
                || matches!(name.as_str(), "." | "..")
                || name.contains(['/', '\\', '*', '?', '[', ']'])
                || name.chars().any(char::is_control)
            {
                errors.push("ignore_dirs entries must be nonempty directory names, without paths or glob patterns".to_string());
            }
        }

        if !MAX_NPM_TARBALL_VERIFICATIONS_RANGE.contains(&self.max_npm_tarball_verifications) {
            errors.push(format!(
                "max_npm_tarball_verifications must be between {} and {} (got {})",
                MAX_NPM_TARBALL_VERIFICATIONS_RANGE.start(),
                MAX_NPM_TARBALL_VERIFICATIONS_RANGE.end(),
                self.max_npm_tarball_verifications
            ));
        }

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

        for eco in self.trusted_indexes.keys() {
            if eco != "pypi" {
                errors.push(format!(
                    "Unknown ecosystem '{}' in trusted_indexes section. Valid: pypi",
                    eco
                ));
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
                if rule.check != crate::names::METADATA_MAINTAINER_CHANGE {
                    errors.push(format!(
                        "Invalid metadata exception check '{}' in {}. Only '{}' is currently supported.",
                        rule.check,
                        eco,
                        crate::names::METADATA_MAINTAINER_CHANGE
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
                } else if eco == "npm"
                    && (!crate::npm_config::valid_route_name(&rule.name)
                        || crate::npm_config::normalize_registry_url(rule.source.trim()).is_none())
                {
                    errors.push(format!(
                        "Invalid trusted registry in npm: name must be \"{}\" or an @scope, and source must be a credential-free https:// registry URL",
                        crate::npm_config::DEFAULT_ROUTE
                    ));
                } else if eco == "jvm"
                    && (rule.name != TRUSTED_PLUGIN_REPOSITORY_NAME
                        || crate::npm_config::normalize_registry_url(rule.source.trim()).is_none())
                {
                    errors.push(format!(
                        "Invalid trusted registry in jvm: name must be \"{}\", and source must be a credential-free https:// repository URL",
                        TRUSTED_PLUGIN_REPOSITORY_NAME
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

        for (eco, indexes) in &self.trusted_indexes {
            for index in indexes {
                if index.trim().is_empty() {
                    errors.push(format!(
                        "Invalid trusted index in {}: index URL must be non-empty",
                        eco
                    ));
                } else if !python_index_url_has_supported_scheme(index) {
                    errors.push(format!(
                        "Invalid trusted index in {}: only http:// and https:// package index URLs are supported",
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

    config = maybe_apply_local_overlay(config, project_dir)?;
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
        if config_source_has_scheme(source, "http") {
            return Err(format!(
                "Config URL must use HTTPS.\n  URL: {}\n  Fix: Use an https:// URL or a local path outside the project directory.",
                redact_url_for_display(source)
            ));
        } else if config_source_has_scheme(source, "https") {
            fetch_config_from_url(source).await?
        } else {
            return load_config_with_project(Some(Path::new(source)), project_dir);
        }
    } else {
        SloppyJoeConfig::default()
    };

    config = maybe_apply_local_overlay(config, project_dir)?;
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

pub(crate) fn redact_url_for_display(url: &str) -> String {
    let Ok(mut parsed) = reqwest::Url::parse(url) else {
        return "<invalid URL redacted>".to_string();
    };
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

/// Walks any JSON value and rejects objects that repeat a key. serde_json
/// otherwise keeps the last value for map keys, silently dropping policy.
struct NoDuplicateKeys;

impl<'de> Deserialize<'de> for NoDuplicateKeys {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NoDuplicateKeysVisitor)
    }
}

struct NoDuplicateKeysVisitor;

impl<'de> serde::de::Visitor<'de> for NoDuplicateKeysVisitor {
    type Value = NoDuplicateKeys;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<NoDuplicateKeys>()?.is_some() {}
        Ok(NoDuplicateKeys)
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut seen = std::collections::HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!("duplicate key `{key}`")));
            }
            map.next_value::<NoDuplicateKeys>()?;
        }
        Ok(NoDuplicateKeys)
    }
}

fn reject_duplicate_keys(content: &str, label: &str, source: &str) -> Result<(), String> {
    match serde_json::from_str::<NoDuplicateKeys>(content) {
        // Syntax errors are reported by the typed parse with better hints.
        Err(e) if e.is_data() => Err(format!(
            "{label} has a duplicate key.\n  Source: {source}\n  Error: {e}\n  Fix: Remove the repeated key; only one value per key is allowed."
        )),
        _ => Ok(()),
    }
}

/// Parse config JSON content with actionable error messages.
fn parse_config_content(content: &str, source: &str) -> Result<SloppyJoeConfig, String> {
    if content.trim().is_empty() {
        return Err(format!(
            "Config is empty.\n  Source: {}\n  Fix: Use 'sloppy-joe init > /secure/location/sloppy-joe.json' to generate a template outside the repo.",
            source
        ));
    }

    reject_duplicate_keys(content, "Config", source)?;
    let mut config: SloppyJoeConfig = serde_json::from_str(content).map_err(|e| {
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

    for indexes in config.trusted_indexes.values_mut() {
        for index in indexes.iter_mut() {
            *index = normalize_python_index_url(index);
        }
    }

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

    reject_duplicate_keys(content, "Local overlay config", source)?;
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

fn config_source_has_scheme(source: &str, scheme: &str) -> bool {
    source
        .get(..scheme.len() + 3)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(&format!("{scheme}://")))
}

fn maybe_apply_local_overlay(
    config: SloppyJoeConfig,
    project_dir: Option<&Path>,
) -> Result<SloppyJoeConfig, String> {
    if running_in_ci() {
        return Ok(config);
    }

    let overlay_path = local_overlay_path()?;
    if !overlay_path.exists() {
        return Ok(config);
    }
    if let Some(dir) = project_dir
        && let Some(config_home) = overlay_path.parent()
    {
        registry::ensure_config_home_outside_project(dir, config_home)?;
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

    let project_dir = registry::find_git_root(project_dir)?
        .unwrap_or(std::fs::canonicalize(project_dir).map_err(|err| err.to_string())?);
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
#[cfg(test)]
#[path = "strict_parsing_tests.rs"]
mod strict_parsing_tests;

#[cfg(test)]
#[path = "tarball_limit_tests.rs"]
mod tarball_limit_tests;

#[cfg(test)]
mod tests;
