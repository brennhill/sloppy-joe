mod loading;
pub mod registry;
mod validate;

pub(crate) use loading::redact_url_for_display;
#[cfg(test)]
use loading::*;
pub use loading::{
    load_config, load_config_from_source, load_config_with_project, resolve_config_source,
};

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
    /// Config keys the built-in allowlists do not list but the operator accepts, one exact key
    /// per entry. Each applied entry is reported as a warning. Read only from the out-of-repo
    /// config, never from the local overlay.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub config_key_allow: Vec<crate::config_surface::KeyAllow>,
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
            config_key_allow: Vec::new(),
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

#[cfg(test)]
#[path = "strict_parsing_tests.rs"]
mod strict_parsing_tests;

#[cfg(test)]
#[path = "tarball_limit_tests.rs"]
mod tarball_limit_tests;

#[cfg(test)]
mod tests;
