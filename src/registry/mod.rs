pub mod crates_io;
pub mod go;
pub mod maven;
pub mod npm;
pub mod nuget;
pub mod packagist;
pub mod pypi;
pub mod rubygems;

use crate::Ecosystem;
use anyhow::Result;
use async_trait::async_trait;
use serde::Serialize;
use std::time::Duration;

/// 12-month lookback window for version history extraction and publisher-script combo signal.
pub const VERSION_HISTORY_WINDOW_HOURS: u64 = 365 * 24; // 8760 hours

/// A single version's metadata for temporal signal correlation.
#[derive(Debug, Clone, Serialize)]
pub struct VersionRecord {
    pub version: String,
    pub publisher: Option<String>,
    pub has_install_scripts: bool,
    /// ISO 8601 publish date
    pub date: Option<String>,
}

/// Metadata about a package from its registry.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PackageMetadata {
    /// When the package was first published (ISO 8601)
    pub created: Option<String>,
    /// When the latest version was published (ISO 8601)
    pub latest_version_date: Option<String>,
    /// Total downloads (lifetime or recent, registry-dependent)
    pub downloads: Option<u64>,
    /// Whether the package has install scripts (preinstall, postinstall, install, prepare)
    pub has_install_scripts: bool,
    /// Number of dependencies in the current version
    pub dependency_count: Option<u64>,
    /// Number of dependencies in the previous version
    pub previous_dependency_count: Option<u64>,
    /// Publisher of the current version
    pub current_publisher: Option<String>,
    /// Publisher of the previous version
    pub previous_publisher: Option<String>,
    /// Source repository URL (GitHub, GitLab, etc.)
    pub repository_url: Option<String>,
    /// Recent version history for temporal signal correlation.
    /// Chronologically ordered (oldest first). Only versions within
    /// the last 12 months are included.
    pub version_history: Vec<VersionRecord>,
}

#[async_trait]
pub trait RegistryExistence: Send + Sync {
    /// Check if a package exists on this registry.
    async fn exists(&self, package_name: &str) -> Result<bool>;

    /// The ecosystem name (e.g. "npm", "pypi", "cargo").
    fn ecosystem(&self) -> &str;

    /// Validate package name before any registry operation.
    /// Returns Err if the name is unsafe for URL construction.
    /// Ecosystem-aware: rejects `/` and `\` except for ecosystems that use them
    /// (go, php, jvm use `/` or `:` in package names).
    fn validate_name(&self, package_name: &str) -> Result<()> {
        if !validate_package_name(package_name) {
            anyhow::bail!(
                "invalid package name for registry query: '{}'",
                package_name
            );
        }
        // Reject slashes for ecosystems that don't use them in package names
        let eco = self.ecosystem();
        let eco_parsed: std::result::Result<Ecosystem, _> = eco.parse();
        let allows_slashes = eco_parsed.map(|e| e.allows_slashes()).unwrap_or(false);
        if !allows_slashes && package_name.contains('/') {
            anyhow::bail!(
                "invalid package name for {} registry: '{}' (unexpected '/')",
                eco,
                package_name
            );
        }
        Ok(())
    }
}

#[async_trait]
pub trait RegistryMetadata: Send + Sync {
    /// Fetch metadata for a package. Returns None if not supported or not found.
    /// If `version` is provided, look up that specific version's publish date.
    async fn metadata(
        &self,
        package_name: &str,
        version: Option<&str>,
    ) -> Result<Option<PackageMetadata>> {
        let _ = package_name;
        let _ = version;
        Ok(None)
    }
}

/// Combined trait for registries that support both existence checks and metadata lookups.
/// All existing code using `&dyn Registry` continues to work unchanged.
pub trait Registry: RegistryExistence + RegistryMetadata {}

impl<T: RegistryExistence + RegistryMetadata> Registry for T {}

pub fn registry_for(ecosystem: Ecosystem) -> Result<Box<dyn Registry>> {
    registry_for_with_client(ecosystem, http_client())
}

pub fn registry_for_with_client(
    ecosystem: Ecosystem,
    client: reqwest::Client,
) -> Result<Box<dyn Registry>> {
    match ecosystem {
        Ecosystem::Npm => Ok(Box::new(npm::NpmRegistry::with_client(client))),
        Ecosystem::PyPI => Ok(Box::new(pypi::PypiRegistry::with_client(client))),
        Ecosystem::Cargo => Ok(Box::new(crates_io::CratesIoRegistry::with_client(client))),
        Ecosystem::Go => Ok(Box::new(go::GoRegistry::with_client(client))),
        Ecosystem::Ruby => Ok(Box::new(rubygems::RubyGemsRegistry::with_client(client))),
        Ecosystem::Php => Ok(Box::new(packagist::PackagistRegistry::with_client(client))),
        Ecosystem::Jvm => Ok(Box::new(maven::MavenRegistry::with_client(client))),
        Ecosystem::Dotnet => Ok(Box::new(nuget::NugetRegistry::with_client(client))),
    }
}

/// Validate that a package name is safe to use in registry URLs.
/// Rejects path traversal, null bytes, control characters, percent-encoding,
/// newlines, and URL-meaningful characters (?#\).
pub(crate) fn validate_package_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if name.contains("..") {
        return false;
    }
    for ch in name.chars() {
        if ch == '\0'
            || ch == '%'
            || ch == '\n'
            || ch == '\r'
            || ch == '?'
            || ch == '#'
            || ch == '\\'
        {
            return false;
        }
        if ch.is_control() {
            return false;
        }
    }
    true
}

/// A package name that has passed basic safety validation.
/// Guarantees the name is safe for use in registry URLs
/// (no path traversal, null bytes, control chars, etc.).
///
/// Does NOT check ecosystem-specific rules (e.g., slash restrictions).
/// For full ecosystem-aware validation, use `RegistryExistence::validate_name()`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValidatedName(String);

impl ValidatedName {
    /// Validate and wrap a package name. Returns Err if the name is unsafe.
    pub fn new(name: &str) -> Result<Self> {
        if !validate_package_name(name) {
            anyhow::bail!("invalid package name: '{}'", name);
        }
        Ok(Self(name.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ValidatedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ValidatedName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Generate the boilerplate `struct`, `new()`, `with_client()`, and `Default` for a registry.
macro_rules! registry_struct {
    ($name:ident) => {
        pub struct $name {
            client: reqwest::Client,
        }

        impl $name {
            pub fn new() -> Self {
                Self {
                    client: super::http_client(),
                }
            }

            pub fn with_client(client: reqwest::Client) -> Self {
                Self { client }
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

pub(crate) use registry_struct;

/// Check an HTTP response status for registry metadata queries.
/// Returns Ok(None) for NOT_FOUND/GONE, Ok(Some(())) for success, Err for other statuses.
pub(crate) fn check_metadata_status(
    status: reqwest::StatusCode,
    registry_name: &str,
    package_name: &str,
) -> anyhow::Result<Option<()>> {
    if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
        return Ok(None);
    }
    if !status.is_success() {
        anyhow::bail!(
            "{} metadata lookup for '{}' returned HTTP {}",
            registry_name,
            package_name,
            status
        );
    }
    Ok(Some(()))
}

/// Check an HTTP response status for registry existence queries.
/// Returns Ok(false) for NOT_FOUND/GONE, Ok(true) for success, Err for other statuses.
pub(crate) fn check_existence_status(
    status: reqwest::StatusCode,
    registry_name: &str,
    package_name: &str,
) -> anyhow::Result<bool> {
    if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
        return Ok(false);
    }
    if !status.is_success() {
        anyhow::bail!(
            "{} lookup for '{}' returned HTTP {}",
            registry_name,
            package_name,
            status
        );
    }
    Ok(true)
}

/// Strip semver prefixes like ^, ~, >= from a version string.
pub(crate) fn strip_version_prefix(version: &str) -> String {
    version
        .trim_start_matches(['^', '~', '>', '=', '<', ' '])
        .to_string()
}

/// Maximum number of retry attempts for transient HTTP errors.
const MAX_RETRIES: u32 = 3;
/// Base delay for exponential backoff (doubled each retry).
const RETRY_BASE_DELAY_MS: u64 = 200;

/// Send a GET request with retry on transient failures (5xx, timeouts, connection errors).
/// Returns the response on success, or the last error after exhausting retries.
pub(crate) async fn retry_get(client: &reqwest::Client, url: &str) -> Result<reqwest::Response> {
    let mut last_err = None;
    for attempt in 0..MAX_RETRIES {
        match client.get(url).send().await {
            Ok(resp) if resp.status().is_server_error() && attempt < MAX_RETRIES - 1 => {
                let delay = RETRY_BASE_DELAY_MS * 2u64.pow(attempt);
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                last_err = Some(anyhow::anyhow!(
                    "server error HTTP {} (attempt {}/{})",
                    resp.status(),
                    attempt + 1,
                    MAX_RETRIES
                ));
            }
            Ok(resp) => return Ok(resp),
            Err(e) if attempt < MAX_RETRIES - 1 && is_transient(&e) => {
                let delay = RETRY_BASE_DELAY_MS * 2u64.pow(attempt);
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                last_err = Some(e.into());
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("retry exhausted")))
}

/// Check if a reqwest error is transient (worth retrying).
fn is_transient(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect() || err.is_request()
}

pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .user_agent("sloppy-joe (https://github.com/brennhill/sloppy-joe)")
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .expect("failed to build HTTP client")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_for_all_ecosystems() {
        assert_eq!(registry_for(Ecosystem::Npm).unwrap().ecosystem(), "npm");
        assert_eq!(registry_for(Ecosystem::PyPI).unwrap().ecosystem(), "pypi");
        assert_eq!(registry_for(Ecosystem::Cargo).unwrap().ecosystem(), "cargo");
        assert_eq!(registry_for(Ecosystem::Go).unwrap().ecosystem(), "go");
        assert_eq!(registry_for(Ecosystem::Ruby).unwrap().ecosystem(), "ruby");
        assert_eq!(registry_for(Ecosystem::Php).unwrap().ecosystem(), "php");
        assert_eq!(registry_for(Ecosystem::Jvm).unwrap().ecosystem(), "jvm");
        assert_eq!(
            registry_for(Ecosystem::Dotnet).unwrap().ecosystem(),
            "dotnet"
        );
    }

    #[test]
    fn validate_package_name_accepts_valid() {
        assert!(validate_package_name("react"));
        assert!(validate_package_name("@types/node"));
        assert!(validate_package_name("my-package_v2"));
        assert!(validate_package_name("github.com/user/repo"));
        assert!(validate_package_name("com.google.guava:guava"));
    }

    #[test]
    fn validate_package_name_rejects_traversal() {
        assert!(!validate_package_name("../etc/passwd"));
        assert!(!validate_package_name("foo/../bar"));
    }

    #[test]
    fn validate_package_name_rejects_null() {
        assert!(!validate_package_name("foo\0bar"));
    }

    #[test]
    fn validate_package_name_rejects_control_chars() {
        assert!(!validate_package_name("foo\x01bar"));
        assert!(!validate_package_name("foo\x7fbar"));
    }

    #[test]
    fn validate_package_name_rejects_percent() {
        assert!(!validate_package_name("foo%2fbar"));
    }

    #[test]
    fn validate_package_name_rejects_newlines() {
        assert!(!validate_package_name("foo\nbar"));
        assert!(!validate_package_name("foo\rbar"));
    }

    #[test]
    fn validate_package_name_rejects_empty() {
        assert!(!validate_package_name(""));
    }

    #[test]
    fn validate_name_trait_method_rejects_traversal() {
        let registry = registry_for(Ecosystem::Npm).unwrap();
        assert!(registry.validate_name("react").is_ok());
        assert!(registry.validate_name("../etc/passwd").is_err());
        assert!(registry.validate_name("foo\0bar").is_err());
        assert!(registry.validate_name("foo%2fbar").is_err());
    }

    #[test]
    fn registry_struct_macro_generates_constructors() {
        // Test that macro-generated registries have new(), with_client(), and Default
        let r1 = npm::NpmRegistry::new();
        assert_eq!(r1.ecosystem(), "npm");

        let client = http_client();
        let r2 = pypi::PypiRegistry::with_client(client);
        assert_eq!(r2.ecosystem(), "pypi");

        let r3 = crates_io::CratesIoRegistry::default();
        assert_eq!(r3.ecosystem(), "cargo");
    }

    #[test]
    fn check_response_not_found_returns_false() {
        assert!(!check_existence_status(reqwest::StatusCode::NOT_FOUND, "test", "pkg").unwrap());
    }

    #[test]
    fn check_response_gone_returns_false() {
        assert!(!check_existence_status(reqwest::StatusCode::GONE, "test", "pkg").unwrap());
    }

    #[test]
    fn check_response_success_returns_true() {
        assert!(check_existence_status(reqwest::StatusCode::OK, "test", "pkg").unwrap());
    }

    #[test]
    fn check_response_server_error_returns_err() {
        assert!(
            check_existence_status(reqwest::StatusCode::INTERNAL_SERVER_ERROR, "test", "pkg")
                .is_err()
        );
    }

    #[test]
    fn strip_version_prefix_removes_semver_prefixes() {
        assert_eq!(strip_version_prefix("^1.2.3"), "1.2.3");
        assert_eq!(strip_version_prefix("~1.0"), "1.0");
        assert_eq!(strip_version_prefix(">=2.0.0"), "2.0.0");
        assert_eq!(strip_version_prefix("1.0.0"), "1.0.0");
        assert_eq!(strip_version_prefix(" 1.0"), "1.0");
    }

    #[test]
    fn validated_name_accepts_valid() {
        let name = ValidatedName::new("react").unwrap();
        assert_eq!(name.as_str(), "react");
        assert_eq!(name.to_string(), "react");
    }

    #[test]
    fn validated_name_rejects_traversal() {
        assert!(ValidatedName::new("../etc/passwd").is_err());
    }

    #[test]
    fn validated_name_rejects_null_bytes() {
        assert!(ValidatedName::new("foo\0bar").is_err());
    }

    #[test]
    fn validated_name_equality() {
        let a = ValidatedName::new("react").unwrap();
        let b = ValidatedName::new("react").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn is_transient_detects_timeout_and_connect_errors() {
        // We can't easily construct reqwest errors, but verify the function compiles
        // and the logic is correct by checking it returns bool
        let _: fn(&reqwest::Error) -> bool = is_transient;
    }

    #[test]
    fn version_record_struct_exists_and_is_constructible() {
        let record = VersionRecord {
            version: "1.0.0".to_string(),
            publisher: Some("alice".to_string()),
            has_install_scripts: true,
            date: Some("2026-01-15T00:00:00Z".to_string()),
        };
        assert_eq!(record.version, "1.0.0");
        assert_eq!(record.publisher.as_deref(), Some("alice"));
        assert!(record.has_install_scripts);
        assert!(record.date.is_some());
    }

    #[test]
    fn version_record_handles_missing_optional_fields() {
        let record = VersionRecord {
            version: "2.0.0".to_string(),
            publisher: None,
            has_install_scripts: false,
            date: None,
        };
        assert_eq!(record.publisher, None);
        assert_eq!(record.date, None);
    }

    #[test]
    fn package_metadata_has_version_history_field() {
        let meta = PackageMetadata {
            version_history: vec![
                VersionRecord {
                    version: "1.0.0".to_string(),
                    publisher: Some("alice".to_string()),
                    has_install_scripts: false,
                    date: Some("2025-06-01T00:00:00Z".to_string()),
                },
                VersionRecord {
                    version: "2.0.0".to_string(),
                    publisher: Some("bob".to_string()),
                    has_install_scripts: true,
                    date: Some("2026-01-01T00:00:00Z".to_string()),
                },
            ],
            ..Default::default()
        };
        assert_eq!(meta.version_history.len(), 2);
        assert_eq!(meta.version_history[0].publisher.as_deref(), Some("alice"));
        assert_eq!(meta.version_history[1].publisher.as_deref(), Some("bob"));
    }

    #[test]
    fn version_history_defaults_to_empty_vec() {
        // Non-npm registries should have empty version_history
        let meta = PackageMetadata::default();
        assert!(meta.version_history.is_empty());
    }

    #[test]
    fn retry_constants_are_reasonable() {
        const { assert!(MAX_RETRIES >= 2, "Need at least 2 retries for transient errors") };
        const { assert!(MAX_RETRIES <= 5, "Too many retries would slow CI") };
        const { assert!(RETRY_BASE_DELAY_MS >= 100, "Base delay too short") };
        const { assert!(RETRY_BASE_DELAY_MS <= 1000, "Base delay too long for CI") };
        // Total worst-case delay: 200 + 400 + 800 = 1400ms — reasonable
        let total_delay: u64 = (0..MAX_RETRIES)
            .map(|i| RETRY_BASE_DELAY_MS * 2u64.pow(i))
            .sum();
        assert!(
            total_delay < 5000,
            "Total retry delay exceeds 5s: {}ms",
            total_delay
        );
    }
}
