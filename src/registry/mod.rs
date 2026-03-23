pub mod crates_io;
pub mod go;
pub mod maven;
pub mod npm;
pub mod nuget;
pub mod packagist;
pub mod pypi;
pub mod rubygems;

use anyhow::Result;
use async_trait::async_trait;
use serde::Serialize;
use std::time::Duration;

/// Metadata about a package from its registry.
#[derive(Debug, Clone, Serialize)]
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
        if !matches!(eco, "npm" | "go" | "php" | "jvm") && package_name.contains('/') {
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

pub fn registry_for(ecosystem: &str) -> Result<Box<dyn Registry>> {
    registry_for_with_client(ecosystem, http_client())
}

pub fn registry_for_with_client(
    ecosystem: &str,
    client: reqwest::Client,
) -> Result<Box<dyn Registry>> {
    match ecosystem {
        "npm" => Ok(Box::new(npm::NpmRegistry::with_client(client))),
        "pypi" => Ok(Box::new(pypi::PypiRegistry::with_client(client))),
        "cargo" => Ok(Box::new(crates_io::CratesIoRegistry::with_client(client))),
        "go" => Ok(Box::new(go::GoRegistry::with_client(client))),
        "ruby" => Ok(Box::new(rubygems::RubyGemsRegistry::with_client(client))),
        "php" => Ok(Box::new(packagist::PackagistRegistry::with_client(client))),
        "jvm" => Ok(Box::new(maven::MavenRegistry::with_client(client))),
        "dotnet" => Ok(Box::new(nuget::NugetRegistry::with_client(client))),
        other => anyhow::bail!("unsupported ecosystem: {}", other),
    }
}

/// Validate that a package name is safe to use in registry URLs.
/// Rejects path traversal, null bytes, control characters, percent-encoding, and newlines.
pub fn validate_package_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if name.contains("..") {
        return false;
    }
    for ch in name.chars() {
        if ch == '\0' || ch == '%' || ch == '\n' || ch == '\r' {
            return false;
        }
        if ch.is_control() {
            return false;
        }
    }
    true
}

/// Per-registry concurrency limits for similarity queries.
pub fn similarity_concurrency(ecosystem: &str) -> usize {
    match ecosystem {
        "cargo" => 2,
        "go" => 5,
        _ => 20,
    }
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
        assert_eq!(registry_for("npm").unwrap().ecosystem(), "npm");
        assert_eq!(registry_for("pypi").unwrap().ecosystem(), "pypi");
        assert_eq!(registry_for("cargo").unwrap().ecosystem(), "cargo");
        assert_eq!(registry_for("go").unwrap().ecosystem(), "go");
        assert_eq!(registry_for("ruby").unwrap().ecosystem(), "ruby");
        assert_eq!(registry_for("php").unwrap().ecosystem(), "php");
        assert_eq!(registry_for("jvm").unwrap().ecosystem(), "jvm");
        assert_eq!(registry_for("dotnet").unwrap().ecosystem(), "dotnet");
    }

    #[test]
    fn registry_for_unknown_returns_error() {
        assert!(registry_for("unknown").is_err());
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
        let registry = registry_for("npm").unwrap();
        assert!(registry.validate_name("react").is_ok());
        assert!(registry.validate_name("../etc/passwd").is_err());
        assert!(registry.validate_name("foo\0bar").is_err());
        assert!(registry.validate_name("foo%2fbar").is_err());
    }
}
