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
pub trait Registry: Send + Sync {
    /// Check if a package exists on this registry.
    async fn exists(&self, package_name: &str) -> Result<bool>;

    /// Fetch metadata for a package. Returns None if not supported or not found.
    /// If `version` is provided, look up that specific version's publish date.
    async fn metadata(&self, package_name: &str, version: Option<&str>) -> Result<Option<PackageMetadata>> {
        let _ = package_name;
        let _ = version;
        Ok(None)
    }

    /// The ecosystem name (e.g. "npm", "pypi", "cargo").
    fn ecosystem(&self) -> &str;
}

pub fn registry_for(ecosystem: &str) -> Box<dyn Registry> {
    match ecosystem {
        "npm" => Box::new(npm::NpmRegistry::new()),
        "pypi" => Box::new(pypi::PypiRegistry::new()),
        "cargo" => Box::new(crates_io::CratesIoRegistry::new()),
        "go" => Box::new(go::GoRegistry::new()),
        "ruby" => Box::new(rubygems::RubyGemsRegistry::new()),
        "php" => Box::new(packagist::PackagistRegistry::new()),
        "jvm" => Box::new(maven::MavenRegistry::new()),
        "dotnet" => Box::new(nuget::NugetRegistry::new()),
        _ => Box::new(npm::NpmRegistry::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_for_all_ecosystems() {
        assert_eq!(registry_for("npm").ecosystem(), "npm");
        assert_eq!(registry_for("pypi").ecosystem(), "pypi");
        assert_eq!(registry_for("cargo").ecosystem(), "cargo");
        assert_eq!(registry_for("go").ecosystem(), "go");
        assert_eq!(registry_for("ruby").ecosystem(), "ruby");
        assert_eq!(registry_for("php").ecosystem(), "php");
        assert_eq!(registry_for("jvm").ecosystem(), "jvm");
        assert_eq!(registry_for("dotnet").ecosystem(), "dotnet");
    }

    #[test]
    fn registry_for_unknown_defaults_to_npm() {
        assert_eq!(registry_for("unknown").ecosystem(), "npm");
    }
}
