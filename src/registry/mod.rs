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

#[async_trait]
pub trait Registry: Send + Sync {
    /// Check if a package exists on this registry.
    /// Returns Ok(true) if it exists, Ok(false) if it doesn't.
    async fn exists(&self, package_name: &str) -> Result<bool>;

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
