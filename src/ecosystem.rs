use std::fmt;
use std::str::FromStr;

use serde::Serialize;

/// Type-safe ecosystem identifier. Replaces stringly-typed `&str` ecosystem
/// dispatch throughout the codebase. All ecosystem-specific behavior is
/// centralized here as methods on the enum.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum Ecosystem {
    Npm,
    PyPI,
    Cargo,
    Go,
    Ruby,
    Php,
    Jvm,
    Dotnet,
}

impl Ecosystem {
    /// The canonical lowercase string for this ecosystem.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::PyPI => "pypi",
            Self::Cargo => "cargo",
            Self::Go => "go",
            Self::Ruby => "ruby",
            Self::Php => "php",
            Self::Jvm => "jvm",
            Self::Dotnet => "dotnet",
        }
    }

    /// Whether package names in this ecosystem can contain `/`.
    /// npm: @scope/pkg, go: github.com/org/repo, php: vendor/pkg, jvm: group:artifact (uses `:` not `/` but group can have dots)
    pub fn allows_slashes(&self) -> bool {
        matches!(self, Self::Npm | Self::Go | Self::Php | Self::Jvm)
    }

    /// Whether the registry treats package names case-insensitively.
    pub fn is_case_insensitive(&self) -> bool {
        matches!(self, Self::Npm | Self::PyPI | Self::Cargo | Self::Dotnet | Self::Php)
    }

    /// Max concurrent registry queries for similarity checks.
    pub fn similarity_concurrency(&self) -> usize {
        match self {
            Self::Cargo => 2,
            Self::Go => 5,
            _ => 20,
        }
    }

    /// The OSV database ecosystem name.
    pub fn osv_name(&self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::PyPI => "PyPI",
            Self::Cargo => "crates.io",
            Self::Go => "Go",
            Self::Ruby => "RubyGems",
            Self::Jvm => "Maven",
            Self::Dotnet => "NuGet",
            Self::Php => "Packagist",
        }
    }

    /// Whether this ecosystem's registry supports metadata lookups
    /// (version history, download counts, install scripts, publisher info).
    pub fn supports_metadata(&self) -> bool {
        matches!(self, Self::Npm | Self::PyPI | Self::Cargo | Self::Ruby | Self::Jvm)
    }

    /// User-facing registry URL for a package in this ecosystem.
    pub fn registry_url_for(&self, name: &str) -> String {
        match self {
            Self::Npm => format!("https://www.npmjs.com/package/{}", name),
            Self::PyPI => format!("https://pypi.org/project/{}/", name),
            Self::Cargo => format!("https://crates.io/crates/{}", name),
            Self::Go => format!("https://pkg.go.dev/{}", name),
            Self::Ruby => format!("https://rubygems.org/gems/{}", name),
            Self::Php => format!("https://packagist.org/packages/{}", name),
            Self::Jvm => {
                let parts: Vec<&str> = name.splitn(2, ':').collect();
                if parts.len() == 2 {
                    format!("https://search.maven.org/artifact/{}/{}", parts[0], parts[1])
                } else {
                    format!("https://search.maven.org/search?q={}", name)
                }
            }
            Self::Dotnet => format!("https://www.nuget.org/packages/{}", name),
        }
    }
    /// Error rate threshold for fail-closed behavior.
    /// Go proxy is slower/flakier, so it gets a more lenient threshold.
    pub fn error_rate_threshold(&self) -> f64 {
        match self {
            Self::Go => 0.25,     // Go proxy is flaky — 25% threshold
            Self::Jvm => 0.20,    // Maven Solr can be slow — 20% threshold
            _ => 0.10,            // Default: 10%
        }
    }

    /// Hard error count limit for fail-closed behavior.
    pub fn error_hard_limit(&self) -> usize {
        match self {
            Self::Go => 10,       // Go proxy is flaky — higher limit
            _ => 5,               // Default: 5 errors
        }
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Ecosystem {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "npm" => Ok(Self::Npm),
            "pypi" => Ok(Self::PyPI),
            "cargo" => Ok(Self::Cargo),
            "go" => Ok(Self::Go),
            "ruby" => Ok(Self::Ruby),
            "php" => Ok(Self::Php),
            "jvm" => Ok(Self::Jvm),
            "dotnet" => Ok(Self::Dotnet),
            other => anyhow::bail!("unknown ecosystem: {}", other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_round_trips_through_from_str() {
        let ecosystems = [
            Ecosystem::Npm,
            Ecosystem::PyPI,
            Ecosystem::Cargo,
            Ecosystem::Go,
            Ecosystem::Ruby,
            Ecosystem::Php,
            Ecosystem::Jvm,
            Ecosystem::Dotnet,
        ];
        for eco in ecosystems {
            let s = eco.as_str();
            let parsed: Ecosystem = s.parse().unwrap();
            assert_eq!(parsed, eco, "round-trip failed for {}", s);
        }
    }

    #[test]
    fn from_str_case_insensitive() {
        assert_eq!("NPM".parse::<Ecosystem>().unwrap(), Ecosystem::Npm);
        assert_eq!("PyPI".parse::<Ecosystem>().unwrap(), Ecosystem::PyPI);
        assert_eq!("CARGO".parse::<Ecosystem>().unwrap(), Ecosystem::Cargo);
    }

    #[test]
    fn from_str_rejects_unknown() {
        assert!("unknown".parse::<Ecosystem>().is_err());
        assert!("".parse::<Ecosystem>().is_err());
    }

    #[test]
    fn display_matches_as_str() {
        for eco in [Ecosystem::Npm, Ecosystem::PyPI, Ecosystem::Cargo, Ecosystem::Go,
                     Ecosystem::Ruby, Ecosystem::Php, Ecosystem::Jvm, Ecosystem::Dotnet] {
            assert_eq!(format!("{}", eco), eco.as_str());
        }
    }

    #[test]
    fn allows_slashes_correct() {
        assert!(Ecosystem::Npm.allows_slashes());   // @scope/pkg
        assert!(Ecosystem::Go.allows_slashes());    // github.com/org/repo
        assert!(Ecosystem::Php.allows_slashes());   // vendor/package
        assert!(Ecosystem::Jvm.allows_slashes());   // group has dots, artifact uses :
        assert!(!Ecosystem::PyPI.allows_slashes());
        assert!(!Ecosystem::Cargo.allows_slashes());
        assert!(!Ecosystem::Ruby.allows_slashes());
        assert!(!Ecosystem::Dotnet.allows_slashes());
    }

    #[test]
    fn similarity_concurrency_values() {
        assert_eq!(Ecosystem::Cargo.similarity_concurrency(), 2);
        assert_eq!(Ecosystem::Go.similarity_concurrency(), 5);
        assert_eq!(Ecosystem::Npm.similarity_concurrency(), 20);
    }

    #[test]
    fn supports_metadata_correct() {
        assert!(Ecosystem::Npm.supports_metadata());
        assert!(Ecosystem::PyPI.supports_metadata());
        assert!(Ecosystem::Cargo.supports_metadata());
        assert!(Ecosystem::Ruby.supports_metadata());
        assert!(Ecosystem::Jvm.supports_metadata());
        assert!(!Ecosystem::Go.supports_metadata());
        assert!(!Ecosystem::Php.supports_metadata());
        assert!(!Ecosystem::Dotnet.supports_metadata());
    }

    #[test]
    fn registry_url_for_all_ecosystems() {
        assert!(Ecosystem::Npm.registry_url_for("react").contains("npmjs.com"));
        assert!(Ecosystem::PyPI.registry_url_for("flask").contains("pypi.org"));
        assert!(Ecosystem::Cargo.registry_url_for("serde").contains("crates.io"));
        assert!(Ecosystem::Go.registry_url_for("github.com/gin-gonic/gin").contains("pkg.go.dev"));
        assert!(Ecosystem::Ruby.registry_url_for("rails").contains("rubygems.org"));
        assert!(Ecosystem::Php.registry_url_for("laravel/framework").contains("packagist.org"));
        assert!(Ecosystem::Jvm.registry_url_for("com.google.guava:guava").contains("maven.org"));
        assert!(Ecosystem::Dotnet.registry_url_for("Newtonsoft.Json").contains("nuget.org"));
    }

    #[test]
    fn go_has_higher_error_thresholds() {
        assert!(Ecosystem::Go.error_rate_threshold() > Ecosystem::Npm.error_rate_threshold());
        assert!(Ecosystem::Go.error_hard_limit() > Ecosystem::Npm.error_hard_limit());
    }

    #[test]
    fn error_thresholds_are_reasonable() {
        for eco in [
            Ecosystem::Npm, Ecosystem::PyPI, Ecosystem::Cargo,
            Ecosystem::Go, Ecosystem::Ruby, Ecosystem::Php,
            Ecosystem::Jvm, Ecosystem::Dotnet,
        ] {
            assert!(eco.error_rate_threshold() > 0.0 && eco.error_rate_threshold() <= 0.5,
                "Error rate threshold for {} should be between 0 and 50%", eco);
            assert!(eco.error_hard_limit() >= 3 && eco.error_hard_limit() <= 20,
                "Error hard limit for {} should be between 3 and 20", eco);
        }
    }
}
