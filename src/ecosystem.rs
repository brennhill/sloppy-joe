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
        matches!(
            self,
            Self::Npm | Self::PyPI | Self::Cargo | Self::Dotnet | Self::Php
        )
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
        matches!(
            self,
            Self::Npm
                | Self::PyPI
                | Self::Cargo
                | Self::Ruby
                | Self::Jvm
                | Self::Go
                | Self::Dotnet
                | Self::Php
        )
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
                    format!(
                        "https://search.maven.org/artifact/{}/{}",
                        parts[0], parts[1]
                    )
                } else {
                    format!("https://search.maven.org/search?q={}", name)
                }
            }
            Self::Dotnet => format!("https://www.nuget.org/packages/{}", name),
        }
    }

    /// Whether the package name matches the expected shape for this ecosystem.
    pub fn has_valid_package_name_shape(&self, name: &str) -> bool {
        match self {
            Self::Npm => valid_npm_name(name),
            Self::PyPI => valid_simple_name(name),
            Self::Cargo => valid_simple_name(name),
            Self::Go => valid_go_name(name),
            Self::Ruby => valid_simple_name(name),
            Self::Php => valid_php_name(name),
            Self::Jvm => valid_jvm_name(name),
            Self::Dotnet => valid_simple_name(name),
        }
    }
}

fn valid_simple_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
}

fn valid_npm_name(name: &str) -> bool {
    let (scope, package) = if let Some(rest) = name.strip_prefix('@') {
        let (scope, package) = match rest.split_once('/') {
            Some(parts) => parts,
            None => return false,
        };
        if package.contains('/') {
            return false;
        }
        (Some(scope), package)
    } else {
        if name.contains('/') {
            return false;
        }
        (None, name)
    };

    let valid_segment = |segment: &str| {
        !segment.is_empty()
            && !segment.starts_with('.')
            && !segment.starts_with('_')
            && segment
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~'))
    };

    scope.is_none_or(valid_segment) && valid_segment(package)
}

fn valid_go_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && !name.ends_with('/')
        && name
            .split('/')
            .all(|segment| !segment.is_empty() && valid_go_segment(segment))
}

fn valid_go_segment(segment: &str) -> bool {
    segment
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~'))
}

fn valid_php_name(name: &str) -> bool {
    let Some((vendor, package)) = name.split_once('/') else {
        return false;
    };
    !vendor.is_empty()
        && !package.is_empty()
        && !package.contains('/')
        && valid_simple_name(vendor)
        && valid_simple_name(package)
}

fn valid_jvm_name(name: &str) -> bool {
    let Some((group, artifact)) = name.split_once(':') else {
        return false;
    };
    !group.is_empty()
        && !artifact.is_empty()
        && !artifact.contains(':')
        && group
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
        && artifact
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
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
        for eco in [
            Ecosystem::Npm,
            Ecosystem::PyPI,
            Ecosystem::Cargo,
            Ecosystem::Go,
            Ecosystem::Ruby,
            Ecosystem::Php,
            Ecosystem::Jvm,
            Ecosystem::Dotnet,
        ] {
            assert_eq!(format!("{}", eco), eco.as_str());
        }
    }

    #[test]
    fn allows_slashes_correct() {
        assert!(Ecosystem::Npm.allows_slashes()); // @scope/pkg
        assert!(Ecosystem::Go.allows_slashes()); // github.com/org/repo
        assert!(Ecosystem::Php.allows_slashes()); // vendor/package
        assert!(Ecosystem::Jvm.allows_slashes()); // group has dots, artifact uses :
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
        assert!(Ecosystem::Go.supports_metadata());
        assert!(Ecosystem::Php.supports_metadata());
        assert!(Ecosystem::Dotnet.supports_metadata());
    }

    #[test]
    fn registry_url_for_all_ecosystems() {
        assert!(
            Ecosystem::Npm
                .registry_url_for("react")
                .contains("npmjs.com")
        );
        assert!(
            Ecosystem::PyPI
                .registry_url_for("flask")
                .contains("pypi.org")
        );
        assert!(
            Ecosystem::Cargo
                .registry_url_for("serde")
                .contains("crates.io")
        );
        assert!(
            Ecosystem::Go
                .registry_url_for("github.com/gin-gonic/gin")
                .contains("pkg.go.dev")
        );
        assert!(
            Ecosystem::Ruby
                .registry_url_for("rails")
                .contains("rubygems.org")
        );
        assert!(
            Ecosystem::Php
                .registry_url_for("laravel/framework")
                .contains("packagist.org")
        );
        assert!(
            Ecosystem::Jvm
                .registry_url_for("com.google.guava:guava")
                .contains("maven.org")
        );
        assert!(
            Ecosystem::Dotnet
                .registry_url_for("Newtonsoft.Json")
                .contains("nuget.org")
        );
    }

    // ── osv_name exhaustive tests (lines 57-66) ──

    #[test]
    fn osv_name_npm() {
        assert_eq!(Ecosystem::Npm.osv_name(), "npm");
    }

    #[test]
    fn osv_name_pypi() {
        assert_eq!(Ecosystem::PyPI.osv_name(), "PyPI");
    }

    #[test]
    fn osv_name_cargo() {
        assert_eq!(Ecosystem::Cargo.osv_name(), "crates.io");
    }

    #[test]
    fn osv_name_go() {
        assert_eq!(Ecosystem::Go.osv_name(), "Go");
    }

    #[test]
    fn osv_name_ruby() {
        assert_eq!(Ecosystem::Ruby.osv_name(), "RubyGems");
    }

    #[test]
    fn osv_name_jvm() {
        assert_eq!(Ecosystem::Jvm.osv_name(), "Maven");
    }

    #[test]
    fn osv_name_dotnet() {
        assert_eq!(Ecosystem::Dotnet.osv_name(), "NuGet");
    }

    #[test]
    fn osv_name_php() {
        assert_eq!(Ecosystem::Php.osv_name(), "Packagist");
    }

    // ── registry_url_for Jvm edge cases (line 90) ──

    #[test]
    fn registry_url_for_jvm_with_colon() {
        let url = Ecosystem::Jvm.registry_url_for("com.google.guava:guava");
        assert_eq!(
            url,
            "https://search.maven.org/artifact/com.google.guava/guava"
        );
    }

    #[test]
    fn registry_url_for_jvm_without_colon() {
        // When there's no colon, falls back to search URL (line 90)
        let url = Ecosystem::Jvm.registry_url_for("guava");
        assert_eq!(url, "https://search.maven.org/search?q=guava");
    }

    // ── is_case_insensitive exhaustive ──

    #[test]
    fn is_case_insensitive_correct() {
        assert!(Ecosystem::Npm.is_case_insensitive());
        assert!(Ecosystem::PyPI.is_case_insensitive());
        assert!(Ecosystem::Cargo.is_case_insensitive());
        assert!(Ecosystem::Dotnet.is_case_insensitive());
        assert!(Ecosystem::Php.is_case_insensitive());
        assert!(!Ecosystem::Go.is_case_insensitive());
        assert!(!Ecosystem::Ruby.is_case_insensitive());
        assert!(!Ecosystem::Jvm.is_case_insensitive());
    }
}
