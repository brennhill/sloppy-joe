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
///   "min_version_age_hours": 72
/// }
/// ```
///
/// - `canonical`: keys are approved packages, values are rejected alternatives.
/// - `internal`: your org's packages. Skip ALL checks. These change constantly.
/// - `allowed`: vetted external packages. Skip existence + similarity, but
///   still subject to version age gating.
/// - `min_version_age_hours`: block any dependency whose latest version was
///   published less than this many hours ago. Default: 72 (3 days).
///   Internal packages are exempt. Allowed packages are NOT exempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloppyJoeConfig {
    #[serde(default)]
    pub canonical: HashMap<String, HashMap<String, Vec<String>>>,
    #[serde(default)]
    pub internal: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub allowed: HashMap<String, Vec<String>>,
    #[serde(default = "default_min_version_age_hours")]
    pub min_version_age_hours: u64,
}

fn default_min_version_age_hours() -> u64 {
    72
}

impl Default for SloppyJoeConfig {
    fn default() -> Self {
        Self {
            canonical: HashMap::new(),
            internal: HashMap::new(),
            allowed: HashMap::new(),
            min_version_age_hours: default_min_version_age_hours(),
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

/// Resolve config path: --config flag overrides SLOPPY_JOE_CONFIG env var.
/// Never reads from the project directory.
pub fn resolve_config_path(cli_config: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = cli_config {
        return Some(path.to_path_buf());
    }
    std::env::var("SLOPPY_JOE_CONFIG")
        .ok()
        .map(PathBuf::from)
}

/// Load config from a resolved path. Returns empty config if no path.
pub fn load_config(config_path: Option<&Path>) -> SloppyJoeConfig {
    match config_path {
        Some(path) => {
            let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
                eprintln!("Warning: could not read config {}: {}", path.display(), e);
                String::new()
            });
            serde_json::from_str(&content).unwrap_or_default()
        }
        None => SloppyJoeConfig::default(),
    }
}

/// Print a template config to stdout.
pub fn print_template() {
    let config = SloppyJoeConfig {
        canonical: {
            let mut m = HashMap::new();
            m.insert(
                "npm".to_string(),
                HashMap::from([
                    ("lodash".to_string(), vec!["underscore".to_string(), "ramda".to_string()]),
                    ("dayjs".to_string(), vec!["moment".to_string(), "luxon".to_string()]),
                    ("axios".to_string(), vec!["request".to_string(), "got".to_string(), "node-fetch".to_string(), "superagent".to_string()]),
                ]),
            );
            m.insert(
                "pypi".to_string(),
                HashMap::from([
                    ("httpx".to_string(), vec!["urllib3".to_string(), "requests".to_string()]),
                    ("ruff".to_string(), vec!["flake8".to_string(), "pylint".to_string()]),
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
        allowed: HashMap::from([
            ("npm".to_string(), vec!["some-vetted-external-pkg".to_string()]),
        ]),
        min_version_age_hours: 72,
    };
    let json = serde_json::to_string_pretty(&config).unwrap();
    println!("{json}");
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
    fn alternatives_map_builds_reverse_lookup() {
        let config = SloppyJoeConfig {
            canonical: HashMap::from([(
                "npm".to_string(),
                HashMap::from([
                    ("lodash".to_string(), vec!["underscore".to_string(), "ramda".to_string()]),
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
        let config = load_config(None);
        assert!(config.canonical.is_empty());
        assert!(config.internal.is_empty());
        assert!(config.allowed.is_empty());
        assert_eq!(config.min_version_age_hours, 72);
    }

    #[test]
    fn load_config_nonexistent_path_returns_default() {
        let config = load_config(Some(Path::new("/tmp/nonexistent-sloppy-joe-config.json")));
        assert!(config.canonical.is_empty());
        assert_eq!(config.min_version_age_hours, 72);
    }

    #[test]
    fn load_config_valid_file() {
        let dir = std::env::temp_dir().join("sloppy-joe-test-config-v2");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(
            &path,
            r#"{"canonical":{"npm":{"lodash":["underscore"]}},"internal":{"npm":["@myorg/*"]},"allowed":{"npm":["vetted"]},"min_version_age_hours":48}"#,
        ).unwrap();
        let config = load_config(Some(&path));
        assert!(config.canonical.contains_key("npm"));
        assert!(config.internal.contains_key("npm"));
        assert!(config.allowed.contains_key("npm"));
        assert_eq!(config.min_version_age_hours, 48);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn default_min_version_age_is_72() {
        let config = SloppyJoeConfig::default();
        assert_eq!(config.min_version_age_hours, 72);
    }

    #[test]
    fn resolve_config_path_with_cli_flag() {
        let path = resolve_config_path(Some(Path::new("/some/path.json")));
        assert_eq!(path, Some(PathBuf::from("/some/path.json")));
    }

    #[test]
    fn print_template_does_not_panic() {
        print_template();
    }
}
