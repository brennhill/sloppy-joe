//! Load-time validation of a parsed config.
use super::*;

pub(super) fn valid_similarity_generators() -> [&'static str; 13] {
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

pub(super) fn valid_similarity_generator(generator: &str) -> bool {
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

impl SloppyJoeConfig {
    /// Validate config at load time. Returns a list of errors.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        validate_ignore_dirs(&self.ignore_dirs, &mut errors);
        if !MAX_NPM_TARBALL_VERIFICATIONS_RANGE.contains(&self.max_npm_tarball_verifications) {
            errors.push(format!(
                "max_npm_tarball_verifications must be between {} and {} (got {})",
                MAX_NPM_TARBALL_VERIFICATIONS_RANGE.start(),
                MAX_NPM_TARBALL_VERIFICATIONS_RANGE.end(),
                self.max_npm_tarball_verifications
            ));
        }
        self.validate_ecosystem_names(&mut errors);
        self.validate_glob_patterns(&mut errors);
        validate_similarity_exceptions(&self.similarity_exceptions, &mut errors);
        validate_metadata_exceptions(&self.metadata_exceptions, &mut errors);
        validate_trusted_local_paths(&self.trusted_local_paths, &mut errors);
        validate_trusted_registries(&self.trusted_registries, &mut errors);
        validate_trusted_git_sources(&self.trusted_git_sources, &mut errors);
        validate_trusted_indexes(&self.trusted_indexes, &mut errors);
        self.validate_canonical_conflicts(&mut errors);
        errors
    }

    fn validate_ecosystem_names(&self, errors: &mut Vec<String>) {
        let valid_ecosystems = ["npm", "pypi", "cargo", "go", "ruby", "php", "jvm", "dotnet"];
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
    }

    /// `*` is only allowed as the last character of an internal/allowed pattern.
    fn validate_glob_patterns(&self, errors: &mut Vec<String>) {
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
    }

    /// A package that is both canonical and an alternative is contradictory.
    fn validate_canonical_conflicts(&self, errors: &mut Vec<String>) {
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
    }
}

fn validate_ignore_dirs(ignore_dirs: &[String], errors: &mut Vec<String>) {
    for name in ignore_dirs {
        if name.trim().is_empty()
            || matches!(name.as_str(), "." | "..")
            || name.contains(['/', '\\', '*', '?', '[', ']'])
            || name.chars().any(char::is_control)
        {
            errors.push("ignore_dirs entries must be nonempty directory names, without paths or glob patterns".to_string());
        }
    }
}

fn validate_similarity_exceptions(
    exceptions: &HashMap<String, Vec<SimilarityException>>,
    errors: &mut Vec<String>,
) {
    for (eco, rules) in exceptions {
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
}

fn validate_metadata_exceptions(
    exceptions: &HashMap<String, Vec<MetadataException>>,
    errors: &mut Vec<String>,
) {
    let blank = |value: &Option<String>| value.as_deref().unwrap_or("").trim().is_empty();
    for (eco, rules) in exceptions {
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
            if blank(&rule.previous_publisher) || blank(&rule.current_publisher) {
                errors.push(format!(
                    "Invalid metadata exception in {}: maintainer-change exceptions require exact previous_publisher and current_publisher values",
                    eco
                ));
            }
        }
    }
}

fn validate_trusted_local_paths(
    paths_by_eco: &HashMap<String, Vec<String>>,
    errors: &mut Vec<String>,
) {
    for (eco, paths) in paths_by_eco {
        for path in paths {
            if path.trim().is_empty() {
                errors.push(format!(
                    "Invalid trusted local path in {}: path must be non-empty",
                    eco
                ));
            }
        }
    }
}

fn validate_trusted_registries(
    registries: &HashMap<String, Vec<TrustedRegistry>>,
    errors: &mut Vec<String>,
) {
    for (eco, rules) in registries {
        for rule in rules {
            if rule.name.trim().is_empty() || rule.source.trim().is_empty() {
                errors.push(format!(
                    "Invalid trusted registry in {}: name and source must be non-empty",
                    eco
                ));
                continue;
            }
            let source_is_bad =
                crate::npm_config::normalize_registry_url(rule.source.trim()).is_none();
            if eco == "npm" && (!crate::npm_config::valid_route_name(&rule.name) || source_is_bad) {
                errors.push(format!(
                    "Invalid trusted registry in npm: name must be \"{}\" or an @scope, and source must be a credential-free https:// registry URL",
                    crate::npm_config::DEFAULT_ROUTE
                ));
            } else if eco == "jvm" && (rule.name != TRUSTED_PLUGIN_REPOSITORY_NAME || source_is_bad)
            {
                errors.push(format!(
                    "Invalid trusted registry in jvm: name must be \"{}\", and source must be a credential-free https:// repository URL",
                    TRUSTED_PLUGIN_REPOSITORY_NAME
                ));
            }
        }
    }
}

fn validate_trusted_git_sources(sources: &HashMap<String, Vec<String>>, errors: &mut Vec<String>) {
    for (eco, list) in sources {
        for source in list {
            if source.trim().is_empty() {
                errors.push(format!(
                    "Invalid trusted git source in {}: source must be non-empty",
                    eco
                ));
            }
        }
    }
}

fn validate_trusted_indexes(indexes: &HashMap<String, Vec<String>>, errors: &mut Vec<String>) {
    for (eco, urls) in indexes {
        for index in urls {
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
}
