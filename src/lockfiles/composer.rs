use crate::Dependency;
use anyhow::Result;
use std::path::Path;

#[cfg(test)]
use super::add_manifest_exact_fallbacks;
use super::{
    ResolutionKey, ResolutionMode, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, missing_entry_issue, no_trusted_lockfile_sync_issue,
    out_of_sync_issue,
};

#[cfg(test)]
pub(super) fn resolve_from_value(
    parsed: &serde_json::Value,
    deps: &[Dependency],
) -> Result<ResolutionResult> {
    resolve_from_value_with_mode(parsed, deps, ResolutionMode::Direct)
}

pub(super) fn resolve_from_value_with_mode(
    parsed: &serde_json::Value,
    deps: &[Dependency],
    mode: ResolutionMode,
) -> Result<ResolutionResult> {
    let packages = extract_versions(parsed);
    let mut result = ResolutionResult::default();

    for dep in deps {
        match packages.get(&dep.name) {
            Some(versions) => {
                let version = locked_version_for(dep, versions, mode);
                if let Some(exact_manifest) = dep.exact_version()
                    && exact_manifest != *version
                {
                    result.push_issue_for(dep, out_of_sync_issue(dep, version));
                    add_manifest_exact_fallback(&mut result, dep);
                    continue;
                }
                if mode == ResolutionMode::Direct
                    && dep.version.is_some()
                    && dep.exact_version().is_none()
                {
                    result
                        .push_issue_for(dep, no_trusted_lockfile_sync_issue(dep, "composer.lock"));
                    continue;
                }
                result.exact_versions.insert(
                    ResolutionKey::from(dep),
                    ResolvedVersion {
                        version: version.clone(),
                        source: ResolutionSource::Lockfile,
                    },
                );
            }
            None => {
                result.push_issue_for(dep, missing_entry_issue(dep, "composer.lock"));
                add_manifest_exact_fallback(&mut result, dep);
            }
        }
    }

    Ok(result)
}

pub(super) fn parse_all_from_value(parsed: &serde_json::Value) -> Result<Vec<Dependency>> {
    Ok(extract_entries(parsed)
        .into_iter()
        .map(|(name, version)| Dependency {
            name,
            version: Some(version),
            ecosystem: crate::Ecosystem::Php,
            actual_name: None,
        })
        .collect())
}

pub(super) fn read_lockfile(project_dir: &Path) -> Result<Option<serde_json::Value>> {
    let path = project_dir.join("composer.lock");
    if !crate::parsers::path_detected(&path)? {
        return Ok(None);
    }
    let content = crate::untrusted::read_validated(
        &path,
        crate::untrusted::Format::Json,
        crate::parsers::MAX_MANIFEST_BYTES,
    )?;
    let parsed = serde_json::from_str(&content)
        .map_err(|err| anyhow::anyhow!("Failed to parse {}: {}", path.display(), err))?;
    validate_provenance(&parsed, &path)?;
    Ok(Some(parsed))
}

/// Hosts a `composer.lock` may fetch package archives and sources from.
const TRUSTED_COMPOSER_HOSTS: &[&str] = &[
    "repo.packagist.org",
    "packagist.org",
    "api.github.com",
    "github.com",
    "codeload.github.com",
    "gitlab.com",
    "bitbucket.org",
    "api.bitbucket.org",
];

/// `composer install` downloads from each entry's `dist.url` / `source.url`, not from
/// the registry, so a committed lock could point any package at an attacker's archive.
pub(crate) fn validate_provenance(parsed: &serde_json::Value, lockfile_path: &Path) -> Result<()> {
    for section in ["packages", "packages-dev"] {
        let Some(entries) = parsed.get(section).and_then(|value| value.as_array()) else {
            continue;
        };
        for entry in entries {
            let name = entry
                .get("name")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            if !crate::ecosystem::validate_package_name(name) {
                anyhow::bail!(
                    "Invalid package name '{}' in '{}': composer.lock entries with names the scanner cannot check are not skipped.",
                    crate::report::sanitize_for_terminal(name),
                    lockfile_path.display()
                );
            }
            if entry.get("transport-options").is_some() {
                anyhow::bail!(
                    "Unsupported composer.lock entry '{name}' in '{}': 'transport-options' changes how it is downloaded.",
                    lockfile_path.display()
                );
            }
            for field in ["dist", "source"] {
                let Some(location) = entry.get(field).filter(|value| !value.is_null()) else {
                    continue;
                };
                // Composer fetches `mirrors` (preferred ones first) instead of `url`, and an
                // empty `shasum` leaves what they serve unverified.
                if let Some(key) = location.as_object().and_then(|fields| {
                    fields.keys().find(|key| {
                        !matches!(key.as_str(), "type" | "url" | "reference" | "shasum")
                    })
                }) {
                    anyhow::bail!(
                        "Unsupported composer.lock {field} field '{}' for '{name}' in '{}': composer install may download from locations other than the scanned URL.",
                        crate::report::sanitize_for_terminal(key),
                        lockfile_path.display()
                    );
                }
                let url = location.get("url").and_then(|value| value.as_str());
                let trusted = url.is_some_and(|url| {
                    url.strip_prefix("https://")
                        .and_then(|rest| rest.split(['/', '?', '#']).next())
                        .is_some_and(|authority| {
                            !authority.contains('@')
                                && !authority.contains(':')
                                && TRUSTED_COMPOSER_HOSTS
                                    .contains(&authority.to_ascii_lowercase().as_str())
                        })
                });
                if !trusted {
                    anyhow::bail!(
                        "Untrusted composer.lock {field} for '{name}' in '{}': '{}' is not an https URL on a known package host ({}). composer install downloads from it instead of Packagist. Fix: regenerate composer.lock from Packagist.",
                        lockfile_path.display(),
                        url.unwrap_or("<missing>"),
                        TRUSTED_COMPOSER_HOSTS.join(", ")
                    );
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn resolve(project_dir: &Path, deps: &[Dependency]) -> Result<ResolutionResult> {
    let Some(parsed) = read_lockfile(project_dir)? else {
        let mut result = ResolutionResult::default();
        add_manifest_exact_fallbacks(&mut result, deps);
        return Ok(result);
    };
    resolve_from_value(&parsed, deps)
}

/// Every locked version of each package, the `packages` (production) entry first.
fn extract_versions(parsed: &serde_json::Value) -> std::collections::HashMap<String, Vec<String>> {
    let mut packages: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for (name, version) in extract_entries(parsed) {
        packages.entry(name).or_default().push(version);
    }
    packages
}

/// The locked version `dep` is checked at. A package listed in both `packages` and
/// `packages-dev` is a production dependency, so a direct dependency resolves to its
/// `packages` version. A full scan lists every locked entry as its own dependency, so each
/// resolves to the entry it came from.
fn locked_version_for<'a>(
    dep: &Dependency,
    versions: &'a [String],
    mode: ResolutionMode,
) -> &'a String {
    let own_entry = (mode == ResolutionMode::Transitive)
        .then(|| dep.exact_version())
        .flatten()
        .and_then(|exact| versions.iter().find(|version| **version == exact));
    own_entry.unwrap_or(&versions[0])
}

/// Every locked `(name, version)`, `packages` before `packages-dev`. Composer never lists one
/// package in both sections; when a lock does, both versions are kept so both are checked.
fn extract_entries(parsed: &serde_json::Value) -> Vec<(String, String)> {
    let mut packages: Vec<(String, String)> = Vec::new();

    for section in ["packages", "packages-dev"] {
        let Some(entries) = parsed.get(section).and_then(|value| value.as_array()) else {
            continue;
        };

        for entry in entries {
            let Some(name) = entry.get("name").and_then(|value| value.as_str()) else {
                continue;
            };
            if !crate::ecosystem::validate_package_name(name) {
                continue;
            }
            let Some(version) = entry.get("version").and_then(|value| value.as_str()) else {
                continue;
            };
            let entry = (name.to_string(), version.to_string());
            if !packages.contains(&entry) {
                packages.push(entry);
            }
        }
    }

    packages
}

#[cfg(test)]
mod provenance_tests {
    use super::*;

    fn lock(dist_url: &str, source_url: &str) -> serde_json::Value {
        serde_json::json!({"packages": [{
            "name": "monolog/monolog", "version": "3.0.0",
            "source": {"type": "git", "url": source_url, "reference": "abc"},
            "dist": {"type": "zip", "url": dist_url, "reference": "abc"}
        }]})
    }

    #[test]
    fn known_hosts_are_accepted() {
        let parsed = lock(
            "https://api.github.com/repos/Seldaek/monolog/zipball/abc",
            "https://github.com/Seldaek/monolog.git",
        );
        validate_provenance(&parsed, Path::new("composer.lock")).unwrap();
    }

    #[test]
    fn mirrors_and_unknown_location_fields_block() {
        for field in ["dist", "source"] {
            for (key, value) in [
                (
                    "mirrors",
                    serde_json::json!([{"url": "https://evil.invalid/%package%", "preferred": true}]),
                ),
                ("transport", serde_json::json!("x")),
            ] {
                let mut parsed = lock(
                    "https://api.github.com/repos/Seldaek/monolog/zipball/abc",
                    "https://github.com/Seldaek/monolog.git",
                );
                parsed["packages"][0][field][key] = value;
                assert!(
                    validate_provenance(&parsed, Path::new("composer.lock")).is_err(),
                    "{field} {key}"
                );
            }
        }
        let mut parsed = lock(
            "https://api.github.com/repos/Seldaek/monolog/zipball/abc",
            "https://github.com/Seldaek/monolog.git",
        );
        parsed["packages"][0]["dist"]["shasum"] = serde_json::json!("");
        validate_provenance(&parsed, Path::new("composer.lock")).unwrap();
        parsed["packages"][0]["transport-options"] = serde_json::json!({"ssl": {}});
        assert!(validate_provenance(&parsed, Path::new("composer.lock")).is_err());
    }

    #[test]
    fn entries_with_invalid_names_block_instead_of_being_skipped() {
        let mut parsed = lock(
            "https://api.github.com/repos/Seldaek/monolog/zipball/abc",
            "https://github.com/Seldaek/monolog.git",
        );
        parsed["packages"][0]["name"] = serde_json::json!("../evil");
        assert!(validate_provenance(&parsed, Path::new("composer.lock")).is_err());
        parsed["packages"][0]
            .as_object_mut()
            .unwrap()
            .remove("name");
        assert!(validate_provenance(&parsed, Path::new("composer.lock")).is_err());
    }

    #[test]
    fn foreign_dist_or_source_hosts_block() {
        for (dist, source) in [
            (
                "https://mirror.example.invalid/monolog.zip",
                "https://github.com/a/b.git",
            ),
            ("https://api.github.com/x", "https://evil.example/a.git"),
            ("http://api.github.com/x", "https://github.com/a/b.git"),
            (
                "https://github.com@evil.example/x",
                "https://github.com/a/b.git",
            ),
            ("../local", "https://github.com/a/b.git"),
        ] {
            assert!(
                validate_provenance(&lock(dist, source), Path::new("composer.lock")).is_err(),
                "{dist} {source}"
            );
        }
    }
}

#[cfg(test)]
mod section_tests {
    use super::*;

    /// `guzzlehttp/psr7` locked at 1.8.3 in `packages` and 2.6.2 in `packages-dev`.
    fn both_sections() -> serde_json::Value {
        serde_json::json!({
            "packages": [{"name": "guzzlehttp/psr7", "version": "1.8.3"}],
            "packages-dev": [
                {"name": "guzzlehttp/psr7", "version": "2.6.2"},
                {"name": "phpunit/phpunit", "version": "10.0.0"}
            ]
        })
    }

    fn php(name: &str, version: Option<&str>) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.map(str::to_string),
            ecosystem: crate::Ecosystem::Php,
            actual_name: None,
        }
    }

    #[test]
    fn a_package_in_both_sections_resolves_to_its_production_version() {
        for mode in [ResolutionMode::Direct, ResolutionMode::Transitive] {
            let dep = php("guzzlehttp/psr7", Some("1.8.3"));
            let result =
                resolve_from_value_with_mode(&both_sections(), std::slice::from_ref(&dep), mode)
                    .unwrap();
            assert_eq!(result.exact_version(&dep), Some("1.8.3"));
            assert!(result.issues.is_empty(), "{:?}", result.issues);
        }
    }

    #[test]
    fn a_direct_pin_to_the_dev_version_does_not_hide_the_production_one() {
        let dep = php("guzzlehttp/psr7", Some("2.6.2"));
        let result = resolve_from_value_with_mode(
            &both_sections(),
            std::slice::from_ref(&dep),
            ResolutionMode::Direct,
        )
        .unwrap();
        assert!(
            result
                .issues
                .iter()
                .any(|issue| issue.check == crate::names::RESOLUTION_LOCKFILE_OUT_OF_SYNC),
            "{:?}",
            result.issues
        );
    }

    #[test]
    fn a_full_scan_checks_each_locked_entry_at_its_own_version() {
        let deps = parse_all_from_value(&both_sections()).unwrap();
        let result =
            resolve_from_value_with_mode(&both_sections(), &deps, ResolutionMode::Transitive)
                .unwrap();
        assert!(result.issues.is_empty(), "{:?}", result.issues);
        for dep in &deps {
            assert_eq!(result.exact_version(dep), dep.version.as_deref(), "{dep:?}");
        }
    }

    #[test]
    fn every_locked_version_of_a_package_in_both_sections_is_listed() {
        let mut all: Vec<(String, Option<String>)> = parse_all_from_value(&both_sections())
            .unwrap()
            .into_iter()
            .map(|dep| (dep.name, dep.version))
            .collect();
        all.sort();
        assert_eq!(
            all,
            [
                ("guzzlehttp/psr7".to_string(), Some("1.8.3".to_string())),
                ("guzzlehttp/psr7".to_string(), Some("2.6.2".to_string())),
                ("phpunit/phpunit".to_string(), Some("10.0.0".to_string())),
            ]
        );
    }
}
