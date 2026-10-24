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
    let packages = extract_packages(parsed);
    let mut result = ResolutionResult::default();

    for dep in deps {
        match packages.get(&dep.name) {
            Some(version) => {
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
    Ok(extract_packages(parsed)
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
    let content = crate::parsers::read_file_limited(&path, crate::parsers::MAX_MANIFEST_BYTES)?;
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
                .unwrap_or("<unnamed>");
            for field in ["dist", "source"] {
                let Some(location) = entry.get(field).filter(|value| !value.is_null()) else {
                    continue;
                };
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

fn extract_packages(parsed: &serde_json::Value) -> std::collections::HashMap<String, String> {
    let mut packages = std::collections::HashMap::new();

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
            packages.insert(name.to_string(), version.to_string());
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
