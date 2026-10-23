//! Pipfile.lock: Pipenv's flat lockfile. Every installable package is recorded
//! in the section of the category that pulls it in (`default`, `develop`, or a
//! custom category), pinned with `==` and hash-locked. Packages the Pipfile
//! does not declare are transitives.

use super::{
    ResolutionKey, ResolutionMode, ResolutionResult, ResolutionSource, ResolvedVersion,
    add_manifest_exact_fallback, ambiguous_issue, missing_entry_issue, out_of_sync_issue,
};
use crate::Dependency;
use crate::parsers::pipfile::ParsedPipfile;
use crate::parsers::requirements::normalize_distribution_name;
use anyhow::{Result, bail};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

pub(crate) const LOCKFILE_NAME: &str = "Pipfile.lock";

const META_KEY: &str = "_meta";

/// Keys that make Pipenv install from somewhere other than a package index.
const NON_REGISTRY_KEYS: &[&str] = &["git", "path", "file", "editable", "ref", "subdirectory"];

pub(super) fn read_lockfile(project_dir: &Path) -> Result<Option<serde_json::Value>> {
    let path = project_dir.join(LOCKFILE_NAME);
    if !crate::parsers::path_detected(&path)? {
        return Ok(None);
    }
    read_lockfile_at(&path).map(Some)
}

pub(crate) fn read_lockfile_at(path: &Path) -> Result<serde_json::Value> {
    let content = crate::parsers::read_file_limited(path, crate::parsers::MAX_MANIFEST_BYTES)
        .map_err(|err| {
            anyhow::anyhow!(
                "Required lockfile '{}' is unreadable: {}",
                path.display(),
                err
            )
        })?;
    let value: serde_json::Value = serde_json::from_str(&content)
        .map_err(|err| anyhow::anyhow!("Broken lockfile '{}': {}", path.display(), err))?;
    if !value.is_object() {
        bail!(
            "Broken lockfile '{}': expected a JSON object",
            path.display()
        );
    }
    Ok(value)
}

/// One locked package.
struct LockEntry<'a> {
    section: &'a str,
    name: &'a str,
    version: String,
}

/// Every locked package, after checking each entry's provenance: an exact
/// `==` pin, hashes, and no git/path/file/editable or non-PyPI index source.
fn checked_entries<'a>(
    lock: &'a serde_json::Value,
    path: &Path,
) -> Result<(Vec<LockEntry<'a>>, HashMap<&'a str, String>)> {
    let fail = |detail: String| anyhow::anyhow!("Broken lockfile '{}': {}", path.display(), detail);
    let object = lock
        .as_object()
        .ok_or_else(|| fail("expected a JSON object".to_string()))?;
    let meta = object
        .get(META_KEY)
        .and_then(|meta| meta.as_object())
        .ok_or_else(|| fail("missing _meta table".to_string()))?;

    let mut sources = HashMap::new();
    if let Some(entries) = meta.get("sources") {
        let entries = entries
            .as_array()
            .ok_or_else(|| fail("_meta.sources must be an array".to_string()))?;
        for source in entries {
            let name = source.get("name").and_then(|value| value.as_str());
            let url = source.get("url").and_then(|value| value.as_str());
            let (Some(name), Some(url)) = (name, url) else {
                return Err(fail(
                    "_meta.sources entries need a name and url".to_string(),
                ));
            };
            sources.insert(name, crate::config::normalize_python_index_url(url));
        }
    }

    let mut entries = Vec::new();
    for (section, packages) in object {
        if section == META_KEY {
            continue;
        }
        let packages = packages.as_object().ok_or_else(|| {
            fail(format!(
                "section '{}' must map package names to entries",
                crate::report::sanitize_for_terminal(section)
            ))
        })?;
        for (name, entry) in packages {
            let label = format!(
                "{} entry '{}'",
                crate::report::sanitize_for_terminal(section),
                crate::report::sanitize_for_terminal(name)
            );
            if !crate::registry::validate_package_name_for_ecosystem(name, crate::Ecosystem::PyPI) {
                return Err(fail(format!("{label} has an invalid package name")));
            }
            let entry = entry
                .as_object()
                .ok_or_else(|| fail(format!("{label} must be a table")))?;
            if let Some(key) = NON_REGISTRY_KEYS
                .iter()
                .find(|key| entry.contains_key(**key))
            {
                return Err(fail(format!(
                    "{label} installs from a {key} source. Only hash-locked PyPI packages are supported in Pipfile.lock."
                )));
            }
            if let Some(index) = entry.get("index") {
                let index = index
                    .as_str()
                    .ok_or_else(|| fail(format!("{label} has a non-string index")))?;
                let Some(url) = sources.get(index) else {
                    return Err(fail(format!(
                        "{label} references index '{}', which _meta.sources does not declare",
                        crate::report::sanitize_for_terminal(index)
                    )));
                };
                if url != crate::config::normalized_default_pypi_index() {
                    return Err(fail(format!(
                        "{label} resolves from non-PyPI index '{}' ({}). Alternate package indexes are not supported for Pipenv projects.",
                        crate::report::sanitize_for_terminal(index),
                        crate::report::sanitize_for_terminal(url)
                    )));
                }
            }
            let version = entry
                .get("version")
                .and_then(|value| value.as_str())
                .and_then(|value| value.trim().strip_prefix("=="))
                .map(str::trim)
                .filter(|version| {
                    !version.is_empty()
                        && !version.contains(['*', ',', ' ', '<', '>', '=', '!', '~'])
                })
                .ok_or_else(|| fail(format!("{label} is not pinned to an exact '==' version")))?;
            let hashes = entry
                .get("hashes")
                .and_then(|value| value.as_array())
                .filter(|hashes| !hashes.is_empty())
                .ok_or_else(|| fail(format!("{label} has no hashes")))?;
            if !hashes
                .iter()
                .all(|hash| hash.as_str().is_some_and(is_supported_hash))
            {
                return Err(fail(format!("{label} has malformed hashes")));
            }
            entries.push(LockEntry {
                section,
                name,
                version: version.to_string(),
            });
        }
    }
    Ok((entries, sources))
}

fn is_supported_hash(hash: &str) -> bool {
    let Some((algorithm, digest)) = hash.split_once(':') else {
        return false;
    };
    let expected_len = match algorithm {
        "sha256" => 64,
        "sha384" => 96,
        "sha512" => 128,
        _ => return false,
    };
    digest.len() == expected_len && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Reconcile Pipfile.lock with the Pipfile in both directions and enforce the
/// Python index policy on the lock's sources. Lock entries the Pipfile does
/// not declare are transitives and are scanned, not rejected.
pub(crate) fn validate(
    lock: &serde_json::Value,
    pipfile: &ParsedPipfile,
    path: &Path,
    config: &crate::config::SloppyJoeConfig,
) -> Result<()> {
    let (entries, sources) = checked_entries(lock, path)?;

    let recorded_hash = lock
        .get(META_KEY)
        .and_then(|meta| meta.get("hash"))
        .and_then(|hash| hash.get("sha256"))
        .and_then(|hash| hash.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Broken lockfile '{}': _meta.hash.sha256 is missing. Regenerate Pipfile.lock with `pipenv lock`.",
                path.display()
            )
        })?;
    if let Some(expected) = &pipfile.hash
        && !recorded_hash.eq_ignore_ascii_case(expected)
    {
        bail!(
            "Required lockfile '{}' is out of date with the Pipfile: _meta.hash does not match the Pipfile's hash, so the lock was generated from a different Pipfile. Run `pipenv lock` and commit Pipfile.lock.",
            path.display()
        );
    }

    let declared_sources: BTreeSet<&str> = if pipfile.source_urls.is_empty() {
        // Pipenv falls back to PyPI when the Pipfile declares no source.
        BTreeSet::from([crate::config::normalized_default_pypi_index()])
    } else {
        pipfile.source_urls.iter().map(String::as_str).collect()
    };
    for (name, url) in &sources {
        if !config.is_trusted_index("pypi", url) {
            bail!(
                "Broken lockfile '{}': source '{}' points at index '{}', which is not PyPI and not allowlisted in trusted_indexes.pypi.",
                path.display(),
                crate::report::sanitize_for_terminal(name),
                crate::report::sanitize_for_terminal(url)
            );
        }
        if !declared_sources.contains(url.as_str()) {
            bail!(
                "Broken lockfile '{}': source '{}' ({}) is not declared in the Pipfile. Regenerate Pipfile.lock with `pipenv lock`.",
                path.display(),
                crate::report::sanitize_for_terminal(name),
                crate::report::sanitize_for_terminal(url)
            );
        }
    }

    let mut locked: HashMap<(&str, String), &str> = HashMap::new();
    for entry in &entries {
        locked.insert(
            (entry.section, normalize_distribution_name(entry.name)),
            entry.version.as_str(),
        );
    }
    for category in &pipfile.categories {
        for dep in &category.deps {
            let key = (
                category.lock_section.as_str(),
                normalize_distribution_name(dep.package_name()),
            );
            let Some(version) = locked.get(&key) else {
                bail!(
                    "Required lockfile '{}' is out of sync with the Pipfile: '{}' is not locked in section '{}'. Run `pipenv lock` and commit Pipfile.lock.",
                    path.display(),
                    crate::report::sanitize_for_terminal(dep.package_name()),
                    crate::report::sanitize_for_terminal(&category.lock_section)
                );
            };
            let satisfied =
                super::uv::version_matches_uv_specifier(version, dep.version.as_deref())
                    .unwrap_or(false);
            if !satisfied {
                bail!(
                    "Required lockfile '{}' is out of sync with the Pipfile: '{}' is locked at {} in section '{}', which does not satisfy '{}'. Run `pipenv lock` and commit Pipfile.lock.",
                    path.display(),
                    crate::report::sanitize_for_terminal(dep.package_name()),
                    crate::report::sanitize_for_terminal(version),
                    crate::report::sanitize_for_terminal(&category.lock_section),
                    crate::report::sanitize_for_terminal(dep.version.as_deref().unwrap_or("*"))
                );
            }
        }
    }
    Ok(())
}

/// Locked (name, version) pairs, without re-validating provenance (preflight
/// already did). Unparseable entries are skipped here because preflight blocks
/// on them.
fn locked_packages(lock: &serde_json::Value) -> Vec<(String, String)> {
    let Some(object) = lock.as_object() else {
        return Vec::new();
    };
    let mut packages = Vec::new();
    for (section, entries) in object {
        if section == META_KEY {
            continue;
        }
        let Some(entries) = entries.as_object() else {
            continue;
        };
        for (name, entry) in entries {
            if let Some(version) = entry
                .get("version")
                .and_then(|value| value.as_str())
                .and_then(|value| value.trim().strip_prefix("=="))
            {
                packages.push((name.clone(), version.trim().to_string()));
            }
        }
    }
    packages
}

pub(super) fn resolve_from_value_with_mode(
    lock: &serde_json::Value,
    deps: &[Dependency],
    mode: ResolutionMode,
) -> Result<ResolutionResult> {
    let packages = locked_packages(lock);
    let mut result = ResolutionResult::default();
    for dep in deps {
        let normalized = normalize_distribution_name(dep.package_name());
        let candidates: BTreeSet<&str> = packages
            .iter()
            .filter(|(name, _)| normalize_distribution_name(name) == normalized)
            .map(|(_, version)| version.as_str())
            .filter(|version| {
                mode == ResolutionMode::Transitive
                    || super::uv::version_matches_uv_specifier(version, dep.version.as_deref())
                        .unwrap_or(false)
            })
            .collect();
        let mut candidates = candidates.into_iter();
        match (candidates.next(), candidates.next()) {
            (Some(version), None) => {
                result.exact_versions.insert(
                    ResolutionKey::from(dep),
                    ResolvedVersion {
                        version: version.to_string(),
                        source: ResolutionSource::Lockfile,
                    },
                );
            }
            (Some(_), Some(_)) => {
                if let Some(version) = dep
                    .exact_version()
                    .filter(|exact| packages.iter().any(|(_, version)| version == exact))
                {
                    result.exact_versions.insert(
                        ResolutionKey::from(dep),
                        ResolvedVersion {
                            version,
                            source: ResolutionSource::Lockfile,
                        },
                    );
                } else {
                    result.push_issue_for(dep, ambiguous_issue(dep));
                }
            }
            (None, _) => {
                match packages
                    .iter()
                    .find(|(name, _)| normalize_distribution_name(name) == normalized)
                {
                    Some((_, version)) => {
                        result.push_issue_for(dep, out_of_sync_issue(dep, version))
                    }
                    None => result.push_issue_for(dep, missing_entry_issue(dep, LOCKFILE_NAME)),
                }
                add_manifest_exact_fallback(&mut result, dep);
            }
        }
    }
    Ok(result)
}

pub(super) fn parse_all_from_value(lock: &serde_json::Value) -> Result<Vec<Dependency>> {
    Ok(locked_packages(lock)
        .into_iter()
        .map(|(name, version)| Dependency {
            name,
            version: Some(version),
            ecosystem: crate::Ecosystem::PyPI,
            actual_name: None,
        })
        .collect())
}
