//! Integrity hashes that npm-family lockfiles record per registry package
//! version.
//!
//! The lockfile hash is what the package manager enforces at install time, so
//! it must describe the same artifact the registry serves for that version.
//! `checks::lockfile_integrity` compares these values with the packument's
//! `dist.integrity` / `dist.shasum`.
//!
//! Covered: `package-lock.json` / `npm-shrinkwrap.json` (v1 `dependencies` and
//! v2/v3 `packages`), `pnpm-lock.yaml`, `bun.lock` and Yarn classic
//! `yarn.lock` (`integrity` plus the SHA-1 in the `resolved` URL fragment).
//!
//! Not covered: Yarn Berry. Its `checksum` is a hash of the zip archive Yarn
//! builds from the tarball, not of the registry tarball, so it can never be
//! compared with registry metadata. Selected Berry versions still get tarball
//! verification against the packument.

use super::ParsedLockfile;
use std::collections::HashMap;

/// How one lockfile entry for a package version is sourced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LockedSource {
    /// A registry package. `integrity` is the lockfile's SRI string (absent
    /// when the entry records none); `sha1_hex` is an additional SHA-1 hex
    /// digest (the `#<sha1>` fragment of a Yarn classic `resolved` URL).
    Registry {
        integrity: Option<String>,
        sha1_hex: Option<String>,
    },
    /// Not fetched from the registry under this identity (bundled in a parent
    /// tarball, a link, a directory, git or tarball-URL source). Registry
    /// metadata says nothing about it; provenance policy handles it.
    NotRegistry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LockedEntry {
    /// Where the entry lives in the lockfile (package path or key).
    pub(crate) location: String,
    pub(crate) source: LockedSource,
}

/// Lockfile entries by (registry package name, exact version).
#[derive(Debug, Clone, Default)]
pub(crate) struct NpmLockfileIntegrity {
    /// Lockfile file name, for messages.
    pub(crate) lockfile: String,
    pub(crate) entries: HashMap<(String, String), Vec<LockedEntry>>,
}

impl NpmLockfileIntegrity {
    pub(crate) fn new(lockfile: &str) -> Self {
        Self {
            lockfile: lockfile.to_string(),
            entries: HashMap::new(),
        }
    }

    pub(crate) fn insert(
        &mut self,
        name: &str,
        version: &str,
        location: &str,
        source: LockedSource,
    ) {
        self.entries
            .entry((name.to_string(), version.to_string()))
            .or_default()
            .push(LockedEntry {
                location: location.to_string(),
                source,
            });
    }

    pub(crate) fn get(&self, name: &str, version: &str) -> Option<&[LockedEntry]> {
        self.entries
            .get(&(name.to_string(), version.to_string()))
            .map(Vec::as_slice)
    }
}

/// Collect recorded integrity for an npm-family lockfile. `None` for other
/// ecosystems and for Yarn Berry (see the module docs).
pub(super) fn collect(parsed: &ParsedLockfile) -> Option<NpmLockfileIntegrity> {
    match parsed {
        ParsedLockfile::Npm {
            value, file_name, ..
        } => Some(collect_npm_packages(value, file_name)),
        ParsedLockfile::NpmLegacy { value, file_name } => {
            let mut out = NpmLockfileIntegrity::new(file_name);
            if let Some(dependencies) = value.get("dependencies").and_then(|v| v.as_object()) {
                collect_npm_v1(dependencies, "", &mut out);
            }
            Some(out)
        }
        ParsedLockfile::Pnpm { value, .. } => Some(collect_pnpm(value)),
        ParsedLockfile::Bun { value, .. } => Some(collect_bun(value)),
        ParsedLockfile::Yarn(parsed) => {
            let entries = parsed.classic_registry_entries()?;
            let lockfile = parsed
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("yarn.lock");
            let mut out = NpmLockfileIntegrity::new(lockfile);
            for entry in entries {
                let sha1_hex = entry
                    .resolved
                    .as_deref()
                    .and_then(|resolved| resolved.split_once('#'))
                    .map(|(_, fragment)| fragment.trim().to_string())
                    .filter(|fragment| !fragment.is_empty());
                out.insert(
                    &entry.name,
                    &entry.version,
                    &entry.location,
                    LockedSource::Registry {
                        integrity: non_empty(entry.integrity.as_deref()),
                        sha1_hex,
                    },
                );
            }
            Some(out)
        }
        _ => None,
    }
}

fn non_empty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn json_flag(entry: &serde_json::Value, key: &str) -> bool {
    entry.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

/// A `resolved` value that is not an HTTP(S) tarball (git, file, link path).
fn non_http_resolved(entry: &serde_json::Value) -> bool {
    entry
        .get("resolved")
        .and_then(|v| v.as_str())
        .is_some_and(|resolved| {
            let lower = resolved.trim().to_ascii_lowercase();
            !(lower.starts_with("https://") || lower.starts_with("http://"))
        })
}

fn npm_entry_source(entry: &serde_json::Value) -> LockedSource {
    if json_flag(entry, "inBundle") || json_flag(entry, "bundled") || non_http_resolved(entry) {
        return LockedSource::NotRegistry;
    }
    LockedSource::Registry {
        integrity: non_empty(entry.get("integrity").and_then(|v| v.as_str())),
        sha1_hex: None,
    }
}

fn collect_npm_packages(value: &serde_json::Value, file_name: &str) -> NpmLockfileIntegrity {
    let mut out = NpmLockfileIntegrity::new(file_name);
    let Some(packages) = value.get("packages").and_then(|v| v.as_object()) else {
        return out;
    };
    for (key, entry) in packages {
        if key.is_empty() || !key.contains("node_modules/") || json_flag(entry, "link") {
            continue;
        }
        let installed = key
            .rsplit_once("node_modules/")
            .map(|(_, name)| name)
            .unwrap_or(key);
        let name = entry
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(installed);
        let Some(version) = entry.get("version").and_then(|v| v.as_str()) else {
            continue;
        };
        out.insert(name, version, key, npm_entry_source(entry));
    }
    out
}

fn collect_npm_v1(
    dependencies: &serde_json::Map<String, serde_json::Value>,
    parent: &str,
    out: &mut NpmLockfileIntegrity,
) {
    for (key, entry) in dependencies {
        let location = if parent.is_empty() {
            key.clone()
        } else {
            format!("{parent} > {key}")
        };
        if let Some(raw_version) = entry.get("version").and_then(|v| v.as_str()) {
            let alias = raw_version
                .strip_prefix("npm:")
                .and_then(split_name_and_version);
            let (name, version) = match alias {
                Some((name, version)) => (name, version),
                None => (
                    entry.get("name").and_then(|v| v.as_str()).unwrap_or(key),
                    raw_version,
                ),
            };
            let source = if version.contains(':') || version.contains('/') {
                LockedSource::NotRegistry
            } else {
                npm_entry_source(entry)
            };
            out.insert(name, version, &location, source);
        }
        if let Some(nested) = entry.get("dependencies").and_then(|v| v.as_object()) {
            collect_npm_v1(nested, &location, out);
        }
    }
}

/// Split `name@version` / `@scope/name@version`.
fn split_name_and_version(spec: &str) -> Option<(&str, &str)> {
    let spec = spec.trim();
    let split = if spec.starts_with('@') {
        let slash = spec.find('/')?;
        slash + spec[slash..].rfind('@')?
    } else {
        spec.rfind('@')?
    };
    let (name, version) = spec.split_at(split);
    let version = version.strip_prefix('@')?;
    (!name.is_empty() && !version.is_empty()).then_some((name, version))
}

fn collect_pnpm(value: &serde_yaml::Value) -> NpmLockfileIntegrity {
    let mut out = NpmLockfileIntegrity::new("pnpm-lock.yaml");
    let Some(packages) = value.get("packages").and_then(|v| v.as_mapping()) else {
        return out;
    };
    for (key, entry) in packages {
        let Some(key) = key.as_str() else {
            continue;
        };
        let Some((name, version)) = super::pnpm::pnpm_package_key_parts(key) else {
            continue;
        };
        let resolution = entry.get("resolution");
        let integrity = non_empty(
            resolution
                .and_then(|r| r.get("integrity"))
                .and_then(|v| v.as_str()),
        );
        let local_or_git = resolution.is_some_and(|r| {
            ["directory", "repo", "commit", "type"]
                .iter()
                .any(|field| r.get(*field).is_some())
        });
        let source = if integrity.is_none() && local_or_git {
            LockedSource::NotRegistry
        } else {
            LockedSource::Registry {
                integrity,
                sha1_hex: None,
            }
        };
        out.insert(name, version, key, source);
    }
    out
}

fn collect_bun(value: &serde_json::Value) -> NpmLockfileIntegrity {
    let mut out = NpmLockfileIntegrity::new("bun.lock");
    let Some(packages) = value.get("packages").and_then(|v| v.as_object()) else {
        return out;
    };
    for (key, entry) in packages {
        let Some(parts) = entry.as_array() else {
            continue;
        };
        let Some(descriptor) = parts.first().and_then(|v| v.as_str()) else {
            continue;
        };
        let Some((name, version)) = split_name_and_version(descriptor) else {
            continue;
        };
        // Workspace, file, link, git and URL descriptors are not registry
        // identities.
        if version.contains(':') || version.contains('/') || name.contains(':') {
            continue;
        }
        out.insert(
            name,
            version,
            key,
            LockedSource::Registry {
                integrity: non_empty(parts.get(3).and_then(|v| v.as_str())),
                sha1_hex: None,
            },
        );
    }
    out
}

#[cfg(test)]
#[path = "integrity_tests.rs"]
mod tests;
