//! Artifact hashes that Python lockfiles record per package version
//! (`poetry.lock`, `uv.lock`, `Pipfile.lock`).
//!
//! pip enforces these hashes at install time, so they must describe artifacts
//! PyPI actually serves for that version. `checks::python_lockfile_hashes`
//! compares them with the sha256 digests the PyPI JSON API publishes.
//!
//! Only entries installed from the public PyPI index are comparable; entries
//! from another index, git, a URL or a local path are `NotRegistry` (the
//! source-policy checks own those).

use super::ParsedLockfile;
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PythonLockedSource {
    /// Installed from public PyPI. `sha256` holds lowercase hex digests;
    /// `other_algorithms` is true when entries used a different algorithm
    /// (never comparable with PyPI's sha256).
    Registry {
        sha256: BTreeSet<String>,
        other_algorithms: bool,
    },
    NotRegistry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PythonLockedEntry {
    pub(crate) location: String,
    pub(crate) source: PythonLockedSource,
}

/// Lockfile entries by (PEP 503 normalized name, exact version).
#[derive(Debug, Clone, Default)]
pub(crate) struct PythonLockfileHashes {
    pub(crate) lockfile: String,
    entries: HashMap<(String, String), Vec<PythonLockedEntry>>,
}

impl PythonLockfileHashes {
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
        location: String,
        source: PythonLockedSource,
    ) {
        self.entries
            .entry((normalize_name(name), version.to_string()))
            .or_default()
            .push(PythonLockedEntry { location, source });
    }

    pub(crate) fn get(&self, name: &str, version: &str) -> Option<&[PythonLockedEntry]> {
        self.entries
            .get(&(normalize_name(name), version.to_string()))
            .map(Vec::as_slice)
    }
}

/// PEP 503 name normalization.
pub(crate) fn normalize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_was_separator = false;
    for ch in name.to_lowercase().chars() {
        if matches!(ch, '-' | '_' | '.') {
            if !last_was_separator {
                out.push('-');
            }
            last_was_separator = true;
        } else {
            out.push(ch);
            last_was_separator = false;
        }
    }
    out
}

pub(super) fn collect(parsed: &ParsedLockfile) -> Option<PythonLockfileHashes> {
    match parsed {
        ParsedLockfile::Python(value) => Some(collect_poetry(value)),
        ParsedLockfile::Uv(value) => Some(collect_uv(value)),
        ParsedLockfile::Pipfile(value) => Some(collect_pipfile(value)),
        _ => None,
    }
}

/// `sha256:<hex>` → the hex digest; other `alg:digest` shapes → `None`.
fn split_hash(hash: &str) -> (Option<String>, bool) {
    match hash.trim().split_once(':') {
        Some(("sha256", digest)) if !digest.is_empty() => {
            (Some(digest.to_ascii_lowercase()), false)
        }
        _ => (None, true),
    }
}

fn registry_source<'a>(hashes: impl Iterator<Item = &'a str>) -> PythonLockedSource {
    let mut sha256 = BTreeSet::new();
    let mut other_algorithms = false;
    for hash in hashes {
        match split_hash(hash) {
            (Some(digest), _) => {
                sha256.insert(digest);
            }
            (None, other) => other_algorithms |= other,
        }
    }
    PythonLockedSource::Registry {
        sha256,
        other_algorithms,
    }
}

fn is_public_pypi(url: &str) -> bool {
    crate::config::normalize_python_index_url(url) == crate::config::normalized_default_pypi_index()
}

fn packages(value: &toml::Value) -> impl Iterator<Item = &toml::value::Table> {
    value
        .get("package")
        .and_then(|packages| packages.as_array())
        .into_iter()
        .flatten()
        .filter_map(|package| package.as_table())
}

fn collect_poetry(value: &toml::Value) -> PythonLockfileHashes {
    let mut out = PythonLockfileHashes::new("poetry.lock");
    let legacy_files = value
        .get("metadata")
        .and_then(|metadata| metadata.get("files"))
        .and_then(|files| files.as_table());
    for package in packages(value) {
        let (Some(name), Some(version)) = (
            package.get("name").and_then(|v| v.as_str()),
            package.get("version").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        let location = format!("{name} {version}");
        let from_public_index = match package.get("source").and_then(|v| v.as_table()) {
            None => true,
            Some(source) => {
                source.get("type").and_then(|v| v.as_str()) == Some("legacy")
                    && source
                        .get("url")
                        .and_then(|v| v.as_str())
                        .is_some_and(is_public_pypi)
            }
        };
        if !from_public_index {
            out.insert(name, version, location, PythonLockedSource::NotRegistry);
            continue;
        }
        let files = package
            .get("files")
            .or_else(|| legacy_files.and_then(|table| table.get(name)))
            .and_then(|files| files.as_array());
        let hashes = files
            .into_iter()
            .flatten()
            .filter_map(|file| file.get("hash").and_then(|hash| hash.as_str()));
        out.insert(name, version, location, registry_source(hashes));
    }
    out
}

fn collect_uv(value: &toml::Value) -> PythonLockfileHashes {
    let mut out = PythonLockfileHashes::new("uv.lock");
    for package in packages(value) {
        let (Some(name), Some(version)) = (
            package.get("name").and_then(|v| v.as_str()),
            package.get("version").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        let location = format!("{name} {version}");
        let public = package
            .get("source")
            .and_then(|source| source.get("registry"))
            .and_then(|registry| registry.as_str())
            .is_some_and(is_public_pypi);
        if !public {
            out.insert(name, version, location, PythonLockedSource::NotRegistry);
            continue;
        }
        let sdist = package.get("sdist").and_then(|v| v.as_table());
        let wheels = package
            .get("wheels")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter_map(|wheel| wheel.as_table());
        let hashes = sdist
            .into_iter()
            .chain(wheels)
            .filter_map(|artifact| artifact.get("hash").and_then(|hash| hash.as_str()));
        out.insert(name, version, location, registry_source(hashes));
    }
    out
}

fn collect_pipfile(value: &serde_json::Value) -> PythonLockfileHashes {
    let mut out = PythonLockfileHashes::new("Pipfile.lock");
    for section in ["default", "develop"] {
        let Some(entries) = value.get(section).and_then(|v| v.as_object()) else {
            continue;
        };
        for (name, entry) in entries {
            let Some(version) = entry
                .get("version")
                .and_then(|v| v.as_str())
                .and_then(|v| v.trim().strip_prefix("=="))
            else {
                continue;
            };
            let location = format!("{section}.{name}");
            let hashes = entry
                .get("hashes")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .filter_map(|hash| hash.as_str());
            out.insert(name, version.trim(), location, registry_source(hashes));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry(entry: &PythonLockedEntry) -> (&BTreeSet<String>, bool) {
        match &entry.source {
            PythonLockedSource::Registry {
                sha256,
                other_algorithms,
            } => (sha256, *other_algorithms),
            PythonLockedSource::NotRegistry => panic!("expected registry entry"),
        }
    }

    #[test]
    fn poetry_two_reads_package_files_and_normalizes_names() {
        let lock: toml::Value = toml::from_str(
            r#"
[[package]]
name = "Typing_Extensions"
version = "4.0.0"
files = [
  {file = "a.whl", hash = "sha256:AAAA"},
  {file = "a.tar.gz", hash = "sha256:bbbb"},
]
"#,
        )
        .unwrap();
        let hashes = collect_poetry(&lock);
        let entries = hashes.get("typing-extensions", "4.0.0").unwrap();
        let (sha, other) = registry(&entries[0]);
        assert_eq!(sha.iter().collect::<Vec<_>>(), ["aaaa", "bbbb"]);
        assert!(!other);
    }

    #[test]
    fn poetry_one_reads_metadata_files() {
        let lock: toml::Value = toml::from_str(
            r#"
[[package]]
name = "six"
version = "1.0"

[metadata.files]
six = [{file = "six.whl", hash = "sha256:cccc"}]
"#,
        )
        .unwrap();
        let hashes = collect_poetry(&lock);
        let (sha, _) = registry(&hashes.get("six", "1.0").unwrap()[0]);
        assert!(sha.contains("cccc"));
    }

    #[test]
    fn poetry_private_index_and_git_are_not_registry() {
        let lock: toml::Value = toml::from_str(
            r#"
[[package]]
name = "internal"
version = "1.0"
files = []
[package.source]
type = "legacy"
url = "https://pypi.corp.example/simple"

[[package]]
name = "gitdep"
version = "1.0"
[package.source]
type = "git"
url = "https://github.com/x/y"
"#,
        )
        .unwrap();
        let hashes = collect_poetry(&lock);
        assert_eq!(
            hashes.get("internal", "1.0").unwrap()[0].source,
            PythonLockedSource::NotRegistry
        );
        assert_eq!(
            hashes.get("gitdep", "1.0").unwrap()[0].source,
            PythonLockedSource::NotRegistry
        );
    }

    #[test]
    fn poetry_entry_without_files_is_registry_with_no_hashes() {
        let lock: toml::Value =
            toml::from_str("[[package]]\nname = \"p\"\nversion = \"1\"\n").unwrap();
        let hashes = collect_poetry(&lock);
        let (sha, other) = registry(&hashes.get("p", "1").unwrap()[0]);
        assert!(sha.is_empty() && !other);
    }

    #[test]
    fn uv_reads_sdist_and_wheels_from_public_registry_only() {
        let lock: toml::Value = toml::from_str(
            r#"
[[package]]
name = "requests"
version = "2.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files/x.tar.gz", hash = "sha256:aa" }
wheels = [{ url = "https://files/x.whl", hash = "sha256:bb" }]

[[package]]
name = "corp"
version = "1.0"
source = { registry = "https://pypi.corp.example/simple" }
wheels = [{ url = "https://corp/x.whl", hash = "sha256:cc" }]

[[package]]
name = "app"
version = "0.1"
source = { editable = "." }
"#,
        )
        .unwrap();
        let hashes = collect_uv(&lock);
        let (sha, _) = registry(&hashes.get("requests", "2.0").unwrap()[0]);
        assert_eq!(sha.len(), 2);
        assert_eq!(
            hashes.get("corp", "1.0").unwrap()[0].source,
            PythonLockedSource::NotRegistry
        );
        assert_eq!(
            hashes.get("app", "0.1").unwrap()[0].source,
            PythonLockedSource::NotRegistry
        );
    }

    #[test]
    fn pipfile_reads_exact_pins_and_flags_other_algorithms() {
        let lock: serde_json::Value = serde_json::json!({
            "default": {"Flask": {"version": "==2.0", "hashes": ["sha256:AA", "sha512:zz"]}},
            "develop": {"pytest": {"version": "==7.0", "hashes": ["sha256:bb"]}}
        });
        let hashes = collect_pipfile(&lock);
        let (sha, other) = registry(&hashes.get("flask", "2.0").unwrap()[0]);
        assert!(sha.contains("aa") && other);
        assert!(hashes.get("pytest", "7.0").is_some());
    }

    #[test]
    fn normalize_collapses_separator_runs() {
        assert_eq!(normalize_name("Foo.__Bar--baz"), "foo-bar-baz");
    }
}
