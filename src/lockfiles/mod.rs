mod cargo;
mod composer;
mod dotnet;
mod gradle;
mod npm;
mod python;
mod ruby;

use crate::Dependency;
use crate::Ecosystem;
use crate::report::{Issue, Severity};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionSource {
    Lockfile,
    ManifestExact,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedVersion {
    pub version: String,
    pub source: ResolutionSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResolutionKey {
    package: String,
    requested_version: Option<String>,
}

impl From<&Dependency> for ResolutionKey {
    fn from(dep: &Dependency) -> Self {
        Self {
            package: dep.name.clone(),
            requested_version: dep.version.clone(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ResolutionResult {
    pub exact_versions: HashMap<ResolutionKey, ResolvedVersion>,
    pub issues: Vec<Issue>,
}

impl ResolutionResult {
    pub fn resolved_version(&self, dep: &Dependency) -> Option<&ResolvedVersion> {
        self.exact_versions.get(&ResolutionKey::from(dep))
    }

    pub fn exact_version(&self, dep: &Dependency) -> Option<&str> {
        self.resolved_version(dep)
            .map(|resolved| resolved.version.as_str())
    }

    pub fn is_unresolved(&self, dep: &Dependency) -> bool {
        dep.has_unresolved_version() && self.exact_version(dep).is_none()
    }
}

/// In-memory representation of a parsed lockfile.
/// Parsed once, used for both version resolution and transitive dep extraction.
enum ParsedLockfile {
    Npm {
        value: serde_json::Value,
        file_name: String,
    },
    Cargo(toml::Value),
    Composer(serde_json::Value),
    Dotnet(serde_json::Value),
    Gradle(String),
    Python(toml::Value),
    Ruby(String),
    None,
}

/// Pre-parsed lockfile data. Reads and parses the lockfile once, then provides
/// version resolution, transitive dep extraction, and re-resolution for transitive
/// deps — all from the same in-memory data.
pub struct LockfileData {
    /// Resolved versions for direct dependencies (from lockfile or manifest fallback).
    pub resolution: ResolutionResult,
    /// Dependencies found in the lockfile but not in the direct dependency list.
    pub transitive_deps: Vec<Dependency>,
    /// Retained parsed lockfile for re-resolution of transitive deps without re-reading disk.
    parsed: ParsedLockfile,
}

impl LockfileData {
    #[cfg(test)]
    pub fn parse(project_dir: &Path, direct_deps: &[Dependency]) -> Result<Self> {
        Self::parse_for_kind(project_dir, None, direct_deps)
    }

    pub fn parse_for_kind(
        project_dir: &Path,
        project_kind: Option<crate::ProjectInputKind>,
        direct_deps: &[Dependency],
    ) -> Result<Self> {
        let ecosystem = direct_deps.first().map(|d| d.ecosystem);

        // Read and parse the lockfile once
        let parsed = read_lockfile(project_dir, ecosystem, project_kind)?;

        // Resolve direct dep versions from the parsed data
        let resolution = resolve_from_parsed(&parsed, direct_deps)?;

        // Extract all deps from the parsed data
        let all_deps = parse_all_from_parsed_for_project(&parsed, direct_deps)?;

        // Filter to transitive only
        let direct_versions: HashSet<(String, String)> = direct_deps
            .iter()
            .filter_map(|dep| {
                resolution
                    .exact_version(dep)
                    .map(|version| (dep.package_name().to_string(), version.to_string()))
            })
            .collect();
        let mut transitive: Vec<Dependency> = all_deps
            .into_iter()
            .filter(|dep| {
                let Some(version) = dep.version.as_deref() else {
                    return true;
                };
                !direct_versions.contains(&(dep.package_name().to_string(), version.to_string()))
            })
            .collect();
        let mut seen = HashSet::new();
        transitive.retain(|dep| seen.insert((dep.package_name().to_string(), dep.version.clone())));

        Ok(Self {
            resolution,
            transitive_deps: transitive,
            parsed,
        })
    }

    /// Resolve versions for transitive deps from the already-parsed lockfile.
    /// Eliminates the redundant disk read that `resolve_versions()` would do.
    pub fn resolve_transitive(&self, deps: &[Dependency]) -> Result<ResolutionResult> {
        resolve_from_parsed(&self.parsed, deps)
    }
}

/// Read and parse the lockfile from disk (once).
fn read_lockfile(
    project_dir: &Path,
    ecosystem: Option<Ecosystem>,
    project_kind: Option<crate::ProjectInputKind>,
) -> Result<ParsedLockfile> {
    if let Some(kind) = project_kind {
        return read_lockfile_for_project_kind(project_dir, kind);
    }

    match ecosystem {
        Some(Ecosystem::Npm) => {
            let Some(path) =
                first_existing(project_dir, &["npm-shrinkwrap.json", "package-lock.json"])
            else {
                return Ok(ParsedLockfile::None);
            };
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("npm-shrinkwrap.json")
                .to_string();
            let content =
                crate::parsers::read_file_limited(&path, crate::parsers::MAX_MANIFEST_BYTES)?;
            let value = serde_json::from_str(&content)
                .map_err(|err| anyhow::anyhow!("Failed to parse {}: {}", file_name, err))?;
            Ok(ParsedLockfile::Npm { value, file_name })
        }
        Some(Ecosystem::Cargo) => {
            let path = project_dir.join("Cargo.lock");
            if !crate::parsers::path_detected(&path)? {
                return Ok(ParsedLockfile::None);
            }
            let content =
                crate::parsers::read_file_limited(&path, crate::parsers::MAX_MANIFEST_BYTES)?;
            let value = toml::from_str(&content)
                .map_err(|err| anyhow::anyhow!("Failed to parse Cargo.lock: {}", err))?;
            Ok(ParsedLockfile::Cargo(value))
        }
        Some(Ecosystem::Php) => match composer::read_lockfile(project_dir)? {
            Some(value) => Ok(ParsedLockfile::Composer(value)),
            None => Ok(ParsedLockfile::None),
        },
        Some(Ecosystem::Jvm) => match gradle::read_lockfile(project_dir)? {
            Some(content) => Ok(ParsedLockfile::Gradle(content)),
            None => Ok(ParsedLockfile::None),
        },
        Some(Ecosystem::Dotnet) => match dotnet::read_lockfile(project_dir)? {
            Some(value) => Ok(ParsedLockfile::Dotnet(value)),
            None => Ok(ParsedLockfile::None),
        },
        Some(Ecosystem::Ruby) => match ruby::read_lockfile(project_dir) {
            Some(content) => Ok(ParsedLockfile::Ruby(content)),
            None => Ok(ParsedLockfile::None),
        },
        Some(Ecosystem::PyPI) => match python::read_lockfile(project_dir)? {
            Some(value) => Ok(ParsedLockfile::Python(value)),
            None => Ok(ParsedLockfile::None),
        },
        _ => Ok(ParsedLockfile::None),
    }
}

fn read_lockfile_for_project_kind(
    project_dir: &Path,
    project_kind: crate::ProjectInputKind,
) -> Result<ParsedLockfile> {
    match project_kind {
        crate::ProjectInputKind::Npm => read_lockfile(project_dir, Some(Ecosystem::Npm), None),
        crate::ProjectInputKind::PyProjectPoetry => {
            read_lockfile(project_dir, Some(Ecosystem::PyPI), None)
        }
        crate::ProjectInputKind::PyRequirements
        | crate::ProjectInputKind::PyProjectLegacy
        | crate::ProjectInputKind::PyPipfile
        | crate::ProjectInputKind::PySetupPy
        | crate::ProjectInputKind::PySetupCfg => Ok(ParsedLockfile::None),
        crate::ProjectInputKind::Cargo => read_lockfile(project_dir, Some(Ecosystem::Cargo), None),
        crate::ProjectInputKind::Go => read_lockfile(project_dir, Some(Ecosystem::Go), None),
        crate::ProjectInputKind::Ruby => read_lockfile(project_dir, Some(Ecosystem::Ruby), None),
        crate::ProjectInputKind::Php => read_lockfile(project_dir, Some(Ecosystem::Php), None),
        crate::ProjectInputKind::Gradle => read_lockfile(project_dir, Some(Ecosystem::Jvm), None),
        crate::ProjectInputKind::Maven => Ok(ParsedLockfile::None),
        crate::ProjectInputKind::Dotnet => {
            read_lockfile(project_dir, Some(Ecosystem::Dotnet), None)
        }
    }
}

/// Resolve versions from a pre-parsed lockfile.
fn resolve_from_parsed(parsed: &ParsedLockfile, deps: &[Dependency]) -> Result<ResolutionResult> {
    match parsed {
        ParsedLockfile::Npm { value, file_name } => npm::resolve_from_value(value, deps, file_name),
        ParsedLockfile::Cargo(value) => cargo::resolve_from_value(value, deps),
        ParsedLockfile::Composer(value) => composer::resolve_from_value(value, deps),
        ParsedLockfile::Dotnet(value) => dotnet::resolve_from_value(value, deps),
        ParsedLockfile::Gradle(content) => gradle::resolve_from_content(content, deps),
        ParsedLockfile::Python(value) => python::resolve_from_value(value, deps),
        ParsedLockfile::Ruby(content) => ruby::resolve_from_content(content, deps),
        ParsedLockfile::None => {
            let mut result = ResolutionResult::default();
            add_manifest_exact_fallbacks(&mut result, deps);
            Ok(result)
        }
    }
}

/// Extract all deps from a pre-parsed lockfile.
fn parse_all_from_parsed(parsed: &ParsedLockfile) -> Result<Vec<Dependency>> {
    match parsed {
        ParsedLockfile::Npm { value, .. } => npm::parse_all_from_value(value),
        ParsedLockfile::Cargo(value) => cargo::parse_all_from_value(value),
        ParsedLockfile::Composer(value) => composer::parse_all_from_value(value),
        ParsedLockfile::Dotnet(value) => dotnet::parse_all_from_value(value),
        ParsedLockfile::Gradle(content) => gradle::parse_all_from_content(content),
        ParsedLockfile::Python(value) => python::parse_all_from_value(value),
        ParsedLockfile::Ruby(content) => ruby::parse_all_from_content(content),
        ParsedLockfile::None => Ok(vec![]),
    }
}

fn parse_all_from_parsed_for_project(
    parsed: &ParsedLockfile,
    direct_deps: &[Dependency],
) -> Result<Vec<Dependency>> {
    match parsed {
        ParsedLockfile::Npm { value, .. } => npm::parse_transitive_from_value(value, direct_deps),
        _ => parse_all_from_parsed(parsed),
    }
}

#[cfg(test)]
pub(crate) fn resolve_versions(
    project_dir: &Path,
    deps: &[Dependency],
) -> Result<ResolutionResult> {
    let Some(first) = deps.first() else {
        return Ok(ResolutionResult::default());
    };

    match first.ecosystem {
        Ecosystem::Npm => npm::resolve(project_dir, deps),
        Ecosystem::Cargo => cargo::resolve(project_dir, deps),
        Ecosystem::Php => composer::resolve(project_dir, deps),
        Ecosystem::Jvm => gradle::resolve(project_dir, deps),
        Ecosystem::Dotnet => dotnet::resolve(project_dir, deps),
        Ecosystem::Ruby => ruby::resolve(project_dir, deps),
        Ecosystem::PyPI => python::resolve(project_dir, deps),
        _ => {
            let mut result = ResolutionResult::default();
            add_manifest_exact_fallbacks(&mut result, deps);
            Ok(result)
        }
    }
}

// -- Shared helpers used by npm.rs and cargo.rs --

fn first_existing(project_dir: &Path, names: &[&str]) -> Option<PathBuf> {
    names.iter().find_map(|name| {
        let path = project_dir.join(name);
        match crate::parsers::path_detected(&path) {
            Ok(true) => Some(path),
            _ => None,
        }
    })
}

fn add_manifest_exact_fallbacks(result: &mut ResolutionResult, deps: &[Dependency]) {
    for dep in deps {
        add_manifest_exact_fallback(result, dep);
    }
}

fn add_manifest_exact_fallback(result: &mut ResolutionResult, dep: &Dependency) {
    if let Some(exact_version) = dep.exact_version() {
        result.exact_versions.insert(
            ResolutionKey::from(dep),
            ResolvedVersion {
                version: exact_version,
                source: ResolutionSource::ManifestExact,
            },
        );
    }
}

fn parse_failed_issue(lockfile: &str, detail: String) -> Issue {
    Issue::new("<lockfile>", crate::checks::names::RESOLUTION_PARSE_FAILED, Severity::Error)
        .message(format!(
            "Could not parse '{}'. Exact lockfile resolution is unavailable, so version-sensitive checks cannot trust this project state. {}",
            lockfile, detail
        ))
        .fix(format!(
            "Repair or regenerate '{}', then rerun sloppy-joe.",
            lockfile
        ))
}

fn missing_entry_issue(dep: &Dependency, lockfile: &str) -> Issue {
    Issue::new(&dep.name, crate::checks::names::RESOLUTION_MISSING_LOCKFILE_ENTRY, Severity::Error)
        .message(format!(
            "'{}' is declared in the manifest but was not found in '{}'. Exact version-sensitive checks cannot trust this lockfile state.",
            dep.name, lockfile
        ))
        .fix(format!(
            "Regenerate '{}' so it contains the direct dependency '{}', then rerun sloppy-joe.",
            lockfile, dep.name
        ))
}

fn out_of_sync_issue(dep: &Dependency, resolved_version: &str) -> Issue {
    Issue::new(&dep.name, crate::checks::names::RESOLUTION_LOCKFILE_OUT_OF_SYNC, Severity::Error)
        .message(format!(
            "'{}' is pinned to '{}' in the manifest but resolves to '{}' in the lockfile. Exact version-sensitive checks cannot trust this project state.",
            dep.name,
            dep.version.as_deref().unwrap_or(""),
            resolved_version
        ))
        .fix("Update the manifest or regenerate the lockfile so both describe the same direct dependency version.")
}

fn ambiguous_issue(dep: &Dependency) -> Issue {
    Issue::new(&dep.name, crate::checks::names::RESOLUTION_AMBIGUOUS, Severity::Error)
        .message(format!(
            "'{}' resolves to multiple locked versions and the direct dependency version cannot be proven exactly from the manifest.",
            dep.name
        ))
        .fix("Pin an exact manifest version or regenerate the lockfile so the direct dependency version is unambiguous.")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_dir() -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sj-lockfiles-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn npm_dep(name: &str, version: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: Some(version.to_string()),
            ecosystem: Ecosystem::Npm,
            actual_name: None,
        }
    }

    fn cargo_dep(name: &str, version: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: Some(version.to_string()),
            ecosystem: Ecosystem::Cargo,
            actual_name: None,
        }
    }

    // -- Resolution tests (unchanged, exercising the same public API) --

    #[test]
    fn uses_manifest_exact_when_no_supported_lockfile_exists() {
        let dir = unique_dir();
        let deps = vec![npm_dep("react", "18.3.1")];
        let result = resolve_versions(&dir, &deps).unwrap();
        let resolved = result.resolved_version(&deps[0]).unwrap();
        assert_eq!(resolved.version, "18.3.1");
        assert_eq!(resolved.source, ResolutionSource::ManifestExact);
        assert!(result.issues.is_empty());
    }

    #[test]
    fn npm_package_lock_v3_resolves_direct_dependency() {
        let dir = unique_dir();
        std::fs::write(dir.join("package-lock.json"), r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.2.0"}},"node_modules/react":{"version":"18.3.1"}}}"#).unwrap();
        let deps = vec![npm_dep("react", "^18.2.0")];
        let result = resolve_versions(&dir, &deps).unwrap();
        let resolved = result.resolved_version(&deps[0]).unwrap();
        assert_eq!(resolved.version, "18.3.1");
        assert_eq!(resolved.source, ResolutionSource::Lockfile);
        assert!(result.issues.is_empty());
    }

    #[test]
    fn npm_package_lock_v1_resolves_direct_dependency() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{"name":"demo","lockfileVersion":1,"dependencies":{"react":{"version":"18.3.1"}}}"#,
        )
        .unwrap();
        let deps = vec![npm_dep("react", "^18.2.0")];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert_eq!(result.resolved_version(&deps[0]).unwrap().version, "18.3.1");
    }

    #[test]
    fn npm_shrinkwrap_takes_precedence_over_package_lock() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.2.0"}},"node_modules/react":{"version":"18.3.1"}}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("npm-shrinkwrap.json"),
            r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.2.0"}},"node_modules/react":{"version":"18.2.9"}}}"#,
        )
        .unwrap();
        let deps = vec![npm_dep("react", "^18.2.0")];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert_eq!(result.resolved_version(&deps[0]).unwrap().version, "18.2.9");
    }

    #[test]
    fn npm_alias_resolves_against_alias_path_but_real_package_identity() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package.json"),
            r#"{"dependencies":{"lodash":"npm:evil-pkg@1.2.3"}}"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"lodash":"npm:evil-pkg@1.2.3"}},"node_modules/lodash":{"name":"evil-pkg","version":"1.2.3"}}}"#,
        )
        .unwrap();

        let deps = crate::parsers::package_json::parse(&dir).unwrap();
        let data = LockfileData::parse(&dir, &deps).unwrap();

        assert_eq!(data.resolution.exact_version(&deps[0]), Some("1.2.3"));
        assert!(
            data.transitive_deps.is_empty(),
            "direct alias target must not be reintroduced as transitive"
        );
    }

    #[test]
    fn npm_parse_retains_nested_versions_of_direct_package_names() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.3.1"}},"node_modules/react":{"version":"18.3.1"},"node_modules/other":{"version":"1.0.0"},"node_modules/other/node_modules/react":{"version":"17.0.2"}}}"#,
        )
        .unwrap();

        let direct = vec![npm_dep("react", "18.3.1")];
        let data = LockfileData::parse(&dir, &direct).expect(
            "nested locked versions of a direct package must still be scanned as transitive deps",
        );

        assert!(
            data.transitive_deps
                .iter()
                .any(|dep| dep.name == "react" && dep.version.as_deref() == Some("17.0.2")),
            "nested direct-name versions must remain visible as transitive deps"
        );
    }

    #[test]
    fn npm_parse_skips_linked_workspace_entries() {
        let lockfile = r#"{
            "packages": {
                "": { "name": "demo" },
                "packages/local-lib": { "name": "local-lib", "version": "1.0.0" },
                "node_modules/local-lib": { "resolved": "packages/local-lib", "link": true },
                "node_modules/react": { "version": "18.3.1" }
            }
        }"#;
        let deps =
            npm::parse_all(lockfile).expect("lockfile parsing should ignore linked local entries");
        let names: Vec<&str> = deps.iter().map(|dep| dep.name.as_str()).collect();
        assert_eq!(names, vec!["react"]);
    }

    #[test]
    fn npm_v1_parse_retains_nested_transitive_dependencies() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{"name":"demo","lockfileVersion":1,"dependencies":{"react":{"version":"18.3.1","dependencies":{"loose-envify":{"version":"1.4.0"}}}}}"#,
        )
        .unwrap();

        let direct = vec![npm_dep("react", "18.3.1")];
        let data = LockfileData::parse(&dir, &direct)
            .expect("legacy npm lockfiles must recurse nested transitive dependencies");

        assert!(
            data.transitive_deps
                .iter()
                .any(|dep| dep.name == "loose-envify" && dep.version.as_deref() == Some("1.4.0")),
            "nested v1 transitive dependencies must remain visible"
        );
    }

    #[test]
    fn npm_exact_pin_out_of_sync_emits_resolution_issue() {
        let dir = unique_dir();
        std::fs::write(dir.join("package-lock.json"), r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.2.0"}},"node_modules/react":{"version":"18.3.1"}}}"#).unwrap();
        let deps = vec![npm_dep("react", "18.2.0")];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert_eq!(
            result.resolved_version(&deps[0]).unwrap().source,
            ResolutionSource::ManifestExact
        );
        assert!(
            result
                .issues
                .iter()
                .any(|i| i.check == crate::checks::names::RESOLUTION_LOCKFILE_OUT_OF_SYNC)
        );
    }

    #[test]
    fn npm_missing_direct_dependency_emits_resolution_issue() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("package-lock.json"),
            r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo"}}}"#,
        )
        .unwrap();
        let deps = vec![npm_dep("react", "^18.2.0")];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert!(result.resolved_version(&deps[0]).is_none());
        assert!(
            result
                .issues
                .iter()
                .any(|i| i.check == crate::checks::names::RESOLUTION_MISSING_LOCKFILE_ENTRY)
        );
    }

    #[test]
    fn npm_malformed_lockfile_emits_parse_failed_issue() {
        let dir = unique_dir();
        std::fs::write(dir.join("package-lock.json"), "{not json").unwrap();
        let deps = vec![npm_dep("react", "18.2.0")];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert_eq!(
            result.resolved_version(&deps[0]).unwrap().source,
            ResolutionSource::ManifestExact
        );
        assert!(
            result
                .issues
                .iter()
                .any(|i| i.check == crate::checks::names::RESOLUTION_PARSE_FAILED)
        );
    }

    #[test]
    fn lockfile_data_parse_npm_malformed_lockfile_errors() {
        let dir = unique_dir();
        std::fs::write(dir.join("package-lock.json"), "{not json").unwrap();
        let deps = vec![npm_dep("react", "^18.2.0")];

        let err = match LockfileData::parse(&dir, &deps) {
            Ok(_) => panic!("malformed npm lockfiles must block scanning"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("package-lock.json"));
    }

    #[test]
    fn cargo_lock_resolves_single_locked_version() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("Cargo.lock"),
            "[[package]]\nname = \"serde\"\nversion = \"1.0.203\"\n",
        )
        .unwrap();
        let deps = vec![cargo_dep("serde", "1")];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert_eq!(
            result.resolved_version(&deps[0]).unwrap().version,
            "1.0.203"
        );
        assert_eq!(
            result.resolved_version(&deps[0]).unwrap().source,
            ResolutionSource::Lockfile
        );
    }

    #[test]
    fn cargo_lock_uses_exact_manifest_match_when_multiple_versions_exist() {
        let dir = unique_dir();
        std::fs::write(dir.join("Cargo.lock"), "[[package]]\nname = \"serde\"\nversion = \"1.0.201\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.203\"\n").unwrap();
        let deps = vec![cargo_dep("serde", "=1.0.203")];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert_eq!(
            result.resolved_version(&deps[0]).unwrap().version,
            "1.0.203"
        );
    }

    #[test]
    fn cargo_lock_resolves_lockfile_extracted_version_against_multiple() {
        // Transitive deps from parse_all have version "0.52.0" (no = prefix).
        // When re-resolved against a lockfile with multiple versions of the same
        // package, the version should match directly — not emit ambiguous.
        let dir = unique_dir();
        std::fs::write(
            dir.join("Cargo.lock"),
            "[[package]]\nname = \"windows-sys\"\nversion = \"0.52.0\"\n\n[[package]]\nname = \"windows-sys\"\nversion = \"0.59.0\"\n",
        ).unwrap();
        // This is what parse_all_from_value produces: version without = prefix
        let deps = vec![cargo_dep("windows-sys", "0.52.0")];
        let result = resolve_versions(&dir, &deps).unwrap();
        // Should resolve successfully — the version matches exactly
        assert_eq!(
            result.resolved_version(&deps[0]).unwrap().version,
            "0.52.0",
            "Lockfile-extracted version should resolve against multiple versions"
        );
        assert!(
            !result
                .issues
                .iter()
                .any(|i| i.check == crate::checks::names::RESOLUTION_AMBIGUOUS),
            "Should not emit ambiguous issue when version matches"
        );
    }

    #[test]
    fn cargo_lock_ambiguous_versions_emit_resolution_issue() {
        let dir = unique_dir();
        std::fs::write(dir.join("Cargo.lock"), "[[package]]\nname = \"serde\"\nversion = \"1.0.201\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.203\"\n").unwrap();
        let deps = vec![cargo_dep("serde", "1")];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert!(result.resolved_version(&deps[0]).is_none());
        assert!(
            result
                .issues
                .iter()
                .any(|i| i.check == crate::checks::names::RESOLUTION_AMBIGUOUS)
        );
    }

    #[test]
    fn cargo_lock_missing_direct_dependency_emits_resolution_issue() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("Cargo.lock"),
            "[[package]]\nname = \"tokio\"\nversion = \"1.42.0\"\n",
        )
        .unwrap();
        let deps = vec![cargo_dep("serde", "1")];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert!(result.resolved_version(&deps[0]).is_none());
        assert!(
            result
                .issues
                .iter()
                .any(|i| i.check == crate::checks::names::RESOLUTION_MISSING_LOCKFILE_ENTRY)
        );
    }

    #[test]
    fn parse_all_npm_fails_on_malformed_json() {
        let result = npm::parse_all("{not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn parse_all_npm_succeeds_on_valid_lockfile() {
        let content = r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo"},"node_modules/react":{"version":"18.3.1"},"node_modules/lodash":{"version":"4.17.21"}}}"#;
        let deps = npm::parse_all(content).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.name == "react"));
        assert!(deps.iter().any(|d| d.name == "lodash"));
    }

    #[test]
    fn parse_all_cargo_fails_on_malformed_toml() {
        let result = cargo::parse_all("[[package]");
        assert!(result.is_err());
    }

    #[test]
    fn parse_all_cargo_succeeds_on_valid_lockfile() {
        let content = "[[package]]\nname = \"serde\"\nversion = \"1.0.203\"\n\n[[package]]\nname = \"tokio\"\nversion = \"1.42.0\"\n";
        let deps = cargo::parse_all(content).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().any(|d| d.name == "serde"));
        assert!(deps.iter().any(|d| d.name == "tokio"));
    }

    #[test]
    fn cargo_lock_rejects_path_traversal() {
        let dir = unique_dir();
        std::fs::write(dir.join("Cargo.lock"), "[[package]]\nname = \"../malicious\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"safe-pkg\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"foo\\u0000bar\"\nversion = \"1.0.0\"\n").unwrap();
        let deps = vec![
            cargo_dep("../malicious", "1.0.0"),
            cargo_dep("safe-pkg", "1.0.0"),
        ];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert!(result.resolved_version(&deps[0]).is_none());
        assert_eq!(result.resolved_version(&deps[1]).unwrap().version, "1.0.0");
    }

    #[test]
    fn cargo_lock_malformed_lockfile_emits_parse_failed_issue() {
        let dir = unique_dir();
        std::fs::write(dir.join("Cargo.lock"), "[[package]").unwrap();
        let deps = vec![cargo_dep("serde", "1")];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert!(result.resolved_version(&deps[0]).is_none());
        assert!(
            result
                .issues
                .iter()
                .any(|i| i.check == crate::checks::names::RESOLUTION_PARSE_FAILED)
        );
    }

    #[test]
    fn lockfile_data_parse_provides_resolution_and_transitive() {
        let dir = unique_dir();
        std::fs::write(dir.join("package-lock.json"), r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"^18.2.0"}},"node_modules/react":{"version":"18.3.1"},"node_modules/loose-envify":{"version":"1.4.0"}}}"#).unwrap();
        let direct = vec![npm_dep("react", "^18.2.0")];
        let data = LockfileData::parse(&dir, &direct).unwrap();
        assert_eq!(data.resolution.exact_version(&direct[0]), Some("18.3.1"));
        assert_eq!(data.transitive_deps.len(), 1);
        assert_eq!(data.transitive_deps[0].name, "loose-envify");
    }

    // ── Ruby lockfile path tests ──

    fn ruby_dep(name: &str, version: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: Some(version.to_string()),
            ecosystem: Ecosystem::Ruby,
            actual_name: None,
        }
    }

    fn pypi_dep(name: &str, version: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: Some(version.to_string()),
            ecosystem: Ecosystem::PyPI,
            actual_name: None,
        }
    }

    fn go_dep(name: &str, version: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: Some(version.to_string()),
            ecosystem: Ecosystem::Go,
            actual_name: None,
        }
    }

    fn php_dep(name: &str, version: Option<&str>) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.map(str::to_string),
            ecosystem: Ecosystem::Php,
            actual_name: None,
        }
    }

    fn jvm_dep(name: &str, version: Option<&str>) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.map(str::to_string),
            ecosystem: Ecosystem::Jvm,
            actual_name: None,
        }
    }

    fn dotnet_dep(name: &str, version: Option<&str>) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: version.map(str::to_string),
            ecosystem: Ecosystem::Dotnet,
            actual_name: None,
        }
    }

    #[test]
    fn ruby_lockfile_resolves_versions() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("Gemfile.lock"),
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n    pg (1.4.5)\n\nPLATFORMS\n  ruby\n",
        )
        .unwrap();
        let deps = vec![ruby_dep("rails", "~> 7.0"), ruby_dep("pg", "1.4.5")];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert_eq!(result.resolved_version(&deps[0]).unwrap().version, "7.0.4");
        assert_eq!(result.resolved_version(&deps[1]).unwrap().version, "1.4.5");
    }

    #[test]
    fn ruby_no_lockfile_uses_manifest_fallback() {
        let dir = unique_dir();
        // No Gemfile.lock — should fall back to manifest exact
        let deps = vec![ruby_dep("rails", "7.0.4")];
        let result = resolve_versions(&dir, &deps).unwrap();
        // "7.0.4" is exact for Ruby ecosystem
        assert_eq!(
            result.resolved_version(&deps[0]).unwrap().source,
            ResolutionSource::ManifestExact
        );
    }

    #[test]
    fn python_poetry_projects_use_poetry_lock() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("poetry.lock"),
            "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[metadata]\nlock-version = \"2.0\"\npython-versions = \"^3.8\"\n",
        )
        .unwrap();
        let deps = vec![pypi_dep("requests", "==2.31.0")];
        let result = LockfileData::parse_for_kind(
            &dir,
            Some(crate::ProjectInputKind::PyProjectPoetry),
            &deps,
        )
        .unwrap()
        .resolution;
        assert_eq!(
            result.resolved_version(&deps[0]).unwrap().source,
            ResolutionSource::Lockfile
        );
    }

    #[test]
    fn legacy_python_projects_do_not_use_poetry_lock() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("poetry.lock"),
            "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[metadata]\nlock-version = \"2.0\"\npython-versions = \"^3.8\"\n",
        )
        .unwrap();
        let deps = vec![pypi_dep("requests", "==2.31.0")];
        let result = LockfileData::parse_for_kind(
            &dir,
            Some(crate::ProjectInputKind::PyRequirements),
            &deps,
        )
        .unwrap()
        .resolution;
        assert_eq!(
            result.resolved_version(&deps[0]).unwrap().source,
            ResolutionSource::ManifestExact
        );
    }

    #[test]
    fn python_no_lockfile_uses_manifest_fallback() {
        let dir = unique_dir();
        let deps = vec![pypi_dep("requests", "==2.31.0")];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert_eq!(
            result.resolved_version(&deps[0]).unwrap().source,
            ResolutionSource::ManifestExact
        );
    }

    #[test]
    fn lockfile_data_parse_python_rejects_malformed_poetry_lockfiles() {
        let dir = unique_dir();
        std::fs::write(dir.join("poetry.lock"), "not = [valid").unwrap();
        let deps = vec![pypi_dep("requests", "==2.31.0")];

        let err = match LockfileData::parse(&dir, &deps) {
            Ok(_) => panic!("trusted Python lockfiles must fail closed on parse errors"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("poetry.lock"));
    }

    #[test]
    fn maven_projects_do_not_read_gradle_lockfiles() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("gradle.lockfile"),
            "com.google.guava:guava:31.1-jre=compileClasspath\n",
        )
        .unwrap();
        let deps = vec![jvm_dep("com.google.guava:guava", Some("31.1-jre"))];

        let data = LockfileData::parse_for_kind(&dir, Some(crate::ProjectInputKind::Maven), &deps)
            .expect("Maven projects must not consume gradle.lockfile");

        assert_eq!(
            data.resolution.resolved_version(&deps[0]).unwrap().source,
            ResolutionSource::ManifestExact
        );
        assert!(data.transitive_deps.is_empty());
    }

    #[test]
    fn go_no_lockfile_uses_manifest_fallback() {
        let dir = unique_dir();
        let deps = vec![go_dep("github.com/gin-gonic/gin", "v1.9.0")];
        let result = resolve_versions(&dir, &deps).unwrap();
        // Go ecosystem uses the "other" fallback path
        assert_eq!(
            result.resolved_version(&deps[0]).unwrap().source,
            ResolutionSource::ManifestExact
        );
    }

    #[test]
    fn lockfile_data_parse_ruby_with_transitive() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("Gemfile.lock"),
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.4)\n    actioncable (7.0.4)\n    pg (1.4.5)\n\nPLATFORMS\n  ruby\n",
        )
        .unwrap();
        let direct = vec![ruby_dep("rails", "~> 7.0")];
        let data = LockfileData::parse(&dir, &direct).unwrap();
        assert_eq!(data.resolution.exact_version(&direct[0]), Some("7.0.4"));
        // actioncable and pg are transitive
        assert!(data.transitive_deps.len() >= 2);
        let names: Vec<&str> = data
            .transitive_deps
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert!(names.contains(&"actioncable"));
        assert!(names.contains(&"pg"));
    }

    #[test]
    fn lockfile_data_parse_python_exposes_transitive_dependencies_from_trusted_lockfile() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("poetry.lock"),
            "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[[package]]\nname = \"urllib3\"\nversion = \"2.1.0\"\n\n[metadata]\nlock-version = \"2.0\"\npython-versions = \"^3.8\"\n",
        )
        .unwrap();
        let direct = vec![pypi_dep("requests", "==2.31.0")];
        let data = LockfileData::parse(&dir, &direct).unwrap();
        assert_eq!(data.resolution.exact_version(&direct[0]), Some("2.31.0"));
        assert!(
            data.transitive_deps
                .iter()
                .any(|dep| dep.name == "urllib3" && dep.version.as_deref() == Some("2.1.0"))
        );
    }

    #[test]
    fn lockfile_data_parse_php_with_transitive() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("composer.lock"),
            r#"{
  "packages": [
    {"name": "laravel/framework", "version": "v10.0.0"},
    {"name": "symfony/console", "version": "v6.4.0"}
  ],
  "packages-dev": []
}"#,
        )
        .unwrap();
        let direct = vec![php_dep("laravel/framework", Some("^10.0"))];
        let data = LockfileData::parse(&dir, &direct).unwrap();
        let resolved = data.resolution.resolved_version(&direct[0]).unwrap();
        assert_eq!(resolved.version, "v10.0.0");
        assert_eq!(resolved.source, ResolutionSource::Lockfile);
        assert_eq!(data.transitive_deps.len(), 1);
        assert_eq!(data.transitive_deps[0].name, "symfony/console");
    }

    #[test]
    fn lockfile_data_parse_gradle_with_transitive() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("gradle.lockfile"),
            "\
org.slf4j:slf4j-api:2.0.9=compileClasspath,runtimeClasspath\n\
ch.qos.logback:logback-core:1.4.14=runtimeClasspath\n\
empty=annotationProcessor\n",
        )
        .unwrap();
        let direct = vec![jvm_dep("org.slf4j:slf4j-api", None)];
        let data = LockfileData::parse(&dir, &direct).unwrap();
        let resolved = data.resolution.resolved_version(&direct[0]).unwrap();
        assert_eq!(resolved.version, "2.0.9");
        assert_eq!(resolved.source, ResolutionSource::Lockfile);
        assert_eq!(data.transitive_deps.len(), 1);
        assert_eq!(data.transitive_deps[0].name, "ch.qos.logback:logback-core");
    }

    #[test]
    fn lockfile_data_parse_dotnet_with_transitive() {
        let dir = unique_dir();
        std::fs::write(
            dir.join("packages.lock.json"),
            r#"{
  "version": 1,
  "dependencies": {
    ".NETCoreApp,Version=v8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "13.0.1",
        "resolved": "13.0.1",
        "dependencies": {
          "System.Runtime.CompilerServices.Unsafe": "6.0.0"
        }
      },
      "System.Runtime.CompilerServices.Unsafe": {
        "type": "Transitive",
        "resolved": "6.0.0"
      }
    }
  }
}"#,
        )
        .unwrap();
        let direct = vec![dotnet_dep("Newtonsoft.Json", Some("13.0.1"))];
        let data = LockfileData::parse(&dir, &direct).unwrap();
        let resolved = data.resolution.resolved_version(&direct[0]).unwrap();
        assert_eq!(resolved.version, "13.0.1");
        assert_eq!(resolved.source, ResolutionSource::Lockfile);
        assert_eq!(data.transitive_deps.len(), 1);
        assert_eq!(
            data.transitive_deps[0].name,
            "System.Runtime.CompilerServices.Unsafe"
        );
    }

    #[test]
    fn lockfile_data_parse_no_lockfile_returns_empty_transitive() {
        let dir = unique_dir();
        let direct = vec![npm_dep("react", "18.3.1")];
        let data = LockfileData::parse(&dir, &direct).unwrap();
        assert!(data.transitive_deps.is_empty());
    }

    #[test]
    fn resolve_versions_empty_deps_returns_default() {
        let dir = unique_dir();
        let deps: Vec<Dependency> = vec![];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert!(result.exact_versions.is_empty());
        assert!(result.issues.is_empty());
    }
}
