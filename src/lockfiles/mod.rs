mod cargo;
mod npm;

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
    None,
}

/// Pre-parsed lockfile data. Reads and parses the lockfile once, then provides
/// version resolution, transitive dep extraction, and re-resolution for transitive
/// deps — all from the same in-memory data.
pub struct LockfileData {
    pub resolution: ResolutionResult,
    pub transitive_deps: Vec<Dependency>,
    parsed: ParsedLockfile,
}

impl LockfileData {
    pub fn parse(project_dir: &Path, direct_deps: &[Dependency]) -> Result<Self> {
        let ecosystem = direct_deps.first().map(|d| d.ecosystem);

        // Read and parse the lockfile once
        let parsed = read_lockfile(project_dir, ecosystem)?;

        // Resolve direct dep versions from the parsed data
        let resolution = resolve_from_parsed(&parsed, direct_deps)?;

        // Extract all deps from the parsed data
        let all_deps = parse_all_from_parsed(&parsed)?;

        // Filter to transitive only
        let direct_names: HashSet<String> = direct_deps.iter().map(|d| d.name.clone()).collect();
        let mut transitive: Vec<Dependency> = all_deps
            .into_iter()
            .filter(|dep| !direct_names.contains(&dep.name))
            .collect();
        let mut seen = HashSet::new();
        transitive.retain(|dep| seen.insert((dep.name.clone(), dep.version.clone())));

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
fn read_lockfile(project_dir: &Path, ecosystem: Option<Ecosystem>) -> Result<ParsedLockfile> {
    match ecosystem {
        Some(Ecosystem::Npm) => {
            let Some(path) =
                first_existing(project_dir, &["package-lock.json", "npm-shrinkwrap.json"])
            else {
                return Ok(ParsedLockfile::None);
            };
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("package-lock.json")
                .to_string();
            let content =
                crate::parsers::read_file_limited(&path, crate::parsers::MAX_MANIFEST_BYTES)?;
            match serde_json::from_str(&content) {
                Ok(value) => Ok(ParsedLockfile::Npm { value, file_name }),
                Err(_) => Ok(ParsedLockfile::None), // parse error handled in resolve
            }
        }
        Some(Ecosystem::Cargo) => {
            let path = project_dir.join("Cargo.lock");
            if !path.exists() {
                return Ok(ParsedLockfile::None);
            }
            let content =
                crate::parsers::read_file_limited(&path, crate::parsers::MAX_MANIFEST_BYTES)?;
            match toml::from_str(&content) {
                Ok(value) => Ok(ParsedLockfile::Cargo(value)),
                Err(_) => Ok(ParsedLockfile::None),
            }
        }
        _ => Ok(ParsedLockfile::None),
    }
}

/// Resolve versions from a pre-parsed lockfile.
fn resolve_from_parsed(parsed: &ParsedLockfile, deps: &[Dependency]) -> Result<ResolutionResult> {
    match parsed {
        ParsedLockfile::Npm { value, file_name } => {
            npm::resolve_from_value(value, deps, file_name)
        }
        ParsedLockfile::Cargo(value) => cargo::resolve_from_value(value, deps),
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
        ParsedLockfile::None => Ok(vec![]),
    }
}

pub fn resolve_versions(project_dir: &Path, deps: &[Dependency]) -> Result<ResolutionResult> {
    let Some(first) = deps.first() else {
        return Ok(ResolutionResult::default());
    };

    match first.ecosystem {
        Ecosystem::Npm => npm::resolve(project_dir, deps),
        Ecosystem::Cargo => cargo::resolve(project_dir, deps),
        _ => {
            let mut result = ResolutionResult::default();
            add_manifest_exact_fallbacks(&mut result, deps);
            Ok(result)
        }
    }
}

// -- Shared helpers used by npm.rs and cargo.rs --

fn first_existing(project_dir: &Path, names: &[&str]) -> Option<PathBuf> {
    names
        .iter()
        .map(|name| project_dir.join(name))
        .find(|path| path.exists())
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
    Issue {
        package: "<lockfile>".to_string(),
        check: "resolution/parse-failed".to_string(),
        severity: Severity::Error,
        message: format!(
            "Could not parse '{}'. Exact lockfile resolution is unavailable, so version-sensitive checks cannot trust this project state. {}",
            lockfile, detail
        ),
        fix: format!(
            "Repair or regenerate '{}', then rerun sloppy-joe.",
            lockfile
        ),
        suggestion: None,
        registry_url: None,
        source: None,
    }
}

fn missing_entry_issue(dep: &Dependency, lockfile: &str) -> Issue {
    Issue {
        package: dep.name.clone(),
        check: "resolution/missing-lockfile-entry".to_string(),
        severity: Severity::Error,
        message: format!(
            "'{}' is declared in the manifest but was not found in '{}'. Exact version-sensitive checks cannot trust this lockfile state.",
            dep.name, lockfile
        ),
        fix: format!(
            "Regenerate '{}' so it contains the direct dependency '{}', then rerun sloppy-joe.",
            lockfile, dep.name
        ),
        suggestion: None,
        registry_url: None,
        source: None,
    }
}

fn out_of_sync_issue(dep: &Dependency, resolved_version: &str) -> Issue {
    Issue {
        package: dep.name.clone(),
        check: "resolution/lockfile-out-of-sync".to_string(),
        severity: Severity::Error,
        message: format!(
            "'{}' is pinned to '{}' in the manifest but resolves to '{}' in the lockfile. Exact version-sensitive checks cannot trust this project state.",
            dep.name,
            dep.version.as_deref().unwrap_or(""),
            resolved_version
        ),
        fix: "Update the manifest or regenerate the lockfile so both describe the same direct dependency version.".to_string(),
        suggestion: None,
        registry_url: None,
        source: None,
    }
}

fn ambiguous_issue(dep: &Dependency) -> Issue {
    Issue {
        package: dep.name.clone(),
        check: "resolution/ambiguous".to_string(),
        severity: Severity::Error,
        message: format!(
            "'{}' resolves to multiple locked versions and the direct dependency version cannot be proven exactly from the manifest.",
            dep.name
        ),
        fix: "Pin an exact manifest version or regenerate the lockfile so the direct dependency version is unambiguous.".to_string(),
        suggestion: None,
        registry_url: None,
        source: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_dir() -> std::path::PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("sj-lockfiles-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn npm_dep(name: &str, version: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: Some(version.to_string()),
            ecosystem: Ecosystem::Npm,
        }
    }

    fn cargo_dep(name: &str, version: &str) -> Dependency {
        Dependency {
            name: name.to_string(),
            version: Some(version.to_string()),
            ecosystem: Ecosystem::Cargo,
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
        std::fs::write(dir.join("package-lock.json"), r#"{"name":"demo","lockfileVersion":1,"dependencies":{"react":{"version":"18.3.1"}}}"#).unwrap();
        let deps = vec![npm_dep("react", "^18.2.0")];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert_eq!(result.resolved_version(&deps[0]).unwrap().version, "18.3.1");
    }

    #[test]
    fn npm_exact_pin_out_of_sync_emits_resolution_issue() {
        let dir = unique_dir();
        std::fs::write(dir.join("package-lock.json"), r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","dependencies":{"react":"18.2.0"}},"node_modules/react":{"version":"18.3.1"}}}"#).unwrap();
        let deps = vec![npm_dep("react", "18.2.0")];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert_eq!(result.resolved_version(&deps[0]).unwrap().source, ResolutionSource::ManifestExact);
        assert!(result.issues.iter().any(|i| i.check == "resolution/lockfile-out-of-sync"));
    }

    #[test]
    fn npm_missing_direct_dependency_emits_resolution_issue() {
        let dir = unique_dir();
        std::fs::write(dir.join("package-lock.json"), r#"{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo"}}}"#).unwrap();
        let deps = vec![npm_dep("react", "^18.2.0")];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert!(result.resolved_version(&deps[0]).is_none());
        assert!(result.issues.iter().any(|i| i.check == "resolution/missing-lockfile-entry"));
    }

    #[test]
    fn npm_malformed_lockfile_emits_parse_failed_issue() {
        let dir = unique_dir();
        std::fs::write(dir.join("package-lock.json"), "{not json").unwrap();
        let deps = vec![npm_dep("react", "18.2.0")];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert_eq!(result.resolved_version(&deps[0]).unwrap().source, ResolutionSource::ManifestExact);
        assert!(result.issues.iter().any(|i| i.check == "resolution/parse-failed"));
    }

    #[test]
    fn cargo_lock_resolves_single_locked_version() {
        let dir = unique_dir();
        std::fs::write(dir.join("Cargo.lock"), "[[package]]\nname = \"serde\"\nversion = \"1.0.203\"\n").unwrap();
        let deps = vec![cargo_dep("serde", "1")];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert_eq!(result.resolved_version(&deps[0]).unwrap().version, "1.0.203");
        assert_eq!(result.resolved_version(&deps[0]).unwrap().source, ResolutionSource::Lockfile);
    }

    #[test]
    fn cargo_lock_uses_exact_manifest_match_when_multiple_versions_exist() {
        let dir = unique_dir();
        std::fs::write(dir.join("Cargo.lock"), "[[package]]\nname = \"serde\"\nversion = \"1.0.201\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.203\"\n").unwrap();
        let deps = vec![cargo_dep("serde", "=1.0.203")];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert_eq!(result.resolved_version(&deps[0]).unwrap().version, "1.0.203");
    }

    #[test]
    fn cargo_lock_ambiguous_versions_emit_resolution_issue() {
        let dir = unique_dir();
        std::fs::write(dir.join("Cargo.lock"), "[[package]]\nname = \"serde\"\nversion = \"1.0.201\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.203\"\n").unwrap();
        let deps = vec![cargo_dep("serde", "1")];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert!(result.resolved_version(&deps[0]).is_none());
        assert!(result.issues.iter().any(|i| i.check == "resolution/ambiguous"));
    }

    #[test]
    fn cargo_lock_missing_direct_dependency_emits_resolution_issue() {
        let dir = unique_dir();
        std::fs::write(dir.join("Cargo.lock"), "[[package]]\nname = \"tokio\"\nversion = \"1.42.0\"\n").unwrap();
        let deps = vec![cargo_dep("serde", "1")];
        let result = resolve_versions(&dir, &deps).unwrap();
        assert!(result.resolved_version(&deps[0]).is_none());
        assert!(result.issues.iter().any(|i| i.check == "resolution/missing-lockfile-entry"));
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
        let deps = vec![cargo_dep("../malicious", "1.0.0"), cargo_dep("safe-pkg", "1.0.0")];
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
        assert!(result.issues.iter().any(|i| i.check == "resolution/parse-failed"));
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
}
