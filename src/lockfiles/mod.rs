/// How a project reads its lockfile: the parser itself, chosen by the project's descriptor.
/// There is no tag to match on; the format is the function.
#[derive(Clone, Copy)]
pub(crate) struct LockfileKind(pub(crate) fn(&Path, Option<&Path>) -> Result<ParsedLockfile>);

impl std::fmt::Debug for LockfileKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LockfileKind")
    }
}

mod nesting;
#[cfg(test)]
mod parse_helpers_tests;
pub(crate) use nesting::*;
mod issues;
pub(crate) use issues::*;
mod importer;
pub(crate) use importer::*;
mod read;
pub(crate) use read::*;
pub(crate) mod bun;
mod cargo;
mod composer;
mod dotnet;
mod gradle;
pub(crate) mod integrity;
pub(crate) mod npm;
pub(crate) mod pipfile_lock;
pub(crate) mod pnpm;
pub(crate) mod python;
pub(crate) mod python_hashes;
mod ruby;
pub(crate) mod uv;
pub(crate) mod yarn;

#[cfg(test)]
mod redteam_tests;

#[cfg(test)]
mod js_reachability_tests;

#[cfg(test)]
mod bun_nested_tests;

#[cfg(test)]
mod poetry_split_resolution_tests;

#[cfg(test)]
mod pnpm_multidoc_tests;

#[cfg(test)]
mod cargo_range_tests;

use crate::Dependency;
use crate::Ecosystem;
use crate::parsers::python_scope::{PythonProfile, PythonRootExtras};
use crate::report::{Issue, Severity};
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub(crate) struct PythonLockfileProfile {
    pub(crate) environment: PythonProfile,
    pub(crate) root_extras: PythonRootExtras,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct PythonPackageIdentity {
    pub(crate) normalized_name: String,
    pub(crate) version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionSource {
    Lockfile,
    ManifestExact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResolutionMode {
    Direct,
    Transitive,
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
    issue_keys: HashSet<(String, ResolutionKey)>,
    /// Integrity recorded by an npm-family lockfile, per package version.
    pub(crate) npm_integrity: Option<std::sync::Arc<integrity::NpmLockfileIntegrity>>,
    /// Artifact hashes recorded by a Python lockfile, per package version.
    pub(crate) python_hashes: Option<std::sync::Arc<python_hashes::PythonLockfileHashes>>,
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

    pub fn has_issue_for(&self, dep: &Dependency, check: &str) -> bool {
        self.issue_keys
            .contains(&(check.to_string(), ResolutionKey::from(dep)))
    }

    pub fn push_issue(&mut self, issue: Issue) {
        self.issues.push(issue);
    }

    pub fn push_issue_for(&mut self, dep: &Dependency, issue: Issue) {
        self.issue_keys
            .insert((issue.check.clone(), ResolutionKey::from(dep)));
        self.issues.push(issue);
    }
}

/// In-memory representation of a parsed lockfile.
/// Parsed once, used for both version resolution and transitive dep extraction.
pub(crate) enum ParsedLockfile {
    Npm {
        value: serde_json::Value,
        file_name: String,
        project_key: String,
    },
    NpmLegacy {
        value: serde_json::Value,
        file_name: String,
    },
    Pnpm {
        value: serde_yaml::Value,
        importer_key: String,
        path: PathBuf,
    },
    Bun {
        value: serde_json::Value,
        importer_key: String,
    },
    Yarn(yarn::ParsedYarnLock),
    Cargo(toml::Value),
    Composer(serde_json::Value),
    Dotnet(serde_json::Value),
    Gradle(String),
    Python(toml::Value),
    Uv(toml::Value),
    Pipfile(serde_json::Value),
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
    npm_integrity: Option<std::sync::Arc<integrity::NpmLockfileIntegrity>>,
    python_hashes: Option<std::sync::Arc<python_hashes::PythonLockfileHashes>>,
}

impl LockfileData {
    pub fn parse_for_kind_with_lockfile_and_profile(
        project_dir: &Path,
        project_kind: LockfileKind,
        direct_deps: &[Dependency],
        lockfile_override: Option<&Path>,
        python_profile: Option<&PythonLockfileProfile>,
    ) -> Result<Self> {
        // Read and parse the lockfile once
        let parsed = read_lockfile(project_dir, project_kind, lockfile_override)?;

        // Resolve direct dep versions from the parsed data
        let mut resolution =
            resolve_from_parsed(&parsed, direct_deps, ResolutionMode::Direct, python_profile)?;
        let npm_integrity = integrity::collect(&parsed).map(std::sync::Arc::new);
        resolution.npm_integrity = npm_integrity.clone();
        let python_hashes = python_hashes::collect(&parsed).map(std::sync::Arc::new);
        resolution.python_hashes = python_hashes.clone();

        let (all_deps, lockfile_issues) =
            parse_all_from_parsed_for_project(&parsed, direct_deps, project_dir, python_profile)?;
        resolution.issues.extend(lockfile_issues);

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
            npm_integrity,
            python_hashes,
        })
    }

    /// Resolve versions for transitive deps from the already-parsed lockfile.
    /// Eliminates the redundant disk read that `resolve_versions()` would do.
    pub fn resolve_transitive(&self, deps: &[Dependency]) -> Result<ResolutionResult> {
        let mut resolution =
            resolve_from_parsed(&self.parsed, deps, ResolutionMode::Transitive, None)?;
        resolution.npm_integrity = self.npm_integrity.clone();
        resolution.python_hashes = self.python_hashes.clone();
        Ok(resolution)
    }

    /// Treat every registry package the lockfile records as a transitive
    /// dependency. Used when the manifest declares no roots at all, so nothing
    /// proves which locked packages are installable (fail closed).
    pub fn scan_all_locked_packages(&mut self) -> Result<()> {
        let mut seen = HashSet::new();
        self.transitive_deps = parse_all_from_parsed(&self.parsed)?
            .into_iter()
            .filter(|dep| seen.insert((dep.package_name().to_string(), dep.version.clone())))
            .collect();
        Ok(())
    }

    pub fn reduced_confidence_from_manifest(direct_deps: &[Dependency]) -> Self {
        let mut resolution = ResolutionResult::default();
        add_manifest_exact_fallbacks(&mut resolution, direct_deps);
        Self {
            resolution,
            transitive_deps: Vec::new(),
            parsed: ParsedLockfile::None,
            npm_integrity: None,
            python_hashes: None,
        }
    }
}

#[cfg(test)]
mod tests;
