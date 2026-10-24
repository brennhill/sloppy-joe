//! One plugin per ecosystem.
//!
//! The scan engine never matches on a [`ProjectInputKind`]: it asks [`for_kind`] for the plugin
//! that owns a project and calls the trait. Static facts about a kind live in
//! [`ProjectInputKind::descriptor`]; behavior lives here. The trait's required methods have no
//! default implementation, so a new ecosystem does not compile until it answers each security
//! question (what is parsed, which lockfile is required, what blocks).

use crate::*;
use std::path::{Path, PathBuf};

mod cargo;
pub(crate) mod common;
mod dotnet;
mod go;
mod js;
mod jvm;
mod php;
mod python;
mod ruby;

pub(crate) use common::first_existing_lockfile;
use common::*;

/// Plugin internals that unit tests exercise directly. Production code goes through the trait.
#[cfg(test)]
pub(crate) mod test_access {
    pub(crate) use super::cargo::*;
    pub(crate) use super::js::*;
}

/// What a plugin needs to know about the scan it is part of.
pub(crate) struct ScanCtx<'a> {
    pub(crate) scan_root: &'a Path,
    pub(crate) config: &'a config::SloppyJoeConfig,
    pub(crate) opts: &'a ScanOptions<'a>,
}

/// Everything a preflight needs: the scan, the whole project set, and the selected projects.
pub(crate) struct PreflightCtx<'a> {
    pub(crate) scan: ScanCtx<'a>,
    pub(crate) canonical_root: PathBuf,
    js: js::JsPreflightState,
}

impl<'a> PreflightCtx<'a> {
    pub(crate) fn new(
        scan: ScanCtx<'a>,
        all_specs: &[ProjectInputSpec],
        selected: &[ProjectInputSpec],
    ) -> Result<Self> {
        let canonical_root = std::fs::canonicalize(scan.scan_root).map_err(|err| {
            anyhow::anyhow!(
                "Failed to inspect {} for project manifests: {}",
                scan.scan_root.display(),
                err
            )
        })?;
        let js = js::JsPreflightState::load(all_specs, selected)?;
        Ok(Self {
            scan,
            canonical_root,
            js,
        })
    }
}

pub(crate) trait EcosystemSupport: Sync {
    /// The project kinds this plugin owns. Every kind is owned by exactly one plugin.
    fn kinds(&self) -> &'static [ProjectInputKind];

    /// Lockfile the project is verified against when no explicit lockfile was bound; `None` when
    /// the kind has no lockfile of its own.
    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf>;

    /// Dependencies declared by the manifest, without scan-specific resolution.
    fn parse_manifest(&self, scan_root: &Path, spec: &ProjectInputSpec) -> Result<Vec<Dependency>>;

    /// Dependencies (and warnings/tooling) the scan checks for this project.
    fn parse(&self, ctx: &ScanCtx<'_>, spec: &ProjectInputSpec) -> Result<ParsedInput>;

    /// Classify a manifest path as one of this plugin's kinds. Unsupported lookalikes the scan
    /// would otherwise skip silently (e.g. `gems.rb`) are errors, never `None`.
    fn detect(&self, path: &Path) -> Result<Option<ProjectInputKind>>;

    /// Adjust the discovered projects after `--type` filtering: add local path dependencies,
    /// drop manifests another one owns, refuse ambiguity. No-op for most ecosystems.
    fn refine_specs(
        &self,
        _scan_root: &Path,
        _config: &config::SloppyJoeConfig,
        _specs: &mut Vec<ProjectInputSpec>,
    ) -> Result<()> {
        Ok(())
    }

    /// Bind projects to their package manager and lockfile. Projects that cannot be bound are
    /// returned with the reason; the scan reports them as incomplete. No-op for most ecosystems.
    fn bind(
        &self,
        _scan_root: &Path,
        _specs: &mut [ProjectInputSpec],
    ) -> std::collections::HashMap<PathBuf, anyhow::Error> {
        std::collections::HashMap::new()
    }

    /// Split build/tooling dependencies that no lockfile records into the groups that resolve
    /// from separate repositories. One group by default.
    fn tooling_groups(&self, unlocked: Vec<Dependency>) -> Vec<Vec<Dependency>> {
        vec![unlocked]
    }

    /// Verify the project's lockfile and policy before anything is scanned. An error blocks the
    /// project; the returned issues are warnings about reduced confidence.
    fn preflight(&self, ctx: &PreflightCtx<'_>, spec: &ProjectInputSpec) -> Result<Vec<Issue>>;
}

static PLUGINS: [&dyn EcosystemSupport; 8] = [
    &cargo::Cargo,
    &dotnet::Dotnet,
    &go::Go,
    &js::Js,
    &jvm::Jvm,
    &php::Php,
    &python::Python,
    &ruby::Ruby,
];

pub(crate) fn all() -> &'static [&'static dyn EcosystemSupport] {
    &PLUGINS
}

/// The plugin that owns `kind`.
pub(crate) fn for_kind(kind: ProjectInputKind) -> &'static dyn EcosystemSupport {
    all()
        .iter()
        .copied()
        .find(|plugin| plugin.kinds().contains(&kind))
        .unwrap_or_else(|| panic!("no ecosystem plugin registered for {kind:?}"))
}

/// The kind of project the manifest at `path` is, if it is one.
pub(crate) fn detect(path: &Path) -> Result<Option<ProjectInputKind>> {
    for plugin in all() {
        if let Some(kind) = plugin.detect(path)? {
            return Ok(Some(kind));
        }
    }
    Ok(None)
}

/// Let every plugin adjust the discovered projects, then order them by manifest path.
pub(crate) fn refine_specs(
    scan_root: &Path,
    config: &config::SloppyJoeConfig,
    specs: &mut Vec<ProjectInputSpec>,
) -> Result<()> {
    for plugin in all() {
        plugin.refine_specs(scan_root, config, specs)?;
    }
    specs.sort_by(|left, right| left.manifest_path.cmp(&right.manifest_path));
    Ok(())
}

/// Bind every project; returns the projects that could not be bound, with the reason.
pub(crate) fn bind(
    scan_root: &Path,
    specs: &mut [ProjectInputSpec],
) -> std::collections::HashMap<PathBuf, anyhow::Error> {
    let mut errors = std::collections::HashMap::new();
    for plugin in all() {
        errors.extend(plugin.bind(scan_root, specs));
    }
    errors
}

/// Bind JS projects, failing on the first one that cannot be bound (no workspace-member check).
#[cfg(test)]
pub(crate) fn bind_strict(scan_root: &Path, specs: &mut [ProjectInputSpec]) -> Result<()> {
    js::bind_strict(scan_root, specs)
}

/// Groups of unlocked tooling dependencies for a project.
pub(crate) fn tooling_groups(
    kind: ProjectInputKind,
    unlocked: Vec<Dependency>,
) -> Vec<Vec<Dependency>> {
    for_kind(kind).tooling_groups(unlocked)
}

/// Verify one project's lockfile and policy; see [`EcosystemSupport::preflight`].
pub(crate) fn preflight(ctx: &PreflightCtx<'_>, spec: &ProjectInputSpec) -> Result<Vec<Issue>> {
    for_kind(spec.kind).preflight(ctx, spec)
}

/// A plugin was handed a project it does not own: an engine bug, never user input.
pub(crate) fn wrong_plugin(kind: ProjectInputKind) -> ! {
    panic!("project kind {kind:?} dispatched to the wrong ecosystem plugin")
}

/// Lockfile for `spec`: the bound override, else the plugin's default.
pub(crate) fn selected_lockfile_path(spec: &ProjectInputSpec) -> Option<PathBuf> {
    spec.lockfile_path_override
        .clone()
        .or_else(|| for_kind(spec.kind).default_lockfile_path(spec))
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
