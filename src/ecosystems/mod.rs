//! One plugin per ecosystem.
//!
//! The scan engine never matches on a [`ProjectInputKind`]: it asks [`for_kind`] for the plugin
//! that owns a project and calls the trait. Static facts about a kind live in
//! [`ProjectInputKind::descriptor`]; behavior lives here. The trait's required methods have no
//! default implementation, so a new ecosystem does not compile until it answers each security
//! question (what is parsed, which lockfile is required, what blocks).

use crate::*;
use std::path::{Path, PathBuf};
use tree::walk_project_tree;

pub(crate) mod ambient;
mod cargo;
pub(crate) mod common;
mod dotnet;
mod go;
mod js;
mod jvm;
mod php;
mod python;
mod ruby;
pub(crate) mod tree;

pub(crate) use common::first_existing_lockfile;
use common::*;

/// Plugin internals that unit tests exercise directly. Production code goes through the trait.
#[cfg(test)]
pub(crate) mod test_access {
    pub(crate) use super::cargo::*;
    pub(crate) use super::js::*;
    pub(crate) use super::jvm::*;
    pub(crate) use super::python::*;
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

/// What an ecosystem says about the sources of a project's packages.
pub(crate) enum SourcePolicy {
    /// A lockfile backs the scan and this stage verified where packages may come from; the issues
    /// are warnings about source configuration.
    LockfileBacked(Vec<Issue>),
    /// A lockfile backs the scan, and sources were already verified by an earlier stage that
    /// rejects non-registry sources outright (named here). The conformance suite checks the claim:
    /// every unsupported-source fixture of such a kind must fail that earlier stage.
    #[allow(dead_code)] // the stage is read by the conformance suite and by people
    EnforcedEarlier(&'static str),
    /// No trusted lockfile exists, so resolution-sensitive checks run with reduced confidence.
    ReducedConfidence(Issue),
}

#[allow(clippy::double_must_use)] // async_trait generates this attribute on already-must-use futures.
#[async_trait::async_trait]
pub(crate) trait EcosystemSupport: Sync {
    /// The project kinds this plugin owns. Every kind is owned by exactly one plugin.
    fn kinds(&self) -> &'static [ProjectInputKind];

    /// Lockfile the project is verified against when no explicit lockfile was bound; `None` when
    /// the kind has no lockfile of its own.
    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf>;

    /// Whether transitive dependencies get the similarity (typosquat) check without `--deep`.
    fn similarity_on_transitives(&self) -> bool;

    /// Dependencies declared by the manifest, without scan-specific resolution.
    fn parse_manifest(&self, scan_root: &Path, spec: &ProjectInputSpec) -> Result<Vec<Dependency>>;

    /// Dependencies (and warnings/tooling) the scan checks for this project.
    fn parse(&self, ctx: &ScanCtx<'_>, spec: &ProjectInputSpec) -> Result<ParsedInput>;

    /// What the checks run against: the project's lockfile, parsed and reconciled with `deps`.
    fn lockfile_data(
        &self,
        config: &config::SloppyJoeConfig,
        opts: &ScanOptions<'_>,
        project: &ParsedProject,
        deps: &[Dependency],
    ) -> Result<lockfiles::LockfileData>;

    /// Classify a manifest path as one of this plugin's kinds. Unsupported lookalikes the scan
    /// would otherwise skip silently (e.g. `gems.rb`) are errors, never `None`.
    fn detect(&self, path: &Path) -> Result<Option<ProjectInputKind>>;

    /// Adjust the discovered projects after `--type` filtering: add local path dependencies,
    /// drop manifests another one owns, refuse ambiguity. Ecosystems with nothing to adjust say so.
    fn refine_specs(
        &self,
        scan_root: &Path,
        config: &config::SloppyJoeConfig,
        specs: &mut Vec<ProjectInputSpec>,
    ) -> Result<()>;

    /// Bind projects to their package manager and lockfile. Projects that cannot be bound are
    /// returned with the reason; the scan reports them as incomplete.
    fn bind(
        &self,
        scan_root: &Path,
        specs: &mut [ProjectInputSpec],
    ) -> std::collections::HashMap<PathBuf, anyhow::Error>;

    /// Split build/tooling dependencies that no lockfile records into the groups that resolve
    /// from separate repositories.
    fn tooling_groups(&self, unlocked: Vec<Dependency>) -> Vec<Vec<Dependency>>;

    /// Verify the project's lockfile: it exists, is readable, is well formed and backs the
    /// declared dependencies. An error blocks the project; the returned issues are warnings.
    fn validate_lockfile(
        &self,
        ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        parsed: &ParsedInput,
    ) -> Result<Vec<Issue>>;

    /// Where this project's packages may come from, and how far the scan can trust the answer.
    /// An ecosystem without a trusted lockfile states [`SourcePolicy::ReducedConfidence`].
    fn source_policy(
        &self,
        ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
    ) -> Result<SourcePolicy>;

    /// The repository files this ecosystem's tools read without being told to, and what the scan
    /// does about each. No default: a plugin states its surface or it does not compile.
    fn ambient_inputs(&self) -> &'static [ambient::AmbientInput];

    /// The preflight stage: parse the manifest, verify its lockfile, apply the source policy. An
    /// error blocks the project; the returned issues are warnings. The stages it runs are all
    /// required, so this composition has nothing of its own to get wrong.
    fn preflight(&self, ctx: &PreflightCtx<'_>, spec: &ProjectInputSpec) -> Result<Vec<Issue>> {
        let parsed = self
            .parse(&ctx.scan, spec)
            .map_err(|err| common::broken_manifest(spec, err))?;
        let mut warnings = parsed.warnings.clone();
        warnings.extend(self.validate_lockfile(ctx, spec, &parsed)?);
        match self.source_policy(ctx, spec)? {
            SourcePolicy::LockfileBacked(issues) => warnings.extend(issues),
            SourcePolicy::EnforcedEarlier(_) => {}
            SourcePolicy::ReducedConfidence(issue) => warnings.push(issue),
        }
        let strict = ctx.scan.opts.scan_mode == ScanMode::Ci;
        warnings.extend(ambient::check(self.ambient_inputs(), spec, strict)?);
        Ok(warnings)
    }

    /// A registry client that replaces the ecosystem default for this project, when the project
    /// resolves from somewhere else (Gradle plugin repositories).
    fn scan_registry(
        &self,
        project: &ParsedProject,
        client: reqwest::Client,
    ) -> Result<Option<Box<dyn registry::Registry>>>;

    /// Declarations whose versions come from outside the manifest (Maven properties, BOMs, parent
    /// chain). `None` means the project needs no resolution.
    async fn resolve_versions(
        &self,
        project: &ParsedProject,
        client: &reqwest::Client,
    ) -> Result<Option<ParsedProject>>;

    /// Extra advisory checks on what the declared dependencies actually run (Gradle plugin
    /// implementation artifacts).
    async fn implementation_issues(
        &self,
        project: &ParsedProject,
        client: reqwest::Client,
        osv_client: &dyn checks::malicious::OsvClient,
        opts: &ScanOptions<'_>,
    ) -> Result<Vec<Issue>>;
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

/// The plugin that owns `ecosystem`. A missing plugin is an error, never a default.
pub(crate) fn for_ecosystem(ecosystem: Ecosystem) -> Result<&'static dyn EcosystemSupport> {
    all()
        .iter()
        .copied()
        .find(|plugin| {
            plugin
                .kinds()
                .first()
                .is_some_and(|kind| kind.ecosystem() == ecosystem)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No ecosystem plugin is registered for {}: refusing to scan without one",
                ecosystem.as_str()
            )
        })
}

/// Lockfile data for scanning `deps` of `project`. Tooling that no lockfile records is
/// scanned from the manifest alone, with reduced confidence.
pub(crate) fn lockfile_data(
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
    project: &ParsedProject,
    deps: &[Dependency],
) -> Result<lockfiles::LockfileData> {
    if project.unlocked_tooling {
        return Ok(lockfiles::LockfileData::reduced_confidence_from_manifest(
            deps,
        ));
    }
    for_kind(project.spec.kind).lockfile_data(config, opts, project, deps)
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

/// Verify one project's lockfile and policy; see [`EcosystemSupport::validate_lockfile`] and [`EcosystemSupport::source_policy`].
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

#[cfg(test)]
mod lockfile_data_tests;

pub(crate) fn scan_registry(
    project: &ParsedProject,
    client: reqwest::Client,
) -> Result<Option<Box<dyn registry::Registry>>> {
    for_kind(project.spec.kind).scan_registry(project, client)
}

pub(crate) async fn resolve_versions(
    project: &ParsedProject,
    client: &reqwest::Client,
) -> Result<Option<ParsedProject>> {
    for_kind(project.spec.kind)
        .resolve_versions(project, client)
        .await
}

pub(crate) async fn implementation_issues(
    project: &ParsedProject,
    client: reqwest::Client,
    osv_client: &dyn checks::malicious::OsvClient,
    opts: &ScanOptions<'_>,
) -> Result<Vec<Issue>> {
    for_kind(project.spec.kind)
        .implementation_issues(project, client, osv_client, opts)
        .await
}
