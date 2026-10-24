use super::*;

mod flavors;
mod lockfile_read;
mod parse;
mod specs;
mod warnings;

use flavors::flavor;
pub(crate) use lockfile_read::*;
pub(crate) use parse::*;
use specs::*;
pub(crate) use warnings::*;

pub(super) struct Python;

#[async_trait::async_trait]
impl EcosystemSupport for Python {
    fn scan_registry(
        &self,
        _project: &ParsedProject,
        _client: reqwest::Client,
    ) -> Result<Option<Box<dyn registry::Registry>>> {
        Ok(None)
    }

    async fn resolve_versions(
        &self,
        _project: &ParsedProject,
        _client: &reqwest::Client,
    ) -> Result<Option<ParsedProject>> {
        Ok(None)
    }

    async fn implementation_issues(
        &self,
        _project: &ParsedProject,
        _client: reqwest::Client,
        _osv_client: &dyn checks::malicious::OsvClient,
        _opts: &ScanOptions<'_>,
    ) -> Result<Vec<Issue>> {
        Ok(Vec::new())
    }

    fn similarity_on_transitives(&self) -> bool {
        false
    }

    fn kinds(&self) -> &'static [ProjectInputKind] {
        &[
            ProjectInputKind::PyProjectPoetry,
            ProjectInputKind::PyProjectUv,
            ProjectInputKind::PyRequirements,
            ProjectInputKind::PyRequirementsTrusted,
            ProjectInputKind::PyProjectLegacy,
            ProjectInputKind::PyPipfile,
            ProjectInputKind::PySetupPy,
            ProjectInputKind::PySetupCfg,
        ]
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        flavor(spec.kind).default_lockfile_path(spec)
    }

    fn parse_manifest(&self, scan_root: &Path, spec: &ProjectInputSpec) -> Result<Vec<Dependency>> {
        flavor(spec.kind).parse_manifest(scan_root, spec)
    }

    fn parse(&self, ctx: &ScanCtx<'_>, spec: &ProjectInputSpec) -> Result<ParsedInput> {
        parse_python_project_dependencies(ctx.scan_root, spec, ctx.opts)
    }

    fn lockfile_data(
        &self,
        config: &config::SloppyJoeConfig,
        opts: &ScanOptions<'_>,
        project: &ParsedProject,
        deps: &[Dependency],
    ) -> Result<lockfiles::LockfileData> {
        if let Some(data) = flavor(project.spec.kind).lockfile_data(config, opts, project, deps)? {
            return Ok(data);
        }
        let profile = active_python_lockfile_profile(opts, &project.python_root_extras);
        let mut data = common::read_lockfile_data(project, deps, Some(&profile))?;
        if project.deps.is_empty() && python_manifest_declares_no_dependencies(&project.spec)? {
            data.scan_all_locked_packages()?;
        }
        Ok(data)
    }

    fn detect(&self, path: &Path) -> Result<Option<ProjectInputKind>> {
        if path.file_name().and_then(|name| name.to_str()) == Some("pyproject.toml") {
            return Ok(Some(
                match parsers::pyproject_toml::classify_manifest(path)? {
                    parsers::pyproject_toml::PyprojectKind::Poetry => {
                        ProjectInputKind::PyProjectPoetry
                    }
                    parsers::pyproject_toml::PyprojectKind::Uv => ProjectInputKind::PyProjectUv,
                    parsers::pyproject_toml::PyprojectKind::Legacy => {
                        ProjectInputKind::PyProjectLegacy
                    }
                },
            ));
        }
        if let Some(kind) = common::kind_for_file_name(self.kinds(), path) {
            return Ok(Some(kind));
        }
        Ok(parsers::requirements::is_requirements_manifest_path(path)
            .then_some(ProjectInputKind::PyRequirements))
    }

    fn refine_specs(
        &self,
        scan_root: &Path,
        _config: &config::SloppyJoeConfig,
        specs: &mut Vec<ProjectInputSpec>,
    ) -> Result<()> {
        promote_trusted_pip_tools_specs(scan_root, specs)?;
        prune_included_requirement_specs(scan_root, specs)?;
        reject_ambiguous_python_project_inputs(specs)?;
        prefer_trusted_python_project_inputs(specs);
        Ok(())
    }

    fn bind(
        &self,
        _scan_root: &Path,
        _specs: &mut [ProjectInputSpec],
    ) -> std::collections::HashMap<PathBuf, anyhow::Error> {
        std::collections::HashMap::new()
    }

    fn tooling_groups(&self, unlocked: Vec<Dependency>) -> Vec<Vec<Dependency>> {
        vec![unlocked]
    }

    fn validate_lockfile(
        &self,
        ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        parsed: &ParsedInput,
    ) -> Result<Vec<Issue>> {
        flavor(spec.kind).validate_lockfile(ctx, spec, parsed)
    }

    fn source_policy(
        &self,
        ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
    ) -> Result<SourcePolicy> {
        // `poetry_only` refusal is a descriptor fact; index restrictions are enforced while the
        // flavor validates its lockfile.
        if ctx.scan.config.python_enforcement == config::PythonEnforcement::PoetryOnly
            && let Some(refusal) = spec.kind.descriptor().poetry_only_refusal
        {
            anyhow::bail!(
                "{}",
                refusal.replace("{}", &spec.manifest_path.display().to_string())
            );
        }
        Ok(SourcePolicy::LockfileBacked(Vec::new()))
    }
}
