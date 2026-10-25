use super::*;

mod lock_fixer;

mod ambient_inputs;
mod flavors;
mod gated;
mod interpreter_config;
mod lock_schema;
mod lockfile_read;
mod parse;
mod specs;
mod tool_config;
mod warnings;

use flavors::flavor;
use gated::promote_gated_direct_deps;
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

    fn lockfile_fixer(
        &self,
        ctx: &fixer::FixCtx<'_>,
        spec: &ProjectInputSpec,
        problems: &[fixer::Problem],
    ) -> Result<fixer::FixPlan> {
        lock_fixer::lockfile_fixer(ctx, spec, problems)
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

    fn ambient_inputs(&self) -> &'static [ambient::AmbientInput] {
        ambient_inputs::AMBIENT
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
        let profile =
            python_lockfile_profile_for(&project.spec, opts, &project.python_root_extras)?;
        let mut data = match flavor(project.spec.kind).lockfile_data(config, opts, project, deps)? {
            Some(data) => data,
            None => {
                let mut data = common::read_lockfile_data(project, deps, Some(&profile))?;
                if project.deps.is_empty()
                    && python_manifest_declares_no_dependencies(&project.spec)?
                {
                    data.scan_all_locked_packages()?;
                }
                data
            }
        };
        promote_gated_direct_deps(&mut data, &profile.coverage_roots, &project.deps);
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
        // Every Python manifest is its own install input: a requirements file, setup.py or
        // Pipfile beside a Poetry/uv project or a hash-locked requirements file is scanned too.
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
        let mut issues = tool_config::check_tool_config(ctx, spec)?;
        issues.extend(flavor(spec.kind).validate_lockfile(ctx, spec, parsed)?);
        Ok(issues)
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
        Ok(SourcePolicy::EnforcedEarlier(
            "manifest parse and lockfile validation",
        ))
    }
}
