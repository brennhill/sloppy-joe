use super::*;

pub(super) struct Php;

#[async_trait::async_trait]
impl EcosystemSupport for Php {
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

    fn kinds(&self) -> &'static [ProjectInputKind] {
        &[ProjectInputKind::Php]
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        match spec.kind {
            ProjectInputKind::Php => common::named_lockfile(spec),
            other => wrong_plugin(other),
        }
    }

    fn parse_manifest(
        &self,
        _scan_root: &Path,
        spec: &ProjectInputSpec,
    ) -> Result<Vec<Dependency>> {
        parsers::composer_json::parse(spec.project_dir())
    }

    fn parse(&self, ctx: &ScanCtx<'_>, spec: &ProjectInputSpec) -> Result<ParsedInput> {
        Ok(ParsedInput {
            deps: self.parse_manifest(ctx.scan_root, spec)?,
            ..ParsedInput::default()
        })
    }

    fn lockfile_data(
        &self,
        _config: &config::SloppyJoeConfig,
        _opts: &ScanOptions<'_>,
        project: &ParsedProject,
        deps: &[Dependency],
    ) -> Result<lockfiles::LockfileData> {
        common::read_lockfile_data(project, deps, None)
    }

    fn detect(&self, path: &Path) -> Result<Option<ProjectInputKind>> {
        Ok(common::kind_for_file_name(self.kinds(), path))
    }

    fn refine_specs(
        &self,
        _scan_root: &Path,
        _config: &config::SloppyJoeConfig,
        _specs: &mut Vec<ProjectInputSpec>,
    ) -> Result<()> {
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
        _ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        _parsed: &ParsedInput,
    ) -> Result<Vec<Issue>> {
        let lockfile = common::named_lockfile(spec).expect("Php names composer.lock");
        common::ensure_kind_lockfile(spec, &lockfile)?;
        common::read_json_lockfile(&lockfile)?;
        Ok(Vec::new())
    }

    fn source_policy(
        &self,
        _ctx: &PreflightCtx<'_>,
        _spec: &ProjectInputSpec,
    ) -> Result<SourcePolicy> {
        Ok(SourcePolicy::LockfileBacked(Vec::new()))
    }
}
