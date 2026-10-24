use super::*;

pub(super) struct Go;

#[async_trait::async_trait]
impl EcosystemSupport for Go {
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
        &[ProjectInputKind::Go]
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        match spec.kind {
            ProjectInputKind::Go => common::named_lockfile(spec),
            other => wrong_plugin(other),
        }
    }

    fn parse_manifest(
        &self,
        _scan_root: &Path,
        spec: &ProjectInputSpec,
    ) -> Result<Vec<Dependency>> {
        parsers::go_mod::parse(spec.project_dir())
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
        check_go_sum(spec)?;
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

fn check_go_sum(spec: &ProjectInputSpec) -> Result<()> {
    let manifest_content =
        parsers::read_file_limited(&spec.manifest_path, parsers::MAX_MANIFEST_BYTES)
            .map_err(|err| common::broken_manifest(spec, err))?;
    if !parsers::go_mod::requires_go_sum(&manifest_content) {
        return Ok(());
    }
    let go_sum_path = common::named_lockfile(spec).expect("Go names go.sum");
    common::ensure_kind_lockfile(spec, &go_sum_path)?;
    // Vendored builds ignore go.sum, so only enforce it otherwise.
    if !spec.project_dir().join("vendor/modules.txt").is_file() {
        let go_sum = parsers::read_file_limited(&go_sum_path, parsers::MAX_MANIFEST_BYTES)?;
        parsers::go_mod::check_go_sum_entries(&manifest_content, &go_sum).map_err(|err| {
            anyhow::anyhow!("Broken lockfile '{}': {}", go_sum_path.display(), err)
        })?;
    }
    Ok(())
}
