use super::*;

pub(super) struct Ruby;

#[async_trait::async_trait]
impl EcosystemSupport for Ruby {
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
        &[ProjectInputKind::Ruby]
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        match spec.kind {
            ProjectInputKind::Ruby => common::named_lockfile(spec),
            other => wrong_plugin(other),
        }
    }

    fn parse_manifest(
        &self,
        _scan_root: &Path,
        spec: &ProjectInputSpec,
    ) -> Result<Vec<Dependency>> {
        parsers::gemfile::parse(spec.project_dir())
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
        // Bundler 2 prefers these over Gemfile / Gemfile.lock, so a scan that only reads
        // the old names would miss the dependencies Bundler actually installs.
        if let Some(name @ ("gems.rb" | "gems.locked")) = path.file_name().and_then(|n| n.to_str())
        {
            anyhow::bail!(
                "Unsupported Bundler file '{name}' at '{}': sloppy-joe reads Gemfile and Gemfile.lock only, so these dependencies would go unchecked. Fix: rename to Gemfile / Gemfile.lock.",
                path.display()
            );
        }
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
        parsed: &ParsedInput,
    ) -> Result<Vec<Issue>> {
        common::ensure_kind_lockfile(
            spec,
            &common::named_lockfile(spec).expect("Ruby names Gemfile.lock"),
        )?;
        if !parsed.deps.is_empty() {
            let path = common::named_lockfile(spec).expect("Ruby names Gemfile.lock");
            let content = crate::untrusted::read_line_file(&path)?;
            if !crate::untrusted::rows(&content).any(|line| line.trim_end() == "GEM") {
                anyhow::bail!(
                    "Required lockfile '{}' has no GEM section although the Gemfile declares {} gems: the lockfile is malformed or stale. Fix: regenerate it with 'bundle lock'.",
                    path.display(),
                    parsed.deps.len()
                );
            }
        }
        Ok(Vec::new())
    }

    fn source_policy(
        &self,
        _ctx: &PreflightCtx<'_>,
        _spec: &ProjectInputSpec,
    ) -> Result<SourcePolicy> {
        Ok(SourcePolicy::EnforcedEarlier("manifest parse"))
    }
}
