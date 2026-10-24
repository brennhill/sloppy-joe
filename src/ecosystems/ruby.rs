use super::*;

pub(super) struct Ruby;

impl EcosystemSupport for Ruby {
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

    fn preflight(&self, ctx: &PreflightCtx<'_>, spec: &ProjectInputSpec) -> Result<Vec<Issue>> {
        let parsed = common::parse_for_preflight(self, ctx, spec)?;
        common::ensure_kind_lockfile(
            spec,
            &common::named_lockfile(spec).expect("Ruby names Gemfile.lock"),
        )?;
        Ok(parsed.warnings)
    }
}
