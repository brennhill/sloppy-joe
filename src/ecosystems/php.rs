use super::*;

pub(super) struct Php;

impl EcosystemSupport for Php {
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

    fn preflight(&self, ctx: &PreflightCtx<'_>, spec: &ProjectInputSpec) -> Result<Vec<Issue>> {
        let parsed = common::parse_for_preflight(self, ctx, spec)?;
        let lockfile = common::named_lockfile(spec).expect("Php names composer.lock");
        common::ensure_kind_lockfile(spec, &lockfile)?;
        common::read_json_lockfile(&lockfile)?;
        Ok(parsed.warnings)
    }
}
