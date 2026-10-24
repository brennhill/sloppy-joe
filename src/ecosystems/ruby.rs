use super::*;

pub(super) struct Ruby;

impl EcosystemSupport for Ruby {
    fn kinds(&self) -> &'static [ProjectInputKind] {
        &[ProjectInputKind::Ruby]
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        match spec.kind {
            ProjectInputKind::Ruby => Some(spec.project_dir().join("Gemfile.lock")),
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
}
