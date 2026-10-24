use super::*;

pub(super) struct Go;

impl EcosystemSupport for Go {
    fn kinds(&self) -> &'static [ProjectInputKind] {
        &[ProjectInputKind::Go]
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        match spec.kind {
            ProjectInputKind::Go => Some(spec.project_dir().join("go.sum")),
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
}
