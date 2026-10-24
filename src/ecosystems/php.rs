use super::*;

pub(super) struct Php;

impl EcosystemSupport for Php {
    fn kinds(&self) -> &'static [ProjectInputKind] {
        &[ProjectInputKind::Php]
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        match spec.kind {
            ProjectInputKind::Php => Some(spec.project_dir().join("composer.lock")),
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
}
