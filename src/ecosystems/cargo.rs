use super::*;

pub(super) struct Cargo;

impl EcosystemSupport for Cargo {
    fn kinds(&self) -> &'static [ProjectInputKind] {
        &[ProjectInputKind::Cargo]
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        match spec.kind {
            ProjectInputKind::Cargo => Some(spec.project_dir().join("Cargo.lock")),
            other => wrong_plugin(other),
        }
    }

    fn parse_manifest(
        &self,
        _scan_root: &Path,
        spec: &ProjectInputSpec,
    ) -> Result<Vec<Dependency>> {
        parsers::cargo_toml::parse(spec.project_dir())
    }

    fn parse(&self, ctx: &ScanCtx<'_>, spec: &ProjectInputSpec) -> Result<ParsedInput> {
        Ok(ParsedInput {
            deps: parse_cargo_project_dependencies(ctx.scan_root, spec, ctx.config)?,
            ..ParsedInput::default()
        })
    }
}
