use super::*;

pub(super) struct Dotnet;

impl EcosystemSupport for Dotnet {
    fn kinds(&self) -> &'static [ProjectInputKind] {
        &[ProjectInputKind::Dotnet]
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        match spec.kind {
            ProjectInputKind::Dotnet => {
                Some(spec.manifest_path.with_file_name("packages.lock.json"))
            }
            other => wrong_plugin(other),
        }
    }

    fn parse_manifest(
        &self,
        _scan_root: &Path,
        spec: &ProjectInputSpec,
    ) -> Result<Vec<Dependency>> {
        parsers::csproj::parse_file(&spec.manifest_path)
    }

    fn parse(&self, ctx: &ScanCtx<'_>, spec: &ProjectInputSpec) -> Result<ParsedInput> {
        Ok(ParsedInput {
            deps: self.parse_manifest(ctx.scan_root, spec)?,
            ..ParsedInput::default()
        })
    }
}
