use super::*;

pub(super) struct Js;

impl EcosystemSupport for Js {
    fn kinds(&self) -> &'static [ProjectInputKind] {
        &[ProjectInputKind::Npm]
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        match spec.kind {
            ProjectInputKind::Npm => spec
                .js_binding
                .as_ref()
                .and_then(|binding| binding.lockfile_path.clone())
                .or_else(|| {
                    first_existing_lockfile(
                        spec.project_dir(),
                        &["npm-shrinkwrap.json", "package-lock.json"],
                    )
                }),
            other => wrong_plugin(other),
        }
    }

    fn parse_manifest(
        &self,
        _scan_root: &Path,
        spec: &ProjectInputSpec,
    ) -> Result<Vec<Dependency>> {
        parsers::package_json::parse(spec.project_dir())
    }

    fn parse(&self, ctx: &ScanCtx<'_>, spec: &ProjectInputSpec) -> Result<ParsedInput> {
        Ok(ParsedInput {
            deps: self.parse_manifest(ctx.scan_root, spec)?,
            ..ParsedInput::default()
        })
    }
}
