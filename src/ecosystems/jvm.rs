use super::*;

pub(super) struct Jvm;

impl EcosystemSupport for Jvm {
    fn kinds(&self) -> &'static [ProjectInputKind] {
        &[ProjectInputKind::Gradle, ProjectInputKind::Maven]
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        match spec.kind {
            ProjectInputKind::Gradle => Some(spec.project_dir().join("gradle.lockfile")),
            // Maven has no trusted lockfile format: scans continue with reduced confidence.
            ProjectInputKind::Maven => None,
            other => wrong_plugin(other),
        }
    }

    fn parse_manifest(
        &self,
        _scan_root: &Path,
        spec: &ProjectInputSpec,
    ) -> Result<Vec<Dependency>> {
        parsers::jvm::parse_manifest(&spec.manifest_path)
    }

    fn parse(&self, ctx: &ScanCtx<'_>, spec: &ProjectInputSpec) -> Result<ParsedInput> {
        match spec.kind {
            ProjectInputKind::Gradle => {
                gradle_plugin_scan::parse_gradle_project_input(spec, ctx.config)
            }
            ProjectInputKind::Maven => Ok(ParsedInput {
                deps: self.parse_manifest(ctx.scan_root, spec)?,
                ..ParsedInput::default()
            }),
            other => wrong_plugin(other),
        }
    }
}
