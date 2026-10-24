use super::*;

pub(super) struct Jvm;

impl EcosystemSupport for Jvm {
    fn kinds(&self) -> &'static [ProjectInputKind] {
        &[ProjectInputKind::Gradle, ProjectInputKind::Maven]
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        match spec.kind {
            ProjectInputKind::Gradle => common::named_lockfile(spec),
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

    fn preflight(&self, ctx: &PreflightCtx<'_>, spec: &ProjectInputSpec) -> Result<Vec<Issue>> {
        let parsed = common::parse_for_preflight(self, ctx, spec)?;
        let mut warnings = parsed.warnings.clone();
        match spec.kind {
            ProjectInputKind::Gradle => {
                common::ensure_kind_lockfile(
                    spec,
                    &common::named_lockfile(spec).expect("Gradle names gradle.lockfile"),
                )?;
                common::ensure_no_locked_packages_without_declarations(spec, &parsed.deps)?;
            }
            ProjectInputKind::Maven => warnings.push(maven_no_lockfile_warning(spec)),
            other => wrong_plugin(other),
        }
        Ok(warnings)
    }
}

fn maven_no_lockfile_warning(spec: &ProjectInputSpec) -> Issue {
    Issue::new(
        "<lockfile>",
        checks::names::RESOLUTION_NO_TRUSTED_LOCKFILE,
        Severity::Warning,
    )
    .message(format!(
        "Maven manifest '{}' has no trusted lockfile-backed verification path in sloppy-joe. Resolution-sensitive checks continue with reduced confidence. Gradle dependency locking via gradle.lockfile is recommended when practical.",
        spec.manifest_path.display()
    ))
    .fix(
        "Keep Maven and review resolution-sensitive findings manually, or move the build to Gradle with dependency locking if you need strict lockfile enforcement.",
    )
}
