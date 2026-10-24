use super::*;

pub(super) struct Cargo;

impl EcosystemSupport for Cargo {
    fn kinds(&self) -> &'static [ProjectInputKind] {
        &[ProjectInputKind::Cargo]
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        match spec.kind {
            ProjectInputKind::Cargo => common::named_lockfile(spec),
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

    fn preflight(&self, ctx: &PreflightCtx<'_>, spec: &ProjectInputSpec) -> Result<Vec<Issue>> {
        let ScanCtx {
            scan_root, config, ..
        } = ctx.scan;
        let parsed = common::parse_for_preflight(self, ctx, spec)?;
        let mut warnings = parsed.warnings;
        let lockfile = authoritative_cargo_lockfile_path(scan_root, &spec.manifest_path, config)?;
        common::ensure_kind_lockfile(spec, &lockfile)?;
        warnings.extend(validate_cargo_source_policy(scan_root, spec, config)?);
        cargo_lockfile_value(&lockfile)?;
        Ok(warnings)
    }
}
