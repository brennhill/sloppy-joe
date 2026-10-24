use super::*;

pub(super) struct Ruby;

impl EcosystemSupport for Ruby {
    fn kinds(&self) -> &'static [ProjectInputKind] {
        &[ProjectInputKind::Ruby]
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        match spec.kind {
            ProjectInputKind::Ruby => common::named_lockfile(spec),
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

    fn lockfile_data(
        &self,
        _config: &config::SloppyJoeConfig,
        _opts: &ScanOptions<'_>,
        project: &ParsedProject,
        deps: &[Dependency],
    ) -> Result<lockfiles::LockfileData> {
        common::read_lockfile_data(project, deps, None)
    }

    fn detect(&self, path: &Path) -> Result<Option<ProjectInputKind>> {
        // Bundler 2 prefers these over Gemfile / Gemfile.lock, so a scan that only reads
        // the old names would miss the dependencies Bundler actually installs.
        if let Some(name @ ("gems.rb" | "gems.locked")) = path.file_name().and_then(|n| n.to_str())
        {
            anyhow::bail!(
                "Unsupported Bundler file '{name}' at '{}': sloppy-joe reads Gemfile and Gemfile.lock only, so these dependencies would go unchecked. Fix: rename to Gemfile / Gemfile.lock.",
                path.display()
            );
        }
        Ok(common::kind_for_file_name(self.kinds(), path))
    }

    fn preflight(&self, ctx: &PreflightCtx<'_>, spec: &ProjectInputSpec) -> Result<Vec<Issue>> {
        let parsed = common::parse_for_preflight(self, ctx, spec)?;
        common::ensure_kind_lockfile(
            spec,
            &common::named_lockfile(spec).expect("Ruby names Gemfile.lock"),
        )?;
        Ok(parsed.warnings)
    }
}
