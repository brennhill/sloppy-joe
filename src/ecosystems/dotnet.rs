use super::*;

pub(super) struct Dotnet;

impl EcosystemSupport for Dotnet {
    fn kinds(&self) -> &'static [ProjectInputKind] {
        &[ProjectInputKind::Dotnet]
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        match spec.kind {
            ProjectInputKind::Dotnet => common::named_lockfile(spec),
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

    fn detect(&self, path: &Path) -> Result<Option<ProjectInputKind>> {
        if path.file_name().and_then(|name| name.to_str()) == Some("packages.config") {
            parsers::csproj::reject_packages_config(path)?;
            return Ok(None);
        }
        Ok(parsers::csproj::is_project_file(path).then_some(ProjectInputKind::Dotnet))
    }

    fn preflight(&self, ctx: &PreflightCtx<'_>, spec: &ProjectInputSpec) -> Result<Vec<Issue>> {
        let parsed = common::parse_for_preflight(self, ctx, spec)?;
        let lockfile = common::named_lockfile(spec).expect("Dotnet names packages.lock.json");
        common::ensure_kind_lockfile(spec, &lockfile)?;
        common::ensure_no_locked_packages_without_declarations(spec, &parsed.deps)?;
        let value = common::read_json_lockfile(&lockfile)?;
        if !matches!(value["version"].as_u64(), Some(1 | 2)) || !value["dependencies"].is_object() {
            anyhow::bail!(
                "Broken lockfile '{}': expected a supported version and dependencies object",
                lockfile.display()
            );
        }
        Ok(parsed.warnings)
    }
}
