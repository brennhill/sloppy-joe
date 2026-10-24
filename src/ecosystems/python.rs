use super::*;

pub(super) struct Python;

impl EcosystemSupport for Python {
    fn kinds(&self) -> &'static [ProjectInputKind] {
        &[
            ProjectInputKind::PyProjectPoetry,
            ProjectInputKind::PyProjectUv,
            ProjectInputKind::PyRequirements,
            ProjectInputKind::PyRequirementsTrusted,
            ProjectInputKind::PyProjectLegacy,
            ProjectInputKind::PyPipfile,
            ProjectInputKind::PySetupPy,
            ProjectInputKind::PySetupCfg,
        ]
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        let project_dir = spec.project_dir();
        match spec.kind {
            ProjectInputKind::PyProjectPoetry => Some(project_dir.join("poetry.lock")),
            ProjectInputKind::PyProjectUv => Some(project_dir.join("uv.lock")),
            ProjectInputKind::PyRequirementsTrusted => Some(spec.manifest_path.clone()),
            ProjectInputKind::PyPipfile => {
                first_existing_lockfile(project_dir, &[lockfiles::pipfile_lock::LOCKFILE_NAME])
            }
            ProjectInputKind::PyRequirements
            | ProjectInputKind::PyProjectLegacy
            | ProjectInputKind::PySetupPy
            | ProjectInputKind::PySetupCfg => None,
            other => wrong_plugin(other),
        }
    }

    fn parse_manifest(&self, scan_root: &Path, spec: &ProjectInputSpec) -> Result<Vec<Dependency>> {
        let manifest = &spec.manifest_path;
        match spec.kind {
            ProjectInputKind::PyProjectPoetry => {
                parsers::pyproject_toml::parse_poetry_file(manifest)
            }
            ProjectInputKind::PyProjectUv | ProjectInputKind::PyProjectLegacy => {
                parsers::pyproject_toml::parse_legacy_file(manifest)
            }
            ProjectInputKind::PyRequirements | ProjectInputKind::PyRequirementsTrusted => {
                parsers::requirements::parse_file(manifest, scan_root)
            }
            ProjectInputKind::PyPipfile => parsers::pipfile::parse_file(manifest),
            ProjectInputKind::PySetupPy => parsers::setup_py::parse_file(manifest),
            ProjectInputKind::PySetupCfg => parsers::setup_cfg::parse_file(manifest),
            other => wrong_plugin(other),
        }
    }

    fn parse(&self, ctx: &ScanCtx<'_>, spec: &ProjectInputSpec) -> Result<ParsedInput> {
        parse_python_project_dependencies(ctx.scan_root, spec, ctx.opts)
    }
}
