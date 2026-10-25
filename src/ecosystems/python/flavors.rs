//! The eight Python project kinds as strategies. The plugin picks one by kind and delegates;
//! nothing outside this module knows the split exists.

use super::*;

/// What differs between Python project kinds. Every method is required: a flavor states its
/// lockfile, parsing and validation behavior explicitly.
pub(super) trait PythonFlavor: Sync {
    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf>;

    fn parse_manifest(&self, scan_root: &Path, spec: &ProjectInputSpec) -> Result<Vec<Dependency>>;

    /// Verify the flavor's lockfile (or, for lockfile-less flavors, its index and legacy-format
    /// policy). Errors block; the returned issues are warnings.
    fn validate_lockfile(
        &self,
        ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        parsed: &ParsedInput,
    ) -> Result<Vec<Issue>>;

    /// Lockfile data the flavor computes itself instead of the shared reader: `Some` when the
    /// flavor's own validation decides the confidence.
    fn lockfile_data(
        &self,
        config: &config::SloppyJoeConfig,
        opts: &ScanOptions<'_>,
        project: &ParsedProject,
        deps: &[Dependency],
    ) -> Result<Option<lockfiles::LockfileData>>;

    /// Whether the transitive dependencies are projected from PyPI metadata: only when no
    /// lockfile records them.
    fn projection(&self, spec: &ProjectInputSpec) -> Projection;
}

/// How a flavor's transitive dependencies are found when no lockfile records them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Projection {
    /// A lockfile (or a fully pinned requirements graph) records them.
    Off,
    /// Projected from PyPI metadata. `extras_known`: the manifest parser records the extras
    /// requested of each direct dependency; otherwise every extra of a direct dependency counts.
    On { extras_known: bool },
}

pub(super) fn flavor(kind: ProjectInputKind) -> &'static dyn PythonFlavor {
    match kind {
        ProjectInputKind::PyProjectPoetry => &Poetry,
        ProjectInputKind::PyProjectUv => &Uv,
        ProjectInputKind::PyRequirementsTrusted => &RequirementsTrusted,
        ProjectInputKind::PyRequirements => &Requirements,
        ProjectInputKind::PyProjectLegacy => &PyprojectLegacy,
        ProjectInputKind::PyPipfile => &Pipfile,
        ProjectInputKind::PySetupPy => &SetupPy,
        ProjectInputKind::PySetupCfg => &SetupCfg,
        other => wrong_plugin(other),
    }
}

struct Poetry;
struct Uv;
struct RequirementsTrusted;
struct Requirements;
struct PyprojectLegacy;
struct Pipfile;
struct SetupPy;
struct SetupCfg;

impl PythonFlavor for Poetry {
    fn projection(&self, _spec: &ProjectInputSpec) -> Projection {
        Projection::Off
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        common::named_lockfile(spec)
    }

    fn parse_manifest(
        &self,
        _scan_root: &Path,
        spec: &ProjectInputSpec,
    ) -> Result<Vec<Dependency>> {
        parsers::pyproject_toml::parse_poetry_file(&spec.manifest_path)
    }

    fn validate_lockfile(
        &self,
        ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        parsed: &ParsedInput,
    ) -> Result<Vec<Issue>> {
        common::ensure_kind_lockfile(
            spec,
            &common::named_lockfile(spec).expect("Poetry names poetry.lock"),
        )?;
        let validated = read_validated_poetry_lockfile(
            spec,
            &parsed.deps,
            &parsed.python_root_extras,
            ctx.scan.config,
            ctx.scan.opts,
        )?;
        Ok(validated.warnings)
    }

    fn lockfile_data(
        &self,
        config: &config::SloppyJoeConfig,
        opts: &ScanOptions<'_>,
        project: &ParsedProject,
        deps: &[Dependency],
    ) -> Result<Option<lockfiles::LockfileData>> {
        let validated = read_validated_poetry_lockfile(
            &project.spec,
            deps,
            &project.python_root_extras,
            config,
            opts,
        )?;
        Ok((!validated.fully_trusted)
            .then(|| lockfiles::LockfileData::reduced_confidence_from_manifest(deps)))
    }
}

impl PythonFlavor for Uv {
    fn projection(&self, _spec: &ProjectInputSpec) -> Projection {
        Projection::Off
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        common::named_lockfile(spec)
    }

    fn parse_manifest(
        &self,
        _scan_root: &Path,
        spec: &ProjectInputSpec,
    ) -> Result<Vec<Dependency>> {
        parsers::pyproject_toml::parse_legacy_file(&spec.manifest_path)
    }

    fn validate_lockfile(
        &self,
        ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        parsed: &ParsedInput,
    ) -> Result<Vec<Issue>> {
        common::ensure_kind_lockfile(
            spec,
            &common::named_lockfile(spec).expect("uv names uv.lock"),
        )?;
        let (_, warnings) = read_validated_uv_lockfile(
            spec,
            &parsed.deps,
            &parsed.python_root_extras,
            ctx.scan.config,
            ctx.scan.opts,
        )?;
        Ok(warnings)
    }

    fn lockfile_data(
        &self,
        _config: &config::SloppyJoeConfig,
        _opts: &ScanOptions<'_>,
        _project: &ParsedProject,
        _deps: &[Dependency],
    ) -> Result<Option<lockfiles::LockfileData>> {
        Ok(None)
    }
}

impl PythonFlavor for RequirementsTrusted {
    fn projection(&self, _spec: &ProjectInputSpec) -> Projection {
        Projection::Off
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        Some(spec.manifest_path.clone())
    }

    fn parse_manifest(&self, scan_root: &Path, spec: &ProjectInputSpec) -> Result<Vec<Dependency>> {
        parsers::requirements::parse_file(&spec.manifest_path, scan_root)
    }

    fn validate_lockfile(
        &self,
        ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        _parsed: &ParsedInput,
    ) -> Result<Vec<Issue>> {
        let mut warnings = Vec::new();
        if !validate_hash_locked_requirements_provenance(ctx.scan.scan_root, spec, ctx.scan.config)?
        {
            warnings.push(hash_locked_requirements_reduced_confidence_warning(spec));
        }
        Ok(warnings)
    }

    fn lockfile_data(
        &self,
        _config: &config::SloppyJoeConfig,
        _opts: &ScanOptions<'_>,
        _project: &ParsedProject,
        _deps: &[Dependency],
    ) -> Result<Option<lockfiles::LockfileData>> {
        Ok(None)
    }
}

/// Manifests with no lockfile: they only get the legacy warning (and the index check for plain
/// requirements files).
fn legacy_validation(spec: &ProjectInputSpec) -> Vec<Issue> {
    vec![python_legacy_warning(spec)]
}

impl PythonFlavor for Requirements {
    fn projection(&self, _spec: &ProjectInputSpec) -> Projection {
        Projection::On { extras_known: true }
    }

    fn default_lockfile_path(&self, _spec: &ProjectInputSpec) -> Option<PathBuf> {
        None
    }

    fn parse_manifest(&self, scan_root: &Path, spec: &ProjectInputSpec) -> Result<Vec<Dependency>> {
        parsers::requirements::parse_file(&spec.manifest_path, scan_root)
    }

    fn validate_lockfile(
        &self,
        ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        _parsed: &ParsedInput,
    ) -> Result<Vec<Issue>> {
        parsers::requirements::ensure_trusted_indexes(
            &spec.manifest_path,
            ctx.scan.scan_root,
            ctx.scan.config,
        )?;
        Ok(legacy_validation(spec))
    }

    fn lockfile_data(
        &self,
        _config: &config::SloppyJoeConfig,
        _opts: &ScanOptions<'_>,
        _project: &ParsedProject,
        _deps: &[Dependency],
    ) -> Result<Option<lockfiles::LockfileData>> {
        Ok(None)
    }
}

impl PythonFlavor for PyprojectLegacy {
    fn projection(&self, _spec: &ProjectInputSpec) -> Projection {
        Projection::On { extras_known: true }
    }

    fn default_lockfile_path(&self, _spec: &ProjectInputSpec) -> Option<PathBuf> {
        None
    }

    fn parse_manifest(
        &self,
        _scan_root: &Path,
        spec: &ProjectInputSpec,
    ) -> Result<Vec<Dependency>> {
        parsers::pyproject_toml::parse_legacy_file(&spec.manifest_path)
    }

    fn validate_lockfile(
        &self,
        _ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        _parsed: &ParsedInput,
    ) -> Result<Vec<Issue>> {
        Ok(legacy_validation(spec))
    }

    fn lockfile_data(
        &self,
        _config: &config::SloppyJoeConfig,
        _opts: &ScanOptions<'_>,
        _project: &ParsedProject,
        _deps: &[Dependency],
    ) -> Result<Option<lockfiles::LockfileData>> {
        Ok(None)
    }
}

impl PythonFlavor for Pipfile {
    fn projection(&self, spec: &ProjectInputSpec) -> Projection {
        // Pipfile.lock records the resolved tree; the Pipfile parser drops requested extras.
        if selected_lockfile_path(spec).is_some() {
            Projection::Off
        } else {
            Projection::On {
                extras_known: false,
            }
        }
    }

    fn default_lockfile_path(&self, spec: &ProjectInputSpec) -> Option<PathBuf> {
        first_existing_lockfile(
            spec.project_dir(),
            &[lockfiles::pipfile_lock::LOCKFILE_NAME],
        )
    }

    fn parse_manifest(
        &self,
        _scan_root: &Path,
        spec: &ProjectInputSpec,
    ) -> Result<Vec<Dependency>> {
        parsers::pipfile::parse_file(&spec.manifest_path)
    }

    fn validate_lockfile(
        &self,
        ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        _parsed: &ParsedInput,
    ) -> Result<Vec<Issue>> {
        let mut warnings = legacy_validation(spec);
        warnings.extend(validate_pipfile_lockfile(spec, ctx.scan.config)?);
        Ok(warnings)
    }

    fn lockfile_data(
        &self,
        _config: &config::SloppyJoeConfig,
        _opts: &ScanOptions<'_>,
        _project: &ParsedProject,
        _deps: &[Dependency],
    ) -> Result<Option<lockfiles::LockfileData>> {
        Ok(None)
    }
}

impl PythonFlavor for SetupPy {
    fn projection(&self, _spec: &ProjectInputSpec) -> Projection {
        Projection::On {
            extras_known: false,
        }
    }

    fn default_lockfile_path(&self, _spec: &ProjectInputSpec) -> Option<PathBuf> {
        None
    }

    fn parse_manifest(
        &self,
        _scan_root: &Path,
        spec: &ProjectInputSpec,
    ) -> Result<Vec<Dependency>> {
        parsers::setup_py::parse_file(&spec.manifest_path)
    }

    fn validate_lockfile(
        &self,
        _ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        _parsed: &ParsedInput,
    ) -> Result<Vec<Issue>> {
        Ok(legacy_validation(spec))
    }

    fn lockfile_data(
        &self,
        _config: &config::SloppyJoeConfig,
        _opts: &ScanOptions<'_>,
        _project: &ParsedProject,
        _deps: &[Dependency],
    ) -> Result<Option<lockfiles::LockfileData>> {
        Ok(None)
    }
}

impl PythonFlavor for SetupCfg {
    fn projection(&self, _spec: &ProjectInputSpec) -> Projection {
        Projection::On {
            extras_known: false,
        }
    }

    fn default_lockfile_path(&self, _spec: &ProjectInputSpec) -> Option<PathBuf> {
        None
    }

    fn parse_manifest(
        &self,
        _scan_root: &Path,
        spec: &ProjectInputSpec,
    ) -> Result<Vec<Dependency>> {
        parsers::setup_cfg::parse_file(&spec.manifest_path)
    }

    fn validate_lockfile(
        &self,
        _ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        _parsed: &ParsedInput,
    ) -> Result<Vec<Issue>> {
        Ok(legacy_validation(spec))
    }

    fn lockfile_data(
        &self,
        _config: &config::SloppyJoeConfig,
        _opts: &ScanOptions<'_>,
        _project: &ParsedProject,
        _deps: &[Dependency],
    ) -> Result<Option<lockfiles::LockfileData>> {
        Ok(None)
    }
}
