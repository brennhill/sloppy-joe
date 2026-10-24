use super::*;

mod binding;
mod local_deps;
mod lockfile_read;
mod lockfile_validate;
mod managers;
mod npm_lockfile_checks;
mod workspace;

pub(crate) use binding::*;
pub(crate) use local_deps::*;
pub(crate) use lockfile_read::*;
pub(crate) use lockfile_validate::*;
pub(crate) use npm_lockfile_checks::*;
pub(crate) use workspace::*;

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
        Ok(common::kind_for_file_name(self.kinds(), path))
    }

    fn tooling_groups(&self, unlocked: Vec<Dependency>) -> Vec<Vec<Dependency>> {
        vec![unlocked]
    }

    fn bind(
        &self,
        scan_root: &Path,
        specs: &mut [ProjectInputSpec],
    ) -> std::collections::HashMap<PathBuf, anyhow::Error> {
        let mut binding_errors = std::collections::HashMap::new();
        for spec in specs.iter_mut() {
            if spec.kind != ProjectInputKind::Npm {
                continue;
            }
            match resolve_js_project_binding(scan_root, spec) {
                Ok(binding) => {
                    spec.lockfile_path_override = binding.lockfile_path.clone();
                    spec.js_binding = Some(binding);
                }
                Err(error) => {
                    binding_errors.insert(spec.manifest_path.clone(), error);
                }
            }
        }
        let scanned_js_dirs: std::collections::HashSet<PathBuf> = specs
            .iter()
            .filter(|spec| spec.kind == ProjectInputKind::Npm)
            .filter_map(|spec| std::fs::canonicalize(spec.project_dir()).ok())
            .collect();
        for spec in specs.iter() {
            if spec.kind != ProjectInputKind::Npm
                || binding_errors.contains_key(&spec.manifest_path)
            {
                continue;
            }
            if let Err(error) =
                ensure_js_workspace_members_scanned(scan_root, spec, &scanned_js_dirs)
            {
                binding_errors.insert(spec.manifest_path.clone(), error);
            }
        }
        binding_errors
    }

    fn refine_specs(
        &self,
        _scan_root: &Path,
        _config: &config::SloppyJoeConfig,
        _specs: &mut Vec<ProjectInputSpec>,
    ) -> Result<()> {
        Ok(())
    }

    fn validate_lockfile(
        &self,
        ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        _parsed: &ParsedInput,
    ) -> Result<Vec<Issue>> {
        let manifest = ctx
            .js
            .manifests
            .get(&spec.manifest_path)
            .expect("npm manifests should be parsed during preflight");
        ensure_authoritative_js_lockfile_readable(spec)?;
        let mut warnings = Vec::new();
        preflight_js_project(ctx, spec, manifest, &mut warnings)?;
        Ok(warnings)
    }

    fn source_policy(
        &self,
        _ctx: &PreflightCtx<'_>,
        _spec: &ProjectInputSpec,
    ) -> Result<SourcePolicy> {
        // Registry, tarball and alias restrictions are enforced while the lockfile is validated.
        Ok(SourcePolicy::LockfileBacked(Vec::new()))
    }
}

/// Manifests, workspace index and alias targets shared by every JS project in one preflight.
pub(super) struct JsPreflightState {
    manifests: std::collections::HashMap<PathBuf, serde_json::Value>,
    index: NpmProjectIndex,
    alias_targets: std::collections::HashMap<PathBuf, std::collections::HashMap<String, String>>,
}

impl JsPreflightState {
    pub(super) fn load(
        all_specs: &[ProjectInputSpec],
        selected: &[ProjectInputSpec],
    ) -> Result<Self> {
        let manifests = load_npm_manifests(all_specs)?;
        let index = index_npm_projects(&manifests)?;
        let selected_locks: std::collections::HashSet<_> =
            selected.iter().filter_map(selected_lockfile_path).collect();
        let alias_specs: Vec<_> = all_specs
            .iter()
            .filter(|spec| {
                selected_lockfile_path(spec).is_some_and(|path| selected_locks.contains(&path))
            })
            .cloned()
            .collect();
        let alias_targets = npm_alias_targets_by_lockfile(&alias_specs, &manifests)?;
        Ok(Self {
            manifests,
            index,
            alias_targets,
        })
    }
}

fn preflight_js_project(
    ctx: &PreflightCtx<'_>,
    spec: &ProjectInputSpec,
    manifest: &serde_json::Value,
    warnings: &mut Vec<Issue>,
) -> Result<()> {
    if let Some(workspace) = spec
        .js_binding
        .as_ref()
        .and_then(|b| b.independent_from_workspace.as_ref())
    {
        warnings.push(Issue::new(spec.manifest_path.display().to_string(), checks::names::RESOLUTION_INDEPENDENT_INSTALL_ROOT, Severity::Warning)
            .message(format!("Scanning '{}' independently with its own lockfile: ancestor workspace '{}' does not lock this project and has no explicit packageManager.", spec.manifest_path.display(), workspace.display()))
            .fix("Keep this project's installer and lockfile aligned with CI; remove unused ancestor workspace declarations if appropriate."));
    }
    validate_supported_js_manager(spec)?;
    validate_js_manifest_security_policy(spec, manifest)?;
    let scope_root = npm_trusted_scope_root(&ctx.canonical_root, spec)?;
    let manager = spec
        .js_binding
        .as_ref()
        .map(|binding| binding.manager)
        .unwrap_or(JsPackageManager::Npm);
    warnings.extend(managers::manager(manager).validate_lockfile(
        ctx,
        spec,
        manifest,
        &scope_root,
    )?);
    Ok(())
}

#[cfg(test)]
pub(super) fn bind_strict(scan_root: &Path, specs: &mut [ProjectInputSpec]) -> Result<()> {
    for spec in specs.iter_mut() {
        if spec.kind != ProjectInputKind::Npm {
            continue;
        }
        let binding = resolve_js_project_binding(scan_root, spec)?;
        spec.lockfile_path_override = binding.lockfile_path.clone();
        spec.js_binding = Some(binding);
    }
    Ok(())
}
