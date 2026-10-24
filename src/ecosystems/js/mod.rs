use super::*;

mod binding;
mod local_deps;
mod lockfile_read;
mod lockfile_validate;
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

    fn detect(&self, path: &Path) -> Result<Option<ProjectInputKind>> {
        Ok(common::kind_for_file_name(self.kinds(), path))
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

    fn preflight(&self, ctx: &PreflightCtx<'_>, spec: &ProjectInputSpec) -> Result<Vec<Issue>> {
        let manifest = ctx
            .js
            .manifests
            .get(&spec.manifest_path)
            .expect("npm manifests should be parsed during preflight");
        // Parsed from the already-loaded manifest value.
        parsers::package_json::parse_manifest_value(&spec.manifest_path, manifest)
            .map_err(|err| common::broken_manifest(spec, err))?;
        ensure_authoritative_js_lockfile_readable(spec)?;
        let mut warnings = Vec::new();
        preflight_js_project(ctx, spec, manifest, &mut warnings)?;
        Ok(warnings)
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
    let ignore_dirs = &ctx.scan.config.ignore_dirs;
    let index = &ctx.js.index;
    match spec
        .js_binding
        .as_ref()
        .map(|binding| binding.manager)
        .unwrap_or(JsPackageManager::Npm)
    {
        JsPackageManager::Npm => {
            let allowed_alias_targets = selected_lockfile_path(spec)
                .and_then(|path| ctx.js.alias_targets.get(&path))
                .cloned()
                .unwrap_or_default();
            let (lockfile, npm_warnings) = read_validated_npm_lockfile(
                spec,
                manifest,
                ctx.scan.config,
                &allowed_alias_targets,
            )?;
            warnings.extend(npm_warnings);
            validate_local_npm_dependencies(&scope_root, spec, manifest, &lockfile, index)
        }
        JsPackageManager::Pnpm => {
            let lockfile = read_validated_pnpm_lockfile(spec, manifest)?;
            validate_local_pnpm_dependencies(
                &scope_root,
                spec,
                manifest,
                &lockfile,
                index,
                ignore_dirs,
            )
        }
        JsPackageManager::Bun => {
            let lockfile = read_validated_bun_lockfile(spec, manifest)?;
            validate_local_bun_dependencies(
                &scope_root,
                spec,
                manifest,
                &lockfile,
                index,
                ignore_dirs,
            )
        }
        JsPackageManager::Yarn => {
            let lockfile = read_validated_yarn_lockfile(spec, manifest)?;
            validate_local_yarn_dependencies(&scope_root, spec, manifest, &lockfile, ignore_dirs)
        }
    }
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
