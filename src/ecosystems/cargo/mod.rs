use super::*;

mod ambient_inputs;
mod cargo_surface;
mod config_file;
mod program_settings;
mod rewrite;
mod scope;
mod validate;
mod workspace;

pub(crate) use config_file::*;
pub(crate) use rewrite::*;
pub(crate) use scope::*;
pub(crate) use validate::*;

pub(super) struct Cargo;

#[async_trait::async_trait]
impl EcosystemSupport for Cargo {
    fn scan_registry(
        &self,
        _project: &ParsedProject,
        _client: reqwest::Client,
    ) -> Result<Option<Box<dyn registry::Registry>>> {
        Ok(None)
    }

    async fn resolve_versions(
        &self,
        _project: &ParsedProject,
        _client: &reqwest::Client,
    ) -> Result<Option<ParsedProject>> {
        Ok(None)
    }

    async fn implementation_issues(
        &self,
        _project: &ParsedProject,
        _client: reqwest::Client,
        _osv_client: &dyn checks::malicious::OsvClient,
        _opts: &ScanOptions<'_>,
    ) -> Result<Vec<Issue>> {
        Ok(Vec::new())
    }

    fn similarity_on_transitives(&self) -> bool {
        false
    }

    fn kinds(&self) -> &'static [ProjectInputKind] {
        &[ProjectInputKind::Cargo]
    }

    fn ambient_inputs(&self) -> &'static [ambient::AmbientInput] {
        ambient_inputs::AMBIENT
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

    fn refine_specs(
        &self,
        scan_root: &Path,
        config: &config::SloppyJoeConfig,
        specs: &mut Vec<ProjectInputSpec>,
    ) -> Result<()> {
        expand_cargo_project_inputs(scan_root, specs, config)
    }

    fn bind(
        &self,
        _scan_root: &Path,
        _specs: &mut [ProjectInputSpec],
    ) -> std::collections::HashMap<PathBuf, anyhow::Error> {
        std::collections::HashMap::new()
    }

    fn tooling_groups(&self, unlocked: Vec<Dependency>) -> Vec<Vec<Dependency>> {
        vec![unlocked]
    }

    fn validate_lockfile(
        &self,
        ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
        _parsed: &ParsedInput,
    ) -> Result<Vec<Issue>> {
        let ScanCtx {
            scan_root, config, ..
        } = ctx.scan;
        let lockfile = authoritative_cargo_lockfile_path(scan_root, &spec.manifest_path, config)?;
        common::ensure_kind_lockfile(spec, &lockfile)?;
        cargo_lockfile_value(&lockfile)?;
        Ok(Vec::new())
    }

    fn source_policy(
        &self,
        ctx: &PreflightCtx<'_>,
        spec: &ProjectInputSpec,
    ) -> Result<SourcePolicy> {
        let ScanCtx {
            scan_root, config, ..
        } = ctx.scan;
        Ok(SourcePolicy::LockfileBacked(validate_cargo_source_policy(
            scan_root, spec, config,
        )?))
    }
}

fn expand_cargo_project_inputs(
    scan_root: &std::path::Path,
    specs: &mut Vec<ProjectInputSpec>,
    config: &config::SloppyJoeConfig,
) -> Result<()> {
    let mut seen = specs
        .iter()
        .map(|spec| spec.manifest_path.clone())
        .collect::<std::collections::HashSet<_>>();

    let mut index = 0usize;
    while index < specs.len() {
        if specs[index].kind != ProjectInputKind::Cargo {
            index += 1;
            continue;
        }

        let manifest_path = specs[index].manifest_path.clone();
        specs[index].lockfile_path_override = Some(authoritative_cargo_lockfile_path(
            scan_root,
            &manifest_path,
            config,
        )?);

        let manifest = parsers::cargo_toml::parse_manifest_file(&manifest_path)?;
        let (cargo_config_rewrites, _) =
            load_effective_cargo_config_rewrites(scan_root, &manifest_path, config)?;
        let rewrites =
            collect_effective_cargo_rewrites(scan_root, &manifest, config, &cargo_config_rewrites)?;
        let effective = resolve_cargo_effective_dependencies(scan_root, &manifest, config)?;

        for member in workspace::workspace_member_manifests(scan_root, &manifest)? {
            let known = specs.iter().any(|spec| {
                std::fs::canonicalize(&spec.manifest_path).ok().as_ref() == Some(&member)
            });
            if !known && seen.insert(member.clone()) {
                specs.push(ProjectInputSpec {
                    kind: ProjectInputKind::Cargo,
                    manifest_path: member,
                    lockfile_path_override: None,
                    js_binding: None,
                });
            }
        }

        for dep in effective {
            if let parsers::cargo_toml::CargoSourceSpec::Path(path) = dep.spec.source
                && let Some(target_manifest) = cargo_local_target_manifest(
                    scan_root,
                    &dep.base_dir,
                    &path,
                    &dep.spec.package_name,
                    config,
                )?
                && seen.insert(target_manifest.clone())
            {
                specs.push(ProjectInputSpec {
                    kind: ProjectInputKind::Cargo,
                    manifest_path: target_manifest,
                    lockfile_path_override: None,
                    js_binding: None,
                });
            }
        }

        for rewrite in rewrites {
            if let parsers::cargo_toml::CargoSourceSpec::Path(path) = &rewrite.spec.source
                && let Some(target_manifest) = cargo_local_target_manifest(
                    scan_root,
                    &rewrite.base_dir,
                    path,
                    &rewrite.spec.package_name,
                    config,
                )?
                && seen.insert(target_manifest.clone())
            {
                specs.push(ProjectInputSpec {
                    kind: ProjectInputKind::Cargo,
                    manifest_path: target_manifest,
                    lockfile_path_override: None,
                    js_binding: None,
                });
            }
        }

        index += 1;
    }

    specs.sort_by(|left, right| left.manifest_path.cmp(&right.manifest_path));
    Ok(())
}

pub(crate) fn parse_cargo_project_dependencies(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    config: &config::SloppyJoeConfig,
) -> Result<Vec<Dependency>> {
    let manifest = parsers::cargo_toml::parse_manifest_file(&spec.manifest_path)?;
    let mut deps = Vec::new();
    for dep in resolve_cargo_effective_dependencies(scan_root, &manifest, config)? {
        match dep.spec.source {
            parsers::cargo_toml::CargoSourceSpec::CratesIo
            | parsers::cargo_toml::CargoSourceSpec::RegistryAlias(_)
            | parsers::cargo_toml::CargoSourceSpec::RegistryIndex(_) => {
                let dependency = Dependency {
                    name: dep.spec.package_name,
                    version: dep.spec.version,
                    ecosystem: Ecosystem::Cargo,
                    actual_name: None,
                };
                parsers::validate_dependency(&dependency, &spec.manifest_path)?;
                deps.push(dependency);
            }
            parsers::cargo_toml::CargoSourceSpec::Path(_)
            | parsers::cargo_toml::CargoSourceSpec::Git { .. }
            | parsers::cargo_toml::CargoSourceSpec::Workspace => {}
        }
    }
    Ok(deps)
}
