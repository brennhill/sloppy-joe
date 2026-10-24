use super::*;

/// Parse for preflight, naming the manifest in the error.
pub(super) fn parse_for_preflight(
    plugin: &dyn EcosystemSupport,
    ctx: &PreflightCtx<'_>,
    spec: &ProjectInputSpec,
) -> Result<ParsedInput> {
    plugin
        .parse(&ctx.scan, spec)
        .map_err(|err| broken_manifest(spec, err))
}

pub(super) fn broken_manifest(spec: &ProjectInputSpec, err: anyhow::Error) -> anyhow::Error {
    anyhow::anyhow!(
        "Broken manifest '{}': {}",
        spec.manifest_path.display(),
        err
    )
}

/// Require a readable lockfile at `lockfile`, naming the kind's remedy when it is missing.
pub(super) fn ensure_kind_lockfile(spec: &ProjectInputSpec, lockfile: &Path) -> Result<()> {
    let descriptor = spec.kind.descriptor();
    let (LockfilePolicy::Required, Some(help)) =
        (descriptor.lockfile, descriptor.missing_lockfile_help)
    else {
        anyhow::bail!(
            "Internal error: {} projects have no required lockfile to check",
            descriptor.manifest_label
        );
    };
    ensure_lockfile_readable(lockfile, help)
}

/// A lockfile that pins packages while the manifest declares none means the declarations were missed.
pub(super) fn ensure_no_locked_packages_without_declarations(
    spec: &ProjectInputSpec,
    deps: &[Dependency],
) -> Result<()> {
    if !deps.is_empty() {
        return Ok(());
    }
    let locked = lockfiles::LockfileData::parse_for_kind_with_lockfile_and_profile(
        spec.project_dir(),
        Some(spec.kind.lockfile_kind()),
        deps,
        spec.lockfile_path_override.as_deref(),
        None,
    )?;
    if !locked.transitive_deps.is_empty() {
        anyhow::bail!(
            "Scan not supported: '{}' has locked packages but no supported direct dependency declarations",
            spec.manifest_path.display()
        );
    }
    Ok(())
}

/// The lockfile must parse as JSON.
pub(super) fn read_json_lockfile(path: &Path) -> Result<serde_json::Value> {
    let content = parsers::read_file_limited(path, parsers::MAX_MANIFEST_BYTES)?;
    serde_json::from_str::<serde_json::Value>(&content).map_err(|err| {
        anyhow::anyhow!(
            "Broken lockfile '{}': failed to parse JSON: {}",
            path.display(),
            err
        )
    })
}

/// The lockfile the descriptor names for this kind, next to its manifest.
pub(super) fn named_lockfile(spec: &ProjectInputSpec) -> Option<PathBuf> {
    spec.kind
        .descriptor()
        .lockfile_name
        .map(|name| spec.manifest_path.with_file_name(name))
}

/// The kind among `kinds` whose descriptor lists the manifest's exact file name.
pub(super) fn kind_for_file_name(
    kinds: &[ProjectInputKind],
    path: &Path,
) -> Option<ProjectInputKind> {
    let name = path.file_name()?.to_str()?;
    kinds
        .iter()
        .copied()
        .find(|kind| kind.descriptor().manifest_file_names.contains(&name))
}
