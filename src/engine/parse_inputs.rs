use crate::*;

#[cfg(test)]
pub(crate) fn parse_project_inputs(
    scan_root: &std::path::Path,
    specs: &[ProjectInputSpec],
    config: &config::SloppyJoeConfig,
) -> Result<Vec<ParsedProject>> {
    parse_project_inputs_with_options(scan_root, specs, config, &ScanOptions::default())
}

pub(crate) fn parse_project_inputs_with_options(
    scan_root: &std::path::Path,
    specs: &[ProjectInputSpec],
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> Result<Vec<ParsedProject>> {
    let mut projects = Vec::new();
    for spec in specs {
        let parsed = parse_project_input_with_config(scan_root, spec, config, opts)?;
        projects.push(ParsedProject {
            spec: spec.clone(),
            deps: parsed.deps,
            python_root_extras: parsed.python_root_extras,
            unlocked_tooling: false,
            package_indexes: parsed.package_indexes.clone(),
        });
        let tooling_groups = ecosystems::tooling_groups(spec.kind, parsed.unlocked_tooling_deps);
        for tooling_deps in tooling_groups.into_iter().filter(|deps| !deps.is_empty()) {
            // The manifest's indexes serve its tooling too.
            projects.push(ParsedProject {
                spec: spec.clone(),
                deps: tooling_deps,
                python_root_extras: PythonRootExtras::new(),
                unlocked_tooling: true,
                package_indexes: parsed.package_indexes.clone(),
            });
        }
    }
    Ok(projects)
}

pub(crate) fn parse_project_input_with_config(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
    config: &config::SloppyJoeConfig,
    opts: &ScanOptions<'_>,
) -> Result<ParsedInput> {
    let ctx = ecosystems::ScanCtx {
        scan_root,
        config,
        opts,
    };
    ecosystems::for_kind(spec.kind).parse(&ctx, spec)
}

#[cfg(test)]
pub(crate) fn parse_project_input(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
) -> Result<Vec<Dependency>> {
    ecosystems::for_kind(spec.kind).parse_manifest(scan_root, spec)
}

pub(crate) fn lockfile_paths_for_project(spec: &ProjectInputSpec) -> Vec<std::path::PathBuf> {
    selected_lockfile_path(spec).into_iter().collect()
}
