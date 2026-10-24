use crate::*;

pub(crate) fn npm_dependency_entries(manifest: &serde_json::Value) -> Vec<(String, String)> {
    [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ]
    .into_iter()
    .flat_map(|section| {
        manifest
            .get(section)
            .and_then(|value| value.as_object())
            .into_iter()
            .flat_map(|section| section.iter())
            .filter_map(|(name, value)| value.as_str().map(|spec| (name.clone(), spec.to_string())))
    })
    .collect()
}

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
        });
        let tooling_groups = ecosystems::tooling_groups(spec.kind, parsed.unlocked_tooling_deps);
        for tooling_deps in tooling_groups.into_iter().filter(|deps| !deps.is_empty()) {
            projects.push(ParsedProject {
                spec: spec.clone(),
                deps: tooling_deps,
                python_root_extras: PythonRootExtras::new(),
                unlocked_tooling: true,
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

pub(crate) fn parse_project_input(
    scan_root: &std::path::Path,
    spec: &ProjectInputSpec,
) -> Result<Vec<Dependency>> {
    ecosystems::for_kind(spec.kind).parse_manifest(scan_root, spec)
}

pub(crate) fn js_lockfile_help(spec: &ProjectInputSpec) -> String {
    match spec.js_binding.as_ref().map(|binding| binding.manager) {
        Some(JsPackageManager::Pnpm) => {
            "Run `pnpm install --lockfile-only` and commit pnpm-lock.yaml.".to_string()
        }
        Some(JsPackageManager::Yarn) => {
            "Commit the authoritative yarn.lock for this project.".to_string()
        }
        Some(JsPackageManager::Bun) => {
            "Commit the authoritative bun.lock or bun.lockb for this project.".to_string()
        }
        _ => spec
            .kind
            .missing_lockfile_help()
            .unwrap_or("Commit the authoritative lockfile for this project.")
            .to_string(),
    }
}

pub(crate) fn lockfile_paths_for_project(spec: &ProjectInputSpec) -> Vec<std::path::PathBuf> {
    selected_lockfile_path(spec).into_iter().collect()
}
